"""Operator lifecycle operations for an installed setup."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, cast

from signet.attachment_crypto import AttachmentCipher
from signet.backup import (
    BackupBundleManager,
    BackupError,
    RestoredBundle,
    remove_private_tree_checked,
)
from signet.credential_broker import KeychainSecretStore, SecretReference
from signet.db import Database
from signet.private_paths import PrivatePathError, ensure_private_directory
from signet.production import create_production_assembly, load_production_config
from signet.production_state import ProductionStateStore
from signet.setup_platform import ProductionSetupPlatform
from signet.setup_state import (
    PolicyMode,
    SetupEngine,
    SetupError,
    SetupJournal,
    SetupJournalStore,
    SetupSpec,
)
from signet.staging import StagingStore


class SetupOperations:
    def __init__(
        self,
        root: Path,
        *,
        platform: ProductionSetupPlatform | None = None,
    ) -> None:
        self.root = root
        self.store = SetupJournalStore(root)
        self.platform = platform or ProductionSetupPlatform()

    def spec(self) -> SetupSpec:
        journal = self.store.load()
        try:
            document = journal.spec
            return SetupSpec(
                root=Path(document["root"]),
                public_origin=str(document["public_origin"]),
                owner_user_id=str(document["owner_user_id"]),
                hermes_profiles=tuple(str(value) for value in document["hermes_profiles"]),
                executable=Path(document["executable"]),
                open_browser=bool(document["open_browser"]),
                policy_mode=cast(PolicyMode, document.get("policy_mode", "deny")),
            )
        except (KeyError, TypeError, ValueError):
            raise SetupError("setup journal specification is invalid") from None

    def status(self) -> dict[str, Any]:
        journal = self.store.load()
        result: dict[str, Any] = {
            "setup_id": journal.setup_id,
            "setup_status": journal.status,
            "steps": {step.name: step.status for step in journal.steps},
            "provider_rollout": "disabled",
            "services": self.platform.service_status(self.spec()),
        }
        try:
            config = load_production_config(self.root / "production.json")
            database_path = config.storage.database_path
            if database_path.is_symlink() or not database_path.is_file():
                raise SetupError("production database is unavailable for read-only inspection")
            production = ProductionStateStore(
                Database(database_path),
                provider_rollout_enabled=config.provider_rollout.state == "enabled",
            ).status(read_only=True)
            result["provider_rollout"] = config.provider_rollout.state
        except Exception as exc:
            result["production"] = {
                "available": False,
                "error_kind": type(exc).__name__,
            }
        else:
            result["production"] = {
                "available": True,
                "ready": production.ready,
                "missing_prerequisites": list(production.missing_prerequisites),
                "live_providers_ready": production.live_providers_ready,
                "services": {
                    name: {
                        "kind": service.kind,
                        "state": service.state,
                        "host": service.host,
                        "port": service.port,
                        "updated_at": service.updated_at,
                    }
                    for name, service in production.services.items()
                },
            }
        return result

    def doctor(self) -> dict[str, Any]:
        checks: dict[str, dict[str, Any]] = {}
        try:
            journal = self.store.load()
        except Exception as exc:
            checks["journal"] = _failed_check(exc)
            return {"healthy": False, "checks": checks}
        checks["journal"] = {"ok": journal.status == "completed", "status": journal.status}
        try:
            config = load_production_config(self.root / "production.json")
        except Exception as exc:
            checks["configuration"] = _failed_check(exc)
        else:
            checks["configuration"] = {
                "ok": True,
                "provider_rollout": config.provider_rollout.state,
                "connector_count": len(config.connectors),
            }
            store = KeychainSecretStore()
            missing: list[str] = []
            for reference in config.secrets.model_dump().values():
                if reference is None:
                    continue
                try:
                    store.get(SecretReference.parse(reference))
                except Exception:
                    missing.append(reference.rsplit("/", 1)[-1].split("-", 1)[-1])
            checks["secrets"] = {"ok": not missing, "missing_purposes": sorted(missing)}
        services = self.platform.service_status(self.spec())
        checks["services"] = {
            "ok": bool(services) and all(status == "active" for status in services.values()),
            "status": services,
        }
        checks["hermes_reload"] = {
            "ok": False,
            "manual_action": (
                "Review each configured MCP entry, then run /reload-mcp in each profile."
            ),
            "profiles": list(self.spec().hermes_profiles),
        }
        return {
            "healthy": all(
                check["ok"] for name, check in checks.items() if name != "hermes_reload"
            ),
            "checks": checks,
        }

    def backup(self, destination: Path | None = None) -> Path:
        journal = self.store.load()
        manager = self._backup_manager(journal)
        selected = destination or (
            self.root
            / "backups"
            / (
                time.strftime("signet-%Y%m%dT%H%M%SZ-", time.gmtime())
                + secrets.token_hex(4)
                + ".signet-backup"
            )
        )
        if not selected.is_absolute() or ".." in selected.parts:
            raise SetupError("backup destination must be an absolute lexical path")
        try:
            return manager.create(selected)
        except BackupError as exc:
            raise SetupError(str(exc)) from exc

    def restore(self, bundle: Path) -> RestoredBundle:
        if not bundle.is_absolute() or ".." in bundle.parts:
            raise SetupError("restore bundle must be an absolute lexical path")
        journal = self.store.load()
        destination = self.root / "restore" / f"restore-{secrets.token_hex(8)}"
        try:
            return self._backup_manager(journal).restore(bundle, destination)
        except BackupError as exc:
            raise SetupError(str(exc)) from exc

    def upgrade(self) -> dict[str, Any]:
        backup = self.backup()
        backup_receipt = self._verified_backup_receipt(backup)
        # Reassembly performs locked schema migrations only after the verified backup above.
        assembly = create_production_assembly(
            self.root / "production.json",
            secret_store=KeychainSecretStore(),
            components=frozenset(),
        )
        return {
            "backup": str(backup),
            "backup_receipt": backup_receipt,
            "schema_version": assembly.status().schema_version,
            "provider_rollout": assembly.config.provider_rollout.state,
        }

    def uninstall(self, *, purge: bool = False) -> dict[str, Any]:
        spec = self.spec()
        backup: Path | None = None
        backup_receipt: dict[str, Any] | None = None
        recovery_receipt: Path | None = None
        if purge:
            journal = self.store.load()
            recovery_directory = self.root.parent / f"{self.root.name}-recovery"
            try:
                recovery_directory.mkdir(mode=0o700, exist_ok=True)
                ensure_private_directory(recovery_directory)
            except (OSError, PrivatePathError) as exc:
                raise SetupError("purge recovery directory is unavailable or unsafe") from exc
            backup = self.backup(
                recovery_directory
                / (
                    time.strftime("purge-%Y%m%dT%H%M%SZ-", time.gmtime())
                    + secrets.token_hex(4)
                    + ".signet-backup"
                )
            )
            backup_receipt = self._verified_backup_receipt(backup)
            recovery_receipt = recovery_directory / (
                f"recovery-{journal.setup_id}-{secrets.token_hex(4)}.json"
            )
            _write_private_json(
                recovery_receipt,
                {
                    "format": 1,
                    "setup_id": journal.setup_id,
                    "backup_path": str(backup),
                    "backup_sha256": backup_receipt["artifact_sha256"],
                    "source_schema_version": backup_receipt["source_schema_version"],
                    "verified_restore_schema_version": backup_receipt[
                        "verified_restore_schema_version"
                    ],
                    "required_key_accounts": [
                        f"{journal.setup_id}-{purpose}"
                        for purpose in ("capability", "payload", "attachment", "backup")
                    ],
                },
            )
        engine = SetupEngine(self.store, self.platform)
        if purge:
            assert backup is not None
            assert recovery_receipt is not None
            journal = engine.rollback(spec)
            removed = [record.name for record in reversed(journal.steps)]
        else:
            removed = ["owner_bootstrap", "hermes_profiles", "services"]
            engine.rollback_steps(
                spec,
                removed,
                final_status="uninstalled",
            )
        result: dict[str, Any] = {"purged": purge, "removed": removed}
        if purge:
            result.update(
                {
                    "backup": str(backup),
                    "backup_key_preserved": True,
                    "backup_receipt": backup_receipt,
                    "recovery_receipt": str(recovery_receipt),
                }
            )
        else:
            result["data_preserved_at"] = str(self.root)
        return result

    def manage(self, action: str) -> dict[str, str]:
        if action not in {"start", "stop", "restart"}:
            raise SetupError("service action must be start, stop, or restart")
        self.platform.manage_services(self.spec(), action)
        return self.platform.service_status(self.spec())

    def _verified_backup_receipt(self, bundle: Path) -> dict[str, Any]:
        manager = self._backup_manager(self.store.load())
        with manager.database.read_only() as connection:
            source_schema_version = int(
                connection.execute("PRAGMA user_version").fetchone()[0]
            )
        restored: RestoredBundle | None = None
        try:
            restored = manager.restore(
                bundle,
                self.root / "restore" / f"verify-{secrets.token_hex(8)}",
            )
            with Database(restored.database_path).read_only() as connection:
                restored_schema_version = int(
                    connection.execute("PRAGMA user_version").fetchone()[0]
                )
            if (
                restored.manifest.get("schema_version") != source_schema_version
                or restored_schema_version != source_schema_version
            ):
                raise SetupError("backup verification schema version is inconsistent")
        except BackupError as exc:
            raise SetupError("backup verification restore did not complete") from exc
        finally:
            if restored is not None:
                try:
                    remove_private_tree_checked(
                        restored.root,
                        parent_identity=restored.parent_identity,
                        tree_identity=restored.root_identity,
                    )
                except Exception as exc:
                    raise SetupError(
                        "backup verification completed, but cleanup could not be confirmed"
                    ) from exc
        return {
            "artifact_path": str(bundle),
            "artifact_sha256": _file_sha256(bundle),
            "source_schema_version": source_schema_version,
            "verified_restore_schema_version": source_schema_version,
        }

    def _backup_manager(self, journal: SetupJournal) -> BackupBundleManager:
        secret_store = KeychainSecretStore()
        backup_reference = SecretReference.parse(
            f"keychain://Signet-Setup/{journal.setup_id}-backup"
        )
        attachment_reference_value = f"keychain://Signet-Setup/{journal.setup_id}-attachment"
        attachment_reference = SecretReference.parse(attachment_reference_value)
        try:
            backup_secret = secret_store.get(backup_reference)
            attachment_secret = secret_store.get(attachment_reference)
        except Exception as exc:
            raise SetupError("backup recovery secrets are unavailable") from exc
        database = Database(self.root / "data" / "signet.db")
        staging = StagingStore(
            self.root / "staging",
            database=database,
            cipher=AttachmentCipher(attachment_secret, attachment_reference_value),
        )
        encryption_key = hashlib.sha256(backup_secret.reveal().encode("utf-8")).digest()
        return BackupBundleManager(
            database,
            staging=staging,
            encryption_key=encryption_key,
        )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        with os.fdopen(descriptor, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise SetupError("backup artifact is unavailable for receipt verification") from exc
    return digest.hexdigest()


def _write_private_json(path: Path, document: dict[str, Any]) -> None:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as destination:
            descriptor = None
            destination.write(encoded)
            destination.flush()
            os.fsync(destination.fileno())
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise SetupError("purge recovery receipt could not be written durably") from exc


def _failed_check(exc: Exception) -> dict[str, Any]:
    return {"ok": False, "error_kind": type(exc).__name__}
