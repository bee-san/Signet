"""Operator lifecycle operations for an installed setup."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
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
from signet.private_paths import (
    PrivatePathError,
    ensure_private_directory,
    require_no_acl_grants,
)
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
        engine = SetupEngine(self.store, self.platform)
        backup: Path | None = None
        backup_receipt: dict[str, Any] | None = None
        recovery_receipt: Path | None = None
        if purge:
            journal = self.store.load()
            self._require_recovery_secrets(journal)
            recovery_directory = self.root.parent / f"{self.root.name}-recovery"
            try:
                recovery_directory.mkdir(mode=0o700, exist_ok=True)
                ensure_private_directory(recovery_directory)
                _fsync_directory(recovery_directory.parent)
            except (OSError, PrivatePathError) as exc:
                raise SetupError("purge recovery directory is unavailable or unsafe") from exc

            if journal.purge_backup is not None:
                _require_purge_checkpoint_epoch(journal)
                backup, recovery_receipt, backup_receipt = _verify_purge_checkpoint(
                    journal.purge_backup,
                    recovery_directory,
                    setup_id=journal.setup_id,
                )
                resumed = engine.rollback(spec)
                return {
                    "purged": True,
                    "removed": [record.name for record in reversed(resumed.steps)],
                    "backup": str(backup),
                    "backup_key_preserved": True,
                    "backup_receipt": backup_receipt,
                    "recovery_receipt": str(recovery_receipt),
                }

            resume_quiesced_services = journal.status != "uninstalled"
            journal = engine.quiesce_services_for_purge(spec)
            try:
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
                journal.purge_backup = _build_purge_checkpoint(
                    recovery_directory,
                    backup,
                    recovery_receipt,
                    backup_receipt,
                    setup_id=journal.setup_id,
                )
                self.store.save(journal)
            except Exception as backup_exc:
                if not resume_quiesced_services:
                    raise
                try:
                    engine.apply(spec)
                except Exception as resume_exc:
                    raise SetupError(
                        f"{backup_exc}; managed services could not be resumed"
                    ) from resume_exc
                raise

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
        if action != "stop" and self.store.load().purge_backup is not None:
            raise SetupError(
                "a durable purge checkpoint exists; finish purge or rerun setup "
                "before starting services"
            )
        self.platform.manage_services(self.spec(), action)
        return self.platform.service_status(self.spec())

    def _require_recovery_secrets(self, journal: SetupJournal) -> None:
        references = [
            SecretReference(
                service="Signet-Setup",
                account=f"{journal.setup_id}-{purpose}",
            )
            for purpose in ("capability", "payload", "attachment", "backup")
        ]
        self._require_secret_references(references)

    @staticmethod
    def _require_secret_references(references: list[SecretReference]) -> None:
        store = KeychainSecretStore()
        for reference in references:
            try:
                secret = store.get(reference)
            except Exception as exc:
                raise SetupError("a required purge recovery secret is unavailable") from exc
            if not secret.reveal():
                raise SetupError("a required purge recovery secret is empty")

    def _verified_backup_receipt(self, bundle: Path) -> dict[str, Any]:
        manager = self._backup_manager(self.store.load())
        with manager.database.read_only() as connection:
            source_schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        restored: RestoredBundle | None = None
        try:
            restored = manager.restore(
                bundle,
                self.root / "restore" / f"verify-{secrets.token_hex(8)}",
            )
            raw_references = restored.manifest.get("key_references")
            if not isinstance(raw_references, list) or not all(
                isinstance(reference, str) for reference in raw_references
            ):
                raise SetupError("backup recovery key inventory is invalid")
            try:
                references = [SecretReference.parse(reference) for reference in raw_references]
            except Exception as exc:
                raise SetupError("backup recovery key inventory is invalid") from exc
            self._require_secret_references(references)
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


def _fsync_directory(path: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        os.fsync(descriptor)
    except OSError as exc:
        raise SetupError(f"recovery directory parent could not be made durable: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require_purge_checkpoint_epoch(journal: SetupJournal) -> None:
    if (
        journal.status not in {"failed", "rolling_back", "rollback_failed", "rolled_back"}
        or journal.step("services").status != "rolled_back"
    ):
        raise SetupError("purge checkpoint is stale because managed writers are not quiesced")


def _private_file_checkpoint(path: Path) -> dict[str, Any]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        before = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
    except (OSError, PrivatePathError) as exc:
        raise SetupError("purge recovery checkpoint file is unavailable or unsafe") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != current_uid
        or stat.S_IMODE(before.st_mode) != 0o600
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or identity != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
    ):
        raise SetupError("purge recovery checkpoint file changed during inspection")
    return {
        "path": str(path),
        "sha256": digest.hexdigest(),
        "device": before.st_dev,
        "inode": before.st_ino,
        "owner_uid": before.st_uid,
        "mode": stat.S_IMODE(before.st_mode),
        "nlink": before.st_nlink,
        "size": before.st_size,
        "mtime_ns": before.st_mtime_ns,
    }


def _verify_private_file_checkpoint(document: Any, recovery_directory: Path) -> Path:
    keys = {
        "path",
        "sha256",
        "device",
        "inode",
        "owner_uid",
        "mode",
        "nlink",
        "size",
        "mtime_ns",
    }
    if not isinstance(document, dict) or set(document) != keys:
        raise SetupError("purge recovery checkpoint is invalid")
    path = Path(document["path"])
    if not path.is_absolute() or path.parent != recovery_directory:
        raise SetupError("purge recovery checkpoint path is invalid")
    actual = _private_file_checkpoint(path)
    if actual != document:
        raise SetupError("purge recovery checkpoint file identity or digest changed")
    return path


def _file_sha256(path: Path) -> str:
    return str(_private_file_checkpoint(path)["sha256"])


def _build_purge_checkpoint(
    recovery_directory: Path,
    backup: Path,
    recovery_receipt: Path,
    backup_receipt: dict[str, Any],
    *,
    setup_id: str,
) -> dict[str, Any]:
    backup_file = _private_file_checkpoint(backup)
    receipt_file = _private_file_checkpoint(recovery_receipt)
    if (
        backup_receipt.get("artifact_path") != str(backup)
        or backup_receipt.get("artifact_sha256") != backup_file["sha256"]
    ):
        raise SetupError("purge recovery checkpoint does not match the verified backup")
    return {
        "version": 1,
        "setup_id": setup_id,
        "recovery_directory": str(recovery_directory),
        "backup": backup_file,
        "recovery_receipt": receipt_file,
        "backup_receipt": dict(backup_receipt),
    }


def _verify_purge_checkpoint(
    checkpoint: Any,
    recovery_directory: Path,
    *,
    setup_id: str,
) -> tuple[Path, Path, dict[str, Any]]:
    if not isinstance(checkpoint, dict) or set(checkpoint) != {
        "version",
        "setup_id",
        "recovery_directory",
        "backup",
        "recovery_receipt",
        "backup_receipt",
    }:
        raise SetupError("purge recovery checkpoint is invalid")
    if (
        checkpoint["version"] != 1
        or checkpoint["setup_id"] != setup_id
        or checkpoint["recovery_directory"] != str(recovery_directory)
    ):
        raise SetupError("purge recovery checkpoint is invalid")
    backup = _verify_private_file_checkpoint(checkpoint["backup"], recovery_directory)
    receipt = _verify_private_file_checkpoint(checkpoint["recovery_receipt"], recovery_directory)
    backup_receipt = checkpoint["backup_receipt"]
    if not isinstance(backup_receipt, dict) or (
        backup_receipt.get("artifact_path") != str(backup)
        or backup_receipt.get("artifact_sha256") != checkpoint["backup"]["sha256"]
    ):
        raise SetupError("purge recovery checkpoint receipt is invalid")
    try:
        receipt_document = json.loads(receipt.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise SetupError("purge recovery checkpoint receipt is invalid") from exc
    expected_key_accounts = [
        f"{setup_id}-{purpose}" for purpose in ("capability", "payload", "attachment", "backup")
    ]
    if (
        not isinstance(receipt_document, dict)
        or receipt_document.get("setup_id") != setup_id
        or receipt_document.get("backup_path") != str(backup)
        or receipt_document.get("backup_sha256") != checkpoint["backup"]["sha256"]
        or receipt_document.get("required_key_accounts") != expected_key_accounts
    ):
        raise SetupError("purge recovery checkpoint receipt is invalid")
    return backup, receipt, dict(backup_receipt)


def _write_private_json(path: Path, document: dict[str, Any]) -> None:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
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
