"""Operator lifecycle operations for an installed setup."""

from __future__ import annotations

import hashlib
import secrets
import time
from pathlib import Path
from typing import Any, cast

from signet.attachment_crypto import AttachmentCipher
from signet.backup import BackupBundleManager, BackupError, RestoredBundle
from signet.credential_broker import KeychainSecretStore, SecretReference
from signet.db import Database
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
        # Reassembly performs locked schema migrations only after the verified backup above.
        assembly = create_production_assembly(
            self.root / "production.json",
            secret_store=KeychainSecretStore(),
            components=frozenset(),
        )
        return {
            "backup": str(backup),
            "schema_version": assembly.status().schema_version,
            "provider_rollout": assembly.config.provider_rollout.state,
        }

    def uninstall(self, *, purge: bool = False) -> dict[str, Any]:
        spec = self.spec()
        backup = self.backup() if purge else None
        engine = SetupEngine(self.store, self.platform)
        if purge:
            assert backup is not None
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


def _failed_check(exc: Exception) -> dict[str, Any]:
    return {"ok": False, "error_kind": type(exc).__name__}
