"""Operator lifecycle operations for an installed setup."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
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
from signet.crypto import PayloadCipher
from signet.db import LATEST_SCHEMA_VERSION, Database, DatabaseError, MigrationBackupReceipt
from signet.private_paths import (
    PrivatePathError,
    ensure_private_directory,
    require_no_acl_grants,
)
from signet.production import (
    ProductionAssemblyError,
    create_production_assembly,
    load_production_config,
)
from signet.production_state import ProductionStateStore
from signet.setup_platform import (
    ProductionSetupPlatform,
    _replace_private_file,
    validate_active_database_runtime_ownership,
)
from signet.setup_state import (
    PolicyMode,
    SetupEngine,
    SetupError,
    SetupJournal,
    SetupJournalStore,
    SetupSpec,
)
from signet.staging import StagingStore


@contextmanager
def setup_lifecycle_lock(root_path: Path) -> Iterator[None]:
    descriptor = -1
    try:
        root = ensure_private_directory(root_path)
        descriptor = os.open(
            root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        require_no_acl_grants(descriptor)
    except (OSError, PrivatePathError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise SetupError("setup lifecycle lock is unavailable or unsafe") from exc
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SetupError("another setup lifecycle operation is in progress") from None
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


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

    @contextmanager
    def lifecycle_lock(self) -> Iterator[None]:
        with setup_lifecycle_lock(self.root):
            yield

    @contextmanager
    def _use_database(self, database: Database) -> Iterator[None]:
        override = getattr(self.platform, "use_database", None)
        if override is None:
            yield
            return
        with override(database):
            yield

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
            expected_identity, expected_lock_identity = validate_active_database_runtime_ownership(
                database_path.parent,
                setup_id=journal.setup_id,
            )
            production = ProductionStateStore(
                Database(
                    database_path,
                    expected_identity=expected_identity,
                    expected_lock_identity=expected_lock_identity,
                ),
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
        with self.lifecycle_lock():
            return self._backup(destination)

    def _backup(
        self,
        destination: Path | None = None,
        *,
        manager: BackupBundleManager | None = None,
    ) -> Path:
        journal = self.store.load()
        SetupEngine(self.store, self.platform).validate_private_paths(self.spec(), journal=journal)
        if journal.purge_backup is not None:
            raise SetupError(
                "a durable purge checkpoint exists; finish purge before creating another backup"
            )
        manager = manager or self._backup_manager(journal)
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
            return manager.create(
                selected,
                required_key_references=self._production_key_references(),
            )
        except BackupError as exc:
            raise SetupError(str(exc)) from exc

    def restore(self, bundle: Path) -> RestoredBundle:
        with self.lifecycle_lock():
            return self._restore(bundle)

    def _restore(self, bundle: Path) -> RestoredBundle:
        if not bundle.is_absolute() or ".." in bundle.parts:
            raise SetupError("restore bundle must be an absolute lexical path")
        journal = self.store.load()
        SetupEngine(self.store, self.platform).validate_private_paths(self.spec(), journal=journal)
        destination = self.root / "restore" / f"restore-{secrets.token_hex(8)}"
        manager = self._backup_manager(journal)
        restored: RestoredBundle | None = None
        try:
            restored = manager.restore(bundle, destination)
            if restored.manifest.get("format") == 3:
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
                manager.require_key_identities(restored.manifest)
                self._verify_restored_private_records(restored.database_path)
            return restored
        except BaseException as exc:
            if restored is not None:
                try:
                    remove_private_tree_checked(
                        restored.root,
                        parent_identity=restored.parent_identity,
                        tree_identity=restored.root_identity,
                    )
                except Exception as cleanup_exc:
                    raise SetupError(
                        "restore validation failed and cleanup could not be confirmed"
                    ) from cleanup_exc
            if isinstance(exc, BackupError):
                raise SetupError(str(exc)) from exc
            raise

    def upgrade(self) -> dict[str, Any]:
        with self.lifecycle_lock():
            return self._upgrade()

    def _upgrade(self) -> dict[str, Any]:
        spec = self.spec()
        journal = self.store.load()
        self.platform.preflight(spec)
        SetupEngine(self.store, self.platform).validate_private_paths(spec, journal=journal)
        initial_status = self.platform.service_status(spec)
        local_services = {
            name: state
            for name, state in initial_status.items()
            if not name.startswith("tailscale:")
        }
        if len(local_services) != 2 or any(
            state not in {"active", "inactive"} for state in local_services.values()
        ):
            raise SetupError("upgrade could not determine the prior Signet service state")
        prior_active = all(state == "active" for state in local_services.values())
        if not prior_active and any(state != "inactive" for state in local_services.values()):
            raise SetupError("upgrade refuses to change a mixed Signet service state")
        stop_attempted = False
        migration_receipt: Any | None = None
        upgrade_receipt: Path | None = None
        schema_version: int | None = None
        assembly: Any | None = None
        recovery_directory = spec.root.parent / f"{spec.root.name}-recovery"
        try:
            if prior_active:
                stop_attempted = True
                self._stop_and_verify_services(spec)
            manager = self._backup_manager(journal)
            recovery_directory.mkdir(mode=0o700, exist_ok=True)
            ensure_private_directory(recovery_directory)
            _fsync_directory(recovery_directory.parent)
            database = manager.database
            expected_database_path = (spec.root / "data" / "signet.db").absolute()
            if database.path != expected_database_path:
                raise SetupError("upgrade backup manager targets the wrong database")
            with database.read_only() as connection:
                current_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current_version <= 0 or current_version > LATEST_SCHEMA_VERSION:
                raise SetupError("upgrade source schema version is unsupported")
            callback = manager.create_pre_migration_callback(
                recovery_directory,
                required_key_references=self._production_key_references(),
                verify_restored=self._verify_restored_private_records,
            )

            def capture_verified_backup(candidate: Database, version: int) -> Any:
                nonlocal migration_receipt, upgrade_receipt
                if migration_receipt is not None:
                    raise SetupError("upgrade migration backup callback ran more than once")
                if candidate is not database:
                    raise SetupError("upgrade migration and backup sources are not identical")
                receipt = callback(candidate, version)
                upgrade_receipt = _write_upgrade_recovery_receipt(
                    recovery_directory,
                    journal=journal,
                    migration_receipt=receipt,
                    observed_schema_version=version,
                    state="backup_verified_migration_pending",
                )
                migration_receipt = receipt
                return receipt

            if current_version == LATEST_SCHEMA_VERSION:
                with database.migration_backup_source():
                    capture_verified_backup(database, current_version)
            assembly = create_production_assembly(
                self.root / "production.json",
                secret_store=KeychainSecretStore(),
                pre_migration_backup=capture_verified_backup,
                components=frozenset(),
                database_override=database,
            )
            if migration_receipt is None:
                raise SetupError("upgrade did not produce a verified migration backup")
            schema_version = int(assembly.status().schema_version)
            upgrade_receipt = _write_upgrade_recovery_receipt(
                recovery_directory,
                journal=journal,
                migration_receipt=migration_receipt,
                observed_schema_version=schema_version,
                state="migration_applied",
            )
            if prior_active:
                self._restart_services_after_upgrade(spec)
        except BaseException as exc:
            if migration_receipt is not None:
                try:
                    with database.read_only() as connection:
                        observed_schema_version = int(
                            connection.execute("PRAGMA user_version").fetchone()[0]
                        )
                    upgrade_receipt = _write_upgrade_recovery_receipt(
                        recovery_directory,
                        journal=journal,
                        migration_receipt=migration_receipt,
                        observed_schema_version=observed_schema_version,
                        state="assembly_failed_after_backup",
                    )
                except Exception as receipt_exc:
                    if hasattr(exc, "add_note"):
                        exc.add_note(
                            "upgrade recovery receipt failed: "
                            f"{type(receipt_exc).__name__}: {receipt_exc}"
                        )
            if stop_attempted and migration_receipt is None:
                try:
                    self._restart_services_after_upgrade(spec)
                except BaseException as recovery_exc:
                    if isinstance(exc, Exception):
                        exc.add_note(
                            "The pre-upgrade service state could not be restored; Signet may be "
                            "partially stopped."
                        )
                    raise SetupError(
                        "upgrade failed before migration, and services could not be safely resumed"
                    ) from recovery_exc
            if isinstance(exc, (BackupError, ProductionAssemblyError)):
                raise SetupError(str(exc)) from exc
            raise
        assert migration_receipt is not None
        assert upgrade_receipt is not None
        assert schema_version is not None
        assert assembly is not None
        return {
            "backup": str(migration_receipt.artifact_path),
            "upgrade_receipt": str(upgrade_receipt),
            "backup_receipt": {
                "artifact_path": str(migration_receipt.artifact_path),
                "artifact_sha256": migration_receipt.artifact_sha256,
                "source_schema_version": migration_receipt.source_schema_version,
                "verified_restore_schema_version": (
                    migration_receipt.verified_restore_schema_version
                ),
            },
            "schema_version": schema_version,
            "provider_rollout": assembly.config.provider_rollout.state,
        }

    def _stop_and_verify_services(self, spec: SetupSpec) -> None:
        self.platform.manage_services(spec, "stop")
        stopped = self.platform.service_status(spec)
        local_services = {
            name: state for name, state in stopped.items() if not name.startswith("tailscale:")
        }
        if len(local_services) != 2 or any(
            state != "inactive" for state in local_services.values()
        ):
            raise SetupError("upgrade requires every Signet service to be inactive")

    def _restart_services_after_upgrade(self, spec: SetupSpec) -> None:
        try:
            self.platform.manage_services(spec, "start")
            started = self.platform.service_status(spec)
            local_services = {
                name: state for name, state in started.items() if not name.startswith("tailscale:")
            }
            if (
                len(local_services) != 2
                or any(state != "active" for state in local_services.values())
                or any(state != "active" for state in started.values())
            ):
                raise SetupError("upgrade completed but Signet services did not all restart")
            self.platform.verify_service_health(spec)
        except BaseException as start_exc:
            try:
                self.platform.manage_services(spec, "stop")
                stopped = self.platform.service_status(spec)
                local_services = {
                    name: state
                    for name, state in stopped.items()
                    if not name.startswith("tailscale:")
                }
                if len(local_services) != 2 or any(
                    state != "inactive" for state in local_services.values()
                ):
                    raise SetupError("not every local Signet service is inactive")
            except BaseException as stop_exc:
                raise SetupError(
                    "upgrade service restart failed and quiescence could not be confirmed"
                ) from stop_exc
            if not isinstance(start_exc, Exception):
                raise
            raise SetupError(
                "upgrade completed, but Signet services were left stopped after restart failed"
            ) from start_exc

    def uninstall(self, *, purge: bool = False) -> dict[str, Any]:
        with self.lifecycle_lock():
            return self._uninstall(purge=purge)

    def _uninstall(self, *, purge: bool = False) -> dict[str, Any]:
        spec = self.spec()
        engine = SetupEngine(self.store, self.platform)
        backup: Path | None = None
        backup_receipt: dict[str, Any] | None = None
        recovery_receipt: Path | None = None
        if purge:
            journal = self.store.load()
            engine.validate_private_paths(spec, journal=journal)
            all_non_service_steps_completed = all(
                record.status == "completed"
                for record in journal.steps
                if record.name != "services"
            )
            incomplete_install = (
                journal.status != "uninstalled" and not all_non_service_steps_completed
            )
            database_path = self.root / "data" / "signet.db"
            if journal.purge_backup is None and incomplete_install and not database_path.exists():
                removable = [
                    record.name
                    for record in reversed(journal.steps)
                    if record.status not in {"pending", "rolled_back"}
                ]
                engine.rollback(spec)
                return {"purged": True, "removed": removable}
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
                self._require_recovery_secrets(journal)
                manager = self._backup_manager(
                    journal,
                    staging_root=(
                        None
                        if database_path.exists()
                        else recovery_directory / ".verification-staging"
                    ),
                )
                if database_path.exists():
                    self._revoke_hermes_tokens_for_rollback(spec, journal.setup_id)
                    with manager.database.write_fence():
                        cryptographic_receipt = self._verified_backup_receipt(
                            backup,
                            expected_source_schema_version=int(
                                backup_receipt["source_schema_version"]
                            ),
                            manager=manager,
                            verify_live_database=True,
                            verification_parent=recovery_directory,
                        )
                        if cryptographic_receipt != backup_receipt:
                            raise SetupError(
                                "purge backup checkpoint no longer verifies cryptographically"
                            )
                        with self._use_database(manager.database):
                            resumed = engine.rollback_steps(
                                spec,
                                (
                                    "owner_bootstrap",
                                    "hermes_profiles",
                                    "services",
                                    "database",
                                ),
                                final_status="rolling_back",
                            )
                    resumed = engine.rollback_steps(
                        spec,
                        ("configuration", "secrets", "private_paths", "preflight"),
                        final_status="rolled_back",
                    )
                else:
                    cryptographic_receipt = self._verified_backup_receipt(
                        backup,
                        expected_source_schema_version=int(backup_receipt["source_schema_version"]),
                        manager=manager,
                        verify_live_database=False,
                        verification_parent=recovery_directory,
                        verify_runtime=False,
                    )
                    if cryptographic_receipt != backup_receipt:
                        raise SetupError(
                            "purge backup checkpoint no longer verifies cryptographically"
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

            self._require_recovery_secrets(journal)
            resume_quiesced_services = False
            service_rollback_started = journal.step("services").status in {
                "rolling_back",
                "rollback_failed",
                "rolled_back",
            }
            if (
                not incomplete_install
                and journal.status != "uninstalled"
                and not service_rollback_started
            ):
                service_status = self.platform.service_status(spec)
                local_services = {
                    name: state
                    for name, state in service_status.items()
                    if not name.startswith("tailscale:")
                }
                if len(local_services) != 2 or any(
                    state not in {"active", "inactive"} for state in local_services.values()
                ):
                    raise SetupError("purge could not determine the prior Signet service state")
                service_states = set(local_services.values())
                if len(service_states) != 1:
                    raise SetupError("purge refuses a mixed Signet service state")
                resume_quiesced_services = service_states == {"active"}
            if incomplete_install:
                if journal.step("services").status == "pending":
                    journal = engine.mark_pending_services_rolled_back_for_purge(spec)
                elif journal.step("services").status != "rolled_back":
                    journal = engine.rollback_steps(
                        spec,
                        ("services",),
                        final_status="rolling_back",
                    )
            else:
                journal = engine.quiesce_services_for_purge(spec)
            checkpoint_saved = False
            try:
                manager = self._backup_manager(journal)
                manager.require_live_key_references(self._production_key_references())
                with manager.database.write_fence():
                    backup = self._backup(
                        recovery_directory
                        / (
                            time.strftime("purge-%Y%m%dT%H%M%SZ-", time.gmtime())
                            + secrets.token_hex(4)
                            + ".signet-backup"
                        ),
                        manager=manager,
                    )
                    assert backup is not None
                    backup_receipt = self._verified_backup_receipt(
                        backup,
                        manager=manager,
                        verify_live_database=True,
                    )
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
                                for purpose in (
                                    "capability",
                                    "payload",
                                    "attachment",
                                    "backup",
                                )
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
                    checkpoint_saved = True
                    backup, recovery_receipt, verified_receipt = _verify_purge_checkpoint(
                        journal.purge_backup,
                        recovery_directory,
                        setup_id=journal.setup_id,
                    )
                    cryptographic_receipt = self._verified_backup_receipt(
                        backup,
                        expected_source_schema_version=int(
                            verified_receipt["source_schema_version"]
                        ),
                        manager=manager,
                        verify_live_database=True,
                    )
                    if cryptographic_receipt != verified_receipt:
                        raise SetupError(
                            "purge backup checkpoint no longer verifies cryptographically"
                        )
                    backup_receipt = verified_receipt
                try:
                    revocation_started = self._revoke_hermes_tokens_for_rollback(
                        spec, journal.setup_id
                    )
                except Exception:
                    resume_quiesced_services = False
                    raise
                if revocation_started:
                    resume_quiesced_services = False
                with manager.database.write_fence(), self._use_database(manager.database):
                    journal = engine.rollback_steps(
                        spec,
                        (
                            "owner_bootstrap",
                            "hermes_profiles",
                            "services",
                            "database",
                        ),
                        final_status="rolling_back",
                    )
                journal = engine.rollback_steps(
                    spec,
                    ("configuration", "secrets", "private_paths", "preflight"),
                    final_status="rolled_back",
                )
            except Exception as backup_exc:
                if checkpoint_saved or not resume_quiesced_services:
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
        with self.lifecycle_lock():
            return self._manage(action)

    def _manage(self, action: str) -> dict[str, str]:
        if action not in {"start", "stop", "restart"}:
            raise SetupError("service action must be start, stop, or restart")
        if action != "stop" and self.store.load().purge_backup is not None:
            raise SetupError(
                "a durable purge checkpoint exists; finish purge or rerun setup "
                "before starting services"
            )
        if action != "stop":
            journal = self.store.load()
            SetupEngine(self.store, self.platform).validate_private_paths(
                self.spec(),
                journal=journal,
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

    def _verified_backup_receipt(
        self,
        bundle: Path,
        *,
        expected_source_schema_version: int | None = None,
        manager: BackupBundleManager | None = None,
        verify_live_database: bool = False,
        verification_parent: Path | None = None,
        verify_runtime: bool = True,
    ) -> dict[str, Any]:
        manager = manager or self._backup_manager(self.store.load())
        if expected_source_schema_version is None:
            with manager.database.read_only() as connection:
                source_schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        else:
            source_schema_version = expected_source_schema_version
        restored: RestoredBundle | None = None
        restore_parent = verification_parent or (self.root / "restore")
        try:
            restored = manager.restore(
                bundle,
                restore_parent / f"verify-{secrets.token_hex(8)}",
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
            manager.require_key_identities(restored.manifest)
            with Database(restored.database_path).read_only() as connection:
                restored_schema_version = int(
                    connection.execute("PRAGMA user_version").fetchone()[0]
                )
            if (
                restored.manifest.get("schema_version") != source_schema_version
                or restored_schema_version != source_schema_version
            ):
                raise SetupError("backup verification schema version is inconsistent")
            if verify_live_database:
                expected_database_sha256 = restored.manifest.get("database_sha256")
                if not isinstance(expected_database_sha256, str):
                    raise SetupError("backup verification database digest is invalid")
                live_snapshot = manager.database.create_snapshot(
                    restored.root / "live-database.sqlite3"
                )
                try:
                    if _file_sha256(live_snapshot) != expected_database_sha256:
                        raise SetupError("live database changed after the purge backup snapshot")
                finally:
                    live_snapshot.unlink(missing_ok=True)
            if verify_runtime:
                self._verify_restored_runtime(restored)
            else:
                self._verify_restored_private_records(restored.database_path)
        except (BackupError, ProductionAssemblyError) as exc:
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

    def _verify_restored_runtime(self, restored: RestoredBundle) -> None:
        staging_directory = ensure_private_directory(restored.root / "runtime-staging")
        migration_snapshot = restored.root / "runtime-migration-backup.sqlite3"

        def snapshot_before_migration(
            database: Database,
            current_version: int,
        ) -> MigrationBackupReceipt:
            try:
                artifact = database.create_snapshot(migration_snapshot)
                Database.verify_snapshot(artifact)
            except (DatabaseError, OSError) as exc:
                raise SetupError("restored database migration backup failed") from exc
            source_device, source_inode = database.migration_source_identity()
            return MigrationBackupReceipt(
                database_path=database.path,
                artifact_path=artifact,
                source_schema_version=current_version,
                artifact_sha256=_file_sha256(artifact),
                verified_restore_schema_version=current_version,
                source_database_device=source_device,
                source_database_inode=source_inode,
            )

        create_production_assembly(
            self.root / "production.json",
            secret_store=KeychainSecretStore(),
            database_override=Database(restored.database_path),
            attachment_staging_override=staging_directory,
            attachment_source_roots_override=(restored.attachments_root,),
            pre_migration_backup=snapshot_before_migration,
            prepare_directories=False,
        )
        self._verify_restored_private_records(restored.database_path)

    @staticmethod
    def _verify_restored_private_records(database_path: Path) -> None:
        secrets_store = KeychainSecretStore()
        ciphers: dict[str, PayloadCipher] = {}

        def cipher(reference: str) -> PayloadCipher:
            selected = ciphers.get(reference)
            if selected is None:
                parsed = SecretReference.parse(reference)
                selected = PayloadCipher(secrets_store.get(parsed), reference)
                ciphers[reference] = selected
            return selected

        with Database(database_path).read_only() as connection:
            payloads = connection.execute(
                """
                SELECT request_id, version, encrypted_payload, payload_hash,
                       encryption_key_ref
                FROM payload_versions
                WHERE encrypted_payload IS NOT NULL AND purged_at IS NULL
                """
            ).fetchall()
            has_drafts = connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'web_action_drafts'"
            ).fetchone()
            drafts = (
                connection.execute(
                    """
                    SELECT request_id, version, edit_encrypted_payload,
                           edit_payload_hash, edit_encryption_key_ref
                    FROM web_action_drafts
                    WHERE edit_encrypted_payload IS NOT NULL
                    """
                ).fetchall()
                if has_drafts is not None
                else []
            )
        try:
            for row in payloads:
                reference = str(row["encryption_key_ref"])
                cipher(reference).decrypt(
                    bytes(row["encrypted_payload"]),
                    key_reference=reference,
                    request_id=str(row["request_id"]),
                    version=int(row["version"]),
                    payload_hash=str(row["payload_hash"]),
                )
            for row in drafts:
                reference = str(row["edit_encryption_key_ref"])
                cipher(reference).decrypt(
                    bytes(row["edit_encrypted_payload"]),
                    key_reference=reference,
                    request_id=str(row["request_id"]),
                    version=int(row["version"]) + 1,
                    payload_hash=str(row["edit_payload_hash"]),
                )
        except Exception as exc:
            raise SetupError("restored private records could not be decrypted") from exc

    def _revoke_hermes_tokens_for_rollback(self, spec: SetupSpec, setup_id: str) -> bool:
        if not isinstance(self.platform, ProductionSetupPlatform):
            return False
        self.platform.revoke_hermes_tokens_for_rollback(spec, setup_id)
        return True

    def _production_key_references(self) -> tuple[str, ...]:
        try:
            config = load_production_config(self.root / "production.json")
        except (OSError, ProductionAssemblyError, ValueError) as exc:
            raise SetupError("production secret inventory is unavailable") from exc
        references = {
            value for value in config.secrets.model_dump().values() if isinstance(value, str)
        }
        references.update(connector.credential_ref for connector in config.connectors.values())
        return tuple(sorted(references))

    def _backup_manager(
        self,
        journal: SetupJournal,
        *,
        staging_root: Path | None = None,
    ) -> BackupBundleManager:
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
        database_path = self.root / "data" / "signet.db"
        ownership_marker = database_path.parent / ".signet-database-ownership.json"
        expected_identity = None
        expected_lock_identity = None
        if (
            database_path.exists()
            or database_path.is_symlink()
            or ownership_marker.exists()
            or ownership_marker.is_symlink()
        ):
            (
                expected_identity,
                expected_lock_identity,
            ) = validate_active_database_runtime_ownership(
                database_path.parent,
                setup_id=journal.setup_id,
            )
        database = Database(
            database_path,
            expected_identity=expected_identity,
            expected_lock_identity=expected_lock_identity,
        )
        staging = StagingStore(
            staging_root or (self.root / "staging"),
            database=database,
            cipher=AttachmentCipher(attachment_secret, attachment_reference_value),
        )
        encryption_key = hashlib.sha256(backup_secret.reveal().encode("utf-8")).digest()
        return BackupBundleManager(
            database,
            staging=staging,
            encryption_key=encryption_key,
            key_identity_resolver=lambda reference: secret_store.get(
                SecretReference.parse(reference)
            ).reveal(),
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
        journal.status
        not in {"failed", "rolling_back", "rollback_failed", "rolled_back", "uninstalled"}
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


def _read_verified_private_file_checkpoint(
    document: Any,
    recovery_directory: Path,
) -> tuple[Path, bytes]:
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
    try:
        path = Path(document["path"])
    except TypeError as exc:
        raise SetupError("purge recovery checkpoint path is invalid") from exc
    if not path.is_absolute() or path.parent != recovery_directory:
        raise SetupError("purge recovery checkpoint path is invalid")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        before = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        chunks: list[bytes] = []
        remaining = 1_048_577
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        after = os.fstat(descriptor)
        current = path.lstat()
    except (OSError, PrivatePathError) as exc:
        raise SetupError("purge recovery checkpoint file is unavailable or unsafe") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(encoded) > 1_048_576:
        raise SetupError("purge recovery checkpoint file is too large")
    actual = {
        "path": str(path),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "device": before.st_dev,
        "inode": before.st_ino,
        "owner_uid": before.st_uid,
        "mode": stat.S_IMODE(before.st_mode),
        "nlink": before.st_nlink,
        "size": before.st_size,
        "mtime_ns": before.st_mtime_ns,
    }
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        actual != document
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or identity != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
    ):
        raise SetupError("purge recovery checkpoint file identity or digest changed")
    return path, encoded


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
    receipt, receipt_encoded = _read_verified_private_file_checkpoint(
        checkpoint["recovery_receipt"],
        recovery_directory,
    )
    backup_receipt = checkpoint["backup_receipt"]
    if not isinstance(backup_receipt, dict) or (
        backup_receipt.get("artifact_path") != str(backup)
        or backup_receipt.get("artifact_sha256") != checkpoint["backup"]["sha256"]
    ):
        raise SetupError("purge recovery checkpoint receipt is invalid")
    try:
        receipt_document = json.loads(receipt_encoded)
    except json.JSONDecodeError as exc:
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


def _write_upgrade_recovery_receipt(
    recovery_directory: Path,
    *,
    journal: SetupJournal,
    migration_receipt: Any,
    observed_schema_version: int,
    state: str,
) -> Path:
    artifact_sha256 = str(migration_receipt.artifact_sha256)
    path = recovery_directory / f"upgrade-{journal.setup_id}-{artifact_sha256[:16]}.json"
    document = {
        "format": 2,
        "setup_id": journal.setup_id,
        "state": state,
        "backup_path": str(migration_receipt.artifact_path),
        "backup_sha256": artifact_sha256,
        "source_schema_version": int(migration_receipt.source_schema_version),
        "source_database_device": migration_receipt.source_database_device,
        "source_database_inode": migration_receipt.source_database_inode,
        "verified_restore_schema_version": int(migration_receipt.verified_restore_schema_version),
        "observed_schema_version": observed_schema_version,
    }
    if path.exists() or path.is_symlink():
        _replace_upgrade_recovery_receipt(path, document)
    else:
        _write_private_json(path, document)
    return path


def _replace_upgrade_recovery_receipt(path: Path, document: dict[str, Any]) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        before = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        current_bytes = b""
        while chunk := os.read(descriptor, 1024 * 1024):
            current_bytes += chunk
        after = os.fstat(descriptor)
        named = path.lstat()
    except (OSError, PrivatePathError) as exc:
        raise SetupError("upgrade recovery receipt is unavailable or unsafe") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != (os.geteuid() if hasattr(os, "geteuid") else os.getuid())
        or stat.S_IMODE(before.st_mode) != 0o600
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or identity != (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns)
    ):
        raise SetupError("upgrade recovery receipt is unavailable or unsafe")
    try:
        current = json.loads(current_bytes)
    except json.JSONDecodeError as exc:
        raise SetupError("upgrade recovery receipt is invalid") from exc
    immutable = {
        "format",
        "setup_id",
        "backup_path",
        "backup_sha256",
        "source_schema_version",
        "source_database_device",
        "source_database_inode",
        "verified_restore_schema_version",
    }
    if (
        not isinstance(current, dict)
        or set(current) != set(document)
        or any(current.get(key) != document.get(key) for key in immutable)
    ):
        raise SetupError("upgrade recovery receipt does not match the migration backup")
    current_state = current.get("state")
    next_state = document["state"]
    if current_state == next_state and current.get("observed_schema_version") == document.get(
        "observed_schema_version"
    ):
        return
    if current_state == "migration_applied" and next_state == "assembly_failed_after_backup":
        return
    if current_state != "backup_verified_migration_pending" or next_state not in {
        "migration_applied",
        "assembly_failed_after_backup",
    }:
        raise SetupError("upgrade recovery receipt state transition is invalid")
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    _replace_private_file(
        path,
        encoded,
        expected_content=current_bytes,
        expected_identity=(before.st_dev, before.st_ino),
        require_present=True,
    )
    _private_file_checkpoint(path)
    _fsync_directory(path.parent)


def _write_private_json(path: Path, document: dict[str, Any]) -> None:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    _replace_private_file(path, encoded, require_absent=True)
    _private_file_checkpoint(path)
    _fsync_directory(path.parent)


def _failed_check(exc: Exception) -> dict[str, Any]:
    return {"ok": False, "error_kind": type(exc).__name__}
