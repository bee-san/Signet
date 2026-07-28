"""Operator lifecycle operations for an installed setup."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
import time
from collections.abc import Callable, Iterator
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
from signet.credential_broker import CredentialError, KeychainSecretStore, SecretReference
from signet.crypto import PayloadCipher
from signet.db import LATEST_SCHEMA_VERSION, Database, DatabaseError, MigrationBackupReceipt
from signet.lifecycle import (
    LifecycleOperationRecord,
    LifecycleOperationStore,
    LifecyclePlan,
    lifecycle_recovery_directory,
    setup_lifecycle_lock,
)
from signet.private_paths import (
    PrivatePathError,
    ensure_private_directory,
    require_no_acl_grants,
    require_private_directory_identity,
    revalidate_directory_identity,
)
from signet.production import (
    ProductionAssemblyError,
    create_production_assembly,
    load_production_config,
)
from signet.production_state import ProductionStateStore
from signet.service_lifecycle import (
    ServiceLifecycle,
    local_service_states,
    require_same_service_inventory,
    service_observation,
    tailscale_port,
    validate_service_snapshot,
)
from signet.setup_platform import (
    ProductionSetupPlatform,
    ServiceUnitGeneration,
    _managed_tailnet_port,
    _replace_private_file,
    storage_path_status,
    storage_status,
    validate_active_database_runtime_ownership,
)
from signet.setup_state import (
    ExecutableIdentity,
    PolicyMode,
    SetupEngine,
    SetupError,
    SetupJournal,
    SetupJournalStore,
    SetupSpec,
)
from signet.staging import StagingStore
from signet.storage_lifecycle import BACKUPS_HARD_BYTES


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
        with setup_lifecycle_lock(lifecycle_recovery_directory(self.root)):
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
            executable_identity_document = document.get("executable_identity")
            executable_identity = (
                ExecutableIdentity(
                    device=executable_identity_document["device"],
                    inode=executable_identity_document["inode"],
                    size=executable_identity_document["size"],
                    sha256=executable_identity_document["sha256"],
                )
                if isinstance(executable_identity_document, dict)
                else None
            )
            return SetupSpec(
                root=Path(document["root"]),
                public_origin=str(document["public_origin"]),
                owner_user_id=str(document["owner_user_id"]),
                hermes_profiles=tuple(str(value) for value in document["hermes_profiles"]),
                executable=Path(document["executable"]),
                open_browser=bool(document["open_browser"]),
                policy_mode=cast(PolicyMode, document.get("policy_mode", "deny")),
                data_root=(
                    Path(str(document["data_root"]))
                    if document.get("data_root") is not None
                    else None
                ),
                backup_root=(
                    Path(str(document["backup_root"]))
                    if document.get("backup_root") is not None
                    else None
                ),
                data_device=cast(int | None, document.get("data_device")),
                executable_identity=executable_identity,
            )
        except (KeyError, TypeError, ValueError):
            raise SetupError("setup journal specification is invalid") from None

    def status(self) -> dict[str, Any]:
        journal = self.store.load()
        lifecycle = LifecycleOperationStore(self.root).load_optional()
        spec = self.spec()
        result: dict[str, Any] = {
            "setup_id": journal.setup_id,
            "setup_status": journal.status,
            "steps": {step.name: step.status for step in journal.steps},
            "provider_rollout": "disabled",
            "lifecycle_operation": (
                None if lifecycle is None else _lifecycle_operation_metadata(lifecycle)
            ),
            "services": self.platform.service_status(spec),
        }
        try:
            result["storage"] = storage_status(spec)
        except Exception as exc:
            result["storage"] = {"available": False, "error_kind": type(exc).__name__}
        try:
            config = load_production_config(self.root / "production.json")
            database_path = config.storage.database_path
            if database_path.is_symlink() or not database_path.is_file():
                raise SetupError("production database is unavailable for read-only inspection")
            expected_identity, expected_lock_identity, expected_parent_identity = (
                validate_active_database_runtime_ownership(
                    database_path.parent,
                    setup_id=journal.setup_id,
                    instance_root=self.root,
                    require_external_storage=spec.data_root is not None,
                )
            )
            database = Database(
                database_path,
                expected_parent_identity=expected_parent_identity,
                expected_identity=expected_identity,
                expected_lock_identity=expected_lock_identity,
            )
            production = ProductionStateStore(
                database,
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
            try:
                result["metrics"] = {
                    "available": True,
                    **_bounded_operational_metrics(
                        database,
                        storage=(
                            result["storage"]
                            if isinstance(result.get("storage"), dict)
                            and result["storage"].get("available") is not False
                            else None
                        ),
                    ),
                }
            except Exception as exc:
                result["metrics"] = {
                    "available": False,
                    "error_kind": type(exc).__name__,
                }
        return result

    def doctor(self) -> dict[str, Any]:
        checks: dict[str, dict[str, Any]] = {}
        try:
            journal = self.store.load()
        except Exception as exc:
            checks["journal"] = {
                **_failed_check(exc),
                "remediation": "Restore the owned setup journal from a verified backup.",
            }
            return {"healthy": False, "checks": checks}
        checks["journal"] = {
            "ok": journal.status == "completed",
            "status": journal.status,
            "remediation": "Resume or roll back the recorded setup operation.",
        }
        try:
            lifecycle = LifecycleOperationStore(self.root).load_optional()
        except Exception as exc:
            checks["lifecycle_operation"] = {
                **_failed_check(exc),
                "remediation": (
                    "Inspect and restore the owned lifecycle receipt before applying plans."
                ),
            }
        else:
            lifecycle_ok = lifecycle is None or lifecycle.status in {"completed", "rolled_back"}
            checks["lifecycle_operation"] = {
                "ok": lifecycle_ok,
                "status": "idle" if lifecycle is None else lifecycle.status,
                "remediation": (
                    "No action required."
                    if lifecycle_ok
                    else (
                        "Resume the exact reviewed plan; use explicit rollback only for "
                        "a service plan."
                    )
                ),
            }
        try:
            config = load_production_config(self.root / "production.json")
        except Exception as exc:
            checks["configuration"] = {
                **_failed_check(exc),
                "remediation": "Restore the exact owned production configuration.",
            }
        else:
            checks["configuration"] = {
                "ok": True,
                "provider_rollout": config.provider_rollout.state,
                "connector_count": len(config.connectors),
                "remediation": "No action required.",
            }
            configured_references = tuple(
                value for value in config.secrets.model_dump().values() if isinstance(value, str)
            )
            try:
                secret_store = KeychainSecretStore()
                for raw_reference in configured_references:
                    secret = secret_store.get(SecretReference.parse(raw_reference))
                    encoded = secret.reveal().encode("utf-8")
                    if not 32 <= len(encoded) <= 4_096:
                        raise CredentialError("the configured Keychain secret is unavailable")
            except Exception as exc:
                checks["secret_references"] = {
                    **_failed_check(exc),
                    "remediation": "Restore the configured secret in the platform secret store.",
                }
            else:
                checks["secret_references"] = {
                    "ok": True,
                    "verification": "resolved",
                    "configured_count": len(configured_references),
                    "remediation": "No action required.",
                }
        spec = self.spec()
        services = self.platform.service_status(spec)
        checks["services"] = {
            "ok": bool(services) and all(status == "active" for status in services.values()),
            "status": services,
            "remediation": "Review the service plan, then apply a start or restart plan.",
        }
        try:
            self.platform.verify_service_health(spec)
        except Exception as exc:
            checks["service_health"] = {
                **_failed_check(exc),
                "remediation": ("Inspect owned service logs, then apply a reviewed restart plan."),
            }
        else:
            checks["service_health"] = {
                "ok": True,
                "remediation": "No action required.",
            }
        try:
            storage = storage_status(spec)
            policy = storage["policy"]
            roots = storage["roots"]
            bounded = {
                "data": int(policy["database_hard_bytes"]),
                "attachments": int(policy["attachments_hard_bytes"]),
                "logs": int(policy["logs_hard_bytes"]),
                "backups": int(policy["backups_hard_bytes"]),
                "cache": int(policy["cache_hard_bytes"]),
                "staging": int(policy["staging_hard_bytes"]),
            }
            storage_ok = all(
                int(item["free_bytes"]) >= int(policy["minimum_reserve_bytes"])
                for item in roots.values()
            ) and all(int(roots[name]["usage_bytes"]) <= limit for name, limit in bounded.items())
        except Exception as exc:
            checks["storage"] = {
                **_failed_check(exc),
                "remediation": "Restore the reviewed storage roots and device identity.",
            }
        else:
            checks["storage"] = {
                "ok": storage_ok,
                "status": storage,
                "remediation": (
                    "No action required."
                    if storage_ok
                    else "Stop new work, free reviewed storage, then rerun doctor."
                ),
            }
        checks["hermes_reload"] = {
            "ok": False,
            "manual_action": (
                "Review each configured MCP entry, then run /reload-mcp in each profile."
            ),
            "profiles": list(spec.hermes_profiles),
        }
        return {
            "healthy": all(
                check["ok"] for name, check in checks.items() if name != "hermes_reload"
            ),
            "checks": checks,
        }

    def verify(self) -> dict[str, Any]:
        doctor = self.doctor()
        return {
            "automatic_safe_checks": doctor,
            "required_human_ceremonies": [
                {
                    "name": "owner_authentication_enrollment",
                    "action": (
                        "Complete the attended passkey and TOTP enrollment ceremony, "
                        "then retain recovery material offline."
                    ),
                },
                {
                    "name": "hermes_mcp_review_and_reload",
                    "action": (
                        "Review each generated MCP block and run /reload-mcp in each "
                        "configured Hermes profile."
                    ),
                },
            ],
            "deferred_live_provider_proof": [
                "credential_configuration",
                "read_only_discovery",
                "live_send",
            ],
            "gateway_restart": False,
        }

    def plan_backup(self, destination: Path | None = None) -> LifecyclePlan:
        journal = self._completed_journal()
        if destination is not None and (not destination.is_absolute() or ".." in destination.parts):
            raise SetupError("backup destination must be an absolute lexical path")
        previous_plan_id = self._previous_lifecycle_plan_id()
        spec = self.spec()
        selected_destination = destination or _default_reviewed_backup_destination(
            spec.backup_dir,
            setup_id=journal.setup_id,
            previous_plan_id=previous_plan_id,
        )
        return LifecyclePlan(
            setup_id=journal.setup_id,
            operation="backup",
            action="backup",
            observed={
                "setup_status": journal.status,
                "setup_spec_digest": journal.spec_digest,
                "previous_lifecycle_plan_id": previous_plan_id,
                "destination": str(selected_destination),
            },
            steps=(
                "inspect_setup_ownership",
                "validate_private_path_identity",
                "create_consistent_encrypted_bundle",
                "verify_encrypted_bundle",
            ),
            automatic_safe_checks=("setup_ownership", "private_path_identity"),
            destructive_actions=(),
        )

    def apply_backup(self, plan_id: str, destination: Path | None = None) -> dict[str, Any]:
        selected_destination = destination
        if selected_destination is None:
            existing = LifecycleOperationStore(self.root).load_optional()
            if existing is not None and existing.plan.plan_id == plan_id:
                selected_destination = _backup_destination(existing.plan)
            else:
                selected_destination = _backup_destination(self.plan_backup())
        return self._apply_reviewed_operation(
            plan_id=plan_id,
            operation="backup",
            action="backup",
            plan_factory=lambda: self.plan_backup(selected_destination),
            runner=lambda record: self._apply_reviewed_backup(record, selected_destination),
            resume_validator=lambda plan: _require_backup_destination(
                plan,
                selected_destination,
            ),
        )

    def _apply_reviewed_backup(
        self,
        record: LifecycleOperationRecord,
        destination: Path,
    ) -> dict[str, Any]:
        effect = _load_lifecycle_effect_receipt(self.root, record, operation="backup")
        if destination.exists() or destination.is_symlink():
            if effect is None:
                raise SetupError("reviewed backup destination appeared after plan review")
            state, checkpoint = _reviewed_backup_effect_resource(effect)
            actual = _private_file_checkpoint(destination)
            if checkpoint != actual:
                raise SetupError("reviewed backup changed after effect publication")
            if state == "prepared":
                _publish_reviewed_backup_effect_receipt(
                    self.root,
                    record,
                    state="published",
                    artifact=destination,
                )
            self._verified_backup_receipt(destination, verify_live_database=False)
            if _private_file_checkpoint(destination) != checkpoint:
                raise SetupError("reviewed backup changed during resume verification")
            return {"backup": str(destination)}
        if effect is not None:
            state, _ = _reviewed_backup_effect_resource(effect)
            if state == "published":
                raise SetupError("reviewed backup effect receipt has no matching artifact")
        artifact = self._backup(destination, completion_record=record)
        published = _load_lifecycle_effect_receipt(self.root, record, operation="backup")
        if published is None:
            raise SetupError("reviewed backup effect publication was not recorded")
        state, resource = _reviewed_backup_effect_resource(published)
        if state != "published" or _private_file_checkpoint(artifact) != resource:
            raise SetupError("reviewed backup artifact changed during effect publication")
        self._verified_backup_receipt(artifact, verify_live_database=False)
        if _private_file_checkpoint(artifact) != resource:
            raise SetupError("reviewed backup changed during verification")
        return {"backup": str(artifact)}

    def backup(self, destination: Path | None = None) -> Path:
        with self.lifecycle_lock():
            return self._backup(destination)

    def _backup(
        self,
        destination: Path | None = None,
        *,
        manager: BackupBundleManager | None = None,
        completion_record: LifecycleOperationRecord | None = None,
    ) -> Path:
        journal = self.store.load()
        SetupEngine(self.store, self.platform).validate_private_paths(self.spec(), journal=journal)
        if journal.purge_backup is not None:
            raise SetupError(
                "a durable purge checkpoint exists; finish purge before creating another backup"
            )
        spec = self.spec()
        selected = destination or (
            spec.backup_dir
            / (
                time.strftime("signet-%Y%m%dT%H%M%SZ-", time.gmtime())
                + secrets.token_hex(4)
                + ".signet-backup"
            )
        )
        if not selected.is_absolute() or ".." in selected.parts:
            raise SetupError("backup destination must be an absolute lexical path")
        report = storage_status(spec)
        roots = report["roots"]
        policy = report["policy"]
        estimated_bytes = max(
            int(roots["data"]["usage_bytes"])
            + int(roots["attachments"]["usage_bytes"])
            + int(roots["staging"]["usage_bytes"]),
            64 * 1024**2,
        )
        disk_usage_provider = getattr(
            self.platform,
            "disk_usage_provider",
            shutil.disk_usage,
        )
        destination_status = storage_path_status(
            selected.parent,
            disk_usage_provider=disk_usage_provider,
            include_usage=False,
        )
        backups_hard_bytes = int(policy["backups_hard_bytes"])
        owned_backup_bytes = (
            int(roots["backups"]["usage_bytes"]) if selected.is_relative_to(spec.backup_dir) else 0
        )
        if (
            estimated_bytes > backups_hard_bytes
            or owned_backup_bytes + estimated_bytes > backups_hard_bytes
            or int(destination_status["free_bytes"]) - estimated_bytes
            < int(policy["minimum_reserve_bytes"])
        ):
            raise SetupError("backup storage budget would exceed the reviewed hard limit")
        manager = manager or self._backup_manager(journal)
        try:
            return manager.create(
                selected,
                required_key_references=self._production_key_references(),
                prepare_publication=(
                    None
                    if completion_record is None
                    else lambda artifact: _publish_reviewed_backup_effect_receipt(
                        self.root,
                        completion_record,
                        state="prepared",
                        artifact=artifact,
                    )
                ),
                finalize_publication=(
                    None
                    if completion_record is None
                    else lambda artifact: _publish_reviewed_backup_effect_receipt(
                        self.root,
                        completion_record,
                        state="published",
                        artifact=artifact,
                    )
                ),
            )
        except BackupError as exc:
            raise SetupError(str(exc)) from exc

    def restore(self, bundle: Path) -> RestoredBundle:
        with self.lifecycle_lock():
            return self._restore(bundle)

    def plan_restore(self, bundle: Path) -> LifecyclePlan:
        journal = self._completed_journal()
        if not bundle.is_absolute() or ".." in bundle.parts:
            raise SetupError("restore bundle must be an absolute lexical path")
        bundle_checkpoint = _private_file_checkpoint(bundle)
        previous_plan_id = self._previous_lifecycle_plan_id()
        destination = _default_reviewed_restore_destination(
            self.root,
            setup_id=journal.setup_id,
            bundle_checkpoint=bundle_checkpoint,
            previous_plan_id=previous_plan_id,
        )
        return LifecyclePlan(
            setup_id=journal.setup_id,
            operation="restore",
            action="restore",
            observed={
                "setup_status": journal.status,
                "setup_spec_digest": journal.spec_digest,
                "previous_lifecycle_plan_id": previous_plan_id,
                "bundle": bundle_checkpoint,
                "destination": str(destination),
            },
            steps=(
                "inspect_setup_ownership",
                "verify_encrypted_bundle_identity",
                "decrypt_into_new_private_staging_root",
                "validate_restored_schema_and_key_references",
            ),
            automatic_safe_checks=(
                "setup_ownership",
                "private_path_identity",
                "encrypted_bundle_identity",
            ),
            destructive_actions=(),
        )

    def apply_restore(self, plan_id: str, bundle: Path) -> dict[str, Any]:
        def restore(record: LifecycleOperationRecord) -> dict[str, Any]:
            destination = _restore_destination(record.plan, self.root)
            effect = _load_lifecycle_effect_receipt(self.root, record, operation="restore")
            if destination.exists() or destination.is_symlink():
                if effect is None:
                    effect = _load_restore_tree_effect_receipt(destination, record)
                    if effect is None:
                        raise SetupError("reviewed restore destination appeared after plan review")
                resource = effect.get("resource")
                restored = self._resume_restored_bundle(destination, resource)
                if effect.get("resource") != _restore_effect_checkpoint(restored):
                    raise SetupError("reviewed restore tree changed after effect publication")
                _publish_lifecycle_effect_receipt(
                    self.root,
                    record,
                    operation="restore",
                    resource=_restore_effect_checkpoint(restored),
                )
            else:
                if effect is not None:
                    raise SetupError("reviewed restore effect receipt has no matching tree")
                restored = self._restore(
                    bundle,
                    destination=destination,
                    completion_record=record,
                )
                resource = _restore_effect_checkpoint(restored)
                _publish_lifecycle_effect_receipt(
                    self.root,
                    record,
                    operation="restore",
                    resource=resource,
                )
                if _restore_effect_checkpoint(restored) != resource:
                    raise SetupError("reviewed restore tree changed during effect publication")
            return {
                "restored_to": str(restored.root),
                "database": str(restored.database_path),
                "activated": False,
            }

        return self._apply_reviewed_operation(
            plan_id=plan_id,
            operation="restore",
            action="restore",
            plan_factory=lambda: self.plan_restore(bundle),
            runner=restore,
            resume_validator=lambda plan: _require_restore_bundle(plan, bundle, self.root),
        )

    def _restore(
        self,
        bundle: Path,
        *,
        destination: Path | None = None,
        completion_record: LifecycleOperationRecord | None = None,
    ) -> RestoredBundle:
        if not bundle.is_absolute() or ".." in bundle.parts:
            raise SetupError("restore bundle must be an absolute lexical path")
        journal = self.store.load()
        SetupEngine(self.store, self.platform).validate_private_paths(self.spec(), journal=journal)
        selected_destination = destination or (
            self.root / "restore" / f"restore-{secrets.token_hex(8)}"
        )
        manager = self._backup_manager(journal)
        restored: RestoredBundle | None = None
        try:
            if completion_record is None:
                restored = manager.restore(bundle, selected_destination)
            else:
                restored = manager.restore(
                    bundle,
                    selected_destination,
                    prepare_publication=lambda selected, published_root: (
                        _publish_restore_tree_effect_receipt(
                            selected,
                            completion_record,
                            published_root=published_root,
                        )
                    ),
                )
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

    def _resume_restored_bundle(
        self,
        destination: Path,
        expected_resource: Any,
    ) -> RestoredBundle:
        try:
            parent_identity = require_private_directory_identity(destination.parent)
            root_identity = require_private_directory_identity(destination)
            attachments_root = destination / "attachments"
            attachments_identity = require_private_directory_identity(attachments_root)
            database_path = destination / "approvals.sqlite3"
            database_checkpoint = _private_file_checkpoint(database_path)
            manifest_checkpoint = _private_file_checkpoint(destination / "manifest.json")
            resource = {
                "root": {
                    "path": str(destination),
                    "device": root_identity.device,
                    "inode": root_identity.inode,
                    "owner_uid": root_identity.owner_uid,
                },
                "database": database_checkpoint,
                "manifest": manifest_checkpoint,
            }
            if expected_resource != resource:
                raise SetupError("reviewed restore tree changed after effect publication")
            manifest = SetupJournalStore._read_document(
                destination / "manifest.json",
                label="restored backup manifest",
            )
            if manifest.get("format") not in {2, 3}:
                raise SetupError("reviewed restore tree manifest format is unsupported")
            Database.verify_snapshot(database_path)
            with Database(database_path).read_only() as connection:
                schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if manifest.get("schema_version") != schema_version:
                raise SetupError("reviewed restore tree schema does not match its manifest")
            manager = self._backup_manager(self.store.load())
            manager._verify_restored_attachments(destination, database_path, manifest)
            if manifest.get("format") == 3:
                raw_references = manifest.get("key_references")
                if not isinstance(raw_references, list) or not all(
                    isinstance(reference, str) for reference in raw_references
                ):
                    raise SetupError("backup recovery key inventory is invalid")
                references = [SecretReference.parse(reference) for reference in raw_references]
                self._require_secret_references(references)
                manager.require_key_identities(manifest)
                self._verify_restored_private_records(database_path)
            revalidate_directory_identity(root_identity, private=True)
            revalidate_directory_identity(attachments_identity, private=True)
            revalidate_directory_identity(parent_identity, private=True)
            if (
                _private_file_checkpoint(database_path) != database_checkpoint
                or _private_file_checkpoint(destination / "manifest.json") != manifest_checkpoint
            ):
                raise SetupError("reviewed restore tree changed during verification")
            return RestoredBundle(
                root=destination,
                database_path=database_path,
                attachments_root=attachments_root,
                manifest=manifest,
                root_identity=root_identity,
                parent_identity=parent_identity,
            )
        except SetupError:
            raise
        except (BackupError, DatabaseError, OSError, PrivatePathError, ValueError) as exc:
            raise SetupError("reviewed restore tree could not be verified") from exc

    def plan_upgrade(self) -> LifecyclePlan:
        journal = self._completed_journal()
        spec = self.spec()
        services, unit_generation = self._review_upgrade_services(spec)
        tailscale_port = _managed_tailnet_port(spec)
        validate_service_snapshot(
            services,
            allow_mixed=False,
            tailscale_port=tailscale_port,
        )
        schema_version = self._current_schema_version()
        return LifecyclePlan(
            setup_id=journal.setup_id,
            operation="upgrade",
            action="upgrade",
            observed={
                "setup_status": journal.status,
                "setup_spec_digest": journal.spec_digest,
                "previous_lifecycle_plan_id": self._previous_lifecycle_plan_id(),
                "tailscale_serve_port": tailscale_port,
                "services": dict(sorted(services.items())),
                "service_unit_generation": unit_generation,
                "schema_version": schema_version,
                "target_schema_version": LATEST_SCHEMA_VERSION,
            },
            steps=(
                "run_read_only_preflight",
                "quiesce_active_local_services",
                "create_and_verify_pre_migration_backup",
                "apply_schema_migrations",
                "restore_prior_local_service_state",
                "verify_instance_bound_service_health_if_started",
            ),
            automatic_safe_checks=(
                "setup_ownership",
                "private_path_identity",
                "service_manager_state",
                "database_schema_version",
            ),
            destructive_actions=(),
        )

    def apply_upgrade(self, plan_id: str) -> dict[str, Any]:
        return self._apply_reviewed_operation(
            plan_id=plan_id,
            operation="upgrade",
            action="upgrade",
            plan_factory=self.plan_upgrade,
            runner=lambda record: self._apply_reviewed_upgrade(record, plan_id),
            resume_validator=_require_upgrade_target,
        )

    def _apply_reviewed_upgrade(
        self,
        record: LifecycleOperationRecord,
        plan_id: str,
    ) -> dict[str, Any]:
        plan = self._reviewed_plan(plan_id, operation="upgrade")
        if record.attempts > 1:
            resumed = self._resume_reviewed_upgrade(plan)
            if resumed is not None:
                return resumed
        return self._upgrade(plan)

    def _resume_reviewed_upgrade(self, plan: LifecyclePlan) -> dict[str, Any] | None:
        source_version = plan.observed.get("schema_version")
        target_version = plan.observed.get("target_schema_version")
        if (
            not isinstance(source_version, int)
            or isinstance(source_version, bool)
            or not isinstance(target_version, int)
            or isinstance(target_version, bool)
        ):
            raise SetupError("reviewed upgrade schema observation is invalid")
        current_version = self._current_schema_version()
        if current_version not in {source_version, target_version}:
            raise SetupError("interrupted upgrade database state is unknown")
        spec = self.spec()
        recovery_directory = spec.root.parent / f"{spec.root.name}-recovery"
        receipt = self._reviewed_upgrade_recovery(plan, recovery_directory)
        if receipt is None:
            if current_version == source_version:
                return None
            raise SetupError("completed upgrade has no matching durable recovery receipt")
        receipt_path, receipt_document, migration_receipt = receipt
        self.platform.preflight(spec)
        state = receipt_document["state"]
        resumes_source_database = current_version == source_version and state in {
            "backup_verified_migration_pending",
            "assembly_failed_after_backup",
        }
        if resumes_source_database:
            self._quiesce_reviewed_upgrade_services(plan, spec)
        verified = self._verified_backup_receipt(
            migration_receipt.artifact_path,
            expected_source_schema_version=source_version,
            verify_live_database=resumes_source_database,
            verification_parent=recovery_directory,
        )
        if (
            verified["artifact_path"] != str(migration_receipt.artifact_path)
            or verified["artifact_sha256"] != migration_receipt.artifact_sha256
        ):
            raise SetupError("upgrade recovery backup verification receipt is inconsistent")
        if state == "assembly_failed_after_backup":
            if receipt_document["observed_schema_version"] != current_version:
                raise SetupError("failed upgrade receipt conflicts with the live schema")
            return self._continue_reviewed_upgrade(
                plan,
                spec,
                receipt_path,
                receipt_document,
                migration_receipt,
            )
        if state == "backup_verified_migration_pending":
            return self._continue_reviewed_upgrade(
                plan,
                spec,
                receipt_path,
                receipt_document,
                migration_receipt,
            )
        if (
            current_version == source_version
            and current_version != target_version
            and state != "backup_verified_migration_pending"
        ):
            raise SetupError("upgrade recovery receipt conflicts with the source database")
        config = load_production_config(self.root / "production.json")
        self._recover_reviewed_upgrade_services(plan, spec)
        return {
            "backup": str(migration_receipt.artifact_path),
            "upgrade_receipt": str(receipt_path),
            "backup_receipt": verified,
            "schema_version": target_version,
            "provider_rollout": config.provider_rollout.state,
        }

    def _reviewed_upgrade_recovery(
        self,
        plan: LifecyclePlan,
        recovery_directory: Path,
    ) -> tuple[Path, dict[str, Any], MigrationBackupReceipt] | None:
        if not recovery_directory.exists() and not recovery_directory.is_symlink():
            return None
        directory_identity = require_private_directory_identity(recovery_directory)
        before_names = tuple(sorted(entry.name for entry in recovery_directory.iterdir()))
        source_version = cast(int, plan.observed["schema_version"])
        target_version = cast(int, plan.observed["target_schema_version"])
        prefix = f"upgrade-{plan.setup_id}-"
        candidate_names = tuple(
            name for name in before_names if name.startswith(prefix) and name.endswith(".json")
        )
        if not candidate_names:
            revalidate_directory_identity(directory_identity, private=True)
            after_names = tuple(sorted(entry.name for entry in recovery_directory.iterdir()))
            revalidate_directory_identity(directory_identity, private=True)
            if before_names != after_names:
                raise SetupError("upgrade recovery directory changed during inspection")
            return None
        matches: list[tuple[Path, dict[str, Any], MigrationBackupReceipt]] = []
        expected_keys = {
            "format",
            "setup_id",
            "lifecycle_plan_id",
            "state",
            "backup_path",
            "backup_sha256",
            "source_schema_version",
            "source_database_device",
            "source_database_inode",
            "verified_restore_schema_version",
            "observed_schema_version",
        }
        manager = self._backup_manager(self.store.load())
        source_identity, _lock_identity, _parent_identity = (
            validate_active_database_runtime_ownership(
                manager.database.path.parent,
                setup_id=plan.setup_id,
                instance_root=self.root,
                require_external_storage=self.spec().data_root is not None,
            )
        )
        source_device, source_inode = source_identity
        for name in candidate_names:
            path = recovery_directory / name
            document = SetupJournalStore._read_document(
                path,
                label="upgrade recovery receipt",
            )
            if (
                document.get("setup_id") != plan.setup_id
                or document.get("source_schema_version") != source_version
                or document.get("lifecycle_plan_id") != plan.plan_id
            ):
                continue
            if set(document) != expected_keys or document.get("format") != 2:
                raise SetupError("upgrade recovery receipt is invalid")
            state = document.get("state")
            if state not in {
                "backup_verified_migration_pending",
                "migration_applied",
                "assembly_failed_after_backup",
            }:
                raise SetupError("upgrade recovery receipt state is invalid")
            observed_version = document.get("observed_schema_version")
            if state == "assembly_failed_after_backup":
                valid_observed = observed_version in {source_version, target_version}
            else:
                expected_observed = source_version if state.endswith("pending") else target_version
                valid_observed = observed_version == expected_observed
            backup_text = document.get("backup_path")
            backup_sha256 = document.get("backup_sha256")
            if (
                not valid_observed
                or not isinstance(backup_text, str)
                or not isinstance(backup_sha256, str)
                or document.get("verified_restore_schema_version") != source_version
                or document.get("source_database_device") != source_device
                or document.get("source_database_inode") != source_inode
            ):
                raise SetupError("upgrade recovery receipt does not match the reviewed upgrade")
            backup_path = Path(backup_text)
            if (
                not backup_path.is_absolute()
                or ".." in backup_path.parts
                or backup_path.parent != recovery_directory
                or name != f"upgrade-{plan.setup_id}-{backup_sha256[:16]}.json"
            ):
                raise SetupError("upgrade recovery receipt path is invalid")
            checkpoint = _private_file_checkpoint(backup_path)
            if checkpoint["sha256"] != backup_sha256:
                raise SetupError("upgrade recovery backup changed after publication")
            matches.append(
                (
                    path,
                    document,
                    MigrationBackupReceipt(
                        database_path=manager.database.path,
                        artifact_path=backup_path,
                        source_schema_version=source_version,
                        artifact_sha256=backup_sha256,
                        verified_restore_schema_version=source_version,
                        source_database_device=source_device,
                        source_database_inode=source_inode,
                    ),
                )
            )
        revalidate_directory_identity(directory_identity, private=True)
        after_names = tuple(sorted(entry.name for entry in recovery_directory.iterdir()))
        revalidate_directory_identity(directory_identity, private=True)
        if before_names != after_names:
            raise SetupError("upgrade recovery directory changed during inspection")
        if len(matches) > 1:
            raise SetupError("multiple upgrade recovery receipts match the reviewed upgrade")
        return matches[0] if matches else None

    def _continue_reviewed_upgrade(
        self,
        plan: LifecyclePlan,
        spec: SetupSpec,
        receipt_path: Path,
        receipt_document: dict[str, Any],
        migration_receipt: MigrationBackupReceipt,
    ) -> dict[str, Any]:
        prior_active = self._quiesce_reviewed_upgrade_services(plan, spec)
        manager = self._backup_manager(self.store.load())
        callback_calls = 0

        def reuse_verified_backup(candidate: Database, version: int) -> MigrationBackupReceipt:
            nonlocal callback_calls
            callback_calls += 1
            if (
                callback_calls != 1
                or candidate is not manager.database
                or version != migration_receipt.source_schema_version
            ):
                raise SetupError("upgrade recovery backup callback received an unexpected source")
            return migration_receipt

        try:
            assembly = create_production_assembly(
                self.root / "production.json",
                secret_store=KeychainSecretStore(),
                pre_migration_backup=reuse_verified_backup,
                components=frozenset(),
                database_override=manager.database,
            )
            schema_version = int(assembly.status().schema_version)
            if schema_version != plan.observed["target_schema_version"]:
                raise SetupError("resumed upgrade did not reach the reviewed schema target")
            updated = dict(receipt_document)
            updated["state"] = "migration_applied"
            updated["observed_schema_version"] = schema_version
            _replace_upgrade_recovery_receipt(receipt_path, updated)
            if prior_active:
                self._restart_services_after_upgrade(spec)
        except BaseException:
            failed = dict(receipt_document)
            failed["state"] = "assembly_failed_after_backup"
            failed["observed_schema_version"] = self._current_schema_version()
            _replace_upgrade_recovery_receipt(receipt_path, failed)
            raise
        return {
            "backup": str(migration_receipt.artifact_path),
            "upgrade_receipt": str(receipt_path),
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

    def _quiesce_reviewed_upgrade_services(
        self,
        plan: LifecyclePlan,
        spec: SetupSpec,
    ) -> bool:
        before = service_observation(plan)
        generation = _upgrade_service_unit_generation(plan)
        current = self._upgrade_service_status(spec, generation)
        validate_service_snapshot(
            current,
            allow_mixed=True,
            tailscale_port=tailscale_port(plan),
        )
        require_same_service_inventory(before, current)
        prior_active = set(local_service_states(before).values()) == {"active"}
        if prior_active:
            if set(local_service_states(current).values()) != {"inactive"}:
                self._stop_and_verify_services(spec, generation)
        elif current != before:
            raise SetupError("interrupted upgrade changed the reviewed inactive service state")
        self._migrate_upgrade_service_units(spec, generation)
        return prior_active

    def _recover_reviewed_upgrade_services(
        self,
        plan: LifecyclePlan,
        spec: SetupSpec,
    ) -> None:
        before = service_observation(plan)
        generation = _upgrade_service_unit_generation(plan)
        current = self._upgrade_service_status(spec, generation)
        validate_service_snapshot(
            current,
            allow_mixed=True,
            tailscale_port=tailscale_port(plan),
        )
        require_same_service_inventory(before, current)
        prior_active = set(local_service_states(before).values()) == {"active"}
        if not prior_active:
            if current != before:
                raise SetupError("completed upgrade changed the reviewed inactive service state")
            self._migrate_upgrade_service_units(spec, generation)
            return
        if current == before:
            self.platform.verify_service_health(spec)
            return
        self._stop_and_verify_services(spec, generation)
        self._migrate_upgrade_service_units(spec, generation)
        self._restart_services_after_upgrade(spec)

    def upgrade(self) -> dict[str, Any]:
        with self.lifecycle_lock():
            return self._upgrade()

    def _upgrade(self, reviewed_plan: LifecyclePlan | None = None) -> dict[str, Any]:
        spec = self.spec()
        journal = self.store.load()
        if reviewed_plan is None:
            self.platform.preflight(spec)
        SetupEngine(self.store, self.platform).validate_private_paths(spec, journal=journal)
        if reviewed_plan is None:
            initial_status, unit_generation = self._review_upgrade_services(spec)
            local_services = local_service_states(initial_status)
            if len(local_services) != 2 or any(
                state not in {"active", "inactive"} for state in local_services.values()
            ):
                raise SetupError("upgrade could not determine the prior Signet service state")
            prior_active = all(state == "active" for state in local_services.values())
            if not prior_active and any(state != "inactive" for state in local_services.values()):
                raise SetupError("upgrade refuses to change a mixed Signet service state")
            services_quiesced = False
        else:
            _require_upgrade_target(reviewed_plan)
            unit_generation = _upgrade_service_unit_generation(reviewed_plan)
            initial_status = self._upgrade_service_status(spec, unit_generation)
            prior_active, services_quiesced = _reviewed_upgrade_service_state(
                reviewed_plan,
                initial_status,
            )
        stop_attempted = services_quiesced
        migration_receipt: Any | None = None
        upgrade_receipt: Path | None = None
        schema_version: int | None = None
        assembly: Any | None = None
        recovery_directory = spec.root.parent / f"{spec.root.name}-recovery"
        try:
            if reviewed_plan is not None:
                self.platform.preflight(spec)
            if prior_active and not services_quiesced:
                stop_attempted = True
                self._stop_and_verify_services(spec, unit_generation)
            self._migrate_upgrade_service_units(spec, unit_generation)
            manager = self._backup_manager(journal)
            recovery_directory.mkdir(mode=0o700, exist_ok=True)
            ensure_private_directory(recovery_directory)
            _fsync_directory(recovery_directory.parent)
            database = manager.database
            expected_database_path = (spec.data_dir / "signet.db").absolute()
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
                    lifecycle_plan_id=(
                        reviewed_plan.plan_id if reviewed_plan is not None else None
                    ),
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
                lifecycle_plan_id=(reviewed_plan.plan_id if reviewed_plan is not None else None),
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
                        lifecycle_plan_id=(
                            reviewed_plan.plan_id if reviewed_plan is not None else None
                        ),
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
                    self._migrate_upgrade_service_units(spec, unit_generation)
                    self._restart_services_after_upgrade(spec)
                except BaseException:
                    try:
                        self._restart_upgrade_source_services(spec, unit_generation)
                    except BaseException as source_recovery_exc:
                        if isinstance(exc, Exception):
                            exc.add_note(
                                "The pre-upgrade service state could not be restored; Signet may "
                                "be partially stopped."
                            )
                        raise SetupError(
                            "upgrade failed before migration, and services could not be safely "
                            "resumed"
                        ) from source_recovery_exc
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

    def _stop_and_verify_services(
        self,
        spec: SetupSpec,
        unit_generation: ServiceUnitGeneration,
    ) -> None:
        stop = self._concrete_upgrade_service_method("stop_upgrade_services")
        if stop is None:
            self.platform.manage_services(spec, "stop")
        else:
            stop(
                spec,
                source_generation=unit_generation,
                allow_migrated=True,
            )
        stopped = self._upgrade_service_status(spec, unit_generation)
        local_services = {
            name: state for name, state in stopped.items() if not name.startswith("tailscale:")
        }
        if len(local_services) != 2 or any(
            state != "inactive" for state in local_services.values()
        ):
            raise SetupError("upgrade requires every Signet service to be inactive")

    def _review_upgrade_services(
        self,
        spec: SetupSpec,
    ) -> tuple[dict[str, str], ServiceUnitGeneration]:
        review = self._concrete_upgrade_service_method("review_upgrade_services")
        if review is None:
            return self.platform.service_status(spec), "current"
        return cast(
            tuple[dict[str, str], ServiceUnitGeneration],
            review(spec),
        )

    def _upgrade_service_status(
        self,
        spec: SetupSpec,
        unit_generation: ServiceUnitGeneration,
    ) -> dict[str, str]:
        status = self._concrete_upgrade_service_method("upgrade_service_status")
        if status is None:
            return self.platform.service_status(spec)
        return cast(
            dict[str, str],
            status(
                spec,
                source_generation=unit_generation,
                allow_migrated=True,
            ),
        )

    def _migrate_upgrade_service_units(
        self,
        spec: SetupSpec,
        unit_generation: ServiceUnitGeneration,
    ) -> None:
        migrate = self._concrete_upgrade_service_method("migrate_upgrade_service_units")
        if migrate is not None:
            migrate(
                spec,
                source_generation=unit_generation,
                allow_migrated=True,
            )

    def _restart_upgrade_source_services(
        self,
        spec: SetupSpec,
        unit_generation: ServiceUnitGeneration,
    ) -> None:
        start = self._concrete_upgrade_service_method("start_upgrade_services")
        if start is None:
            self._restart_services_after_upgrade(spec)
            return
        start(
            spec,
            source_generation=unit_generation,
            allow_migrated=True,
        )
        started = self._upgrade_service_status(spec, unit_generation)
        local_services = {
            name: state for name, state in started.items() if not name.startswith("tailscale:")
        }
        if (
            len(local_services) != 2
            or any(state != "active" for state in local_services.values())
            or any(state != "active" for state in started.values())
        ):
            raise SetupError("pre-upgrade Signet services did not resume")
        self.platform.verify_service_health(spec)

    def _concrete_upgrade_service_method(self, name: str) -> Callable[..., Any] | None:
        if (
            getattr(type(self.platform), "service_status", None)
            is not ProductionSetupPlatform.service_status
        ):
            return None
        return cast(Callable[..., Any] | None, getattr(self.platform, name, None))

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

    def plan_uninstall(self, *, purge: bool = False) -> LifecyclePlan:
        journal = self._completed_journal()
        spec = self.spec()
        services = self.platform.service_status(spec)
        tailscale_port = _managed_tailnet_port(spec)
        validate_service_snapshot(
            services,
            allow_mixed=False,
            tailscale_port=tailscale_port,
        )
        action = "purge" if purge else "uninstall"
        steps = [
            "inspect_setup_ownership",
            "remove_owned_services_and_tailscale_route",
            "remove_owned_hermes_profile_blocks_and_tokens",
        ]
        destructive = [
            "remove_owned_services_and_tailscale_route",
            "remove_owned_hermes_profile_blocks_and_tokens",
        ]
        if purge:
            steps.extend(
                [
                    "create_and_verify_encrypted_backup",
                    "write_durable_external_recovery_receipt",
                    "remove_owned_production_data",
                    "remove_owned_non_backup_secrets",
                ]
            )
            destructive.extend(
                [
                    "remove_owned_production_data",
                    "remove_owned_non_backup_secrets",
                ]
            )
        return LifecyclePlan(
            setup_id=journal.setup_id,
            operation="uninstall",
            action=action,
            observed={
                "setup_status": journal.status,
                "setup_spec_digest": journal.spec_digest,
                "previous_lifecycle_plan_id": self._previous_lifecycle_plan_id(),
                "tailscale_serve_port": tailscale_port,
                "services": dict(sorted(services.items())),
                "data_preserved": not purge,
            },
            steps=tuple(steps),
            automatic_safe_checks=(
                "setup_ownership",
                "private_path_identity",
                "service_manager_state",
            ),
            destructive_actions=tuple(destructive),
        )

    def apply_uninstall(self, plan_id: str, *, purge: bool = False) -> dict[str, Any]:
        return self._apply_reviewed_operation(
            plan_id=plan_id,
            operation="uninstall",
            action="purge" if purge else "uninstall",
            plan_factory=lambda: self.plan_uninstall(purge=purge),
            runner=lambda _record: self._uninstall(purge=purge),
        )

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
            database_path = spec.data_dir / "signet.db"
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

    def plan_services(self, action: str) -> LifecyclePlan:
        return self._service_lifecycle().plan(action)

    def apply_service_plan(self, action: str, plan_id: str) -> dict[str, Any]:
        return self._service_lifecycle().apply(action, plan_id)

    def rollback_service_plan(self, plan_id: str) -> dict[str, Any]:
        return self._service_lifecycle().rollback(plan_id)

    def _service_lifecycle(self) -> ServiceLifecycle:
        return ServiceLifecycle(
            root=self.root,
            platform=self.platform,
            spec_factory=self.spec,
            journal_factory=self._completed_journal,
        )

    def _completed_journal(self) -> SetupJournal:
        journal = self.store.load()
        if journal.status != "completed":
            raise SetupError("lifecycle planning requires a completed owned setup")
        SetupEngine(self.store, self.platform).validate_private_paths(
            self.spec(),
            journal=journal,
        )
        return journal

    def _previous_lifecycle_plan_id(self) -> str | None:
        journal = self._completed_journal()
        previous = LifecycleOperationStore(self.root).load_optional()
        if previous is None:
            return None
        if previous.setup_id != journal.setup_id:
            if previous.status in {"completed", "rolled_back"}:
                return None
            raise SetupError("an incomplete lifecycle plan belongs to another setup")
        if previous.status not in {"completed", "rolled_back"}:
            raise SetupError("a reviewed lifecycle plan is incomplete and must be resumed")
        return previous.plan.plan_id

    def _reviewed_plan(self, plan_id: str, *, operation: str) -> LifecyclePlan:
        record = LifecycleOperationStore(self.root).load_optional()
        if (
            record is None
            or record.plan.plan_id != plan_id
            or record.plan.operation != operation
            or record.setup_id != self.store.load().setup_id
        ):
            raise SetupError("reviewed lifecycle operation receipt is unavailable or mismatched")
        return record.plan

    def _current_schema_version(self) -> int:
        journal = self._completed_journal()
        selected = self.spec()
        database_path = selected.data_dir / "signet.db"
        if database_path.is_symlink() or not database_path.is_file():
            raise SetupError("upgrade planning requires the owned production database")
        expected_identity, expected_lock_identity, expected_parent_identity = (
            validate_active_database_runtime_ownership(
                database_path.parent,
                setup_id=journal.setup_id,
                instance_root=self.root,
                require_external_storage=selected.data_root is not None,
            )
        )
        database = Database(
            database_path,
            expected_parent_identity=expected_parent_identity,
            expected_identity=expected_identity,
            expected_lock_identity=expected_lock_identity,
        )
        try:
            with database.read_only() as connection:
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        except (DatabaseError, OSError, TypeError, ValueError) as exc:
            raise SetupError("upgrade planning could not inspect the database schema") from exc
        if version <= 0 or version > LATEST_SCHEMA_VERSION:
            raise SetupError("upgrade source schema version is unsupported")
        return version

    def _apply_reviewed_operation(
        self,
        *,
        plan_id: str,
        operation: str,
        action: str,
        plan_factory: Callable[[], LifecyclePlan],
        runner: Callable[[LifecycleOperationRecord], dict[str, Any]],
        resume_validator: Callable[[LifecyclePlan], None] | None = None,
    ) -> dict[str, Any]:
        store = LifecycleOperationStore(self.root)
        with self.lifecycle_lock():
            existing = store.load_optional()
            if existing is not None and existing.plan.plan_id == plan_id:
                record = existing
                if record.plan.operation != operation or record.plan.action != action:
                    raise SetupError(
                        "reviewed lifecycle plan does not match the requested operation"
                    )
                if resume_validator is not None:
                    resume_validator(record.plan)
                if operation == "uninstall":
                    try:
                        journal = self.store.load()
                    except SetupError:
                        if record.status == "completed" and not (
                            self.root.exists() or self.root.is_symlink()
                        ):
                            if record.result is None:
                                raise SetupError(
                                    "completed lifecycle operation receipt has no result"
                                ) from None
                            return dict(record.result)
                        raise
                else:
                    journal = self._completed_journal()
                if record.setup_id != journal.setup_id:
                    raise SetupError("reviewed lifecycle plan belongs to another setup")
                if record.status == "completed":
                    if record.result is None:
                        raise SetupError("completed lifecycle operation receipt has no result")
                    return dict(record.result)
                if record.status in {"rolling_back", "rolled_back"}:
                    raise SetupError("reviewed lifecycle operation is in rollback state")
            else:
                self._completed_journal()
                plan = plan_factory()
                if plan.plan_id != plan_id:
                    raise SetupError("reviewed lifecycle plan no longer matches observed state")
                record = store.begin(plan, phase="execute")
            record.status = "applying"
            record.attempts += 1
            record.error_kind = None
            store.save(record)
            try:
                result = runner(record)
            except Exception as exc:
                record.status = "failed"
                record.error_kind = type(exc).__name__
                store.save(record)
                raise
            record.status = "completed"
            record.phase = "completed"
            record.error_kind = None
            record.result = dict(result)
            store.save(record)
            return dict(result)

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
        selected = self.spec()
        database_path = selected.data_dir / "signet.db"
        ownership_marker = database_path.parent / ".signet-database-ownership.json"
        expected_identity = None
        expected_lock_identity = None
        expected_parent_identity = None
        if (
            database_path.exists()
            or database_path.is_symlink()
            or ownership_marker.exists()
            or ownership_marker.is_symlink()
        ):
            (
                expected_identity,
                expected_lock_identity,
                expected_parent_identity,
            ) = validate_active_database_runtime_ownership(
                database_path.parent,
                setup_id=journal.setup_id,
                instance_root=self.root,
                require_external_storage=selected.data_root is not None,
            )
        database = Database(
            database_path,
            expected_parent_identity=expected_parent_identity,
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
            max_bundle_bytes=BACKUPS_HARD_BYTES,
            key_identity_resolver=lambda reference: secret_store.get(
                SecretReference.parse(reference)
            ).reveal(),
        )


def _lifecycle_operation_metadata(record: LifecycleOperationRecord) -> dict[str, Any]:
    return {
        "plan_id": record.plan.plan_id,
        "operation": record.plan.operation,
        "action": record.plan.action,
        "status": record.status,
        "phase": record.phase,
        "attempts": record.attempts,
        "error_kind": record.error_kind,
    }


def _require_backup_destination(plan: LifecyclePlan, destination: Path | None) -> None:
    reviewed = _backup_destination(plan)
    selected = None if destination is None else str(destination)
    if selected != str(reviewed):
        raise SetupError("backup resume destination does not match the reviewed destination")


def _backup_destination(plan: LifecyclePlan) -> Path:
    reviewed = plan.observed.get("destination")
    if not isinstance(reviewed, str):
        raise SetupError("reviewed backup destination is invalid")
    destination = Path(reviewed)
    if not destination.is_absolute() or ".." in destination.parts:
        raise SetupError("reviewed backup destination is invalid")
    return destination


def _default_reviewed_backup_destination(
    backup_root: Path,
    *,
    setup_id: str,
    previous_plan_id: str | None,
) -> Path:
    chain = previous_plan_id or "initial"
    suffix = hashlib.sha256(f"{setup_id}:{chain}:backup-v1".encode()).hexdigest()[:16]
    return (backup_root / f"reviewed-{suffix}.signet-backup").absolute()


def _lifecycle_effect_receipt_path(root: Path, record: LifecycleOperationRecord) -> Path:
    plan_id = record.plan.plan_id
    if len(plan_id) != 64 or any(character not in "0123456789abcdef" for character in plan_id):
        raise SetupError("reviewed lifecycle plan identifier is invalid")
    return root.parent / f"{root.name}-recovery" / f"effect-{plan_id}.json"


def _load_lifecycle_effect_receipt(
    root: Path,
    record: LifecycleOperationRecord,
    *,
    operation: str,
) -> dict[str, Any] | None:
    path = _lifecycle_effect_receipt_path(root, record)
    if not path.exists() and not path.is_symlink():
        return None
    document = SetupJournalStore._read_document(path, label="lifecycle effect receipt")
    if (
        set(document) != {"format", "setup_id", "plan_id", "operation", "resource"}
        or document.get("format") != 1
        or document.get("setup_id") != record.setup_id
        or document.get("plan_id") != record.plan.plan_id
        or document.get("operation") != operation
        or not isinstance(document.get("resource"), dict)
    ):
        raise SetupError("lifecycle effect receipt is invalid or mismatched")
    return document


def _publish_lifecycle_effect_receipt(
    root: Path,
    record: LifecycleOperationRecord,
    *,
    operation: str,
    resource: dict[str, Any],
) -> None:
    path = _lifecycle_effect_receipt_path(root, record)
    parent_identity = require_private_directory_identity(path.parent)
    document = {
        "format": 1,
        "setup_id": record.setup_id,
        "plan_id": record.plan.plan_id,
        "operation": operation,
        "resource": resource,
    }
    existing = _load_lifecycle_effect_receipt(root, record, operation=operation)
    if existing is None:
        _write_private_json(path, document)
    elif existing != document:
        raise SetupError("lifecycle effect receipt conflicts with the completed effect")
    if _load_lifecycle_effect_receipt(root, record, operation=operation) != document:
        raise SetupError("lifecycle effect receipt publication could not be confirmed")
    revalidate_directory_identity(parent_identity, private=True)


def _reviewed_backup_effect_resource(
    effect: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    resource = effect.get("resource")
    if (
        not isinstance(resource, dict)
        or set(resource) != {"state", "artifact"}
        or resource.get("state") not in {"prepared", "published"}
        or not isinstance(resource.get("artifact"), dict)
    ):
        raise SetupError("reviewed backup effect receipt is invalid")
    return str(resource["state"]), cast(dict[str, Any], resource["artifact"])


def _publish_reviewed_backup_effect_receipt(
    root: Path,
    record: LifecycleOperationRecord,
    *,
    state: str,
    artifact: Path,
) -> None:
    if state not in {"prepared", "published"}:
        raise SetupError("reviewed backup effect state is invalid")
    destination = _backup_destination(record.plan)
    checkpoint = _private_file_checkpoint(artifact)
    if state == "prepared":
        checkpoint["path"] = str(destination)
    elif artifact != destination:
        raise SetupError("published reviewed backup path does not match the reviewed plan")
    document = {
        "format": 1,
        "setup_id": record.setup_id,
        "plan_id": record.plan.plan_id,
        "operation": "backup",
        "resource": {"state": state, "artifact": checkpoint},
    }
    existing = _load_lifecycle_effect_receipt(root, record, operation="backup")
    if existing is None:
        if state != "prepared":
            raise SetupError("reviewed backup publication was not prepared")
    else:
        existing_state, existing_checkpoint = _reviewed_backup_effect_resource(existing)
        if existing_state == "published":
            if existing != document:
                raise SetupError("reviewed backup effect receipt conflicts with prior state")
            return
        if state == "published" and existing_checkpoint != checkpoint:
            raise SetupError("published reviewed backup differs from its prepared artifact")
        if state == "prepared" and (destination.exists() or destination.is_symlink()):
            raise SetupError("reviewed backup destination appeared during publication recovery")
    path = _lifecycle_effect_receipt_path(root, record)
    parent_identity = require_private_directory_identity(path.parent)
    SetupJournalStore._write_document(path, document, replace=existing is not None)
    if _load_lifecycle_effect_receipt(root, record, operation="backup") != document:
        raise SetupError("reviewed backup effect receipt publication could not be confirmed")
    revalidate_directory_identity(parent_identity, private=True)


def _restore_tree_effect_receipt_path(destination: Path) -> Path:
    return destination / ".signet-reviewed-restore.json"


def _load_restore_tree_effect_receipt(
    destination: Path,
    record: LifecycleOperationRecord,
) -> dict[str, Any] | None:
    root_identity = require_private_directory_identity(destination)
    path = _restore_tree_effect_receipt_path(destination)
    if not path.exists() and not path.is_symlink():
        revalidate_directory_identity(root_identity, private=True)
        return None
    document = SetupJournalStore._read_document(path, label="restore-tree effect receipt")
    if (
        set(document) != {"format", "setup_id", "plan_id", "operation", "resource"}
        or document.get("format") != 1
        or document.get("setup_id") != record.setup_id
        or document.get("plan_id") != record.plan.plan_id
        or document.get("operation") != "restore"
        or not isinstance(document.get("resource"), dict)
    ):
        raise SetupError("restore-tree effect receipt is invalid or mismatched")
    revalidate_directory_identity(root_identity, private=True)
    return document


def _publish_restore_tree_effect_receipt(
    restored: RestoredBundle,
    record: LifecycleOperationRecord,
    *,
    published_root: Path | None = None,
) -> None:
    root_identity = require_private_directory_identity(restored.root)
    document = {
        "format": 1,
        "setup_id": record.setup_id,
        "plan_id": record.plan.plan_id,
        "operation": "restore",
        "resource": _restore_effect_checkpoint(restored, published_root=published_root),
    }
    existing = _load_restore_tree_effect_receipt(restored.root, record)
    if existing is None:
        _write_private_json(_restore_tree_effect_receipt_path(restored.root), document)
    elif existing != document:
        raise SetupError("restore-tree effect receipt conflicts with the restored tree")
    if _load_restore_tree_effect_receipt(restored.root, record) != document:
        raise SetupError("restore-tree effect receipt publication could not be confirmed")
    revalidate_directory_identity(root_identity, private=True)


def _restore_effect_checkpoint(
    restored: RestoredBundle,
    *,
    published_root: Path | None = None,
) -> dict[str, Any]:
    root_identity = require_private_directory_identity(restored.root)
    root_path = restored.root if published_root is None else published_root
    database = _private_file_checkpoint(restored.database_path)
    manifest = _private_file_checkpoint(restored.root / "manifest.json")
    if published_root is not None:
        database["path"] = str(published_root / restored.database_path.name)
        manifest["path"] = str(published_root / "manifest.json")
    return {
        "root": {
            "path": str(root_path),
            "device": root_identity.device,
            "inode": root_identity.inode,
            "owner_uid": root_identity.owner_uid,
        },
        "database": database,
        "manifest": manifest,
    }


def _default_reviewed_restore_destination(
    root: Path,
    *,
    setup_id: str,
    bundle_checkpoint: dict[str, Any],
    previous_plan_id: str | None,
) -> Path:
    bundle_digest = bundle_checkpoint.get("sha256")
    if not isinstance(bundle_digest, str) or (
        previous_plan_id is not None and not isinstance(previous_plan_id, str)
    ):
        raise SetupError("reviewed restore bundle digest is invalid")
    chain = previous_plan_id or "initial"
    suffix = hashlib.sha256(f"{setup_id}:{bundle_digest}:{chain}:restore-v2".encode()).hexdigest()[
        :16
    ]
    return (root / "restore" / f"reviewed-{suffix}").absolute()


def _require_restore_bundle(plan: LifecyclePlan, bundle: Path, root: Path) -> None:
    reviewed = plan.observed.get("bundle")
    if not isinstance(reviewed, dict) or _private_file_checkpoint(bundle) != reviewed:
        raise SetupError("restore resume bundle does not match the reviewed bundle")
    _restore_destination(plan, root)


def _restore_destination(plan: LifecyclePlan, root: Path) -> Path:
    reviewed_bundle = plan.observed.get("bundle")
    reviewed_destination = plan.observed.get("destination")
    previous_plan_id = plan.observed.get("previous_lifecycle_plan_id")
    if (
        not isinstance(reviewed_bundle, dict)
        or not isinstance(reviewed_destination, str)
        or (previous_plan_id is not None and not isinstance(previous_plan_id, str))
    ):
        raise SetupError("reviewed restore destination is invalid")
    destination = Path(reviewed_destination)
    expected = _default_reviewed_restore_destination(
        root,
        setup_id=plan.setup_id,
        bundle_checkpoint=reviewed_bundle,
        previous_plan_id=previous_plan_id,
    )
    if destination != expected:
        raise SetupError("reviewed restore destination is invalid")
    return destination


def _require_upgrade_target(plan: LifecyclePlan) -> None:
    target = plan.observed.get("target_schema_version")
    if not isinstance(target, int) or isinstance(target, bool) or target != LATEST_SCHEMA_VERSION:
        raise SetupError("upgrade target no longer matches the reviewed schema version")
    _upgrade_service_unit_generation(plan)


def _upgrade_service_unit_generation(plan: LifecyclePlan) -> ServiceUnitGeneration:
    generation = plan.observed.get("service_unit_generation")
    if generation not in {"current", "resource_limits_predecessor"}:
        raise SetupError("reviewed upgrade service-unit generation is invalid")
    return cast(ServiceUnitGeneration, generation)


def _reviewed_upgrade_service_state(
    plan: LifecyclePlan,
    current: dict[str, str],
) -> tuple[bool, bool]:
    before = service_observation(plan)
    managed_tailnet_port = tailscale_port(plan)
    validate_service_snapshot(
        current,
        allow_mixed=False,
        tailscale_port=managed_tailnet_port,
    )
    require_same_service_inventory(before, current)
    prior_active = set(local_service_states(before).values()) == {"active"}
    if current == before:
        return prior_active, False
    quiesced = dict(before)
    for name in local_service_states(quiesced):
        quiesced[name] = "inactive"
    if prior_active and current == quiesced:
        return True, True
    raise SetupError("upgrade service state no longer matches the reviewed plan")


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
    lifecycle_plan_id: str | None = None,
) -> Path:
    artifact_sha256 = str(migration_receipt.artifact_sha256)
    path = recovery_directory / f"upgrade-{journal.setup_id}-{artifact_sha256[:16]}.json"
    document = {
        "format": 2,
        "setup_id": journal.setup_id,
        "lifecycle_plan_id": lifecycle_plan_id,
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
        "lifecycle_plan_id",
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
    transition_allowed = (
        current_state == "backup_verified_migration_pending"
        and next_state in {"migration_applied", "assembly_failed_after_backup"}
    ) or (
        current_state == "assembly_failed_after_backup"
        and next_state in {"migration_applied", "assembly_failed_after_backup"}
    )
    if not transition_allowed:
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


def _bounded_operational_metrics(
    database: Database,
    *,
    storage: dict[str, Any] | None,
) -> dict[str, Any]:
    """Read bounded, non-secret operator counters from an initialized runtime."""

    with database.read_only() as connection:
        schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        request_rows = connection.execute(
            """
            SELECT state, count(*) AS count
            FROM approval_requests GROUP BY state ORDER BY state LIMIT 32
            """
        ).fetchall()
        reconciliation = connection.execute(
            """
            SELECT count(*) AS pending,
                   coalesce(sum(reconciliation_attempt_count), 0) AS attempts
            FROM execution_attempts WHERE phase = 'outcome_unknown'
            """
        ).fetchone()
        notifications = connection.execute(
            """
            SELECT count(*) AS pending, coalesce(max(attempts), 0) AS max_attempts
            FROM notification_outbox WHERE delivered_at IS NULL
            """
        ).fetchone()
        service_rows = connection.execute(
            """
            SELECT service_name, state, updated_at
            FROM production_services ORDER BY service_name LIMIT 32
            """
        ).fetchall()
    storage_metrics: dict[str, dict[str, int]] = {}
    if storage is not None:
        policy = storage.get("policy")
        roots = storage.get("roots")
        if isinstance(policy, dict) and isinstance(roots, dict):
            for name, policy_name in (
                ("data", "database_hard_bytes"),
                ("attachments", "attachments_hard_bytes"),
                ("backups", "backups_hard_bytes"),
                ("logs", "logs_hard_bytes"),
                ("cache", "cache_hard_bytes"),
                ("staging", "staging_hard_bytes"),
            ):
                item = roots.get(name)
                limit = policy.get(policy_name)
                if not isinstance(item, dict) or not isinstance(limit, int):
                    continue
                usage = int(item["usage_bytes"])
                storage_metrics[name] = {
                    "usage_bytes": usage,
                    "budget_headroom_bytes": limit - usage,
                    "free_bytes": int(item["free_bytes"]),
                }
    return {
        "schema_version": schema_version,
        "requests_by_state": {str(row["state"]): int(row["count"]) for row in request_rows},
        "reconciliation": {
            "pending": int(reconciliation["pending"]),
            "attempts": int(reconciliation["attempts"]),
        },
        "notification_outbox": {
            "pending": int(notifications["pending"]),
            "max_attempts": int(notifications["max_attempts"]),
        },
        "workers": {
            str(row["service_name"]): {
                "state": str(row["state"]),
                "updated_at": int(row["updated_at"]),
            }
            for row in service_rows
        },
        "storage": storage_metrics,
    }
