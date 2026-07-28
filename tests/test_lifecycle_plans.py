from __future__ import annotations

import hashlib
import json
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import signet.setup_operations as setup_operations
from signet.credential_broker import CredentialError, Secret
from signet.db import LATEST_SCHEMA_VERSION, Database
from signet.lifecycle import LifecycleOperationStore, LifecyclePlan
from signet.setup_operations import SetupOperations
from signet.setup_platform import render_production_config
from signet.setup_state import SetupEngine, SetupError, SetupJournalStore, SetupSpec


@dataclass
class FakeLifecyclePlatform:
    states: dict[str, str] = field(
        default_factory=lambda: {
            "signet-mcp": "active",
            "signet-web": "active",
            "tailscale:8443": "active",
        }
    )
    events: list[str] = field(default_factory=list)
    crash_after: str | None = None
    fail_partial_start: bool = False
    fail_health: bool = False

    def apply(self, step: str, spec: SetupSpec, setup_id: str) -> None:
        del step, spec, setup_id

    def rollback(self, step: str, spec: SetupSpec, setup_id: str) -> None:
        del step, spec, setup_id

    def validate_private_paths(self, spec: SetupSpec, setup_id: str) -> None:
        del spec, setup_id

    def preflight(self, spec: SetupSpec) -> None:
        del spec
        self.events.append("preflight")

    def service_status(self, spec: SetupSpec) -> dict[str, str]:
        del spec
        return dict(self.states)

    def manage_services(self, spec: SetupSpec, action: str) -> None:
        del spec
        self.events.append(action)
        local = [name for name in self.states if not name.startswith("tailscale:")]
        if action == "start" and self.fail_partial_start:
            self.states[local[0]] = "active"
            raise RuntimeError("injected partial start")
        target = "active" if action == "start" else "inactive"
        for name in local:
            self.states[name] = target
        if self.crash_after == action:
            self.crash_after = None
            raise KeyboardInterrupt(f"injected crash after {action}")

    def verify_service_health(self, spec: SetupSpec) -> None:
        del spec
        self.events.append("health")
        if self.fail_health:
            raise RuntimeError("injected private endpoint detail")


def installed_operations(
    tmp_path: Path,
    *,
    platform: FakeLifecyclePlatform | None = None,
) -> tuple[SetupOperations, FakeLifecyclePlatform, SetupSpec]:
    selected_platform = platform or FakeLifecyclePlatform()
    selected = SetupSpec(
        root=tmp_path / "signet",
        public_origin="https://signet.example.ts.net:8443",
        owner_user_id="user:owner",
        hermes_profiles=("work",),
        executable=Path("/opt/signet/bin/signet"),
        open_browser=False,
    )
    SetupEngine(SetupJournalStore(selected.root), selected_platform).apply(selected)
    return (
        SetupOperations(selected.root, platform=cast(Any, selected_platform)),
        selected_platform,
        selected,
    )


def fail_once_on_completed_lifecycle_save(monkeypatch: pytest.MonkeyPatch) -> None:
    original = LifecycleOperationStore.save
    failed = False

    def save(store: LifecycleOperationStore, record: Any) -> None:
        nonlocal failed
        if record.status == "completed" and not failed:
            failed = True
            raise KeyboardInterrupt("injected crash before completed receipt publication")
        original(store, record)

    monkeypatch.setattr(LifecycleOperationStore, "save", save)


def write_fake_backup(path: Path) -> Path:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(b"fake encrypted backup")
    path.chmod(0o600)
    return path


def write_reviewed_fake_backup(
    operations: SetupOperations,
    path: Path,
    record: Any,
) -> Path:
    assert record is not None
    temporary = path.with_name(f".{path.name}.partial-test")
    write_fake_backup(temporary)
    setup_operations._publish_reviewed_backup_effect_receipt(
        operations.root,
        record,
        state="prepared",
        artifact=temporary,
    )
    temporary.replace(path)
    setup_operations._publish_reviewed_backup_effect_receipt(
        operations.root,
        record,
        state="published",
        artifact=path,
    )
    return path


def accept_fake_backup_verification(
    monkeypatch: pytest.MonkeyPatch,
    operations: SetupOperations,
) -> None:
    monkeypatch.setattr(
        operations,
        "_verified_backup_receipt",
        lambda selected, **kwargs: {
            "artifact_path": str(selected),
            "artifact_sha256": "a" * 64,
        },
    )


def replace_installed_setup(
    operations: SetupOperations,
    platform: FakeLifecyclePlatform,
    selected: SetupSpec,
) -> str:
    previous_setup_id = operations.store.load().setup_id
    shutil.rmtree(selected.root)
    SetupEngine(SetupJournalStore(selected.root), platform).apply(selected)
    replacement_setup_id = SetupJournalStore(selected.root).load().setup_id
    assert replacement_setup_id != previous_setup_id
    return replacement_setup_id


def test_service_plan_is_read_only_and_refuses_unknown_service_or_serve_state(
    tmp_path: Path,
) -> None:
    operations, platform, selected = installed_operations(tmp_path)
    before = {
        path.relative_to(selected.root): path.read_bytes()
        for path in selected.root.rglob("*")
        if path.is_file()
    }

    first = operations.plan_services("stop")
    second = operations.plan_services("stop")

    assert first.plan_id == second.plan_id
    assert first.document()["steps"] == [
        "inspect_owned_service_state",
        "stop_local_services",
        "verify_local_services_inactive",
    ]
    assert first.document()["gateway_restart"] is False
    assert first.document()["human_confirmation_required"] is True
    assert not (tmp_path / "signet-recovery").exists()
    assert before == {
        path.relative_to(selected.root): path.read_bytes()
        for path in selected.root.rglob("*")
        if path.is_file()
    }

    platform.states["tailscale:8443"] = "unavailable"
    with pytest.raises(SetupError, match="Tailscale Serve state"):
        operations.plan_services("stop")
    platform.states["tailscale:8443"] = "active"
    platform.states["signet-web"] = "missing_or_changed"
    with pytest.raises(SetupError, match="service-manager state"):
        operations.plan_services("stop")


def test_service_plan_apply_is_review_bound_and_idempotent(tmp_path: Path) -> None:
    operations, platform, _ = installed_operations(tmp_path)
    plan = operations.plan_services("stop")

    result = operations.apply_service_plan("stop", plan.plan_id)
    repeated = operations.apply_service_plan("stop", plan.plan_id)

    assert result == repeated
    assert result["services"] == {
        "signet-mcp": "inactive",
        "signet-web": "inactive",
        "tailscale:8443": "active",
    }
    assert platform.events == ["stop"]
    receipt = tmp_path / "signet-recovery" / "lifecycle-operation.json"
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
    assert json.loads(receipt.read_text(encoding="utf-8"))["status"] == "completed"
    assert operations.status()["lifecycle_operation"]["status"] == "completed"
    assert operations.doctor()["checks"]["lifecycle_operation"]["status"] == "completed"

    with pytest.raises(SetupError, match="reviewed lifecycle plan"):
        operations.apply_service_plan("stop", "0" * 64)
    assert platform.events == ["stop", "health"]


def test_service_plan_apply_shares_the_setup_operation_lock(tmp_path: Path) -> None:
    operations, platform, _ = installed_operations(tmp_path)
    plan = operations.plan_services("stop")

    with (
        operations.lifecycle_lock(),
        pytest.raises(
            SetupError,
            match="another setup lifecycle operation",
        ),
    ):
        operations.apply_service_plan("stop", plan.plan_id)

    assert platform.events == []


@pytest.mark.parametrize("crash_after", ["stop", "start"])
def test_restart_plan_resumes_after_each_service_manager_crash_boundary(
    tmp_path: Path,
    crash_after: str,
) -> None:
    platform = FakeLifecyclePlatform(crash_after=crash_after)
    operations, _, _ = installed_operations(tmp_path, platform=platform)
    plan = operations.plan_services("restart")

    with pytest.raises(KeyboardInterrupt, match="injected crash"):
        operations.apply_service_plan("restart", plan.plan_id)

    assert platform.states["signet-mcp"] == ("inactive" if crash_after == "stop" else "active")
    assert operations.apply_service_plan("restart", plan.plan_id)["services"]["signet-web"] == (
        "active"
    )
    assert platform.events == ["stop", "start", "health"]


def test_service_apply_refuses_a_plan_when_observed_state_changed(tmp_path: Path) -> None:
    operations, platform, selected = installed_operations(tmp_path)
    plan = operations.plan_services("stop")
    platform.states["signet-mcp"] = "inactive"
    platform.states["signet-web"] = "inactive"

    with pytest.raises(SetupError, match="no longer matches observed state"):
        operations.apply_service_plan("stop", plan.plan_id)

    assert platform.events == []
    assert not LifecycleOperationStore(selected.root).path.exists()


def test_completed_service_plan_cannot_be_replayed_after_a_later_plan(tmp_path: Path) -> None:
    operations, platform, _ = installed_operations(tmp_path)
    old_stop = operations.plan_services("stop")
    operations.apply_service_plan("stop", old_stop.plan_id)
    start = operations.plan_services("start")
    operations.apply_service_plan("start", start.plan_id)

    with pytest.raises(SetupError, match="no longer matches observed state"):
        operations.apply_service_plan("stop", old_stop.plan_id)

    assert platform.events == ["stop", "start", "health"]


def test_service_plan_receipt_cannot_be_replayed_against_a_replacement_setup(
    tmp_path: Path,
) -> None:
    operations, platform, selected = installed_operations(tmp_path)
    plan = operations.plan_services("stop")
    operations.apply_service_plan("stop", plan.plan_id)
    replace_installed_setup(operations, platform, selected)

    with pytest.raises(SetupError, match="another setup"):
        operations.apply_service_plan("stop", plan.plan_id)

    replacement_plan = operations.plan_services("stop")
    operations.apply_service_plan("stop", replacement_plan.plan_id)

    assert platform.events == ["stop"]
    assert replacement_plan.observed["previous_lifecycle_plan_id"] is None


def test_service_plan_requires_the_expected_tailscale_serve_observation(tmp_path: Path) -> None:
    operations, platform, _ = installed_operations(tmp_path)
    del platform.states["tailscale:8443"]

    with pytest.raises(SetupError, match="Tailscale Serve state"):
        operations.plan_services("stop")

    platform.states["tailscale:9999"] = "active"
    with pytest.raises(SetupError, match="Tailscale Serve state"):
        operations.plan_services("stop")


def test_failed_partial_service_apply_can_roll_back_to_the_reviewed_before_state(
    tmp_path: Path,
) -> None:
    platform = FakeLifecyclePlatform(
        states={
            "signet-mcp": "inactive",
            "signet-web": "inactive",
            "tailscale:8443": "active",
        },
        fail_partial_start=True,
    )
    operations, _, _ = installed_operations(tmp_path, platform=platform)
    plan = operations.plan_services("start")

    with pytest.raises(SetupError, match="service plan apply failed"):
        operations.apply_service_plan("start", plan.plan_id)
    assert set(platform.states.values()) >= {"active", "inactive"}
    assert operations.doctor()["checks"]["lifecycle_operation"] == {
        "ok": False,
        "status": "failed",
        "remediation": (
            "Resume the exact reviewed plan; use explicit rollback only for a service plan."
        ),
    }
    platform.fail_partial_start = False
    rolled_back = operations.rollback_service_plan(plan.plan_id)

    assert rolled_back["services"] == {
        "signet-mcp": "inactive",
        "signet-web": "inactive",
        "tailscale:8443": "active",
    }
    assert platform.events == ["start", "health", "stop"]


def test_upgrade_and_uninstall_plans_identify_mutation_and_destruction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    monkeypatch.setattr(operations, "_current_schema_version", lambda: 18)

    upgrade = operations.plan_upgrade().document()
    uninstall = operations.plan_uninstall(purge=False).document()
    purge = operations.plan_uninstall(purge=True).document()

    assert upgrade["observed"]["schema_version"] == 18
    assert upgrade["observed"]["target_schema_version"] >= 18
    assert upgrade["destructive_actions"] == []
    assert upgrade["human_confirmation_required"] is True
    assert uninstall["destructive_actions"] == [
        "remove_owned_services_and_tailscale_route",
        "remove_owned_hermes_profile_blocks_and_tokens",
    ]
    assert "remove_owned_production_data" in purge["destructive_actions"]
    assert "create_and_verify_encrypted_backup" in purge["steps"]
    assert purge["gateway_restart"] is False


def test_backup_and_restore_plans_are_read_only_and_bind_the_encrypted_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, platform, _ = installed_operations(tmp_path)
    destination = tmp_path / "reviewed-backup.signet-backup"
    bundle = tmp_path / "existing-backup.signet-backup"
    bundle.write_bytes(b"encrypted-backup-v1")
    bundle.chmod(0o600)
    before = set(tmp_path.rglob("*"))

    backup = operations.plan_backup(destination).document()
    restore = operations.plan_restore(bundle).document()

    assert backup["operation"] == "backup"
    assert backup["observed"]["destination"] == str(destination)
    assert restore["operation"] == "restore"
    assert restore["observed"]["bundle"]["sha256"]
    assert set(tmp_path.rglob("*")) == before
    assert platform.events == []

    bundle.write_bytes(b"encrypted-backup-v2")
    monkeypatch.setattr(
        operations,
        "_restore",
        lambda selected, **kwargs: pytest.fail("stale restore plan must not decrypt the bundle"),
    )
    with pytest.raises(SetupError, match="no longer matches observed state"):
        operations.apply_restore(restore["plan_id"], bundle)


def test_reviewed_backup_apply_is_not_repeated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    destination = tmp_path / "reviewed-backup.signet-backup"
    calls = 0
    verifications = 0

    def backup(
        selected: Path | None = None,
        *,
        completion_record: Any = None,
    ) -> Path:
        nonlocal calls
        calls += 1
        assert selected == destination
        return write_reviewed_fake_backup(operations, destination, completion_record)

    def verify(selected: Path, **kwargs: object) -> dict[str, object]:
        nonlocal verifications
        verifications += 1
        assert selected == destination
        assert kwargs["verify_live_database"] is False
        return {"artifact_path": str(selected)}

    monkeypatch.setattr(operations, "_backup", backup)
    monkeypatch.setattr(operations, "_verified_backup_receipt", verify)
    plan = operations.plan_backup(destination)

    first = operations.apply_backup(plan.plan_id, destination)
    second = operations.apply_backup(plan.plan_id, destination)

    assert first == second == {"backup": str(destination)}
    assert calls == 1
    assert verifications == 1


def test_completed_backup_receipt_cannot_be_replayed_against_a_replacement_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, platform, selected = installed_operations(tmp_path)
    destination = tmp_path / "reviewed-backup.signet-backup"
    monkeypatch.setattr(
        operations,
        "_backup",
        lambda selected=None, completion_record=None: write_reviewed_fake_backup(
            operations,
            cast(Path, selected),
            completion_record,
        ),
    )
    accept_fake_backup_verification(monkeypatch, operations)
    plan = operations.plan_backup(destination)
    operations.apply_backup(plan.plan_id, destination)
    replace_installed_setup(operations, platform, selected)

    with pytest.raises(SetupError, match="another setup"):
        operations.apply_backup(plan.plan_id, destination)

    replacement_plan = operations.plan_backup(tmp_path / "replacement-backup.signet-backup")
    replacement_result = operations.apply_backup(
        replacement_plan.plan_id,
        tmp_path / "replacement-backup.signet-backup",
    )

    assert replacement_plan.observed["previous_lifecycle_plan_id"] is None
    assert replacement_result["backup"].endswith("replacement-backup.signet-backup")


def test_reviewed_backup_adopts_a_verified_artifact_after_receipt_publication_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    destination = tmp_path / "reviewed-backup.signet-backup"
    calls = 0
    verifications = 0

    def backup(
        selected: Path | None = None,
        *,
        completion_record: Any = None,
    ) -> Path:
        nonlocal calls
        calls += 1
        assert selected == destination
        assert not destination.exists()
        return write_reviewed_fake_backup(operations, destination, completion_record)

    def verify(bundle: Path, **kwargs: Any) -> dict[str, Any]:
        nonlocal verifications
        verifications += 1
        assert bundle == destination
        assert kwargs["verify_live_database"] is False
        return {
            "artifact_path": str(bundle),
            "artifact_sha256": "a" * 64,
            "source_schema_version": 19,
            "verified_restore_schema_version": 19,
        }

    monkeypatch.setattr(operations, "_backup", backup)
    monkeypatch.setattr(operations, "_verified_backup_receipt", verify)
    fail_once_on_completed_lifecycle_save(monkeypatch)
    plan = operations.plan_backup(destination)

    with pytest.raises(KeyboardInterrupt, match="completed receipt"):
        operations.apply_backup(plan.plan_id, destination)

    result = operations.apply_backup(plan.plan_id, destination)

    assert result == {"backup": str(destination)}
    assert calls == 1
    assert verifications == 2


def test_reviewed_backup_recovers_a_prepared_artifact_after_publication_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    destination = tmp_path / "reviewed-backup.signet-backup"
    calls = 0

    class InterruptingManager:
        def create(
            self,
            selected: Path,
            *,
            required_key_references: tuple[str, ...],
            prepare_publication: Any,
            finalize_publication: Any,
        ) -> Path:
            nonlocal calls
            del required_key_references, finalize_publication
            calls += 1
            temporary = selected.with_name(f".{selected.name}.partial-test")
            temporary.write_bytes(b"reviewed encrypted backup")
            temporary.chmod(0o600)
            prepare_publication(temporary)
            temporary.replace(selected)
            raise KeyboardInterrupt("injected crash before final effect publication")

    monkeypatch.setattr(operations, "_backup_manager", lambda journal: InterruptingManager())
    monkeypatch.setattr(operations, "_production_key_references", lambda: ())
    monkeypatch.setattr(
        operations,
        "_verified_backup_receipt",
        lambda bundle, **kwargs: {
            "artifact_path": str(bundle),
            "artifact_sha256": "a" * 64,
            "source_schema_version": 19,
            "verified_restore_schema_version": 19,
        },
    )
    plan = operations.plan_backup(destination)

    with pytest.raises(KeyboardInterrupt, match="final effect publication"):
        operations.apply_backup(plan.plan_id, destination)

    assert operations.apply_backup(plan.plan_id, destination) == {"backup": str(destination)}
    assert calls == 1


def test_reviewed_backup_never_adopts_a_destination_that_appeared_before_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    destination = tmp_path / "reviewed-backup.signet-backup"
    plan = operations.plan_backup(destination)
    destination.write_bytes(b"foreign but structurally valid encrypted backup")
    destination.chmod(0o600)
    verifications = 0

    def verify(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal verifications
        del args, kwargs
        verifications += 1
        return {}

    monkeypatch.setattr(operations, "_verified_backup_receipt", verify)
    for _attempt in range(2):
        with pytest.raises(SetupError, match="appeared after plan review"):
            operations.apply_backup(plan.plan_id, destination)

    assert verifications == 0


def test_reviewed_backup_rechecks_the_effect_identity_after_resume_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    destination = tmp_path / "verified-after-resume.signet-backup"
    plan = operations.plan_backup(destination)
    fail_once_on_completed_lifecycle_save(monkeypatch)
    monkeypatch.setattr(
        operations,
        "_backup",
        lambda selected, completion_record=None: write_reviewed_fake_backup(
            operations,
            selected,
            completion_record,
        ),
    )
    accept_fake_backup_verification(monkeypatch, operations)

    with pytest.raises(KeyboardInterrupt, match="completed receipt"):
        operations.apply_backup(plan.plan_id, destination)

    def verify_and_replace(selected: Path, **_: Any) -> dict[str, Any]:
        selected.write_bytes(b"replacement backup")
        selected.chmod(0o600)
        return {"artifact_path": str(selected)}

    monkeypatch.setattr(operations, "_verified_backup_receipt", verify_and_replace)

    with pytest.raises(SetupError, match="changed during resume verification"):
        operations.apply_backup(plan.plan_id, destination)


def test_default_backup_plan_binds_a_stable_destination_before_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, selected = installed_operations(tmp_path)
    first = operations.plan_backup()
    second = operations.plan_backup()
    destination = Path(str(first.observed["destination"]))

    assert first.plan_id == second.plan_id
    assert destination.parent == selected.root / "backups"
    calls: list[Path | None] = []

    def backup(
        selected: Path | None = None,
        *,
        completion_record: Any = None,
    ) -> Path:
        calls.append(selected)
        return write_reviewed_fake_backup(operations, destination, completion_record)

    monkeypatch.setattr(operations, "_backup", backup)
    accept_fake_backup_verification(monkeypatch, operations)
    assert operations.apply_backup(first.plan_id) == {"backup": str(destination)}
    assert calls == [destination]


def test_backup_capacity_preflight_uses_the_selected_destination_filesystem(
    tmp_path: Path,
) -> None:
    operations, platform, _ = installed_operations(tmp_path)
    destination_root = tmp_path / "reviewed-external-backups"
    destination_root.mkdir(mode=0o700)
    destination = destination_root / "backup.signet-backup"
    cast(Any, platform).disk_usage_provider = lambda _path: SimpleNamespace(
        total=100 * 1024**3,
        used=100 * 1024**3 - 1,
        free=1,
    )

    class ForbiddenManager:
        def create(self, *_args: Any, **_kwargs: Any) -> Path:
            raise AssertionError("backup creation crossed the destination capacity preflight")

    with pytest.raises(SetupError, match="backup storage budget"):
        operations._backup(destination, manager=cast(Any, ForbiddenManager()))


def test_operational_metrics_are_bounded_and_exclude_payload_data(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    database = Database(data / "signet.db")
    database.initialize()
    storage = {
        "policy": {
            "database_hard_bytes": 100,
            "attachments_hard_bytes": 200,
            "backups_hard_bytes": 300,
            "logs_hard_bytes": 400,
            "cache_hard_bytes": 500,
            "staging_hard_bytes": 600,
        },
        "roots": {
            name: {"usage_bytes": index, "free_bytes": 1_000}
            for index, name in enumerate(
                ("data", "attachments", "backups", "logs", "cache", "staging"),
                start=1,
            )
        },
    }

    metrics = setup_operations._bounded_operational_metrics(database, storage=storage)

    assert metrics["schema_version"] == LATEST_SCHEMA_VERSION
    assert metrics["requests_by_state"] == {}
    assert metrics["reconciliation"] == {"pending": 0, "attempts": 0}
    assert metrics["notification_outbox"] == {"pending": 0, "max_attempts": 0}
    assert metrics["workers"] == {}
    assert metrics["storage"]["data"] == {
        "usage_bytes": 1,
        "budget_headroom_bytes": 99,
        "free_bytes": 1_000,
    }
    assert "path" not in repr(metrics)


def test_interrupted_backup_and_restore_reject_unreviewed_resume_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    destination = tmp_path / "reviewed-backup.signet-backup"
    wrong_destination = tmp_path / "wrong-backup.signet-backup"
    backup_plan = operations.plan_backup(destination)
    backup_calls = 0

    def backup(
        selected: Path | None = None,
        *,
        completion_record: Any = None,
    ) -> Path:
        nonlocal backup_calls
        backup_calls += 1
        if backup_calls == 1:
            raise KeyboardInterrupt("injected backup interruption")
        assert selected == destination
        return write_reviewed_fake_backup(operations, destination, completion_record)

    monkeypatch.setattr(operations, "_backup", backup)
    accept_fake_backup_verification(monkeypatch, operations)
    with pytest.raises(KeyboardInterrupt, match="backup interruption"):
        operations.apply_backup(backup_plan.plan_id, destination)
    with pytest.raises(SetupError, match="does not match the reviewed destination"):
        operations.apply_backup(backup_plan.plan_id, wrong_destination)
    assert operations.apply_backup(backup_plan.plan_id, destination) == {"backup": str(destination)}

    bundle = tmp_path / "reviewed-bundle.signet-backup"
    wrong_bundle = tmp_path / "wrong-bundle.signet-backup"
    bundle.write_bytes(b"encrypted-reviewed")
    wrong_bundle.write_bytes(b"encrypted-wrong")
    bundle.chmod(0o600)
    wrong_bundle.chmod(0o600)
    restore_plan = operations.plan_restore(bundle)
    restore_calls = 0

    def restore(selected: Path, **kwargs: Any) -> Any:
        nonlocal restore_calls
        del kwargs
        restore_calls += 1
        raise KeyboardInterrupt(f"injected restore interruption: {selected}")

    monkeypatch.setattr(operations, "_restore", restore)
    with pytest.raises(KeyboardInterrupt, match="restore interruption"):
        operations.apply_restore(restore_plan.plan_id, bundle)
    with pytest.raises(SetupError, match="does not match the reviewed bundle"):
        operations.apply_restore(restore_plan.plan_id, wrong_bundle)
    assert restore_calls == 1


def test_reviewed_restore_reuses_its_verified_tree_after_tree_receipt_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    bundle = tmp_path / "reviewed-bundle.signet-backup"
    bundle.write_bytes(b"encrypted-reviewed")
    bundle.chmod(0o600)
    plan = operations.plan_restore(bundle)
    destination = Path(str(plan.observed["destination"]))
    calls = 0
    adoptions = 0

    def restore(
        selected: Path,
        *,
        destination: Path | None = None,
        completion_record: Any = None,
    ) -> Any:
        nonlocal calls
        calls += 1
        assert selected == bundle
        assert destination is not None
        assert completion_record is not None
        destination.mkdir(mode=0o700, parents=True)
        database_path = destination / "approvals.sqlite3"
        database_path.write_bytes(b"verified database")
        database_path.chmod(0o600)
        manifest = destination / "manifest.json"
        manifest.write_bytes(b"{}")
        manifest.chmod(0o600)
        restored = SimpleNamespace(root=destination, database_path=database_path)
        setup_operations._publish_restore_tree_effect_receipt(restored, completion_record)
        raise KeyboardInterrupt("injected crash after restore-tree effect publication")

    def adopt(selected: Path, expected_resource: Any) -> Any:
        nonlocal adoptions
        adoptions += 1
        assert selected == destination
        assert expected_resource is not None
        return SimpleNamespace(root=selected, database_path=selected / "approvals.sqlite3")

    monkeypatch.setattr(operations, "_restore", restore)
    monkeypatch.setattr(operations, "_resume_restored_bundle", adopt)

    with pytest.raises(KeyboardInterrupt, match="restore-tree effect"):
        operations.apply_restore(plan.plan_id, bundle)

    result = operations.apply_restore(plan.plan_id, bundle)

    assert result == {
        "restored_to": str(destination),
        "database": str(destination / "approvals.sqlite3"),
        "activated": False,
    }
    assert calls == 1
    assert adoptions == 1


def test_reviewed_restore_never_adopts_a_tree_that_appeared_before_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    bundle = tmp_path / "reviewed-bundle.signet-backup"
    bundle.write_bytes(b"encrypted-reviewed")
    bundle.chmod(0o600)
    plan = operations.plan_restore(bundle)
    destination = Path(str(plan.observed["destination"]))
    destination.mkdir(mode=0o700, parents=True)
    adoptions = 0

    def adopt(*args: Any, **kwargs: Any) -> Any:
        nonlocal adoptions
        del args, kwargs
        adoptions += 1
        return SimpleNamespace(root=destination, database_path=destination / "approvals.sqlite3")

    monkeypatch.setattr(operations, "_resume_restored_bundle", adopt)
    for _attempt in range(2):
        with pytest.raises(SetupError, match="appeared after plan review"):
            operations.apply_restore(plan.plan_id, bundle)

    assert adoptions == 0


def test_reviewed_restore_resume_accepts_the_relocated_database_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, selected = installed_operations(tmp_path)
    destination = selected.root / "restore" / "relocated"
    destination.parent.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    attachments = destination / "attachments"
    attachments.mkdir(mode=0o700)
    database = destination / "approvals.sqlite3"
    database.write_bytes(b"relocated attachment paths")
    database.chmod(0o600)
    manifest_path = destination / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "format": 2,
                "database_sha256": hashlib.sha256(b"archive database").hexdigest(),
                "schema_version": 19,
            }
        )
    )
    manifest_path.chmod(0o600)
    resource = setup_operations._restore_effect_checkpoint(
        cast(Any, SimpleNamespace(root=destination, database_path=database))
    )

    class ReadOnly:
        def __enter__(self) -> Any:
            return SimpleNamespace(execute=lambda query: SimpleNamespace(fetchone=lambda: (19,)))

        def __exit__(self, *_: Any) -> None:
            return None

    class FakeDatabase:
        def __init__(self, path: Path) -> None:
            self.path = path

        @staticmethod
        def verify_snapshot(path: Path) -> None:
            assert path == database

        def read_only(self) -> ReadOnly:
            return ReadOnly()

    manager = SimpleNamespace(_verify_restored_attachments=lambda *args: None)
    monkeypatch.setattr(setup_operations, "Database", FakeDatabase)
    monkeypatch.setattr(operations, "_backup_manager", lambda journal: manager)

    restored = operations._resume_restored_bundle(destination, resource)

    assert restored.database_path == database


def test_successive_reviewed_restores_use_distinct_private_destinations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    bundle = tmp_path / "repeatable.signet-backup"
    bundle.write_bytes(b"encrypted backup")
    bundle.chmod(0o600)

    def restore(
        selected: Path,
        *,
        destination: Path | None = None,
        completion_record: Any = None,
    ) -> SimpleNamespace:
        assert selected == bundle
        assert destination is not None
        assert completion_record is not None
        destination.parent.mkdir(mode=0o700, exist_ok=True)
        destination.mkdir(mode=0o700)
        database = destination / "approvals.sqlite3"
        database.write_bytes(b"restored database")
        database.chmod(0o600)
        manifest = destination / "manifest.json"
        manifest.write_bytes(b"{}")
        manifest.chmod(0o600)
        setup_operations._publish_restore_tree_effect_receipt(
            SimpleNamespace(root=destination, database_path=database),
            completion_record,
        )
        return SimpleNamespace(root=destination, database_path=database)

    monkeypatch.setattr(operations, "_restore", restore)
    first = operations.plan_restore(bundle)
    operations.apply_restore(first.plan_id, bundle)
    second = operations.plan_restore(bundle)
    operations.apply_restore(second.plan_id, bundle)

    assert first.observed["destination"] != second.observed["destination"]


def test_reviewed_upgrade_apply_is_not_repeated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    monkeypatch.setattr(operations, "_current_schema_version", lambda: 18)
    calls = 0

    def upgrade(reviewed_plan: LifecyclePlan | None = None) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        assert reviewed_plan is not None
        return {"schema_version": 19, "backup": "/private/verified-backup"}

    monkeypatch.setattr(operations, "_upgrade", upgrade)
    plan = operations.plan_upgrade()

    first = operations.apply_upgrade(plan.plan_id)
    second = operations.apply_upgrade(plan.plan_id)

    assert first == second == {"schema_version": 19, "backup": "/private/verified-backup"}
    assert calls == 1


def test_reviewed_upgrade_apply_resumes_after_an_interrupted_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    monkeypatch.setattr(operations, "_current_schema_version", lambda: 18)
    calls = 0

    def upgrade(reviewed_plan: LifecyclePlan | None = None) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        assert reviewed_plan is not None
        if calls == 1:
            raise KeyboardInterrupt("injected upgrade interruption")
        return {"schema_version": 19, "backup": "/private/verified-backup"}

    monkeypatch.setattr(operations, "_upgrade", upgrade)
    plan = operations.plan_upgrade()

    with pytest.raises(KeyboardInterrupt, match="injected upgrade interruption"):
        operations.apply_upgrade(plan.plan_id)

    result = operations.apply_upgrade(plan.plan_id)
    repeated = operations.apply_upgrade(plan.plan_id)
    assert result == repeated
    assert calls == 2


def test_reviewed_upgrade_adopts_a_completed_migration_after_receipt_publication_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    monkeypatch.setattr(operations, "_current_schema_version", lambda: 18)
    result = {
        "schema_version": 19,
        "backup": "/private/verified-backup",
        "upgrade_receipt": "/private/verified-upgrade-receipt",
    }
    calls = 0
    adoptions = 0

    def upgrade(reviewed_plan: LifecyclePlan | None = None) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        assert reviewed_plan is not None
        return result

    def resume(reviewed_plan: LifecyclePlan) -> dict[str, Any]:
        nonlocal adoptions
        adoptions += 1
        assert reviewed_plan.operation == "upgrade"
        return result

    monkeypatch.setattr(operations, "_upgrade", upgrade)
    monkeypatch.setattr(operations, "_resume_reviewed_upgrade", resume, raising=False)
    fail_once_on_completed_lifecycle_save(monkeypatch)
    plan = operations.plan_upgrade()

    with pytest.raises(KeyboardInterrupt, match="completed receipt"):
        operations.apply_upgrade(plan.plan_id)

    assert operations.apply_upgrade(plan.plan_id) == result
    assert calls == 1
    assert adoptions == 1


def test_reviewed_upgrade_recovery_uses_the_owned_database_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, selected = installed_operations(tmp_path)
    journal = operations.store.load()
    database_path = selected.root / "data" / "signet.db"
    database_path.parent.mkdir(mode=0o700, exist_ok=True)
    database_path.write_bytes(b"owned database")
    database_path.chmod(0o600)
    database_metadata = database_path.stat()
    source_identity = database_metadata.st_dev, database_metadata.st_ino
    recovery = tmp_path / f"{selected.root.name}-recovery"
    recovery.mkdir(mode=0o700)
    backup = recovery / "migration.signet-backup"
    backup.write_bytes(b"encrypted migration backup")
    backup.chmod(0o600)
    backup_digest = hashlib.sha256(backup.read_bytes()).hexdigest()
    receipt_path = recovery / f"upgrade-{journal.setup_id}-{backup_digest[:16]}.json"
    receipt_path.write_text(
        json.dumps(
            {
                "format": 2,
                "setup_id": journal.setup_id,
                "lifecycle_plan_id": "f" * 64,
                "state": "migration_applied",
                "backup_path": str(backup),
                "backup_sha256": backup_digest,
                "source_schema_version": 1,
                "source_database_device": source_identity[0],
                "source_database_inode": source_identity[1],
                "verified_restore_schema_version": 1,
                "observed_schema_version": setup_operations.LATEST_SCHEMA_VERSION,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    receipt_path.chmod(0o600)
    plan = LifecyclePlan(
        setup_id=journal.setup_id,
        operation="upgrade",
        action="upgrade",
        observed={
            "schema_version": 1,
            "target_schema_version": setup_operations.LATEST_SCHEMA_VERSION,
        },
        steps=(),
    )
    database = SimpleNamespace(path=database_path)
    monkeypatch.setattr(
        operations,
        "_backup_manager",
        lambda selected_journal: SimpleNamespace(database=database),
    )
    monkeypatch.setattr(
        setup_operations,
        "validate_active_database_runtime_ownership",
        lambda *args, **kwargs: (source_identity, (1, 2), object()),
    )

    assert operations._reviewed_upgrade_recovery(plan, recovery) is None

    receipt_document = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_document["lifecycle_plan_id"] = plan.plan_id
    receipt_path.write_text(json.dumps(receipt_document, sort_keys=True), encoding="utf-8")
    receipt_path.chmod(0o600)
    recovered = operations._reviewed_upgrade_recovery(plan, recovery)

    assert recovered is not None
    assert recovered[2].source_database_device == source_identity[0]
    assert recovered[2].source_database_inode == source_identity[1]

    receipt_document["state"] = "assembly_failed_after_backup"
    receipt_path.write_text(json.dumps(receipt_document, sort_keys=True), encoding="utf-8")
    receipt_path.chmod(0o600)

    assert operations._reviewed_upgrade_recovery(plan, recovery) is not None


def test_reviewed_upgrade_resumes_a_failed_assembly_from_its_verified_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, selected = installed_operations(tmp_path)
    journal = operations.store.load()
    plan = LifecyclePlan(
        setup_id=journal.setup_id,
        operation="upgrade",
        action="upgrade",
        observed={"schema_version": 18, "target_schema_version": 19},
        steps=("upgrade",),
    )
    backup = tmp_path / "verified-upgrade.signet-backup"
    migration_receipt = SimpleNamespace(
        artifact_path=backup,
        artifact_sha256="a" * 64,
    )
    recovery_receipt = tmp_path / f"{selected.root.name}-recovery" / "upgrade.json"
    receipt_document = {
        "state": "assembly_failed_after_backup",
        "observed_schema_version": 19,
    }
    result = {"schema_version": 19, "backup": str(backup)}
    continuations = 0

    monkeypatch.setattr(operations, "_current_schema_version", lambda: 19)
    monkeypatch.setattr(
        operations,
        "_reviewed_upgrade_recovery",
        lambda reviewed_plan, recovery: (
            recovery_receipt,
            receipt_document,
            migration_receipt,
        ),
    )
    monkeypatch.setattr(
        operations,
        "_verified_backup_receipt",
        lambda *args, **kwargs: {
            "artifact_path": str(backup),
            "artifact_sha256": "a" * 64,
        },
    )

    def continue_upgrade(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal continuations
        del args, kwargs
        continuations += 1
        return result

    monkeypatch.setattr(operations, "_continue_reviewed_upgrade", continue_upgrade)

    assert operations._resume_reviewed_upgrade(plan) == result
    assert continuations == 1


def test_reviewed_upgrade_rechecks_live_source_before_reusing_its_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, platform, selected = installed_operations(tmp_path)
    monkeypatch.setattr(operations, "_current_schema_version", lambda: 18)
    plan = operations.plan_upgrade()
    backup = tmp_path / "verified-upgrade.signet-backup"
    migration_receipt = SimpleNamespace(
        artifact_path=backup,
        artifact_sha256="a" * 64,
    )
    monkeypatch.setattr(
        operations,
        "_reviewed_upgrade_recovery",
        lambda reviewed_plan, recovery: (
            recovery / "upgrade.json",
            {
                "state": "backup_verified_migration_pending",
                "observed_schema_version": 18,
            },
            migration_receipt,
        ),
    )

    def verify(*args: Any, **kwargs: Any) -> dict[str, Any]:
        del args
        assert kwargs["verify_live_database"] is True
        assert kwargs["expected_source_schema_version"] == 18
        raise SetupError("live database changed after the reviewed upgrade backup")

    monkeypatch.setattr(operations, "_verified_backup_receipt", verify)

    with pytest.raises(SetupError, match="live database changed"):
        operations._resume_reviewed_upgrade(plan)

    assert platform.events == ["preflight", "stop"]
    assert all(
        state == "inactive"
        for name, state in platform.states.items()
        if not name.startswith("tailscale:")
    )
    assert selected.root.is_dir()


def test_reviewed_upgrade_replays_pending_assembly_at_the_target_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    monkeypatch.setattr(operations, "_current_schema_version", lambda: 18)
    plan = operations.plan_upgrade()
    backup = tmp_path / "verified-upgrade.signet-backup"
    migration_receipt = SimpleNamespace(
        artifact_path=backup,
        artifact_sha256="a" * 64,
    )
    receipt = {
        "state": "backup_verified_migration_pending",
        "observed_schema_version": 18,
    }
    monkeypatch.setattr(operations, "_current_schema_version", lambda: 19)
    monkeypatch.setattr(
        operations,
        "_reviewed_upgrade_recovery",
        lambda reviewed_plan, recovery: (
            recovery / "upgrade.json",
            receipt,
            migration_receipt,
        ),
    )
    monkeypatch.setattr(
        operations,
        "_verified_backup_receipt",
        lambda *args, **kwargs: {
            "artifact_path": str(backup),
            "artifact_sha256": "a" * 64,
        },
    )
    result = {"schema_version": 19, "backup": str(backup)}
    continuations = 0

    def continue_upgrade(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal continuations
        del args, kwargs
        continuations += 1
        return result

    monkeypatch.setattr(operations, "_continue_reviewed_upgrade", continue_upgrade)

    assert operations._resume_reviewed_upgrade(plan) == result
    assert continuations == 1


def test_completed_reviewed_purge_replay_does_not_recreate_a_missing_root(
    tmp_path: Path,
) -> None:
    operations, _, selected = installed_operations(tmp_path)
    plan = operations.plan_uninstall(purge=True)
    store = LifecycleOperationStore(selected.root)
    record = store.begin(plan, phase="purge")
    record.status = "completed"
    record.attempts = 1
    record.result = {"purge": True, "backup": "verified"}
    store.save(record)
    shutil.rmtree(selected.root)

    assert not selected.root.exists()
    result = operations.apply_uninstall(plan.plan_id, purge=True)

    assert result == {"purge": True, "backup": "verified"}
    assert not selected.root.exists()


@pytest.mark.parametrize("purge", [False, True])
def test_reviewed_uninstall_resumes_after_journal_leaves_completed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    purge: bool,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    plan = operations.plan_uninstall(purge=purge)
    record = LifecycleOperationStore(operations.root).begin(plan, phase="execute")
    setup_id = operations.store.load().setup_id
    record.status = "applying"
    LifecycleOperationStore(operations.root).save(record)
    monkeypatch.setattr(
        operations.store,
        "load",
        lambda: SimpleNamespace(setup_id=setup_id, status="rolling_back"),
    )
    calls = 0

    def resume(*, purge: bool = False) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {"purged": purge, "removed": ["services"]}

    monkeypatch.setattr(operations, "_uninstall", resume)

    assert operations.apply_uninstall(plan.plan_id, purge=purge) == {
        "purged": purge,
        "removed": ["services"],
    }
    assert calls == 1


def test_upgrade_resume_preserves_reviewed_services_and_schema_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, platform, _ = installed_operations(tmp_path)
    monkeypatch.setattr(operations, "_current_schema_version", lambda: 18)
    plan = operations.plan_upgrade()

    calls = 0

    def interrupted(reviewed_plan: LifecyclePlan | None = None) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        assert reviewed_plan == plan
        platform.states["signet-mcp"] = "inactive"
        platform.states["signet-web"] = "inactive"
        raise KeyboardInterrupt("injected process interruption")

    monkeypatch.setattr(operations, "_upgrade", interrupted)
    with pytest.raises(KeyboardInterrupt, match="process interruption"):
        operations.apply_upgrade(plan.plan_id)
    assert setup_operations._reviewed_upgrade_service_state(plan, platform.states) == (
        True,
        True,
    )

    monkeypatch.setattr(setup_operations, "LATEST_SCHEMA_VERSION", 20)
    with pytest.raises(SetupError, match="target no longer matches"):
        operations.apply_upgrade(plan.plan_id)
    assert calls == 1


def test_reviewed_upgrade_apply_holds_the_lifecycle_lock_while_running(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    monkeypatch.setattr(operations, "_current_schema_version", lambda: 18)
    plan = operations.plan_upgrade()
    calls = 0
    nested_errors: list[str] = []

    def upgrade(reviewed_plan: LifecyclePlan | None = None) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        assert reviewed_plan is not None
        if calls == 1:
            try:
                operations.apply_upgrade(plan.plan_id)
            except SetupError as exc:
                nested_errors.append(str(exc))
        return {"schema_version": 19, "backup": "/private/verified-backup"}

    monkeypatch.setattr(operations, "_upgrade", upgrade)

    operations.apply_upgrade(plan.plan_id)

    assert calls == 1
    assert nested_errors == ["another setup lifecycle operation is in progress"]


def test_lifecycle_store_rejects_a_stale_record_save(tmp_path: Path) -> None:
    operations, _, _ = installed_operations(tmp_path)
    plan = operations.plan_services("stop")
    operations.apply_service_plan("stop", plan.plan_id)
    store = LifecycleOperationStore(operations.root)
    first = store.load_optional()
    stale = store.load_optional()
    assert first is not None
    assert stale is not None
    first.attempts += 1
    store.save(first)
    stale.status = "rolled_back"

    with pytest.raises(SetupError, match="changed before update"):
        store.save(stale)


def test_lifecycle_receipt_rejects_a_plan_changed_after_publication(tmp_path: Path) -> None:
    operations, _, _ = installed_operations(tmp_path)
    plan = operations.plan_services("stop")
    operations.apply_service_plan("stop", plan.plan_id)
    receipt = tmp_path / "signet-recovery" / "lifecycle-operation.json"
    document = json.loads(receipt.read_text(encoding="utf-8"))
    document["plan"]["action"] = "start"
    receipt.write_text(json.dumps(document), encoding="utf-8")
    receipt.chmod(0o600)

    with pytest.raises(SetupError, match="receipt digest"):
        operations.apply_service_plan("stop", plan.plan_id)


def test_doctor_resolves_secret_references_without_exposing_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, selected = installed_operations(tmp_path)
    config_path = selected.root / "production.json"
    config_path.write_text(
        json.dumps(
            render_production_config(
                selected,
                setup_id=SetupJournalStore(selected.root).load().setup_id,
            )
        ),
        encoding="utf-8",
    )
    config_path.chmod(0o600)

    resolved: list[object] = []

    class AvailableSecretStore:
        def get(self, reference: object) -> Secret:
            resolved.append(reference)
            return Secret("s" * 48)

    monkeypatch.setattr(setup_operations, "KeychainSecretStore", AvailableSecretStore)

    doctor = operations.doctor()
    verification = operations.verify()

    assert doctor["checks"]["secret_references"] == {
        "ok": True,
        "verification": "resolved",
        "configured_count": 5,
        "remediation": "No action required.",
    }
    assert doctor["checks"]["services"]["remediation"] == (
        "Review the service plan, then apply a start or restart plan."
    )
    assert verification["automatic_safe_checks"]["healthy"] is True
    assert [item["name"] for item in verification["required_human_ceremonies"]] == [
        "owner_authentication_enrollment",
        "hermes_mcp_review_and_reload",
    ]
    assert verification["deferred_live_provider_proof"] == [
        "credential_configuration",
        "read_only_discovery",
        "live_send",
    ]
    assert verification["gateway_restart"] is False
    assert len(resolved) == 10
    assert "s" * 48 not in repr(doctor)


def test_doctor_is_unhealthy_when_owned_service_endpoints_fail(tmp_path: Path) -> None:
    platform = FakeLifecyclePlatform(fail_health=True)
    operations, _, _ = installed_operations(tmp_path, platform=platform)

    doctor = operations.doctor()

    assert doctor["healthy"] is False
    assert doctor["checks"]["service_health"] == {
        "ok": False,
        "error_kind": "RuntimeError",
        "remediation": "Inspect owned service logs, then apply a reviewed restart plan.",
    }
    assert "private endpoint detail" not in repr(doctor)


def test_doctor_fails_closed_when_a_configured_secret_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, selected = installed_operations(tmp_path)
    config_path = selected.root / "production.json"
    config_path.write_text(
        json.dumps(
            render_production_config(
                selected,
                setup_id=SetupJournalStore(selected.root).load().setup_id,
            )
        ),
        encoding="utf-8",
    )
    config_path.chmod(0o600)

    class MissingSecretStore:
        def get(self, _reference: object) -> Secret:
            raise CredentialError("private backend detail")

    monkeypatch.setattr(setup_operations, "KeychainSecretStore", MissingSecretStore)

    doctor = operations.doctor()

    assert doctor["healthy"] is False
    assert doctor["checks"]["secret_references"] == {
        "ok": False,
        "error_kind": "CredentialError",
        "remediation": "Restore the configured secret in the platform secret store.",
    }
    assert "private backend detail" not in repr(doctor)
