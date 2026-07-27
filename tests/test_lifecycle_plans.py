from __future__ import annotations

import json
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest

import signet.setup_operations as setup_operations
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
    assert platform.events == ["stop"]


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

    assert platform.states["signet-mcp"] == (
        "inactive" if crash_after == "stop" else "active"
    )
    assert operations.apply_service_plan("restart", plan.plan_id)["services"]["signet-web"] == (
        "active"
    )
    assert platform.events == ["stop", "start", "health"]


def test_service_apply_refuses_a_plan_when_observed_state_changed(tmp_path: Path) -> None:
    operations, platform, _ = installed_operations(tmp_path)
    plan = operations.plan_services("stop")
    platform.states["signet-mcp"] = "inactive"
    platform.states["signet-web"] = "inactive"

    with pytest.raises(SetupError, match="no longer matches observed state"):
        operations.apply_service_plan("stop", plan.plan_id)

    assert platform.events == []
    assert not (tmp_path / "signet-recovery").exists()


def test_completed_service_plan_cannot_be_replayed_after_a_later_plan(tmp_path: Path) -> None:
    operations, platform, _ = installed_operations(tmp_path)
    old_stop = operations.plan_services("stop")
    operations.apply_service_plan("stop", old_stop.plan_id)
    start = operations.plan_services("start")
    operations.apply_service_plan("start", start.plan_id)

    with pytest.raises(SetupError, match="no longer matches observed state"):
        operations.apply_service_plan("stop", old_stop.plan_id)

    assert platform.events == ["stop", "start", "health"]


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
    assert platform.events == ["start", "stop"]


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
        lambda selected: pytest.fail("stale restore plan must not decrypt the bundle"),
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

    def backup(selected: Path | None = None) -> Path:
        nonlocal calls
        calls += 1
        assert selected == destination
        return destination

    monkeypatch.setattr(operations, "_backup", backup)
    plan = operations.plan_backup(destination)

    first = operations.apply_backup(plan.plan_id, destination)
    second = operations.apply_backup(plan.plan_id, destination)

    assert first == second == {"backup": str(destination)}
    assert calls == 1


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

    def backup(selected: Path | None = None) -> Path:
        calls.append(selected)
        return destination

    monkeypatch.setattr(operations, "_backup", backup)
    assert operations.apply_backup(first.plan_id) == {"backup": str(destination)}
    assert calls == [destination]


def test_interrupted_backup_and_restore_reject_unreviewed_resume_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations, _, _ = installed_operations(tmp_path)
    destination = tmp_path / "reviewed-backup.signet-backup"
    wrong_destination = tmp_path / "wrong-backup.signet-backup"
    backup_plan = operations.plan_backup(destination)
    backup_calls = 0

    def backup(selected: Path | None = None) -> Path:
        nonlocal backup_calls
        backup_calls += 1
        if backup_calls == 1:
            raise KeyboardInterrupt("injected backup interruption")
        assert selected == destination
        return destination

    monkeypatch.setattr(operations, "_backup", backup)
    with pytest.raises(KeyboardInterrupt, match="backup interruption"):
        operations.apply_backup(backup_plan.plan_id, destination)
    with pytest.raises(SetupError, match="does not match the reviewed destination"):
        operations.apply_backup(backup_plan.plan_id, wrong_destination)
    assert operations.apply_backup(backup_plan.plan_id, destination) == {
        "backup": str(destination)
    }

    bundle = tmp_path / "reviewed-bundle.signet-backup"
    wrong_bundle = tmp_path / "wrong-bundle.signet-backup"
    bundle.write_bytes(b"encrypted-reviewed")
    wrong_bundle.write_bytes(b"encrypted-wrong")
    bundle.chmod(0o600)
    wrong_bundle.chmod(0o600)
    restore_plan = operations.plan_restore(bundle)
    restore_calls = 0

    def restore(selected: Path) -> Any:
        nonlocal restore_calls
        restore_calls += 1
        raise KeyboardInterrupt(f"injected restore interruption: {selected}")

    monkeypatch.setattr(operations, "_restore", restore)
    with pytest.raises(KeyboardInterrupt, match="restore interruption"):
        operations.apply_restore(restore_plan.plan_id, bundle)
    with pytest.raises(SetupError, match="does not match the reviewed bundle"):
        operations.apply_restore(restore_plan.plan_id, wrong_bundle)
    assert restore_calls == 1


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


def test_doctor_does_not_read_secret_values_and_verification_classifies_follow_up(
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

    class ForbiddenSecretStore:
        def __init__(self) -> None:
            raise AssertionError("doctor read a secret store")

    monkeypatch.setattr(setup_operations, "KeychainSecretStore", ForbiddenSecretStore)

    doctor = operations.doctor()
    verification = operations.verify()

    assert doctor["checks"]["secret_references"] == {
        "ok": True,
        "verification": "deferred_attended_check",
        "remediation": "Run an attended backup verification before destructive maintenance.",
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
