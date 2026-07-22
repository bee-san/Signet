from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import signet.setup_operations as setup_operations
import signet.setup_platform as setup_platform
import signet.setup_state as setup_state
from signet.backup import BackupError
from signet.browser_auth import BootstrapService
from signet.config import ProductionConfig, production_instance_identity
from signet.credential_broker import KeychainSecretStore
from signet.db import Database, MigrationBackupReceipt
from signet.private_paths import ensure_private_directory, require_private_directory_identity
from signet.production import create_production_assembly, load_production_config
from signet.setup_operations import SetupOperations
from signet.setup_platform import (
    ProductionSetupPlatform,
    _merge_hermes_config,
    _merge_profile_environment,
    _remove_exact_owned_file,
    _remove_hermes_config,
    _remove_profile_environment,
    _replace_private_file,
    browser_assisted_setup,
    render_launchd_services,
    render_production_config,
    render_systemd_services,
)
from signet.setup_state import (
    SETUP_STEPS,
    SetupEngine,
    SetupError,
    SetupJournal,
    SetupJournalStore,
    SetupSpec,
)


class FakePlatform:
    def __init__(self, fail_once: str | None = None, rollback_failure: str | None = None) -> None:
        self.fail_once = fail_once
        self.rollback_failure = rollback_failure
        self.applied: list[str] = []
        self.rolled_back: list[str] = []

    def apply(self, step: str, spec: SetupSpec, setup_id: str) -> None:
        del spec, setup_id
        self.applied.append(step)
        if step == self.fail_once:
            self.fail_once = None
            raise RuntimeError(f"injected {step} failure")

    def rollback(self, step: str, spec: SetupSpec, setup_id: str) -> None:
        del spec, setup_id
        self.rolled_back.append(step)
        if step == self.rollback_failure:
            raise RuntimeError(f"injected {step} rollback failure")


def spec(root: Path, *, profiles: tuple[str, ...] = ("personal", "work")) -> SetupSpec:
    return SetupSpec(
        root=root,
        public_origin="https://signet.tailnet.example",
        owner_user_id="user:owner",
        hermes_profiles=profiles,
        executable=Path("/opt/signet/bin/signet"),
        open_browser=True,
    )


def test_plan_is_read_only_and_defaults_providers_to_disabled(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    plan = SetupEngine(SetupJournalStore(selected.root), FakePlatform()).plan(selected)

    assert [step.name for step in plan.steps] == list(SETUP_STEPS)
    assert plan.provider_rollout == "disabled"
    assert not selected.root.exists()

    config = render_production_config(selected, setup_id=plan.setup_id)
    assert config["provider_rollout"] == {"state": "disabled"}
    assert config["connectors"] == {}
    assert config["caller_principals"] == [
        {"namespace": "profile:personal", "allowed_aliases": ["approvals"]},
        {"namespace": "profile:work", "allowed_aliases": ["approvals"]},
    ]


def test_journal_read_refuses_a_path_replacement_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet-journal-race")
    store = SetupJournalStore(selected.root)
    expected = SetupEngine(store, FakePlatform()).apply(selected)
    replacement_root = tmp_path / "replacement-root"
    replacement_store = SetupJournalStore(replacement_root)
    replacement = SetupEngine(replacement_store, FakePlatform()).apply(spec(replacement_root))
    replacement_path = selected.root / "replacement-journal.json"
    replacement_path.write_bytes(replacement_store.journal_path.read_bytes())
    replacement_path.chmod(0o600)
    real_read = setup_state.os.read
    raced = False

    def replace_before_read(descriptor: int, size: int) -> bytes:
        nonlocal raced
        if not raced:
            raced = True
            replacement_path.replace(store.journal_path)
        return real_read(descriptor, size)

    monkeypatch.setattr(setup_state.os, "read", replace_before_read)

    with pytest.raises(SetupError, match="changed during inspection"):
        store.load()

    assert expected.setup_id != replacement.setup_id


def test_setup_status_and_doctor_do_not_construct_or_mutate_production_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    SetupEngine(SetupJournalStore(selected.root), platform).apply(selected)
    config_path = selected.root / "production.json"
    config_path.write_text(
        json.dumps(
            render_production_config(
                selected,
                setup_id=SetupJournalStore(selected.root).load().setup_id,
            ),
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    before = {
        path.relative_to(selected.root): path.read_bytes()
        for path in selected.root.rglob("*")
        if path.is_file()
    }
    monkeypatch.setattr(
        "signet.setup_operations.create_production_assembly",
        lambda *args, **kwargs: pytest.fail(
            "read-only inspection constructed live production state"
        ),
    )

    class ReadableSecret:
        def reveal(self) -> str:
            return "x" * 48

    class ReadOnlySecretStore:
        def get(self, reference: object) -> ReadableSecret:
            del reference
            return ReadableSecret()

    monkeypatch.setattr("signet.setup_operations.KeychainSecretStore", ReadOnlySecretStore)

    class StatusPlatform(ProductionSetupPlatform):
        def service_status(self, spec: SetupSpec) -> dict[str, str]:
            del spec
            return {"signet-mcp": "active", "signet-web": "active"}

    operations = SetupOperations(selected.root, platform=StatusPlatform())
    result = operations.status()
    doctor = operations.doctor()

    after = {
        path.relative_to(selected.root): path.read_bytes()
        for path in selected.root.rglob("*")
        if path.is_file()
    }
    assert result["production"]["available"] is False
    assert doctor["checks"]["configuration"]["ok"] is True
    assert before == after
    assert not (selected.root / "data" / "signet.db").exists()


def test_setup_origin_uses_the_same_canonical_ipv6_serialization_as_production(
    tmp_path: Path,
) -> None:
    selected = SetupSpec(
        root=tmp_path / "signet",
        public_origin="https://[::1]",
        owner_user_id="user:owner",
        hermes_profiles=("work",),
        executable=Path("/opt/signet/bin/signet"),
    )

    assert selected.public_origin == "https://[::1]"
    rendered = render_production_config(selected, setup_id="setup_0123456789abcdef")
    assert rendered["public_origin"] == "https://[::1]"
    assert ProductionConfig.model_validate(rendered).public_origin == selected.public_origin

    punycode = replace(selected, public_origin="https://xn--bcher-kva.example")
    assert punycode.public_origin == "https://xn--bcher-kva.example"
    with pytest.raises(ValueError, match="canonical HTTPS origin"):
        replace(selected, public_origin="https://bücher.example")


@pytest.mark.parametrize(
    ("origin", "host"),
    (
        ("https://example.com:0", "example.com"),
        ("https://example.com:65536", "example.com"),
        ("https://example.com.", "example.com."),
    ),
)
def test_setup_and_production_reject_the_same_invalid_origins(
    tmp_path: Path,
    origin: str,
    host: str,
) -> None:
    with pytest.raises(ValueError):
        replace(spec(tmp_path / "setup"), public_origin=origin)

    rendered = render_production_config(
        spec(tmp_path / "production"),
        setup_id="setup_0123456789abcdef",
    )
    rendered["public_origin"] = origin
    rendered["rp_id"] = host
    rendered["allowed_hosts"] = [host]
    with pytest.raises(ValueError):
        ProductionConfig.model_validate(rendered)


def test_completed_setup_reconciles_only_the_owner_bootstrap_step(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    engine = SetupEngine(SetupJournalStore(selected.root), platform)
    engine.apply(selected)
    platform.applied.clear()

    engine.apply(selected)

    assert platform.applied == ["owner_bootstrap"]


def test_completed_setup_surfaces_owner_reconciliation_failure_without_reopening_steps(
    tmp_path: Path,
) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    store = SetupJournalStore(selected.root)
    engine = SetupEngine(store, platform)
    engine.apply(selected)
    platform.fail_once = "owner_bootstrap"

    with pytest.raises(SetupError, match="owner reconciliation failed"):
        engine.apply(selected)

    journal = store.load()
    assert journal.status == "completed"
    assert all(step.status == "completed" for step in journal.steps)


def test_purge_quiesce_is_durable_and_normal_apply_restarts_only_services(
    tmp_path: Path,
) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    store = SetupJournalStore(selected.root)
    engine = SetupEngine(store, platform)
    engine.apply(selected)
    platform.applied.clear()

    quiesced = engine.quiesce_services_for_purge(selected)
    assert quiesced.status == "failed"
    assert quiesced.step("services").status == "rolled_back"
    assert platform.rolled_back == ["services"]

    resumed = engine.apply(selected)
    assert resumed.status == "completed"
    assert platform.applied == ["services"]


@pytest.mark.parametrize(
    "interrupted_status",
    ("rolling_back", "rollback_failed", "applying", "failed"),
)
def test_interrupted_purge_quiesce_retries_the_service_rollback(
    tmp_path: Path,
    interrupted_status: str,
) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    store = SetupJournalStore(selected.root)
    engine = SetupEngine(store, platform)
    engine.apply(selected)
    journal = store.load()
    journal.status = "failed"
    journal.step("services").status = interrupted_status  # type: ignore[assignment]
    store.save(journal)
    platform.rolled_back.clear()

    quiesced = engine.quiesce_services_for_purge(selected)

    assert quiesced.status == "failed"
    assert quiesced.step("services").status == "rolled_back"
    assert platform.rolled_back == ["services"]


def test_apply_records_failure_and_resumes_without_repeating_completed_steps(
    tmp_path: Path,
) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform(fail_once="database")
    store = SetupJournalStore(selected.root)
    engine = SetupEngine(store, platform)

    with pytest.raises(SetupError, match="database"):
        engine.apply(selected)

    failed = store.load()
    assert failed.status == "failed"
    assert failed.step("private_paths").status == "completed"
    assert failed.step("database").status == "failed"

    completed = engine.apply(selected)
    assert completed.status == "completed"
    assert platform.applied.count("private_paths") == 1
    assert platform.applied.count("database") == 2
    assert platform.applied[-1] == "owner_bootstrap"


def test_failed_browser_launch_can_resume_without_rebinding_resources(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    store = SetupJournalStore(selected.root)
    platform = FakePlatform(fail_once="owner_bootstrap")
    engine = SetupEngine(store, platform)

    with pytest.raises(SetupError, match="owner_bootstrap"):
        engine.apply(selected)

    resumed = engine.apply(replace(selected, open_browser=False))
    assert resumed.status == "completed"
    assert platform.applied.count("owner_bootstrap") == 2


def test_rollback_cleans_partially_applied_failed_step(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform(fail_once="database")
    store = SetupJournalStore(selected.root)
    engine = SetupEngine(store, platform)

    with pytest.raises(SetupError, match="database"):
        engine.apply(selected)

    journal = engine.rollback(selected)

    assert journal.status == "rolled_back"
    assert journal.step("database").status == "rolled_back"
    assert platform.rolled_back == [
        "database",
        "configuration",
        "secrets",
        "private_paths",
        "preflight",
    ]


def test_rollback_stops_at_the_first_failed_dependency_barrier(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform(rollback_failure="configuration")
    store = SetupJournalStore(selected.root)
    engine = SetupEngine(store, platform)
    engine.apply(selected)

    with pytest.raises(SetupError, match="configuration"):
        engine.rollback(selected)

    journal = store.load()
    assert journal.status == "rollback_failed"
    assert journal.step("configuration").status == "rollback_failed"
    assert platform.rolled_back == [
        "owner_bootstrap",
        "hermes_profiles",
        "services",
        "database",
        "configuration",
    ]
    assert journal.step("secrets").status == "completed"
    assert journal.step("private_paths").status == "completed"


def test_service_rollback_failure_is_a_barrier_for_durable_state(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform(rollback_failure="services")
    store = SetupJournalStore(selected.root)
    engine = SetupEngine(store, platform)
    engine.apply(selected)

    with pytest.raises(SetupError, match="services"):
        engine.rollback(selected)

    assert platform.rolled_back == ["owner_bootstrap", "hermes_profiles", "services"]
    journal = store.load()
    assert journal.step("database").status == "completed"
    assert journal.step("configuration").status == "completed"
    assert journal.step("secrets").status == "completed"


def test_failed_rollback_transition_restores_the_loaded_journal_status(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")

    class TransitionFailingStore(SetupJournalStore):
        loaded_journals: list[SetupJournal]
        reject_transition: bool

        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.loaded_journals = []
            self.reject_transition = True

        def load(self) -> SetupJournal:
            journal = super().load()
            self.loaded_journals.append(journal)
            return journal

        def save(self, journal: SetupJournal) -> None:
            if self.reject_transition and journal.status == "rolling_back":
                self.reject_transition = False
                raise OSError("injected durable transition failure")
            super().save(journal)

    store = TransitionFailingStore(selected.root)
    engine = SetupEngine(store, FakePlatform())
    engine.apply(selected)

    with pytest.raises(SetupError, match="begin rollback"):
        engine.rollback(selected)

    assert store.loaded_journals[-1].status == "completed"
    assert store.load().status == "completed"


def test_interrupted_rolling_back_step_is_retried(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    store = SetupJournalStore(selected.root)
    engine = SetupEngine(store, platform)
    engine.apply(selected)
    journal = store.load()
    journal.status = "rolling_back"
    journal.step("services").status = "rolling_back"
    store.save(journal)

    completed = engine.rollback(selected)

    assert completed.step("services").status == "rolled_back"
    assert "services" in platform.rolled_back


def test_apply_recovers_owned_setup_id_when_crash_precedes_first_journal_save(
    tmp_path: Path,
) -> None:
    selected = spec(tmp_path / "signet")
    store = SetupJournalStore(selected.root)
    setup_id = "setup_0123456789abcdef"
    store.prepare(selected, setup_id)

    journal = SetupEngine(store, FakePlatform()).apply(selected)

    assert journal.setup_id == setup_id
    assert journal.status == "completed"


def test_apply_refuses_nonempty_foreign_root(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    root.mkdir()
    (root / "somebody-elses-file").write_text("leave me alone", encoding="utf-8")

    with pytest.raises(SetupError, match="not owned"):
        SetupEngine(SetupJournalStore(root), FakePlatform()).apply(spec(root))

    assert (root / "somebody-elses-file").read_text(encoding="utf-8") == "leave me alone"
    assert not (root / ".setup-journal.json").exists()


def test_backup_manager_is_constructed_without_live_assembly_or_migration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet")
    journal = SetupEngine(SetupJournalStore(selected.root), FakePlatform()).apply(selected)
    stored = {
        ("Signet-Setup", f"{journal.setup_id}-backup"): "b" * 43,
        ("Signet-Setup", f"{journal.setup_id}-attachment"): "a" * 43,
    }
    monkeypatch.setattr(
        setup_platform.keyring,
        "get_password",
        lambda service, account: stored.get((service, account)),
    )
    monkeypatch.setattr(
        "signet.setup_operations.create_production_assembly",
        lambda *args, **kwargs: pytest.fail("backup initialized live production assembly"),
    )

    manager = SetupOperations(selected.root)._backup_manager(journal)

    assert manager.database.path == selected.root / "data" / "signet.db"
    assert not manager.database.path.exists()


def test_public_backup_refuses_to_cross_an_active_lifecycle_epoch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "backup-lifecycle-lock")
    SetupEngine(SetupJournalStore(selected.root), FakePlatform()).apply(selected)
    operations = SetupOperations(selected.root, platform=FakePlatform())
    monkeypatch.setattr(
        operations,
        "_backup_manager",
        lambda journal: pytest.fail("backup crossed an active lifecycle lock"),
    )

    with (
        setup_operations.setup_lifecycle_lock(selected.root),
        pytest.raises(SetupError, match="another setup lifecycle operation"),
    ):
        operations.backup(tmp_path / "locked.signet-backup")


def test_upgrade_preflights_before_stopping_and_verifies_services_before_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "upgrade-offline-preflight")
    events: list[str] = []

    class UpgradePlatform(FakePlatform):
        def preflight(self, selected_spec: SetupSpec) -> None:
            del selected_spec
            events.append("preflight")

        def manage_services(self, selected_spec: SetupSpec, action: str) -> None:
            del selected_spec
            events.append(action)

        def service_status(self, selected_spec: SetupSpec) -> dict[str, str]:
            del selected_spec
            events.append("status")
            return {
                "signet-mcp": "inactive",
                "signet-web": "inactive",
                "tailscale:8443": "active",
            }

    platform = UpgradePlatform()
    SetupEngine(SetupJournalStore(selected.root), platform).apply(selected)
    operations = SetupOperations(selected.root, platform=platform)
    monkeypatch.setattr(
        operations,
        "_backup_manager",
        lambda journal: (_ for _ in ()).throw(SetupError("stop after order assertion")),
    )
    monkeypatch.setattr(operations, "_restart_services_after_upgrade", lambda selected_spec: None)

    with pytest.raises(SetupError, match="stop after order assertion"):
        operations.upgrade()

    assert events == ["preflight", "stop", "status"]


def test_upgrade_resumes_verified_services_when_pre_migration_backup_cannot_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "upgrade-pre-migration-recovery")
    events: list[str] = []
    active = True

    class UpgradePlatform(FakePlatform):
        def preflight(self, selected_spec: SetupSpec) -> None:
            del selected_spec
            events.append("preflight")

        def manage_services(self, selected_spec: SetupSpec, action: str) -> None:
            nonlocal active
            del selected_spec
            events.append(action)
            active = action == "start"

        def service_status(self, selected_spec: SetupSpec) -> dict[str, str]:
            del selected_spec
            events.append("status")
            state = "active" if active else "inactive"
            return {"signet-mcp": state, "signet-web": state}

        def verify_service_health(self, selected_spec: SetupSpec) -> None:
            del selected_spec
            events.append("health")
            assert active

    platform = UpgradePlatform()
    SetupEngine(SetupJournalStore(selected.root), platform).apply(selected)
    operations = SetupOperations(selected.root, platform=platform)
    monkeypatch.setattr(
        operations,
        "_backup_manager",
        lambda journal: (_ for _ in ()).throw(SetupError("backup unavailable")),
    )

    with pytest.raises(SetupError, match="backup unavailable"):
        operations.upgrade()

    assert events == ["preflight", "stop", "status", "start", "status", "health"]


def test_upgrade_creates_the_reported_backup_inside_the_migration_epoch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "upgrade-migration-epoch")

    class UpgradePlatform(FakePlatform):
        def preflight(self, selected_spec: SetupSpec) -> None:
            del selected_spec

        def manage_services(self, selected_spec: SetupSpec, action: str) -> None:
            del selected_spec, action

        def service_status(self, selected_spec: SetupSpec) -> dict[str, str]:
            del selected_spec
            return {"signet-mcp": "inactive", "signet-web": "inactive"}

    platform = UpgradePlatform()
    SetupEngine(SetupJournalStore(selected.root), platform).apply(selected)
    ensure_private_directory(selected.root / "data")
    database = Database(selected.root / "data" / "signet.db")
    database.initialize()
    with database.transaction(mode="EXCLUSIVE") as connection:
        connection.execute("PRAGMA user_version = 1")
    with database.read_only() as connection:
        source_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    backup_path = tmp_path / "verified-upgrade.signet-backup"
    assembly_active = False
    events: list[str] = []

    def callback(candidate: Database, version: int) -> MigrationBackupReceipt:
        assert assembly_active, "backup callback ran outside the database migration epoch"
        assert candidate.path == database.path
        assert version == source_version
        events.append("backup")
        backup_path.write_bytes(b"encrypted backup")
        backup_path.chmod(0o600)
        return MigrationBackupReceipt(
            database_path=candidate.path,
            source_schema_version=version,
            artifact_path=backup_path,
            artifact_sha256=hashlib.sha256(backup_path.read_bytes()).hexdigest(),
            verified_restore_schema_version=version,
        )

    class Manager:
        def create_pre_migration_callback(self, destination: Path) -> Any:
            assert destination.name.endswith("-recovery")
            return callback

    class Assembly:
        config = type(
            "Config",
            (),
            {"provider_rollout": type("Rollout", (), {"state": "disabled"})()},
        )()

        @staticmethod
        def status() -> Any:
            return type("Status", (), {"schema_version": source_version})()

    def create_assembly(*args: Any, pre_migration_backup: Any, **kwargs: Any) -> Assembly:
        nonlocal assembly_active
        del args, kwargs
        events.append("assembly")
        assembly_active = True
        try:
            pre_migration_backup(database, source_version)
        finally:
            assembly_active = False
        return Assembly()

    operations = SetupOperations(selected.root, platform=platform)
    monkeypatch.setattr(operations, "_backup_manager", lambda journal: Manager())
    monkeypatch.setattr(operations, "_restart_services_after_upgrade", lambda selected_spec: None)
    monkeypatch.setattr(setup_operations, "create_production_assembly", create_assembly)

    result = operations.upgrade()

    assert events == ["assembly", "backup"]
    assert result["backup"] == str(backup_path)


def test_upgrade_requiesces_a_partial_service_restart(
    tmp_path: Path,
) -> None:
    selected = spec(tmp_path / "upgrade-partial-restart")
    events: list[str] = []

    class PartialRestartPlatform(FakePlatform):
        def manage_services(self, selected_spec: SetupSpec, action: str) -> None:
            del selected_spec
            events.append(action)
            if action == "start":
                raise SetupError("second service failed to start")

        def service_status(self, selected_spec: SetupSpec) -> dict[str, str]:
            del selected_spec
            events.append("status")
            return {"signet-mcp": "inactive", "signet-web": "inactive"}

    operations = SetupOperations(selected.root, platform=PartialRestartPlatform())

    with pytest.raises(SetupError, match="services were left stopped"):
        operations._restart_services_after_upgrade(selected)

    assert events == ["start", "stop", "status"]


def test_upgrade_restart_requires_instance_bound_health_before_returning(
    tmp_path: Path,
) -> None:
    selected = spec(tmp_path / "upgrade-health-identity")
    events: list[str] = []
    active = False

    class WrongInstancePlatform(FakePlatform):
        def manage_services(self, selected_spec: SetupSpec, action: str) -> None:
            nonlocal active
            del selected_spec
            events.append(action)
            active = action == "start"

        def service_status(self, selected_spec: SetupSpec) -> dict[str, str]:
            del selected_spec
            events.append("status")
            state = "active" if active else "inactive"
            return {"signet-mcp": state, "signet-web": state}

        def verify_service_health(self, selected_spec: SetupSpec) -> None:
            del selected_spec
            events.append("health")
            raise SetupError("health identity mismatch")

    operations = SetupOperations(selected.root, platform=WrongInstancePlatform())

    with pytest.raises(SetupError, match="services were left stopped"):
        operations._restart_services_after_upgrade(selected)

    assert events == ["start", "status", "health", "stop", "status"]


def test_upgrade_interrupt_during_restart_requiesces_services(
    tmp_path: Path,
) -> None:
    selected = spec(tmp_path / "upgrade-restart-interrupt")
    events: list[str] = []
    interrupted = False

    class InterruptedPlatform(FakePlatform):
        def manage_services(self, selected_spec: SetupSpec, action: str) -> None:
            del selected_spec
            events.append(action)

        def service_status(self, selected_spec: SetupSpec) -> dict[str, str]:
            nonlocal interrupted
            del selected_spec
            events.append("status")
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt
            return {"signet-mcp": "inactive", "signet-web": "inactive"}

        def verify_service_health(self, selected_spec: SetupSpec) -> None:
            pytest.fail(f"health checked after interruption for {selected_spec.root}")

    operations = SetupOperations(selected.root, platform=InterruptedPlatform())

    with pytest.raises(KeyboardInterrupt):
        operations._restart_services_after_upgrade(selected)

    assert events == ["start", "status", "stop", "status"]


def test_purge_preserves_every_key_needed_to_recover_an_encrypted_backup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup_id = "setup_0123456789abcdef"
    stored = {
        ("Signet-Setup", f"{setup_id}-{purpose}"): f"{purpose}-secret"
        for purpose in (
            "session",
            "csrf",
            "capability",
            "payload",
            "attachment",
            "backup",
            "browser-bootstrap",
        )
    }
    monkeypatch.setattr(
        setup_platform.keyring,
        "get_password",
        lambda service, account: stored.get((service, account)),
    )
    monkeypatch.setattr(
        setup_platform.keyring,
        "delete_password",
        lambda service, account: stored.pop((service, account)),
    )

    ProductionSetupPlatform().remove_setup_secrets(setup_id, preserve_backup=True)

    assert {account.removeprefix(f"{setup_id}-") for _, account in stored} == {
        "capability",
        "payload",
        "attachment",
        "backup",
    }


def test_setup_resume_durably_invalidates_a_prior_purge_checkpoint(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    store = SetupJournalStore(selected.root)
    engine = SetupEngine(store, FakePlatform())
    journal = engine.apply(selected)
    journal.purge_backup = {"stale": True}
    store.save(journal)

    resumed = engine.apply(selected)

    assert resumed.purge_backup is None
    assert store.load().purge_backup is None


def test_setup_resume_preserves_a_structurally_valid_purge_checkpoint(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet-valid-purge-checkpoint")
    store = SetupJournalStore(selected.root)
    engine = SetupEngine(store, FakePlatform())
    journal = engine.apply(selected)
    checkpoint = {
        "version": 1,
        "setup_id": journal.setup_id,
        "recovery_directory": str(tmp_path / "recovery"),
        "backup": {},
        "recovery_receipt": {},
        "backup_receipt": {},
    }
    journal.purge_backup = checkpoint
    store.save(journal)

    with pytest.raises(SetupError, match="finish purge"):
        engine.apply(selected)

    assert store.load().purge_backup == checkpoint


def test_service_start_refuses_to_cross_a_purge_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet")
    store = SetupJournalStore(selected.root)
    journal = SetupEngine(store, FakePlatform()).apply(selected)
    journal.purge_backup = {"version": 1}
    store.save(journal)
    operations = SetupOperations(selected.root, platform=FakePlatform())
    monkeypatch.setattr(operations, "spec", lambda: selected)

    with pytest.raises(SetupError, match="purge checkpoint"):
        operations.manage("start")


def test_verified_purge_receipt_read_refuses_a_path_replacement_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recovery = ensure_private_directory(tmp_path / "recovery-checkpoint")
    receipt = recovery / "receipt.json"
    replacement = recovery / "replacement.json"
    receipt.write_bytes(b'{"setup_id":"expected"}')
    receipt.chmod(0o600)
    replacement.write_bytes(b'{"setup_id":"foreign"}')
    replacement.chmod(0o600)
    checkpoint = setup_operations._private_file_checkpoint(receipt)
    real_read = setup_operations.os.read
    raced = False

    def replace_before_read(descriptor: int, size: int) -> bytes:
        nonlocal raced
        if not raced:
            raced = True
            replacement.replace(receipt)
        return real_read(descriptor, size)

    monkeypatch.setattr(setup_operations.os, "read", replace_before_read)

    with pytest.raises(SetupError, match="identity or digest changed"):
        setup_operations._read_verified_private_file_checkpoint(
            checkpoint,
            recovery,
        )

    assert receipt.read_bytes() == b'{"setup_id":"foreign"}'


def test_purge_durably_publishes_the_recovery_directory_before_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    SetupEngine(SetupJournalStore(selected.root), platform).apply(selected)
    operations = SetupOperations(selected.root, platform=platform)
    events: list[str] = []
    monkeypatch.setattr(operations, "spec", lambda: selected)
    monkeypatch.setattr(operations, "_require_recovery_secrets", lambda journal: None)
    monkeypatch.setattr(setup_operations, "_fsync_directory", lambda path: events.append("fsync"))

    def backup(destination: Path | None = None) -> Path:
        assert destination is not None
        events.append("backup")
        raise SetupError("stop after durability assertion")

    monkeypatch.setattr(operations, "_backup", backup)
    with pytest.raises(SetupError, match="stop after durability assertion"):
        operations.uninstall(purge=True)

    assert events[:2] == ["fsync", "backup"]


def test_completed_setup_rejects_changed_identity_or_origin(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    engine = SetupEngine(SetupJournalStore(selected.root), FakePlatform())
    engine.apply(selected)
    changed = SetupSpec(
        root=selected.root,
        public_origin="https://other.tailnet.example",
        owner_user_id=selected.owner_user_id,
        hermes_profiles=selected.hermes_profiles,
        executable=selected.executable,
        open_browser=True,
    )

    with pytest.raises(SetupError, match="different setup specification"):
        engine.apply(changed)


def test_purge_uninstall_quiesces_services_before_the_external_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet")
    events: list[str] = []

    class LifecyclePlatform(FakePlatform):
        def rollback(self, step: str, spec: SetupSpec, setup_id: str) -> None:
            events.append(f"rollback:{step}")
            super().rollback(step, spec, setup_id)

        def remove_setup_secrets(self, setup_id: str, *, preserve_backup: bool) -> None:
            del setup_id
            assert preserve_backup is True
            events.append("remove_setup_secrets")

    platform = LifecyclePlatform()
    setup_journal = SetupEngine(SetupJournalStore(selected.root), platform).apply(selected)
    operations = SetupOperations(selected.root, platform=platform)

    def backup(destination: Path | None = None) -> Path:
        assert destination is not None
        assert selected.root not in destination.parents
        destination.parent.mkdir(mode=0o700, exist_ok=True)
        destination.write_bytes(b"verified encrypted backup")
        destination.chmod(0o600)
        events.append("backup")
        return destination

    monkeypatch.setattr(operations, "_backup", backup)
    monkeypatch.setattr(operations, "_require_recovery_secrets", lambda journal: None)
    monkeypatch.setattr(
        operations,
        "_verified_backup_receipt",
        lambda bundle, **_: {
            "artifact_path": str(bundle),
            "artifact_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
            "source_schema_version": 19,
            "verified_restore_schema_version": 19,
        },
    )

    result = operations.uninstall(purge=True)

    assert not Path(result["backup"]).is_relative_to(selected.root)
    receipt_path = Path(result["recovery_receipt"])
    assert receipt_path.is_file()
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["backup_path"] == result["backup"]
    assert receipt["backup_sha256"] == hashlib.sha256(b"verified encrypted backup").hexdigest()
    assert set(receipt["required_key_accounts"]) == {
        f"{setup_journal.setup_id}-{purpose}"
        for purpose in ("capability", "payload", "attachment", "backup")
    }
    assert events.index("rollback:services") < events.index("backup")
    assert events.count("rollback:services") == 1


def test_purge_verifies_the_published_checkpoint_before_destructive_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet-checkpoint-gate")
    platform = FakePlatform()
    store = SetupJournalStore(selected.root)
    SetupEngine(store, platform).apply(selected)
    operations = SetupOperations(selected.root, platform=platform)

    def backup(destination: Path | None = None) -> Path:
        assert destination is not None
        destination.parent.mkdir(mode=0o700, exist_ok=True)
        destination.write_bytes(b"verified encrypted backup")
        destination.chmod(0o600)
        return destination

    monkeypatch.setattr(operations, "_backup", backup)
    monkeypatch.setattr(operations, "_require_recovery_secrets", lambda journal: None)
    monkeypatch.setattr(
        operations,
        "_verified_backup_receipt",
        lambda bundle, **_: {
            "artifact_path": str(bundle),
            "artifact_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
            "source_schema_version": 19,
            "verified_restore_schema_version": 19,
        },
    )
    monkeypatch.setattr(
        setup_operations,
        "_verify_purge_checkpoint",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            SetupError("published checkpoint did not verify")
        ),
    )

    with pytest.raises(SetupError, match="published checkpoint did not verify"):
        operations.uninstall(purge=True)

    assert platform.rolled_back == ["services"]
    assert store.load().purge_backup is not None


def test_partial_setup_purge_rolls_back_before_any_database_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "partial")
    platform = FakePlatform(fail_once="configuration")
    store = SetupJournalStore(selected.root)
    with pytest.raises(SetupError, match="'configuration' failed"):
        SetupEngine(store, platform).apply(selected)
    monkeypatch.setattr(setup_platform.keyring, "get_password", lambda service, account: None)
    operations = SetupOperations(selected.root, platform=platform)
    monkeypatch.setattr(operations, "spec", lambda: selected)

    result = operations.uninstall(purge=True)

    assert result == {
        "purged": True,
        "removed": ["configuration", "secrets", "private_paths", "preflight"],
    }
    assert store.load().status == "rolled_back"


def test_purge_rejects_missing_recovery_secret_before_quiescing_services(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    SetupEngine(SetupJournalStore(selected.root), platform).apply(selected)
    monkeypatch.setattr(setup_platform.keyring, "get_password", lambda service, account: None)

    with pytest.raises(SetupError, match="recovery secret"):
        SetupOperations(selected.root, platform=platform).uninstall(purge=True)

    assert platform.rolled_back == []


def test_failed_purge_backup_resumes_quiesced_services(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    store = SetupJournalStore(selected.root)
    SetupEngine(store, platform).apply(selected)
    operations = SetupOperations(selected.root, platform=platform)
    monkeypatch.setattr(operations, "_require_recovery_secrets", lambda journal: None)
    monkeypatch.setattr(
        operations,
        "_backup",
        lambda destination=None: (_ for _ in ()).throw(SetupError("backup failed")),
    )

    with pytest.raises(SetupError, match="backup failed"):
        operations.uninstall(purge=True)

    assert store.load().status == "completed"
    assert store.load().step("services").status == "completed"
    assert platform.rolled_back == ["services"]
    assert platform.applied.count("services") == 2


def test_failed_purge_after_preserving_uninstall_does_not_reinstall_integrations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    store = SetupJournalStore(selected.root)
    SetupEngine(store, platform).apply(selected)
    operations = SetupOperations(selected.root, platform=platform)
    operations.uninstall()
    applied_before_purge = list(platform.applied)
    monkeypatch.setattr(operations, "_require_recovery_secrets", lambda journal: None)
    monkeypatch.setattr(
        operations,
        "_backup",
        lambda destination=None: (_ for _ in ()).throw(SetupError("backup failed")),
    )

    with pytest.raises(SetupError, match="backup failed"):
        operations.uninstall(purge=True)

    assert store.load().status == "uninstalled"
    assert platform.applied == applied_before_purge


def test_failed_purge_reports_backup_and_service_resume_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    SetupEngine(SetupJournalStore(selected.root), platform).apply(selected)
    platform.fail_once = "services"
    operations = SetupOperations(selected.root, platform=platform)
    monkeypatch.setattr(operations, "_require_recovery_secrets", lambda journal: None)
    monkeypatch.setattr(
        operations,
        "_backup",
        lambda destination=None: (_ for _ in ()).throw(
            SetupError("backup publication is unknown; inspect the destination before retrying")
        ),
    )

    with pytest.raises(SetupError) as caught:
        operations.uninstall(purge=True)

    message = str(caught.value)
    assert "backup publication is unknown" in message
    assert "inspect the destination before retrying" in message
    assert "managed services could not be resumed" in message


@pytest.mark.parametrize("tamper", (False, True))
def test_purge_retry_reuses_only_a_verified_durable_backup_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: bool,
) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    store = SetupJournalStore(selected.root)
    SetupEngine(store, platform).apply(selected)
    platform.rollback_failure = "database"
    backup_calls = 0

    def backup(destination: Path | None = None) -> Path:
        nonlocal backup_calls
        assert destination is not None
        backup_calls += 1
        destination.parent.mkdir(mode=0o700, exist_ok=True)
        destination.write_bytes(f"backup-{backup_calls}".encode())
        destination.chmod(0o600)
        return destination

    operations = SetupOperations(selected.root, platform=platform)
    monkeypatch.setattr(operations, "_backup", backup)
    monkeypatch.setattr(operations, "_require_recovery_secrets", lambda journal: None)
    monkeypatch.setattr(
        operations,
        "_verified_backup_receipt",
        lambda bundle, **_: {
            "artifact_path": str(bundle),
            "artifact_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
            "source_schema_version": 19,
            "verified_restore_schema_version": 19,
        },
    )
    with pytest.raises(SetupError, match="database"):
        operations.uninstall(purge=True)

    checkpoint = store.load().purge_backup
    assert checkpoint is not None
    backup_path = Path(checkpoint["backup"]["path"])
    platform.rollback_failure = None
    if tamper:
        backup_path.write_bytes(b"tampered")
        backup_path.chmod(0o600)
        with pytest.raises(SetupError, match="purge recovery checkpoint"):
            operations.uninstall(purge=True)
    else:
        result = operations.uninstall(purge=True)
        assert result["backup"] == str(backup_path)
    assert backup_calls == 1


def test_preserving_uninstall_is_checkpointed_and_setup_can_reinstall_integrations(
    tmp_path: Path,
) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    store = SetupJournalStore(selected.root)
    engine = SetupEngine(store, platform)
    engine.apply(selected)

    result = SetupOperations(selected.root, platform=platform).uninstall()

    assert result["purged"] is False
    journal = store.load()
    assert journal.status == "uninstalled"
    assert journal.step("database").status == "completed"
    assert journal.step("services").status == "rolled_back"
    assert journal.step("hermes_profiles").status == "rolled_back"
    assert journal.step("owner_bootstrap").status == "rolled_back"

    resumed = engine.apply(selected)

    assert resumed.status == "completed"
    assert platform.applied.count("database") == 1
    assert platform.applied.count("services") == 2
    assert platform.applied.count("hermes_profiles") == 2
    assert platform.applied.count("owner_bootstrap") == 2


def test_reinstall_mode_survives_a_transient_integration_failure(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    platform = FakePlatform()
    store = SetupJournalStore(selected.root)
    engine = SetupEngine(store, platform)
    engine.apply(selected)
    engine.rollback_steps(
        selected,
        ("owner_bootstrap", "hermes_profiles", "services"),
        final_status="uninstalled",
    )
    platform.fail_once = "services"

    with pytest.raises(SetupError, match="services"):
        engine.apply(selected)

    resumed = engine.apply(selected)
    assert resumed.status == "completed"
    assert platform.applied.count("database") == 1
    assert platform.applied.count("services") == 3


def test_no_open_browser_outputs_the_private_claim_handoff_without_opening() -> None:
    output: list[str] = []

    handoff = Path("/private/signet-owner-capability")
    browser_assisted_setup(
        "https://signet.tailnet.example",
        "sbc1.secret-capability-value",
        output=output.append,
        opener=lambda value: pytest.fail(f"unexpected browser open: {value}"),
        open_browser=False,
        handoff_path=handoff,
    )

    assert output == [
        "Owner setup URL: https://signet.tailnet.example/setup",
        f"Private owner setup capability file: {handoff}",
    ]
    assert "secret-capability-value" not in "\n".join(output)


def test_owner_bootstrap_publishes_and_safely_rotates_a_private_claim_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = replace(spec(tmp_path / "signet"), open_browser=False)
    setup_id = "setup_0123456789abcdef"
    stored: dict[tuple[str, str], str] = {}
    now = 1_000
    output: list[str] = []

    monkeypatch.setattr(
        setup_platform.keyring,
        "get_password",
        lambda service, account: stored.get((service, account)),
    )
    monkeypatch.setattr(
        setup_platform.keyring,
        "set_password",
        lambda service, account, value: stored.__setitem__((service, account), value),
    )
    monkeypatch.setattr(setup_platform, "_now", lambda: now)
    platform = ProductionSetupPlatform(
        output=output.append,
        opener=lambda value: pytest.fail(f"unexpected browser open: {value}"),
    )
    platform._apply_private_paths(selected, setup_id)
    platform._apply_secrets(selected, setup_id)
    platform._apply_configuration(selected, setup_id)
    platform._apply_database(selected, setup_id)

    platform._apply_owner_bootstrap(selected, setup_id)

    handoff = selected.root / ".owner-bootstrap-capability"
    account = ("Signet-Setup", f"{setup_id}-browser-bootstrap")
    first = handoff.read_text(encoding="utf-8").rstrip("\n")
    assert first == stored[account]
    assert handoff.stat().st_mode & 0o777 == 0o600
    assert first not in "\n".join(output)

    now += 601
    handoff.write_text("foreign-content\n", encoding="utf-8")
    with pytest.raises(SetupError, match="changed or is ambiguous"):
        platform._apply_owner_bootstrap(selected, setup_id)
    assert stored[account] == first
    assert handoff.read_text(encoding="utf-8") == "foreign-content\n"

    handoff.write_text(first + "\n", encoding="utf-8")
    platform._apply_owner_bootstrap(selected, setup_id)
    second = handoff.read_text(encoding="utf-8").rstrip("\n")
    assert second == stored[account]
    assert second != first
    assert second not in "\n".join(output)

    BootstrapService(
        Database(selected.root / "data" / "signet.db"),
        owner_user_id=selected.owner_user_id,
    ).claim(
        second,
        "claimed-owner-browser-token-long-enough",
        now=now + 1,
    )
    now += 601
    platform._apply_owner_bootstrap(selected, setup_id)
    third = handoff.read_text(encoding="utf-8").rstrip("\n")
    assert third == stored[account]
    assert third != second

    stored.pop(account)
    now += 601
    platform._apply_owner_bootstrap(selected, setup_id)
    fourth = handoff.read_text(encoding="utf-8").rstrip("\n")
    assert fourth == stored[account]
    assert fourth != third

    stored.pop(account)
    platform._rollback_owner_bootstrap(selected, setup_id)
    assert not handoff.exists()


def test_owner_bootstrap_accepts_a_claim_racing_capability_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "racing-owner-claim")
    setup_id = "setup_0123456789abcdef"
    stored: dict[tuple[str, str], str] = {}
    now = 1_000
    opened: list[str] = []
    monkeypatch.setattr(
        setup_platform.keyring,
        "get_password",
        lambda service, account: stored.get((service, account)),
    )
    monkeypatch.setattr(
        setup_platform.keyring,
        "set_password",
        lambda service, account, value: stored.__setitem__((service, account), value),
    )
    monkeypatch.setattr(setup_platform, "_now", lambda: now)
    platform = ProductionSetupPlatform(
        output=lambda value: None,
        opener=lambda value: not opened.append(value),
    )
    platform._apply_private_paths(selected, setup_id)
    platform._apply_secrets(selected, setup_id)
    platform._apply_configuration(selected, setup_id)
    platform._apply_database(selected, setup_id)
    database = Database(selected.root / "data" / "signet.db")
    capability = BootstrapService(
        database,
        owner_user_id=selected.owner_user_id,
    ).issue_capability(now=900, lifetime=600)
    issue_capability = BootstrapService.issue_capability
    raced = False

    def issue_after_claim(self: BootstrapService, **kwargs: Any) -> str:
        nonlocal raced
        if not raced:
            raced = True
            BootstrapService(
                database,
                owner_user_id=selected.owner_user_id,
            ).claim(
                capability,
                "racing-owner-browser-token-long-enough",
                now=now,
            )
        return issue_capability(self, **kwargs)

    monkeypatch.setattr(BootstrapService, "issue_capability", issue_after_claim)

    platform._apply_owner_bootstrap(selected, setup_id)

    assert raced is True
    assert (
        BootstrapService(
            database,
            owner_user_id=selected.owner_user_id,
        )
        .status(
            now=now,
            claimant_token="racing-owner-browser-token-long-enough",
        )
        .claimed
        is True
    )
    assert opened == ["https://signet.tailnet.example/setup"]
    assert ("Signet-Setup", f"{setup_id}-browser-bootstrap") not in stored


def test_browser_assisted_setup_prints_exact_url_before_opening_without_printing_secret() -> None:
    events: list[tuple[str, str]] = []

    def output(value: str) -> None:
        events.append(("output", value))

    def opener(value: str) -> bool:
        events.append(("open", value))
        return True

    browser_assisted_setup(
        "https://signet.tailnet.example",
        "sbc1.secret-capability-value",
        output=output,
        opener=opener,
    )

    assert events[0] == ("output", "Owner setup URL: https://signet.tailnet.example/setup")
    assert events[1][0] == "open"
    assert events[1][1].startswith("https://signet.tailnet.example/setup#bootstrap=")
    assert "secret-capability-value" not in events[0][1]


def test_service_rollback_failure_preserves_owned_units(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet")
    ensure_private_directory(selected.root / "services")
    home = tmp_path / "home"
    target = home / "Library" / "LaunchAgents"
    target.mkdir(parents=True)
    rendered = render_launchd_services(selected, active=True)
    for name, content in rendered.items():
        for path in (target / name, selected.root / "services" / name):
            path.write_bytes(content)
            path.chmod(0o600)
    monkeypatch.setattr(setup_platform.sys, "platform", "darwin")
    monkeypatch.setattr(setup_platform.Path, "home", classmethod(lambda cls: home))

    platform = ProductionSetupPlatform(
        command_runner=lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, "", "bootout failed"
        )
    )
    with pytest.raises(SetupError, match="launchd could not stop Signet"):
        platform._rollback_services(selected, "setup_0123456789abcdef")
    assert all((target / name).is_file() for name in rendered)
    assert all((selected.root / "services" / name).is_file() for name in rendered)


def test_service_health_checks_reject_a_different_signet_instance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet")
    expected = production_instance_identity(selected.root)

    class Response:
        status = 200

        def read(self, limit: int) -> bytes:
            del limit
            return b'{"status":"ok"}'

        def getheader(self, name: str) -> str | None:
            if name == "X-Signet-Instance":
                return "0" * len(expected)
            if name == "X-Signet-Health-Proof":
                return None
            raise AssertionError(name)

    class Connection:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            del host, port, timeout

        def request(
            self,
            method: str,
            path: str,
            *,
            headers: dict[str, str],
        ) -> None:
            assert (method, path) == ("GET", "/healthz")
            assert "X-Signet-Health-Challenge" in headers

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            pass

    moments = iter((0.0, 1.0, 21.0))
    monkeypatch.setattr(setup_platform.http.client, "HTTPConnection", Connection)
    monkeypatch.setattr(setup_platform.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(setup_platform.time, "sleep", lambda delay: None)
    monkeypatch.setattr(
        ProductionSetupPlatform,
        "_health_secret",
        lambda self, selected_spec: "known-only-to-the-real-services-123456",
    )

    with pytest.raises(SetupError, match="did not become healthy"):
        ProductionSetupPlatform()._wait_for_local_services(selected)


def test_service_health_checks_reject_a_predictable_identity_without_a_valid_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "predictable-health")
    expected = production_instance_identity(selected.root)
    challenges: list[str] = []

    class Response:
        status = 200

        def read(self, limit: int) -> bytes:
            del limit
            return b'{"status":"ok"}'

        def getheader(self, name: str) -> str | None:
            if name == "X-Signet-Instance":
                return expected
            if name == "X-Signet-Health-Proof":
                return "0" * 64
            raise AssertionError(name)

    class Connection:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            del host, port, timeout

        def request(
            self,
            method: str,
            path: str,
            *,
            headers: dict[str, str],
        ) -> None:
            assert (method, path) == ("GET", "/healthz")
            challenges.append(headers["X-Signet-Health-Challenge"])

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            pass

    moments = iter((0.0, 1.0, 21.0))
    monkeypatch.setattr(setup_platform.http.client, "HTTPConnection", Connection)
    monkeypatch.setattr(setup_platform.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(setup_platform.time, "sleep", lambda delay: None)
    monkeypatch.setattr(
        ProductionSetupPlatform,
        "_health_secret",
        lambda self, selected_spec: "known-only-to-the-real-services-123456",
        raising=False,
    )

    with pytest.raises(SetupError, match="did not become healthy"):
        ProductionSetupPlatform()._wait_for_local_services(selected)

    assert challenges


def test_service_plans_use_installed_executable_and_remain_inert(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    launchd = render_launchd_services(selected)
    systemd = render_systemd_services(selected)

    assert set(launchd) == {"ai.hermes.signet.mcp.plist", "ai.hermes.signet.web.plist"}
    assert all(b"/opt/signet/bin/signet" in value for value in launchd.values())
    assert all(b"RunAtLoad" in value and b"<false/>" in value for value in launchd.values())
    assert set(systemd) == {"signet-mcp.service", "signet-web.service"}
    assert all("/opt/signet/bin/signet production serve-" in value for value in systemd.values())
    assert all("WantedBy" not in value for value in systemd.values())


def test_systemd_service_plan_uses_systemd_native_path_escaping() -> None:
    selected = replace(
        spec(Path('/tmp/Signet $HOME/%h/"quoted"/state\\dir')),
        executable=Path("/opt/Signet ${BIN}/%E/bin signet"),
    )

    unit = render_systemd_services(selected)["signet-mcp.service"]

    assert (
        'ExecStart=:"/opt/Signet ${BIN}/%%E/bin signet" '
        "production serve-mcp --config "
        '"/tmp/Signet $HOME/%%h/\\"quoted\\"/state\\\\dir/production.json"'
    ) in unit


@pytest.mark.parametrize("unsupported", ['"', "\\"])
def test_systemd_service_plan_rejects_unrepresentable_executable_paths(
    unsupported: str,
) -> None:
    selected = replace(
        spec(Path("/tmp/signet")),
        executable=Path(f"/opt/signet/{unsupported}/bin/signet"),
    )

    with pytest.raises(ValueError, match="systemd executable path"):
        render_systemd_services(selected)


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd is unavailable")
def test_systemd_service_plan_passes_systemd_analyze(tmp_path: Path) -> None:
    executable = tmp_path / "bin ${BIN} %E signet"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    selected = replace(
        spec(tmp_path / 'state $HOME %h "quoted" \\ data'),
        executable=executable,
    )
    unit_paths: list[Path] = []
    for name, content in render_systemd_services(selected).items():
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        unit_paths.append(path)

    result = subprocess.run(
        ["systemd-analyze", "verify", *(str(path) for path in unit_paths)],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("platform_name", ["darwin", "linux"])
def test_service_install_management_status_and_rollback_are_platform_native(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_name: str,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    commands: list[list[str]] = []
    services_active = False

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        nonlocal services_active
        commands.append(command)
        if command[:2] == ["launchctl", "bootstrap"] or "enable" in command:
            services_active = True
        elif command[:2] == ["launchctl", "bootout"] or "disable" in command:
            services_active = False
        elif command[:2] == ["launchctl", "kickstart"] or "restart" in command:
            services_active = True
        if command[:2] == ["launchctl", "print"]:
            return subprocess.CompletedProcess(command, 0 if services_active else 3, "", "")
        if "is-active" in command:
            return subprocess.CompletedProcess(
                command,
                0 if services_active else 3,
                "active\n" if services_active else "inactive\n",
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(setup_platform.sys, "platform", platform_name)
    monkeypatch.setattr(setup_platform.Path, "home", classmethod(lambda cls: home))
    selected = replace(
        spec(tmp_path / f"root-{platform_name}"),
        public_origin="https://example.com",
    )
    platform = ProductionSetupPlatform(command_runner=run)
    monkeypatch.setattr(platform, "_wait_for_local_services", lambda selected: None)
    platform._apply_private_paths(selected, "setup-service-test")

    platform._apply_services(selected, "setup-service-test")
    status = platform.service_status(selected)
    assert len(status) == 2
    assert set(status.values()) == {"active"}
    for action in ("stop", "start", "restart"):
        platform.manage_services(selected, action)
    platform._rollback_services(selected, "setup-service-test")

    if platform_name == "darwin":
        target = home / "Library" / "LaunchAgents"
        assert not (target / "ai.hermes.signet.mcp.plist").exists()
        assert not (target / "ai.hermes.signet.web.plist").exists()
        assert any(command[:2] == ["launchctl", "bootstrap"] for command in commands)
        assert any(command[:2] == ["launchctl", "bootout"] for command in commands)
        assert any(command[:2] == ["launchctl", "kickstart"] for command in commands)
    else:
        target = home / ".config" / "systemd" / "user"
        assert not (target / "signet-mcp.service").exists()
        assert not (target / "signet-web.service").exists()
        assert any("enable" in command for command in commands)
        assert any("disable" in command for command in commands)
        assert any("restart" in command for command in commands)


@pytest.mark.parametrize("platform_name", ["darwin", "linux"])
def test_service_install_refuses_exact_preexisting_units_without_ownership_plans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_name: str,
) -> None:
    home = ensure_private_directory(tmp_path / "home")
    monkeypatch.setattr(setup_platform.sys, "platform", platform_name)
    monkeypatch.setattr(setup_platform.Path, "home", classmethod(lambda cls: home))
    selected = replace(
        spec(tmp_path / f"preexisting-service-{platform_name}"),
        public_origin="https://example.com",
    )
    platform = ProductionSetupPlatform(
        command_runner=lambda command, **kwargs: (_ for _ in ()).throw(AssertionError(command))
    )
    platform._apply_private_paths(selected, "setup-service-test")
    if platform_name == "darwin":
        rendered: dict[str, bytes] = render_launchd_services(selected, active=True)
        target = ensure_private_directory(home / "Library" / "LaunchAgents")
    else:
        rendered = {
            name: content.encode("utf-8")
            for name, content in render_systemd_services(selected, active=True).items()
        }
        target = ensure_private_directory(home / ".config" / "systemd" / "user")
    for name, content in rendered.items():
        path = target / name
        path.write_bytes(content)
        path.chmod(0o600)

    with pytest.raises(SetupError, match="without an ownership plan"):
        platform._apply_services(selected, "setup-service-test")

    assert not any((selected.root / "services" / name).exists() for name in rendered)
    assert all((target / name).read_bytes() == content for name, content in rendered.items())


def test_launchd_service_stop_retry_tolerates_an_already_stopped_unit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = ensure_private_directory(tmp_path / "home")
    monkeypatch.setattr(setup_platform.sys, "platform", "darwin")
    monkeypatch.setattr(setup_platform.Path, "home", classmethod(lambda cls: home))
    selected = replace(spec(tmp_path / "launchd-stop-retry"), public_origin="https://example.com")
    target = ensure_private_directory(home / "Library" / "LaunchAgents")
    rendered = render_launchd_services(selected, active=True)
    for name, content in rendered.items():
        path = target / name
        path.write_bytes(content)
        path.chmod(0o600)
    bootouts = 0

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        nonlocal bootouts
        if command[:2] == ["launchctl", "bootout"]:
            bootouts += 1
            if bootouts == 1:
                return subprocess.CompletedProcess(command, 3, "", "No such process")
        return subprocess.CompletedProcess(command, 0, "", "")

    ProductionSetupPlatform(command_runner=run).manage_services(selected, "stop")

    assert bootouts == len(rendered)


def test_database_rollback_refuses_a_same_user_replacement_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = replace(
        spec(tmp_path / "root-database-ownership"),
        public_origin="https://example.com",
    )
    platform = ProductionSetupPlatform()
    monkeypatch.setattr(setup_platform, "create_production_assembly", lambda *args, **kwargs: None)
    platform._apply_private_paths(selected, "setup-database-test")
    platform._apply_database(selected, "setup-database-test")
    database = selected.root / "data" / "signet.db"
    marker = selected.root / "data" / ".signet-database-ownership.json"
    replacement = selected.root / "data" / "replacement.db"
    replacement.write_bytes(b"same-user foreign database")
    replacement.chmod(0o600)
    replacement.replace(database)

    with pytest.raises(SetupError, match="database changed after setup ownership"):
        platform._rollback_database(selected, "setup-database-test")

    assert database.read_bytes() == b"same-user foreign database"
    assert marker.is_file()


def test_database_rollback_rejects_unreceipted_sqlite_sidecars_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = replace(
        spec(tmp_path / "root-database-sidecar-ownership"),
        public_origin="https://example.com",
    )
    platform = ProductionSetupPlatform()
    monkeypatch.setattr(setup_platform, "create_production_assembly", lambda *args, **kwargs: None)
    platform._apply_private_paths(selected, "setup-database-test")
    platform._apply_database(selected, "setup-database-test")
    database = selected.root / "data" / "signet.db"
    marker = selected.root / "data" / ".signet-database-ownership.json"
    sidecar = selected.root / "data" / "signet.db-wal"
    sidecar.write_bytes(b"unreceipted same-user file")
    sidecar.chmod(0o600)

    with pytest.raises(SetupError, match="unreceipted database runtime artifact"):
        platform._rollback_database(selected, "setup-database-test")

    assert sidecar.read_bytes() == b"unreceipted same-user file"
    assert database.is_file()
    assert marker.is_file()


def test_database_rollback_removes_every_receipted_runtime_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = replace(
        spec(tmp_path / "root-database-runtime-cleanup"),
        public_origin="https://example.com",
    )
    platform = ProductionSetupPlatform()
    monkeypatch.setattr(setup_platform, "create_production_assembly", lambda *args, **kwargs: None)
    platform._apply_private_paths(selected, "setup-database-test")
    platform._apply_database(selected, "setup-database-test")
    data_directory = selected.root / "data"
    maintenance_lock = data_directory / ".signet.db.maintenance.lock"
    assert maintenance_lock.is_file()

    platform._rollback_database(selected, "setup-database-test")

    assert list(data_directory.iterdir()) == []


def test_systemd_rollback_retries_after_reload_failure_and_tolerates_unloaded_units(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    target = home / ".config" / "systemd" / "user"
    target.mkdir(parents=True)
    target.chmod(0o700)
    selected = replace(spec(tmp_path / "root-systemd-retry"), public_origin="https://example.com")
    ensure_private_directory(selected.root / "services")
    rendered = render_systemd_services(selected, active=True)
    for name, content in rendered.items():
        encoded = content.encode("utf-8")
        for path in (target / name, selected.root / "services" / name):
            path.write_bytes(encoded)
            path.chmod(0o600)
    reloads = 0

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal reloads
        del kwargs
        if "disable" in command:
            return subprocess.CompletedProcess(command, 1, "", "Unit is not loaded")
        if "is-active" in command:
            return subprocess.CompletedProcess(command, 3, "inactive\n", "")
        if command[-1] == "daemon-reload":
            reloads += 1
            return subprocess.CompletedProcess(
                command,
                1 if reloads == 1 else 0,
                "",
                "reload failed" if reloads == 1 else "",
            )
        raise AssertionError(command)

    monkeypatch.setattr(setup_platform.sys, "platform", "linux")
    monkeypatch.setattr(setup_platform.Path, "home", classmethod(lambda cls: home))
    platform = ProductionSetupPlatform(command_runner=run)

    with pytest.raises(SetupError, match="reload after rollback"):
        platform._rollback_services(selected, "setup-service-test")

    assert all(not (target / name).exists() for name in rendered)
    assert all((selected.root / "services" / name).is_file() for name in rendered)

    platform._rollback_services(selected, "setup-service-test")
    assert all(not (selected.root / "services" / name).exists() for name in rendered)


def test_launchd_rollback_stops_every_unit_before_deleting_any_unit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    bootouts = 0

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        nonlocal bootouts
        if command[:2] == ["launchctl", "bootout"]:
            bootouts += 1
            if bootouts == 2:
                return subprocess.CompletedProcess(command, 1, "", "stop failed")
            if bootouts == 3:
                return subprocess.CompletedProcess(command, 3, "", "No such process")
        if command[:2] == ["launchctl", "print"]:
            return subprocess.CompletedProcess(command, 3, "", "No such process")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(setup_platform.sys, "platform", "darwin")
    monkeypatch.setattr(setup_platform.Path, "home", classmethod(lambda cls: home))
    selected = replace(
        spec(tmp_path / "root-darwin-stop-failure"),
        public_origin="https://example.com",
    )
    platform = ProductionSetupPlatform(command_runner=run)
    monkeypatch.setattr(platform, "_wait_for_local_services", lambda selected: None)
    platform._apply_private_paths(selected, "setup-service-test")
    platform._apply_services(selected, "setup-service-test")
    rendered = render_launchd_services(selected, active=True)

    with pytest.raises(SetupError, match="launchd could not stop"):
        platform._rollback_services(selected, "setup-service-test")

    target = home / "Library" / "LaunchAgents"
    for name in rendered:
        assert (target / name).is_file()
        assert (selected.root / "services" / name).is_file()

    platform._rollback_services(selected, "setup-service-test")
    for name in rendered:
        assert not (target / name).exists()
        assert not (selected.root / "services" / name).exists()


def test_launchd_rollback_refuses_a_changed_unit_before_stopping_services(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    commands: list[list[str]] = []

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(setup_platform.sys, "platform", "darwin")
    monkeypatch.setattr(setup_platform.Path, "home", classmethod(lambda cls: home))
    selected = replace(
        spec(tmp_path / "root-darwin-changed-unit"),
        public_origin="https://example.com",
    )
    platform = ProductionSetupPlatform(command_runner=run)
    monkeypatch.setattr(platform, "_wait_for_local_services", lambda selected: None)
    platform._apply_private_paths(selected, "setup-service-test")
    platform._apply_services(selected, "setup-service-test")
    commands.clear()
    name = next(iter(render_launchd_services(selected, active=True)))
    (home / "Library" / "LaunchAgents" / name).write_bytes(b"foreign unit")

    with pytest.raises(SetupError, match="changed or foreign"):
        platform._rollback_services(selected, "setup-service-test")

    assert commands == []


def test_preflight_resolves_the_hermes_default_profile_to_the_hermes_home(
    tmp_path: Path,
) -> None:
    hermes_home = tmp_path / ".hermes"
    profiles_root = hermes_home / "profiles"
    profiles_root.mkdir(parents=True, mode=0o700)
    selected = SetupSpec(
        root=tmp_path / "signet",
        public_origin="https://signet.example",
        owner_user_id="user:owner",
        hermes_profiles=("default",),
        executable=Path(sys.executable).resolve(),
    )

    ProductionSetupPlatform(hermes_home=profiles_root)._apply_preflight(
        selected,
        "setup_0123456789abcdef",
    )


def test_preflight_rejects_linux_executable_paths_systemd_cannot_represent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / 'signet"bin'
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    selected = replace(spec(tmp_path / "signet"), executable=executable)
    monkeypatch.setattr(setup_platform.sys, "platform", "linux")

    with pytest.raises(SetupError, match="systemd executable path"):
        ProductionSetupPlatform()._apply_preflight(selected, "setup_0123456789abcdef")


def test_configuration_rollback_uses_the_selected_policy_mode(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    root.mkdir(mode=0o700)
    selected = replace(spec(root), policy_mode="approval")
    platform = ProductionSetupPlatform()

    platform._apply_configuration(selected, "setup_0123456789abcdef")
    assert "default_mode: approval" in (root / "policy.yaml").read_text(encoding="utf-8")

    platform._rollback_configuration(selected, "setup_0123456789abcdef")
    assert not (root / "policy.yaml").exists()
    assert not (root / "production.json").exists()


def test_setup_journal_contains_no_capability_or_generated_secret(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    engine = SetupEngine(SetupJournalStore(selected.root), FakePlatform())
    engine.apply(selected)

    journal = json.loads((selected.root / ".setup-journal.json").read_text(encoding="utf-8"))
    encoded = json.dumps(journal)
    assert "capability" not in encoded
    assert "secret-capability-value" not in encoded
    assert journal["spec"]["open_browser"] is True


def test_private_replacement_revalidates_the_caller_snapshot(
    tmp_path: Path,
) -> None:
    root = ensure_private_directory(tmp_path / "private")
    path = root / "config.yaml"
    path.write_bytes(b"snapshot")
    path.chmod(0o600)
    path.write_bytes(b"concurrent edit")

    with pytest.raises(SetupError, match="changed or is ambiguous"):
        _replace_private_file(
            path,
            b"replacement",
            expected_content=b"snapshot",
        )
    assert path.read_bytes() == b"concurrent edit"


def test_private_replacement_rechecks_an_expected_empty_file_before_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = ensure_private_directory(tmp_path / "private-empty-race")
    path = root / "config.yaml"
    path.write_bytes(b"")
    path.chmod(0o600)
    real_fsync = setup_platform.os.fsync
    raced = False

    def race_fsync(descriptor: int) -> None:
        nonlocal raced
        if not raced:
            raced = True
            path.unlink()
        real_fsync(descriptor)

    monkeypatch.setattr(setup_platform.os, "fsync", race_fsync)
    with pytest.raises(SetupError, match="changed or is ambiguous"):
        _replace_private_file(
            path,
            b"replacement",
            expected_content=b"",
            require_present=True,
        )

    assert raced is True
    assert not path.exists()


def test_private_replacement_rejects_a_replaced_parent_directory(tmp_path: Path) -> None:
    root = ensure_private_directory(tmp_path / "profile")
    identity = require_private_directory_identity(root)
    moved = root.with_name("original-profile")
    root.rename(moved)
    ensure_private_directory(root)

    with pytest.raises(SetupError, match="parent"):
        _replace_private_file(
            root / "config.yaml",
            b"managed",
            require_absent=True,
            expected_parent_identity=identity,
        )
    assert not (root / "config.yaml").exists()


def test_owned_file_removal_rejects_changed_permissions(tmp_path: Path) -> None:
    root = ensure_private_directory(tmp_path / "private-removal")
    path = root / "owned.service"
    path.write_bytes(b"managed unit")
    path.chmod(0o644)

    with pytest.raises(SetupError, match="changed or foreign"):
        _remove_exact_owned_file(path, b"managed unit")
    assert path.read_bytes() == b"managed unit"


def test_owned_file_removal_quarantines_an_inode_swap_without_deleting_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = ensure_private_directory(tmp_path / "private-removal-race")
    path = root / "owned.service"
    foreign = root / "foreign.service"
    saved = root / "saved-owned.service"
    for selected, content in ((path, b"managed unit"), (foreign, b"foreign unit")):
        selected.write_bytes(content)
        selected.chmod(0o600)
    real_rename = os.rename
    raced = False

    def race_rename(src: str, dst: str, **kwargs: Any) -> None:
        nonlocal raced
        if src == path.name and dst == "owned" and not raced:
            raced = True
            parent_descriptor = kwargs["src_dir_fd"]
            real_rename(
                path.name, saved.name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor
            )
            real_rename(
                foreign.name,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
        real_rename(src, dst, **kwargs)

    monkeypatch.setattr(setup_platform.os, "rename", race_rename)
    with pytest.raises(SetupError, match="changed or foreign"):
        _remove_exact_owned_file(path, b"managed unit")

    assert path.read_bytes() == b"foreign unit"
    assert saved.read_bytes() == b"managed unit"


def test_enabled_owned_hermes_entry_remains_uninstallable() -> None:
    setup_id = "setup_0123456789abcdef"
    original = b"model: test/model\n"
    token_name = "SIGNET_MCP_CALLER_TOKEN_WORK"
    merged = _merge_hermes_config(original, token_name=token_name, setup_id=setup_id)
    enabled = merged.replace(b"enabled: false", b"enabled: true", 1)

    assert (
        _remove_hermes_config(
            enabled,
            token_name=token_name,
            setup_id=setup_id,
        )
        == original
    )


def test_hermes_rollback_rejects_unrelated_entries_inside_owned_marker() -> None:
    setup_id = "setup_0123456789abcdef"
    token_name = "SIGNET_MCP_CALLER_TOKEN_WORK"
    merged = _merge_hermes_config(b"", token_name=token_name, setup_id=setup_id)
    end_marker = f"# signet setup {setup_id}: hermes config end\n".encode()
    changed = merged.replace(
        end_marker,
        b"  unrelated:\n    command: unrelated-server\n" + end_marker,
    )

    with pytest.raises(SetupError, match="changed or foreign"):
        _remove_hermes_config(
            changed,
            token_name=token_name,
            setup_id=setup_id,
        )


def test_hermes_rollback_rejects_comments_added_inside_the_owned_marker() -> None:
    setup_id = "setup_0123456789abcdef"
    token_name = "SIGNET_MCP_CALLER_TOKEN_WORK"
    merged = _merge_hermes_config(b"", token_name=token_name, setup_id=setup_id)
    changed = merged.replace(
        b"    timeout: 120\n",
        b"    # keep this foreign comment\n    timeout: 120\n",
        1,
    )

    with pytest.raises(SetupError, match="changed or foreign"):
        _remove_hermes_config(
            changed,
            token_name=token_name,
            setup_id=setup_id,
        )


def test_hermes_edits_are_exactly_reversible_and_reject_foreign_adoption() -> None:
    setup_id = "setup_0123456789abcdef"
    original_config = b"model: test/model"
    original_env = b"EXISTING=kept"
    token_name = "SIGNET_MCP_CALLER_TOKEN_WORK"
    token = "sgt_0123456789abcdef." + "x" * 43

    merged_config = _merge_hermes_config(
        original_config,
        token_name=token_name,
        setup_id=setup_id,
    )
    merged_env = _merge_profile_environment(
        original_env,
        token_name=token_name,
        token=token,
        setup_id=setup_id,
    )

    assert (
        _remove_hermes_config(
            merged_config,
            token_name=token_name,
            setup_id=setup_id,
        )
        == original_config
    )
    assert (
        _remove_profile_environment(
            merged_env,
            token_name=token_name,
            setup_id=setup_id,
        )
        == original_env
    )
    with pytest.raises(SetupError, match="marker"):
        _merge_hermes_config(
            merged_config,
            token_name=token_name,
            setup_id="setup_fedcba9876543210",
        )
    with pytest.raises(SetupError, match="invalid YAML"):
        _merge_hermes_config(
            b"mcp_servers: {}\nmcp_servers: {}\n",
            token_name=token_name,
            setup_id=setup_id,
        )


@pytest.mark.parametrize("mutation", ("duplicate", "malformed"))
def test_hermes_config_rejects_ambiguous_or_malformed_ownership_markers(
    mutation: str,
) -> None:
    setup_id = "setup_0123456789abcdef"
    token_name = "SIGNET_MCP_CALLER_TOKEN_WORK"
    existing = _merge_hermes_config(b"", token_name=token_name, setup_id=setup_id)
    if mutation == "duplicate":
        existing += b"# signet setup setup_fedcba9876543210: hermes config begin\n"
    else:
        existing = existing.replace(
            f"# signet setup {setup_id}: hermes config begin".encode(),
            b"# signet setup malformed: hermes config begin",
        )

    with pytest.raises(SetupError, match="marker"):
        _merge_hermes_config(
            existing,
            token_name=token_name,
            setup_id=setup_id,
        )


def test_format_one_hermes_profile_snapshots_fail_closed_without_directory_identity(
    tmp_path: Path,
) -> None:
    selected = replace(spec(tmp_path / "legacy-profile-snapshot"), hermes_profiles=("work",))
    profile = ensure_private_directory(tmp_path / "profiles" / "work")
    config = profile / "config.yaml"
    environment = profile / ".env"
    config.write_bytes(b"model: legacy\n")
    environment.write_bytes(b"LEGACY=kept\n")
    config.chmod(0o600)
    environment.chmod(0o600)
    identity = require_private_directory_identity(profile)
    setup_platform._capture_hermes_profile_snapshot(
        selected,
        "work",
        profile_identity=identity,
        config=config.read_bytes(),
        environment=environment.read_bytes(),
        config_exists=True,
        environment_exists=True,
    )
    snapshot_directory = setup_platform._hermes_snapshot_directory(selected, "work")
    metadata_path = snapshot_directory / "metadata.json"
    format_two = metadata_path.read_bytes()
    metadata = json.loads(format_two)
    for key in ("profile_device", "profile_inode", "profile_owner_uid"):
        metadata.pop(key)
    metadata["format"] = 1
    _replace_private_file(
        metadata_path,
        setup_platform._canonical_json_bytes(metadata),
        expected_content=format_two,
        require_present=True,
    )

    with pytest.raises(SetupError, match="metadata is invalid"):
        setup_platform._read_hermes_profile_snapshot(
            selected,
            "work",
            profile_directory=profile,
        )


def test_hermes_snapshot_cleanup_resumes_after_snapshot_removal_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = replace(spec(tmp_path / "profile-cleanup-resume"), hermes_profiles=("work",))
    profile = ensure_private_directory(tmp_path / "profiles" / "work")
    config = profile / "config.yaml"
    environment = profile / ".env"
    original_config = b"model: original\n"
    original_environment = b"EXISTING=kept\n"
    config.write_bytes(original_config)
    environment.write_bytes(original_environment)
    config.chmod(0o600)
    environment.chmod(0o600)
    profile_identity = require_private_directory_identity(profile)
    setup_id = "setup_0123456789abcdef"
    token_name = "SIGNET_MCP_CALLER_TOKEN_WORK"
    token = "sgt_0123456789abcdef." + "x" * 43
    setup_platform._capture_hermes_profile_snapshot(
        selected,
        "work",
        profile_identity=profile_identity,
        config=original_config,
        environment=original_environment,
        config_exists=True,
        environment_exists=True,
    )
    managed_config = _merge_hermes_config(
        original_config,
        token_name=token_name,
        setup_id=setup_id,
    )
    managed_environment = _merge_profile_environment(
        original_environment,
        token_name=token_name,
        token=token,
        setup_id=setup_id,
    )
    _replace_private_file(
        config,
        managed_config,
        expected_content=original_config,
        require_present=True,
        expected_parent_identity=profile_identity,
    )
    _replace_private_file(
        environment,
        managed_environment,
        expected_content=original_environment,
        require_present=True,
        expected_parent_identity=profile_identity,
    )
    real_remove_tree = setup_platform.remove_private_tree_checked
    interrupted = False

    def interrupt_after_removal(*args: Any, **kwargs: Any) -> None:
        nonlocal interrupted
        real_remove_tree(*args, **kwargs)
        if not interrupted:
            interrupted = True
            raise BackupError("simulated cleanup interruption")

    monkeypatch.setattr(setup_platform, "remove_private_tree_checked", interrupt_after_removal)
    with pytest.raises(SetupError, match="could not be completed safely"):
        setup_platform._restore_hermes_profile_snapshot(
            selected,
            "work",
            profile_directory=profile,
            token_name=token_name,
            setup_id=setup_id,
        )
    monkeypatch.setattr(setup_platform, "remove_private_tree_checked", real_remove_tree)

    assert setup_platform._restore_hermes_profile_snapshot(
        selected,
        "work",
        profile_directory=profile,
        token_name=token_name,
        setup_id=setup_id,
    )
    assert config.read_bytes() == original_config
    assert environment.read_bytes() == original_environment


def test_hermes_rollback_refuses_managed_markers_without_a_bound_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_home = tmp_path / "profiles"
    profile = ensure_private_directory(profile_home / "work")
    selected = replace(spec(tmp_path / "missing-profile-snapshot"), hermes_profiles=("work",))
    setup_id = "setup_0123456789abcdef"
    token_name = "SIGNET_MCP_CALLER_TOKEN_WORK"
    config = _merge_hermes_config(b"model: original\n", token_name=token_name, setup_id=setup_id)
    environment = _merge_profile_environment(
        b"EXISTING=kept\n",
        token_name=token_name,
        token="sgt_0123456789abcdef." + "x" * 43,
        setup_id=setup_id,
    )
    (profile / "config.yaml").write_bytes(config)
    (profile / ".env").write_bytes(environment)
    (profile / "config.yaml").chmod(0o600)
    (profile / ".env").chmod(0o600)

    class Registry:
        def list_metadata(self) -> list[Any]:
            return []

    class Assembly:
        token_registry = Registry()

    monkeypatch.setattr(setup_platform, "create_production_assembly", lambda *a, **k: Assembly())
    platform = ProductionSetupPlatform(hermes_home=profile_home)

    with pytest.raises(SetupError, match="without a bound profile snapshot"):
        platform._rollback_hermes_profiles(selected, setup_id)
    assert (profile / "config.yaml").read_bytes() == config
    assert (profile / ".env").read_bytes() == environment


def test_private_profile_file_read_refuses_a_path_replacement_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = ensure_private_directory(tmp_path / "profile-read-race")
    path = directory / "config.yaml"
    replacement = directory / "replacement.yaml"
    path.write_bytes(b"original\n")
    path.chmod(0o600)
    replacement.write_bytes(b"foreign\n")
    replacement.chmod(0o600)
    real_read = setup_platform.os.read
    raced = False

    def replace_before_read(descriptor: int, size: int) -> bytes:
        nonlocal raced
        if not raced:
            raced = True
            replacement.replace(path)
        return real_read(descriptor, size)

    monkeypatch.setattr(setup_platform.os, "read", replace_before_read)

    with pytest.raises(SetupError, match="changed during inspection"):
        setup_platform._read_optional_private_file(path)

    assert path.read_bytes() == b"foreign\n"


def test_absent_hermes_rollback_files_stay_bound_to_the_snapshotted_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = replace(spec(tmp_path / "absent-profile-snapshot"), hermes_profiles=("work",))
    profile = ensure_private_directory(tmp_path / "profiles" / "work")
    identity = require_private_directory_identity(profile)
    setup_platform._capture_hermes_profile_snapshot(
        selected,
        "work",
        profile_identity=identity,
        config=b"",
        environment=b"",
        config_exists=False,
        environment_exists=False,
    )
    real_read = setup_platform._read_optional_private_file
    reads = 0

    def swap_after_reads(path: Path) -> bytes:
        nonlocal reads
        content = real_read(path)
        if path.parent == profile:
            reads += 1
            if reads == 2:
                profile.rename(profile.with_name("work-original"))
                ensure_private_directory(profile)
                for name in ("config.yaml", ".env"):
                    foreign = profile / name
                    foreign.write_bytes(b"")
                    foreign.chmod(0o600)
        return content

    monkeypatch.setattr(setup_platform, "_read_optional_private_file", swap_after_reads)
    with pytest.raises(SetupError, match="parent|directory changed"):
        setup_platform._restore_hermes_profile_snapshot(
            selected,
            "work",
            profile_directory=profile,
            token_name="SIGNET_MCP_CALLER_TOKEN_WORK",
            setup_id="setup_0123456789abcdef",
        )

    assert (profile / "config.yaml").exists()
    assert (profile / ".env").exists()


def test_absent_hermes_rollback_refuses_present_empty_foreign_files(tmp_path: Path) -> None:
    selected = replace(spec(tmp_path / "empty-foreign-profile"), hermes_profiles=("work",))
    profile = ensure_private_directory(tmp_path / "profiles" / "work")
    setup_platform._capture_hermes_profile_snapshot(
        selected,
        "work",
        profile_identity=require_private_directory_identity(profile),
        config=b"",
        environment=b"",
        config_exists=False,
        environment_exists=False,
    )
    for name in ("config.yaml", ".env"):
        path = profile / name
        path.write_bytes(b"")
        path.chmod(0o600)

    with pytest.raises(SetupError, match="changed after its setup snapshot"):
        setup_platform._restore_hermes_profile_snapshot(
            selected,
            "work",
            profile_directory=profile,
            token_name="SIGNET_MCP_CALLER_TOKEN_WORK",
            setup_id="setup_0123456789abcdef",
        )

    assert (profile / "config.yaml").is_file()
    assert (profile / ".env").is_file()


def test_hermes_apply_retry_rejects_drift_outside_the_managed_snapshot(
    tmp_path: Path,
) -> None:
    selected = replace(spec(tmp_path / "profile-retry-drift"), hermes_profiles=("work",))
    profile = ensure_private_directory(tmp_path / "profiles" / "work")
    setup_id = "setup_0123456789abcdef"
    token_name = "SIGNET_MCP_CALLER_TOKEN_WORK"
    original_config = b"model: test/work\n"
    original_environment = b"EXISTING=kept\n"
    identity = require_private_directory_identity(profile)
    setup_platform._capture_hermes_profile_snapshot(
        selected,
        "work",
        profile_identity=identity,
        config=original_config,
        environment=original_environment,
        config_exists=True,
        environment_exists=True,
    )
    drifted_config = (
        _merge_hermes_config(original_config, token_name=token_name, setup_id=setup_id)
        + b"foreign: changed-after-snapshot\n"
    )

    with pytest.raises(SetupError, match="changed after its setup snapshot"):
        setup_platform._capture_hermes_profile_snapshot(
            selected,
            "work",
            profile_identity=identity,
            config=drifted_config,
            environment=original_environment,
            config_exists=True,
            environment_exists=True,
            setup_id=setup_id,
        )


def test_hermes_profile_edits_are_transactional_across_profiles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_home = tmp_path / "profiles"
    originals: dict[Path, bytes] = {}
    for profile in ("personal", "work"):
        directory = profile_home / profile
        directory.mkdir(parents=True)
        directory.chmod(0o700)
        for name, content in (
            ("config.yaml", f"model: test/{profile}\n".encode()),
            (".env", f"EXISTING_{profile.upper()}=kept\n".encode()),
        ):
            path = directory / name
            path.write_bytes(content)
            path.chmod(0o600)
            originals[path] = content

    class Issued:
        def __init__(self, token: str) -> None:
            self.token = token

    class Registry:
        issued = 0

        def authenticate(self, authorization: str, *, alias: str) -> None:
            del authorization, alias

        def list_metadata(self) -> list[Any]:
            return []

        def issue(self, namespace: str, aliases: set[str]) -> Issued:
            del namespace, aliases
            self.issued += 1
            return Issued(f"sgt_{self.issued:016x}." + "x" * 43)

        def revoke(self, token_id: str) -> None:
            del token_id

    class Assembly:
        token_registry = Registry()

    monkeypatch.setattr(setup_platform, "create_production_assembly", lambda *a, **k: Assembly())
    selected = spec(tmp_path / "transactional-hermes")
    platform = ProductionSetupPlatform(hermes_home=profile_home)
    platform._apply_private_paths(selected, "setup_0123456789abcdef")
    real_replace = setup_platform._replace_private_file
    failed = False

    def fail_on_work_config(path: Path, content: bytes, **kwargs: Any) -> None:
        nonlocal failed
        if path == profile_home / "work" / "config.yaml" and not failed:
            failed = True
            raise SetupError("injected second-profile write failure")
        real_replace(path, content, **kwargs)

    monkeypatch.setattr(setup_platform, "_replace_private_file", fail_on_work_config)

    with pytest.raises(SetupError, match="second-profile"):
        platform._apply_hermes_profiles(selected, "setup_0123456789abcdef")

    assert all(path.read_bytes() == content for path, content in originals.items())
    assert not (selected.root / "services" / "hermes-profile-snapshots").exists()


def test_hermes_apply_rejects_a_profile_directory_swap_after_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_home = tmp_path / "profiles"
    profile_dir = ensure_private_directory(profile_home / "work")
    for name, content in (("config.yaml", b"model: test/work\n"), (".env", b"OLD=kept\n")):
        path = profile_dir / name
        path.write_bytes(content)
        path.chmod(0o600)

    class Issued:
        token = "sgt_0000000000000001." + "x" * 43

    class Registry:
        def issue(self, namespace: str, aliases: set[str]) -> Issued:
            del namespace, aliases
            return Issued()

        def revoke(self, token_id: str) -> None:
            del token_id

    class Assembly:
        token_registry = Registry()

    monkeypatch.setattr(setup_platform, "create_production_assembly", lambda *a, **k: Assembly())
    selected = replace(spec(tmp_path / "profile-swap"), hermes_profiles=("work",))
    platform = ProductionSetupPlatform(hermes_home=profile_home)
    platform._apply_private_paths(selected, "setup_0123456789abcdef")
    real_capture = setup_platform._capture_hermes_profile_snapshot

    def swap_after_snapshot(*args: Any, **kwargs: Any) -> None:
        real_capture(*args, **kwargs)
        profile_dir.rename(profile_dir.with_name("work-original"))
        ensure_private_directory(profile_dir)
        for name, content in (("config.yaml", b"model: foreign\n"), (".env", b"FOREIGN=kept\n")):
            path = profile_dir / name
            path.write_bytes(content)
            path.chmod(0o600)

    monkeypatch.setattr(setup_platform, "_capture_hermes_profile_snapshot", swap_after_snapshot)
    with pytest.raises(SetupError, match="rollback after an edit failure failed"):
        platform._apply_hermes_profiles(selected, "setup_0123456789abcdef")

    assert (profile_dir / "config.yaml").read_bytes() == b"model: foreign\n"
    assert (profile_dir / ".env").read_bytes() == b"FOREIGN=kept\n"


def test_tailnet_rollback_rejects_the_right_target_on_the_wrong_port(
    tmp_path: Path,
) -> None:
    selected = SetupSpec(
        root=tmp_path / "owned",
        public_origin="https://signet.example.ts.net:8443",
        owner_user_id="user:owner",
        hermes_profiles=("work",),
        executable=Path("/bin/echo"),
    )
    ensure_private_directory(selected.root / "services")
    before_path = selected.root / "services" / "tailscale-serve-before.json"
    before_path.write_text('{"format":2,"serve":{}}\n', encoding="utf-8")
    before_path.chmod(0o600)
    host_port = "signet.example.ts.net:8443"
    state = {
        "serve": {
            "TCP": {"8443": {"HTTPS": True}},
            "Web": {host_port: {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9999"}}}},
            "AllowFunnel": {host_port: False},
        },
    }
    after_path = selected.root / "services" / "tailscale-serve-after.json"
    after_path.write_text(
        json.dumps({"format": 2, "serve": state["serve"]}) + "\n",
        encoding="utf-8",
    )
    after_path.chmod(0o600)
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del kwargs
        commands.append(command)
        payload = state["serve"]
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    platform = ProductionSetupPlatform(command_runner=run)
    with pytest.raises(SetupError, match="changed Tailscale listener"):
        platform._rollback_tailnet_route(selected)
    assert not any(command[-1] == "off" for command in commands)


def test_tailnet_apply_rejects_a_foreground_listener_before_mutation(
    tmp_path: Path,
) -> None:
    selected = SetupSpec(
        root=tmp_path / "foreground-tailnet",
        public_origin="https://signet.example.ts.net:8443",
        owner_user_id="user:owner",
        hermes_profiles=("work",),
        executable=Path("/bin/echo"),
    )
    ensure_private_directory(selected.root / "services")
    host_port = "signet.example.ts.net:8443"
    serve = {
        "Foreground": {
            "session-1": {
                "TCP": {"8443": {"HTTPS": True}},
                "Web": {host_port: {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9999"}}}},
            }
        }
    }
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del kwargs
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(serve), "")

    platform = ProductionSetupPlatform(command_runner=run)

    with pytest.raises(SetupError, match="listener 8443 is already in use"):
        platform._apply_tailnet_route(selected)

    assert not any("--bg" in command for command in commands)


def test_tailnet_apply_resume_rejects_unreceipted_configuration_drift(
    tmp_path: Path,
) -> None:
    selected = SetupSpec(
        root=tmp_path / "tailnet-resume-drift",
        public_origin="https://signet.example.ts.net:8443",
        owner_user_id="user:owner",
        hermes_profiles=("work",),
        executable=Path("/bin/echo"),
    )
    ensure_private_directory(selected.root / "services")
    before_path = selected.root / "services" / "tailscale-serve-before.json"
    before_path.write_text('{"format":2,"serve":{}}\n', encoding="utf-8")
    before_path.chmod(0o600)
    drifted = {
        "TCP": {"9443": {"HTTPS": True}},
        "Web": {
            "signet.example.ts.net:9443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9444"}}}
        },
    }
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del kwargs
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(drifted), "")

    platform = ProductionSetupPlatform(command_runner=run)
    with pytest.raises(SetupError, match="snapshot changed before apply completed"):
        platform._apply_tailnet_route(selected)
    assert not any("--bg" in command for command in commands)


def test_tailnet_route_is_adopted_only_when_free_and_rolled_back_exactly(
    tmp_path: Path,
) -> None:
    selected = SetupSpec(
        root=tmp_path / "owned",
        public_origin="https://signet.example.ts.net:8443",
        owner_user_id="user:owner",
        hermes_profiles=("work",),
        executable=Path("/bin/echo"),
    )
    ensure_private_directory(selected.root / "services")
    host_port = "signet.example.ts.net:8443"
    state: dict[str, Any] = {"serve": {}}
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del kwargs
        commands.append(command)
        if command[:3] == ["tailscale", "serve", "status"]:
            payload = state["serve"]
        elif "--bg" in command:
            state["serve"] = {
                "TCP": {"8443": {"HTTPS": True}},
                "Web": {host_port: {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8790"}}}},
                "AllowFunnel": {host_port: False},
            }
            payload = {}
        elif command[-1] == "off":
            state["serve"] = {}
            payload = {}
        else:  # pragma: no cover - protects the fake boundary
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    platform = ProductionSetupPlatform(command_runner=run)
    platform._apply_tailnet_route(selected)

    assert any("--https=8443" in command for command in commands)
    assert not any(command[1] == "funnel" for command in commands)
    assert (selected.root / "services" / "tailscale-serve-before.json").is_file()
    assert (selected.root / "services" / "tailscale-serve-after.json").is_file()
    platform._rollback_tailnet_route(selected)
    assert state["serve"] == {}
    assert not (selected.root / "services" / "tailscale-serve-before.json").exists()
    assert not (selected.root / "services" / "tailscale-serve-after.json").exists()


def test_tailnet_route_normalizes_absent_and_empty_serve_states(tmp_path: Path) -> None:
    selected = SetupSpec(
        root=tmp_path / "absent-tailnet",
        public_origin="https://signet.example.ts.net:8443",
        owner_user_id="user:owner",
        hermes_profiles=("work",),
        executable=Path("/bin/echo"),
    )
    ensure_private_directory(selected.root / "services")
    host_port = "signet.example.ts.net:8443"
    state: dict[str, Any] = {"serve": None}

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del kwargs
        if command[:3] == ["tailscale", "serve", "status"]:
            payload = state["serve"]
        elif "--bg" in command:
            state["serve"] = {
                "TCP": {"8443": {"HTTPS": True}},
                "Web": {host_port: {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8790"}}}},
                "AllowFunnel": {host_port: False},
            }
            payload = {}
        elif command[-1] == "off":
            state["serve"] = {}
            payload = {}
        else:  # pragma: no cover - protects the fake boundary
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    platform = ProductionSetupPlatform(command_runner=run)
    platform._apply_tailnet_route(selected)
    platform._rollback_tailnet_route(selected)

    assert state["serve"] == {}
    assert not (selected.root / "services" / "tailscale-serve-before.json").exists()
    assert not (selected.root / "services" / "tailscale-serve-after.json").exists()


def test_tailnet_rollback_resumes_after_restoring_the_pre_setup_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = SetupSpec(
        root=tmp_path / "resumable-tailnet-rollback",
        public_origin="https://signet.example.ts.net:8443",
        owner_user_id="user:owner",
        hermes_profiles=("work",),
        executable=Path("/bin/echo"),
    )
    ensure_private_directory(selected.root / "services")
    host_port = "signet.example.ts.net:8443"
    state: dict[str, Any] = {"serve": {}}
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del kwargs
        commands.append(command)
        if command[:3] == ["tailscale", "serve", "status"]:
            payload = state["serve"]
        elif "--bg" in command:
            state["serve"] = {
                "TCP": {"8443": {"HTTPS": True}},
                "Web": {host_port: {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8790"}}}},
                "AllowFunnel": {host_port: False},
            }
            payload = {}
        elif command[-1] == "off":
            state["serve"] = {}
            payload = {}
        else:  # pragma: no cover - protects the fake boundary
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    platform = ProductionSetupPlatform(command_runner=run)
    platform._apply_tailnet_route(selected)
    real_remove = setup_platform._remove_exact_owned_file

    def interrupt_cleanup(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise SetupError("fault after Tailscale restore")

    monkeypatch.setattr(setup_platform, "_remove_exact_owned_file", interrupt_cleanup)
    with pytest.raises(SetupError, match="fault after Tailscale restore"):
        platform._rollback_tailnet_route(selected)

    monkeypatch.setattr(setup_platform, "_remove_exact_owned_file", real_remove)
    platform._rollback_tailnet_route(selected)

    assert state["serve"] == {}
    assert sum(command[-1] == "off" for command in commands) == 1
    assert not (selected.root / "services" / "tailscale-serve-before.json").exists()
    assert not (selected.root / "services" / "tailscale-serve-after.json").exists()


def test_tailnet_rollback_verifies_the_exact_pre_setup_snapshot(tmp_path: Path) -> None:
    selected = SetupSpec(
        root=tmp_path / "owned-exact-tailnet",
        public_origin="https://signet.example.ts.net:8443",
        owner_user_id="user:owner",
        hermes_profiles=("work",),
        executable=Path("/bin/echo"),
    )
    ensure_private_directory(selected.root / "services")
    host_port = "signet.example.ts.net:8443"
    other_host_port = "signet.example.ts.net:9443"
    before_serve: dict[str, Any] = {
        "TCP": {"9443": {"HTTPS": True}},
        "Web": {other_host_port: {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9444"}}}},
    }
    state: dict[str, Any] = {"serve": before_serve}

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del kwargs
        if command[:3] == ["tailscale", "serve", "status"]:
            payload = state["serve"]
        elif "--bg" in command:
            state["serve"] = {
                "TCP": {"9443": {"HTTPS": True}, "8443": {"HTTPS": True}},
                "Web": {
                    other_host_port: {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9444"}}},
                    host_port: {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8790"}}},
                },
                "AllowFunnel": {host_port: False},
            }
            payload = {}
        elif command[-1] == "off":
            state["serve"] = {}
            payload = {}
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    platform = ProductionSetupPlatform(command_runner=run)
    platform._apply_tailnet_route(selected)

    with pytest.raises(SetupError, match="exact pre-setup snapshot"):
        platform._rollback_tailnet_route(selected)
    assert (selected.root / "services" / "tailscale-serve-before.json").is_file()


def test_real_platform_builds_a_provider_disabled_production_assembly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(
        setup_platform.keyring,
        "get_password",
        lambda service, account: secrets.get((service, account)),
    )
    monkeypatch.setattr(
        setup_platform.keyring,
        "set_password",
        lambda service, account, value: secrets.__setitem__((service, account), value),
    )
    monkeypatch.setattr(
        setup_platform.keyring,
        "delete_password",
        lambda service, account: secrets.pop((service, account), None),
    )

    profile_home = tmp_path / "profiles"
    original_config = (
        b"model: test/model\nmcp_servers:\n  existing:\n    url: http://127.0.0.1:9999\n"
    )
    original_env = b"EXISTING_VALUE=kept"
    for profile in ("personal", "work"):
        directory = profile_home / profile
        directory.mkdir(parents=True)
        directory.chmod(0o700)
        (directory / "config.yaml").write_bytes(original_config)
        (directory / ".env").write_bytes(original_env)
        (directory / "config.yaml").chmod(0o600)
        (directory / ".env").chmod(0o600)

    class NoExternalSideEffects(ProductionSetupPlatform):
        def _apply_services(self, selected: SetupSpec, setup_id: str) -> None:
            del selected, setup_id

        def manage_services(self, selected: SetupSpec, action: str) -> None:
            del selected
            self.services_active = action != "stop"

        def _apply_owner_bootstrap(self, selected: SetupSpec, setup_id: str) -> None:
            del selected, setup_id

        def service_status(self, selected: SetupSpec) -> dict[str, str]:
            del selected
            state = "active" if getattr(self, "services_active", True) else "inactive"
            return {"signet-mcp": state, "signet-web": state}

        def verify_service_health(self, spec: SetupSpec) -> None:
            del spec
            assert getattr(self, "services_active", True)

    selected = SetupSpec(
        root=tmp_path / "owned-root",
        public_origin="https://signet.tailnet.example",
        owner_user_id="user:owner",
        hermes_profiles=("personal", "work"),
        executable=Path("/bin/echo"),
    )
    output: list[str] = []
    external_calls: list[list[str]] = []

    def record_external_call(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        external_calls.append(command)
        return subprocess.CompletedProcess(command, 1, "", "unexpected external command")

    platform = NoExternalSideEffects(
        hermes_home=profile_home,
        output=output.append,
        command_runner=record_external_call,
    )

    journal = SetupEngine(SetupJournalStore(selected.root), platform).apply(selected)

    assert journal.status == "completed"
    assert external_calls == []
    assert any("did not restart the gateway" in message for message in output)
    assert any("/reload-mcp" in message for message in output)
    config_path = selected.root / "production.json"
    config = load_production_config(config_path)
    assert config.provider_rollout.state == "disabled"
    assert config.connectors == {}
    assert config.allowed_principals == {
        "profile:personal": ("approvals",),
        "profile:work": ("approvals",),
    }
    assembly = create_production_assembly(
        config_path,
        secret_store=KeychainSecretStore(),
    )
    assert assembly.status().live_providers_ready is False
    profile_tokens: list[str] = []
    for profile in selected.hermes_profiles:
        rendered = (profile_home / profile / "config.yaml").read_text(encoding="utf-8")
        environment = (profile_home / profile / ".env").read_text(encoding="utf-8")
        assert "enabled: false" in rendered
        assert "existing:" in rendered
        token_line = next(line for line in environment.splitlines() if line.startswith("SIGNET_"))
        profile_tokens.append(token_line.split("=", 1)[1])
    assert len(set(profile_tokens)) == 2
    assert not any("sgt_" in message for message in output)

    operations = SetupOperations(selected.root, platform=platform)
    before_inspection = {
        path.relative_to(selected.root): path.read_bytes()
        for path in selected.root.rglob("*")
        if path.is_file()
    }
    status = operations.status()
    doctor = operations.doctor()
    after_inspection = {
        path.relative_to(selected.root): path.read_bytes()
        for path in selected.root.rglob("*")
        if path.is_file()
    }
    assert status["setup_status"] == "completed"
    assert status["production"]["available"] is True
    assert doctor["healthy"] is True
    assert before_inspection == after_inspection
    upgrade = operations.upgrade()
    assert Path(upgrade["backup"]).is_file()
    assert upgrade["backup_receipt"] == {
        "artifact_path": upgrade["backup"],
        "artifact_sha256": hashlib.sha256(Path(upgrade["backup"]).read_bytes()).hexdigest(),
        "source_schema_version": upgrade["schema_version"],
        "verified_restore_schema_version": upgrade["schema_version"],
    }
    assert upgrade["provider_rollout"] == "disabled"
    backup_path = operations.backup()
    assert backup_path.is_file()
    restored = operations.restore(backup_path)
    assert restored.root.is_dir()
    assert restored.database_path.is_file()

    platform._rollback_hermes_profiles(selected, journal.setup_id)
    for profile in selected.hermes_profiles:
        assert (profile_home / profile / "config.yaml").read_bytes() == original_config
        assert (profile_home / profile / ".env").read_bytes() == original_env
    shutil.rmtree(profile_home / "work")
    platform._rollback_hermes_profiles(selected, journal.setup_id)
    assert not (profile_home / "work").exists()

    platform.remove_setup_secrets(journal.setup_id, preserve_backup=True)
    config_path.unlink()
    for database_file in config.storage.data_dir.iterdir():
        database_file.unlink()
    restored_after_purge = operations.restore(backup_path)
    assert restored_after_purge.database_path.is_file()
    assert restored_after_purge.manifest["format"] == 2
