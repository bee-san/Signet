from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import signet.setup_platform as setup_platform
from signet.config import ProductionConfig, production_instance_identity
from signet.credential_broker import KeychainSecretStore
from signet.private_paths import ensure_private_directory
from signet.production import create_production_assembly, load_production_config
from signet.setup_operations import SetupOperations
from signet.setup_platform import (
    ProductionSetupPlatform,
    _merge_hermes_config,
    _merge_profile_environment,
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


def test_rollback_is_reverse_order_and_records_partial_rollback_failure(tmp_path: Path) -> None:
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
    assert platform.rolled_back == list(reversed(SETUP_STEPS))


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


def test_purge_uninstall_creates_backup_before_removing_any_resource(
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
    SetupEngine(SetupJournalStore(selected.root), platform).apply(selected)
    operations = SetupOperations(selected.root, platform=platform)

    def backup(destination: Path | None = None) -> Path:
        assert destination is None
        events.append("backup")
        return selected.root / "backups" / "before-purge.signet-backup"

    monkeypatch.setattr(operations, "backup", backup)

    result = operations.uninstall(purge=True)

    assert result["backup"].endswith("before-purge.signet-backup")
    assert events[0] == "backup"


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

    stored.pop(account)
    now += 601
    platform._apply_owner_bootstrap(selected, setup_id)
    third = handoff.read_text(encoding="utf-8").rstrip("\n")
    assert third == stored[account]
    assert third != second

    stored.pop(account)
    platform._rollback_owner_bootstrap(selected, setup_id)
    assert not handoff.exists()


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
            assert name == "X-Signet-Instance"
            return "0" * len(expected)

    class Connection:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            del host, port, timeout

        def request(self, method: str, path: str) -> None:
            assert (method, path) == ("GET", "/healthz")

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            pass

    moments = iter((0.0, 1.0, 21.0))
    monkeypatch.setattr(setup_platform.http.client, "HTTPConnection", Connection)
    monkeypatch.setattr(setup_platform.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(setup_platform.time, "sleep", lambda delay: None)

    with pytest.raises(SetupError, match="did not become healthy"):
        ProductionSetupPlatform()._wait_for_local_services(selected)


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

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        stdout = "active\n" if command[-1:] == ["is-active"] else ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

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

    with pytest.raises(SetupError, match="launchd could not stop"):
        platform._rollback_services(selected, "setup-service-test")

    target = home / "Library" / "LaunchAgents"
    for name in render_launchd_services(selected, active=True):
        assert (target / name).is_file()
        assert (selected.root / "services" / name).is_file()


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
    with pytest.raises(SetupError, match="unowned"):
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
    before_path.write_text('{"funnel":{},"serve":{}}\n', encoding="utf-8")
    before_path.chmod(0o600)
    state = {
        "serve": {
            "Web": {
                ":8443": {"Proxy": "http://127.0.0.1:9999"},
                ":443": {"Proxy": "http://127.0.0.1:8790"},
            }
        },
        "funnel": {},
    }
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del kwargs
        commands.append(command)
        payload = state["funnel"] if command[1] == "funnel" else state["serve"]
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    platform = ProductionSetupPlatform(command_runner=run)
    with pytest.raises(SetupError, match="changed Tailscale listener"):
        platform._rollback_tailnet_route(selected)
    assert not any(command[-1] == "off" for command in commands)


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
    state: dict[str, Any] = {"serve": {}, "funnel": {}}
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del kwargs
        commands.append(command)
        if command[:3] == ["tailscale", "serve", "status"]:
            payload = state["serve"]
        elif command[:3] == ["tailscale", "funnel", "status"]:
            payload = state["funnel"]
        elif "--bg" in command:
            state["serve"] = {"Web": {":8443": {"Proxy": "http://127.0.0.1:8790"}}}
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
    assert (selected.root / "services" / "tailscale-serve-before.json").is_file()
    assert (selected.root / "services" / "tailscale-serve-after.json").is_file()
    platform._rollback_tailnet_route(selected)
    assert state["serve"] == {}
    assert not (selected.root / "services" / "tailscale-serve-before.json").exists()
    assert not (selected.root / "services" / "tailscale-serve-after.json").exists()


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

        def _apply_owner_bootstrap(self, selected: SetupSpec, setup_id: str) -> None:
            del selected, setup_id

        def service_status(self, selected: SetupSpec) -> dict[str, str]:
            del selected
            return {"signet-mcp": "active", "signet-web": "active"}

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
