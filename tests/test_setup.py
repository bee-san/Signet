from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import signet.setup_platform as setup_platform
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


def test_apply_refuses_nonempty_foreign_root(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    root.mkdir()
    (root / "somebody-elses-file").write_text("leave me alone", encoding="utf-8")

    with pytest.raises(SetupError, match="not owned"):
        SetupEngine(SetupJournalStore(root), FakePlatform()).apply(spec(root))

    assert (root / "somebody-elses-file").read_text(encoding="utf-8") == "leave me alone"
    assert not (root / ".setup-journal.json").exists()


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
    monkeypatch.setattr(platform, "_wait_for_local_services", lambda: None)
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
    platform._rollback_tailnet_route(selected)
    assert state["serve"] == {}


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
    platform = NoExternalSideEffects(hermes_home=profile_home, output=output.append)

    journal = SetupEngine(SetupJournalStore(selected.root), platform).apply(selected)

    assert journal.status == "completed"
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
    status = operations.status()
    assert status["setup_status"] == "completed"
    assert status["production"]["available"] is True
    assert operations.doctor()["healthy"] is True
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
