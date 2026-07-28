from __future__ import annotations

import hashlib
import json
import os
import shlex
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import signet.production as production_module
import signet.setup_platform as setup_platform
from signet.app import _parser, main
from signet.setup_cli import (
    _discover_hermes_profiles,
    _discover_tailscale_origin,
    run_setup_command,
    setup_error_message,
)
from signet.setup_platform import render_production_config
from signet.setup_state import SETUP_STEPS, SetupError, SetupSpec


class FakePlatform:
    def __init__(self) -> None:
        self.applied: list[str] = []
        self.rolled_back: list[str] = []

    def apply(self, step: str, spec: object, setup_id: str) -> None:
        del spec, setup_id
        self.applied.append(step)

    def rollback(self, step: str, spec: object, setup_id: str) -> None:
        del spec, setup_id
        self.rolled_back.append(step)

    def validate_private_paths(self, spec: object, setup_id: str) -> None:
        del spec, setup_id


def _installed_test_executable(tmp_path: Path) -> Path:
    executable = tmp_path / "bin" / "signet"
    executable.parent.mkdir(mode=0o700)
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    return executable


def test_profile_discovery_includes_the_hermes_default_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    (home / ".hermes" / "profiles" / "work").mkdir(parents=True)
    (home / ".hermes" / "config.yaml").write_text("model: test/model\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))

    assert _discover_hermes_profiles() == ["default", "work"]


def test_origin_discovery_uses_an_absolute_command_and_clean_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reviewed_tailscale = tmp_path / "commands" / "tailscale"
    reviewed_tailscale.parent.mkdir(mode=0o700)
    reviewed_tailscale.write_bytes(b"#!/bin/sh\nexit 0\n")
    reviewed_tailscale.chmod(0o700)
    monkeypatch.setattr(
        setup_platform,
        "_REVIEWED_COMMAND_CANDIDATES",
        {"tailscale": (reviewed_tailscale,)},
    )
    observed: dict[str, Any] = {}

    def run(command: list[str], **kwargs: Any) -> SimpleNamespace:
        observed.update(command=command, **kwargs)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"Self": {"DNSName": "node.example.ts.net."}}),
        )

    monkeypatch.setenv("PYTHONPATH", "/tmp/hostile")
    monkeypatch.setattr("signet.setup_cli.subprocess.run", run)

    assert _discover_tailscale_origin() == "https://node.example.ts.net:8443"
    assert Path(observed["command"][0]).is_absolute()
    assert Path(observed["command"][0]).name.casefold() == "tailscale"
    assert observed["env"] == {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    assert observed["cwd"] == "/"


@pytest.mark.parametrize(
    "command",
    [
        "setup",
        "manage",
        "status",
        "doctor",
        "verify",
        "backup",
        "restore",
        "upgrade",
        "uninstall",
    ],
)
def test_parser_exposes_setup_lifecycle_commands(command: str) -> None:
    parser = _parser()
    if command == "setup":
        args = parser.parse_args(
            [
                command,
                "--plan",
                "--origin",
                "https://signet.example",
                "--profile",
                "personal",
                "--executable",
                "/opt/signet/bin/signet",
            ]
        )
    elif command == "manage":
        args = parser.parse_args([command, "status"])
    elif command == "restore":
        args = parser.parse_args([command, "/tmp/backup.signet-backup"])
    else:
        args = parser.parse_args([command])
    assert args.command == command


def test_top_level_help_documents_plan_defaults_and_stable_exit_codes() -> None:
    help_text = " ".join(_parser().format_help().split())

    assert "manage plan, apply, roll back, or inspect Signet services" in help_text
    assert "backup plan or apply a verified encrypted backup" in help_text
    assert (
        "Exit status: 0 on success; 1 when doctor finds unhealthy checks; 2 for invalid input, "
        "safety refusal, or incomplete work" in help_text
    )


def test_parser_and_dispatch_expose_simple_provider_workflows(tmp_path: Path) -> None:
    calls: list[tuple[str, object]] = []

    class Providers:
        def setup_fastmail(
            self,
            *,
            token: str,
            sender: str,
            recipient: str,
        ) -> dict[str, object]:
            calls.append(("fastmail", (token, sender, recipient)))
            return {"provider": "fastmail", "enabled": True}

        def setup_whatsapp(
            self,
            *,
            recipient: str,
            install_wacli: bool,
        ) -> dict[str, object]:
            calls.append(("whatsapp", (recipient, install_wacli)))
            return {"provider": "whatsapp", "enabled": True}

        def status(self) -> dict[str, object]:
            calls.append(("status", None))
            return {"rollout": "disabled"}

        def enable(self, provider: str) -> dict[str, object]:
            calls.append(("enable", provider))
            return {"provider": provider, "rollout": "enabled"}

        def disable(self, provider: str) -> dict[str, object]:
            calls.append(("disable", provider))
            return {"provider": provider, "rollout": "disabled"}

    roots: list[Path] = []

    def factory(root: Path, platform: object) -> Providers:
        del platform
        roots.append(root)
        return Providers()

    parser = _parser()
    commands = [
        [
            "provider",
            "setup",
            "fastmail",
            "--root",
            str(tmp_path),
            "--from",
            "sender@example.test",
            "--to",
            "recipient@example.test",
            "--token-stdin",
            "--yes",
        ],
        [
            "provider",
            "setup",
            "whatsapp",
            "--root",
            str(tmp_path),
            "--to",
            "+447700900123",
            "--yes",
        ],
        ["provider", "status", "--root", str(tmp_path)],
        ["provider", "enable", "--root", str(tmp_path), "fastmail"],
        ["provider", "disable", "--root", str(tmp_path), "whatsapp"],
    ]
    output: list[str] = []
    for command in commands:
        assert (
            run_setup_command(
                parser.parse_args(command),
                output=output.append,
                platform=FakePlatform(),
                provider_operations_factory=factory,
                stdin=StringIO("secret-token\n"),
            )
            == 0
        )

    assert roots == [tmp_path] * len(commands)
    assert calls == [
        (
            "fastmail",
            ("secret-token", "sender@example.test", "recipient@example.test"),
        ),
        ("whatsapp", ("+447700900123", True)),
        ("status", None),
        ("enable", "fastmail"),
        ("disable", "whatsapp"),
    ]
    assert [json.loads(item) for item in output] == [
        {"provider": "fastmail", "enabled": True},
        {"provider": "whatsapp", "enabled": True},
        {"rollout": "disabled"},
        {"provider": "fastmail", "rollout": "enabled"},
        {"provider": "whatsapp", "rollout": "disabled"},
    ]


def test_provider_setup_requires_confirmation_before_reading_a_secret(
    tmp_path: Path,
) -> None:
    args = _parser().parse_args(
        [
            "provider",
            "setup",
            "fastmail",
            "--root",
            str(tmp_path),
            "--from",
            "sender@example.test",
            "--to",
            "recipient@example.test",
        ]
    )

    with pytest.raises(ValueError, match="confirmation"):
        run_setup_command(
            args,
            input_fn=lambda _: "no",
            secret_input_fn=lambda _: pytest.fail("secret was requested before confirmation"),
            provider_operations_factory=lambda *_args, **_kwargs: object(),
        )


def test_setup_plan_is_json_and_does_not_create_state(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    args = _parser().parse_args(
        [
            "setup",
            "--plan",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--owner",
            "user:owner",
            "--profile",
            "personal",
            "--policy-mode",
            "approval",
            "--executable",
            "/opt/signet/bin/signet",
        ]
    )
    output: list[str] = []

    assert run_setup_command(args, output=output.append, platform=FakePlatform()) == 0
    document = json.loads("\n".join(output))
    assert document["provider_rollout"] == "disabled"
    assert document["policy_mode"] == "approval"
    assert document["data_root"] == str(root / "data")
    assert document["backup_root"] == str(root / "backups")
    assert document["data_device"] is None
    assert document["steps"] == list(SETUP_STEPS)
    assert document["owner_setup_url"] == "https://signet.example/setup"
    assert document["automatic_steps"] == list(SETUP_STEPS[:-1])
    assert document["human_ceremonies"] == [
        "owner_authentication_enrollment",
        "hermes_mcp_review_and_reload",
    ]
    assert document["deferred_provider_proof"] == [
        "credential_configuration",
        "read_only_discovery",
        "live_send",
    ]
    assert document["next_commands"] == [
        f"signet setup --root {root} --origin https://signet.example --owner user:owner "
        "--profile personal --policy-mode approval --executable /opt/signet/bin/signet "
        f"--apply {document['plan_id']}"
    ]
    assert not root.exists()


def test_setup_apply_requires_the_exact_reviewed_plan_id(tmp_path: Path) -> None:
    args = _parser().parse_args(
        [
            "setup",
            "--root",
            str(tmp_path / "signet"),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
            "--executable",
            "/opt/signet/bin/signet",
            "--apply",
            "0" * 64,
        ]
    )

    with pytest.raises(SetupError, match="plan no longer matches"):
        run_setup_command(args, output=lambda _: None, platform=FakePlatform())

    args.apply = "é" * 64
    with pytest.raises(SetupError, match="plan ID must be"):
        run_setup_command(args, output=lambda _: None, platform=FakePlatform())


def test_setup_apply_rejects_an_unbound_missing_executable(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    executable = tmp_path / "missing-signet"
    parser = _parser()
    plan_args = parser.parse_args(
        [
            "setup",
            "--plan",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
            "--executable",
            str(executable),
        ]
    )
    output: list[str] = []
    assert run_setup_command(plan_args, output=output.append, platform=FakePlatform()) == 0
    plan_id = json.loads("\n".join(output))["plan_id"]
    apply_args = parser.parse_args(
        [
            "setup",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
            "--executable",
            str(executable),
            "--apply",
            plan_id,
        ]
    )

    with pytest.raises(SetupError, match="must exist before apply"):
        run_setup_command(apply_args, output=lambda _: None, platform=FakePlatform())

    assert not root.exists()


def test_setup_plan_records_external_storage_paths_and_device(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    data_root = tmp_path / "external-data"
    backup_root = tmp_path / "external-backups"
    data_root.mkdir(mode=0o700)
    backup_root.mkdir(mode=0o700)
    args = _parser().parse_args(
        [
            "setup",
            "--plan",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
            "--executable",
            "/opt/signet/bin/signet",
            "--data-root",
            str(data_root),
            "--backup-root",
            str(backup_root),
        ]
    )
    output: list[str] = []

    assert run_setup_command(args, output=output.append, platform=FakePlatform()) == 0
    document = json.loads("\n".join(output))
    assert document["data_root"] == str(data_root)
    assert document["backup_root"] == str(backup_root)
    assert document["data_device"] == data_root.stat().st_dev


def test_setup_plan_resolves_a_pipx_launcher_and_binds_reviewable_effects(
    tmp_path: Path,
) -> None:
    root = tmp_path / "signet"
    environment = tmp_path / "pipx" / "venvs" / "signet-gateway"
    executable = environment / "bin" / "signet"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    launcher = tmp_path / "pipx" / "bin" / "signet"
    launcher.parent.mkdir(parents=True)
    launcher.symlink_to(executable)
    args = _parser().parse_args(
        [
            "setup",
            "--plan",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
            "--executable",
            str(launcher),
        ]
    )
    output: list[str] = []

    assert run_setup_command(args, output=output.append, platform=FakePlatform()) == 0
    document = json.loads("\n".join(output))

    assert document["setup_spec_digest"] == document["plan_id"]
    assert document["executable"] == {
        "path": str(executable.resolve()),
        "device": executable.stat().st_dev,
        "inode": executable.stat().st_ino,
        "size": executable.stat().st_size,
        "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
    }
    assert document["storage_limits"] == {
        "attachments_hard_bytes": 8 * 1024**3,
        "backups_hard_bytes": 8 * 1024**3,
        "cache_hard_bytes": 1024**3,
        "database_hard_bytes": 1024**3,
        "logs_hard_bytes": 512 * 1024**2,
        "minimum_free_bytes": 1024**3 + 100 * 1024**2 + 25 * 1024**2,
        "staging_hard_bytes": 50 * 1024**2,
    }
    assert set(document["service_effects"]) == {"launchd", "systemd"}
    assert all(
        "WantedBy=default.target" in effect["content"]
        for effect in document["service_effects"]["systemd"].values()
    )
    assert document["configuration_files"] == [
        str(root / "production.json"),
        str(root / "policy.yaml"),
    ]
    assert document["rollback"] == {
        "command": shlex.join(("signet", "setup", "--rollback", "--root", str(root))),
        "preserves": ["verified_backups"],
    }


def test_setup_plan_derives_launcher_from_runtime_without_trusting_ambient_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_bin = tmp_path / "runtime" / "bin"
    runtime_bin.mkdir(parents=True)
    python = runtime_bin / "python"
    python.write_bytes(b"runtime python")
    python.chmod(0o700)
    executable = runtime_bin / "signet"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)

    hostile_bin = tmp_path / "hostile" / "bin"
    hostile_bin.mkdir(parents=True)
    hostile_executable = hostile_bin / "signet"
    hostile_executable.write_bytes(b"#!/bin/sh\nexit 99\n")
    hostile_executable.chmod(0o700)
    monkeypatch.setattr("signet.setup_cli.sys.executable", str(python))
    monkeypatch.setenv("PATH", str(hostile_bin))

    args = _parser().parse_args(
        [
            "setup",
            "--plan",
            "--root",
            str(tmp_path / "signet"),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
        ]
    )
    output: list[str] = []

    assert run_setup_command(args, output=output.append, platform=FakePlatform()) == 0

    document = json.loads(output[-1])
    assert document["executable"]["path"] == str(executable)
    assert document["executable"]["sha256"] == hashlib.sha256(executable.read_bytes()).hexdigest()


def test_setup_plan_quotes_a_rollback_root_with_spaces(tmp_path: Path) -> None:
    root = tmp_path / "root with spaces"
    args = _parser().parse_args(
        [
            "setup",
            "--plan",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
            "--executable",
            "/opt/signet/bin/signet",
        ]
    )
    output: list[str] = []

    assert run_setup_command(args, output=output.append, platform=FakePlatform()) == 0

    document = json.loads(output[-1])
    assert document["rollback"]["command"] == shlex.join(
        ("signet", "setup", "--rollback", "--root", str(root))
    )


def test_setup_resume_restores_selected_policy_mode(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    platform = FakePlatform()
    apply_args = _parser().parse_args(
        [
            "setup",
            "--yes",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
            "--policy-mode",
            "approval_with_edit",
            "--executable",
            str(_installed_test_executable(tmp_path)),
        ]
    )
    assert run_setup_command(apply_args, output=lambda _: None, platform=platform) == 0

    resume_args = _parser().parse_args(["setup", "--yes", "--no-open-browser", "--root", str(root)])

    assert run_setup_command(resume_args, output=lambda _: None, platform=platform) == 0


def test_setup_resume_merges_explicit_policy_with_persisted_spec(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    platform = FakePlatform()
    apply_args = _parser().parse_args(
        [
            "setup",
            "--yes",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
            "--policy-mode",
            "approval",
            "--executable",
            str(_installed_test_executable(tmp_path)),
        ]
    )
    assert run_setup_command(apply_args, output=lambda _: None, platform=platform) == 0

    resume_args = _parser().parse_args(
        [
            "setup",
            "--yes",
            "--no-open-browser",
            "--root",
            str(root),
            "--policy-mode",
            "approval",
        ]
    )

    assert run_setup_command(resume_args, output=lambda _: None, platform=platform) == 0


def test_setup_resume_treats_pre_policy_journal_as_deny(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    platform = FakePlatform()
    apply_args = _parser().parse_args(
        [
            "setup",
            "--yes",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
            "--executable",
            str(_installed_test_executable(tmp_path)),
        ]
    )
    assert run_setup_command(apply_args, output=lambda _: None, platform=platform) == 0

    journal_path = root / ".setup-journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["spec"].pop("policy_mode")
    digest_document = dict(journal["spec"])
    digest_document.pop("open_browser")
    legacy_digest = hashlib.sha256(
        json.dumps(
            digest_document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    journal["spec_digest"] = legacy_digest
    journal_path.write_text(json.dumps(journal), encoding="utf-8")
    owner_path = root / ".setup-owner.json"
    owner = json.loads(owner_path.read_text(encoding="utf-8"))
    owner["spec_digest"] = legacy_digest
    owner_path.write_text(json.dumps(owner), encoding="utf-8")

    resume_args = _parser().parse_args(["setup", "--yes", "--no-open-browser", "--root", str(root)])
    assert run_setup_command(resume_args, output=lambda _: None, platform=platform) == 0


def test_setup_resume_accepts_pre_storage_root_journal(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    platform = FakePlatform()
    apply_args = _parser().parse_args(
        [
            "setup",
            "--yes",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
            "--executable",
            str(_installed_test_executable(tmp_path)),
        ]
    )
    assert run_setup_command(apply_args, output=lambda _: None, platform=platform) == 0

    journal_path = root / ".setup-journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    for field in ("data_root", "backup_root", "data_device"):
        journal["spec"].pop(field)
    digest_document = dict(journal["spec"])
    digest_document.pop("open_browser")
    legacy_digest = hashlib.sha256(
        json.dumps(
            digest_document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    journal["spec_digest"] = legacy_digest
    journal_path.write_text(json.dumps(journal), encoding="utf-8")
    owner_path = root / ".setup-owner.json"
    owner = json.loads(owner_path.read_text(encoding="utf-8"))
    owner["spec_digest"] = legacy_digest
    owner_path.write_text(json.dumps(owner), encoding="utf-8")

    resume_args = _parser().parse_args(["setup", "--yes", "--no-open-browser", "--root", str(root)])
    assert run_setup_command(resume_args, output=lambda _: None, platform=platform) == 0


def test_setup_apply_is_resumable_and_prints_reload_instruction(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    platform = FakePlatform()
    args = _parser().parse_args(
        [
            "setup",
            "--yes",
            "--no-open-browser",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--owner",
            "user:owner",
            "--profile",
            "personal",
            "--executable",
            str(_installed_test_executable(tmp_path)),
        ]
    )
    output: list[str] = []

    assert run_setup_command(args, output=output.append, platform=platform) == 0
    assert platform.applied == list(SETUP_STEPS)
    assert any("/reload-mcp" in line for line in output)
    assert json.loads(output[-1])["setup_status"] == "completed"


def test_setup_rollback_routes_database_removal_through_verified_purge(
    tmp_path: Path,
) -> None:
    root = tmp_path / "signet"
    platform = FakePlatform()
    parser = _parser()
    apply_args = parser.parse_args(
        [
            "setup",
            "--yes",
            "--no-open-browser",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--owner",
            "user:owner",
            "--profile",
            "work",
            "--executable",
            str(_installed_test_executable(tmp_path)),
        ]
    )
    assert run_setup_command(apply_args, output=lambda _: None, platform=platform) == 0
    calls: list[bool] = []

    class Operations:
        def uninstall(self, *, purge: bool = False) -> dict[str, object]:
            calls.append(purge)
            return {
                "setup_status": "uninstalled",
                "purged": True,
                "backup": str(tmp_path / "verified.signet-backup"),
            }

    output: list[str] = []
    rollback_args = parser.parse_args(["setup", "--rollback", "--yes", "--root", str(root)])
    assert (
        run_setup_command(
            rollback_args,
            output=output.append,
            platform=platform,
            operations_factory=lambda root, platform: Operations(),
        )
        == 0
    )

    assert calls == [True]
    assert json.loads(output[-1])["purged"] is True


def test_lifecycle_commands_dispatch_to_operations_without_mutating_setup_state(
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, object]] = []

    class Plan:
        def __init__(self, plan_id: str) -> None:
            self.plan_id = plan_id

        def document(self) -> dict[str, str]:
            return {"plan_id": self.plan_id}

    class Operations:
        def status(self) -> dict[str, str]:
            calls.append(("status", None))
            return {"status": "completed"}

        def doctor(self) -> dict[str, bool]:
            calls.append(("doctor", None))
            return {"healthy": True}

        def verify(self) -> dict[str, bool]:
            calls.append(("verify", None))
            return {"verified": True}

        def plan_backup(self, destination: Path | None = None) -> Plan:
            calls.append(("plan_backup", destination))
            return Plan("backup-plan")

        def apply_backup(
            self,
            plan_id: str,
            destination: Path | None = None,
        ) -> dict[str, str]:
            calls.append(("apply_backup", (plan_id, destination)))
            return {"backup": str(tmp_path / "backup.signet-backup")}

        def plan_restore(self, bundle: Path) -> Plan:
            calls.append(("plan_restore", bundle))
            return Plan("restore-plan")

        def apply_restore(self, plan_id: str, bundle: Path) -> dict[str, object]:
            calls.append(("apply_restore", (plan_id, bundle)))
            return {"restored_to": str(tmp_path / "restore"), "activated": False}

        def plan_services(self, action: str) -> Plan:
            calls.append(("plan_services", action))
            return Plan("service-plan")

        def apply_service_plan(self, action: str, plan_id: str) -> dict[str, str]:
            calls.append(("apply_service_plan", (action, plan_id)))
            return {"action": action}

        def rollback_service_plan(self, plan_id: str) -> dict[str, str]:
            calls.append(("rollback_service_plan", plan_id))
            return {"action": "rollback"}

        def plan_upgrade(self) -> Plan:
            calls.append(("plan_upgrade", None))
            return Plan("upgrade-plan")

        def apply_upgrade(self, plan_id: str) -> dict[str, int]:
            calls.append(("apply_upgrade", plan_id))
            return {"schema_version": 1}

        def plan_uninstall(self, *, purge: bool = False) -> Plan:
            calls.append(("plan_uninstall", purge))
            return Plan("purge-plan" if purge else "uninstall-plan")

        def apply_uninstall(self, plan_id: str, *, purge: bool = False) -> dict[str, bool]:
            calls.append(("apply_uninstall", (plan_id, purge)))
            return {"purged": purge}

    def factory(root: Path, platform: Any) -> Operations:
        del root, platform
        return Operations()

    output: list[str] = []
    parser = _parser()
    commands = (
        ["status", "--root", str(tmp_path)],
        ["doctor", "--root", str(tmp_path)],
        ["verify", "--root", str(tmp_path)],
        ["backup", "--root", str(tmp_path)],
        ["restore", "--root", str(tmp_path), str(tmp_path / "bundle")],
        ["manage", "--root", str(tmp_path), "stop"],
        ["upgrade", "--root", str(tmp_path)],
        ["uninstall", "--root", str(tmp_path), "--purge"],
        ["backup", "--root", str(tmp_path), "--apply", "backup-plan"],
        [
            "restore",
            "--root",
            str(tmp_path),
            str(tmp_path / "bundle"),
            "--apply",
            "restore-plan",
        ],
        ["manage", "--root", str(tmp_path), "stop", "--apply", "service-plan"],
        ["manage", "--root", str(tmp_path), "stop", "--rollback", "service-plan"],
        ["upgrade", "--root", str(tmp_path), "--apply", "upgrade-plan"],
        ["uninstall", "--root", str(tmp_path), "--apply", "uninstall-plan"],
    )
    for command in commands:
        assert (
            run_setup_command(
                parser.parse_args(command),
                output=output.append,
                operations_factory=factory,
            )
            == 0
        )

    assert [name for name, _ in calls] == [
        "status",
        "doctor",
        "verify",
        "plan_backup",
        "plan_restore",
        "plan_services",
        "plan_upgrade",
        "plan_uninstall",
        "apply_backup",
        "apply_restore",
        "apply_service_plan",
        "rollback_service_plan",
        "apply_upgrade",
        "apply_uninstall",
    ]
    assert not (tmp_path / ".setup-journal.json").exists()


def test_setup_apply_requires_confirmation_without_yes(tmp_path: Path) -> None:
    args = _parser().parse_args(
        [
            "setup",
            "--root",
            str(tmp_path / "signet"),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
            "--executable",
            str(_installed_test_executable(tmp_path)),
        ]
    )

    with pytest.raises(ValueError, match="confirmation"):
        run_setup_command(
            args,
            output=lambda _: None,
            input_fn=lambda _: "no",
            platform=FakePlatform(),
        )


def test_setup_apply_prints_review_boundaries_before_confirmation(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    args = _parser().parse_args(
        [
            "setup",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
            "--executable",
            str(_installed_test_executable(tmp_path)),
        ]
    )
    events: list[tuple[str, str]] = []

    with pytest.raises(ValueError, match="confirmation"):
        run_setup_command(
            args,
            output=lambda value: events.append(("output", value)),
            input_fn=lambda prompt: events.append(("prompt", prompt)) or "no",
            platform=FakePlatform(),
        )

    plan = json.loads(events[0][1])
    assert "setup_id" not in plan
    assert plan["automatic_steps"] == list(SETUP_STEPS[:-1])
    assert plan["human_ceremonies"] == [
        "owner_authentication_enrollment",
        "hermes_mcp_review_and_reload",
    ]
    assert plan["deferred_provider_proof"] == [
        "credential_configuration",
        "read_only_discovery",
        "live_send",
    ]
    assert plan["destructive_actions"] == []
    assert events[1] == (
        "prompt",
        "Apply the reviewed automatic steps, then continue with the labelled human ceremonies? "
        "[y/N] ",
    )
    assert not root.exists()


def test_authenticator_management_prints_exact_url_before_browser_open(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    platform = FakePlatform()
    parser = _parser()
    setup_args = parser.parse_args(
        [
            "setup",
            "--yes",
            "--no-open-browser",
            "--root",
            str(root),
            "--origin",
            "https://signet.example",
            "--profile",
            "personal",
            "--executable",
            str(_installed_test_executable(tmp_path)),
        ]
    )
    assert run_setup_command(setup_args, output=lambda _: None, platform=platform) == 0

    events: list[tuple[str, str]] = []
    args = parser.parse_args(["authenticators", "open", "--root", str(root)])

    assert (
        run_setup_command(
            args,
            output=lambda value: events.append(("output", value)),
            platform=platform,
            browser_opener=lambda value: events.append(("open", value)) or True,
        )
        == 0
    )

    assert events[0] == (
        "output",
        "HUMAN CEREMONY — named passkey and TOTP management requires your authenticated browser.",
    )
    assert events[1] == (
        "output",
        "Authenticator management URL: https://signet.example/authenticators",
    )
    assert events[2] == ("open", "https://signet.example/authenticators")
    assert json.loads(events[3][1]) == {
        "authenticator_management_url": "https://signet.example/authenticators",
        "browser_opened": True,
        "credential_material_in_cli": False,
        "enrollment": ["named_passkey", "named_totp"],
    }


def test_setup_failure_uses_stable_exit_code_and_actionable_redacted_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class FailingPlatform(FakePlatform):
        def __init__(self, *, output: object) -> None:
            del output

        def apply(self, step: str, spec: object, setup_id: str) -> None:
            if step == "database":
                raise RuntimeError("private bearer material must not escape")
            super().apply(step, spec, setup_id)

    monkeypatch.setattr("signet.setup_cli.ProductionSetupPlatform", FailingPlatform)
    root = tmp_path / "signet"
    with pytest.raises(SystemExit) as failure:
        main(
            [
                "setup",
                "--yes",
                "--no-open-browser",
                "--root",
                str(root),
                "--origin",
                "https://signet.example",
                "--profile",
                "personal",
                "--executable",
                str(_installed_test_executable(tmp_path)),
            ]
        )

    captured = capsys.readouterr()
    assert failure.value.code == 2
    assert "Recovery:" in captured.err
    assert f"signet status --root {root}" in captured.err
    assert "rerun the same signet setup command to resume" in captured.err
    assert "private bearer material" not in captured.err


def test_recovery_messages_name_only_commands_that_apply_to_the_failed_operation(
    tmp_path: Path,
) -> None:
    parser = _parser()
    root = tmp_path / "signet"

    provider = setup_error_message(
        parser.parse_args(["provider", "status", "--root", str(root)]),
        SetupError("provider unavailable"),
    )
    assert "signet provider status" in provider
    assert "PLAN_ID" not in provider

    authenticators = setup_error_message(
        parser.parse_args(["authenticators", "open", "--root", str(root)]),
        SetupError("browser unavailable"),
    )
    assert "signet authenticators open --no-open-browser" in authenticators
    assert "PLAN_ID" not in authenticators

    lifecycle = setup_error_message(
        parser.parse_args(["backup", "--root", str(root)]),
        SetupError("backup unavailable"),
    )
    assert "PLAN_ID" in lifecycle


def test_parent_traversal_setup_root_is_a_stable_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exited:
        main(["status", "--root", "../signet"])

    assert exited.value.code == 2
    assert "paths must be absolute lexical paths without '..'" in capsys.readouterr().err


def test_doctor_returns_nonzero_when_any_check_is_unhealthy(tmp_path: Path) -> None:
    class UnhealthyOperations:
        def doctor(self) -> dict[str, object]:
            return {
                "healthy": False,
                "checks": {
                    "services": {
                        "ok": False,
                        "remediation": "Apply the reviewed restart plan.",
                    }
                },
            }

    args = _parser().parse_args(["doctor", "--root", str(tmp_path)])
    output: list[str] = []

    assert (
        run_setup_command(
            args,
            output=output.append,
            operations_factory=lambda *_args, **_kwargs: UnhealthyOperations(),
        )
        == 1
    )
    assert json.loads(output[-1])["healthy"] is False


def test_installed_cli_reports_distribution_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exited:
        main(["--version"])

    assert exited.value.code == 0
    assert capsys.readouterr().out == "signet 0.1.0b1\n"


def test_internal_production_service_uses_installed_factory_and_restores_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "owned"
    root.mkdir(mode=0o700)
    policy = root / "policy.yaml"
    policy.write_text("version: 1\ndefault_mode: deny\ndownstreams: {}\n", encoding="utf-8")
    policy.chmod(0o600)
    selected = SetupSpec(
        root=root,
        public_origin="https://signet.example",
        owner_user_id="user:owner",
        hermes_profiles=("work",),
        executable=Path("/opt/signet/bin/signet"),
    )
    config = root / "production.json"
    config.write_text(
        json.dumps(render_production_config(selected, setup_id="setup_0123456789abcdef")),
        encoding="utf-8",
    )
    config.chmod(0o600)
    captured: dict[str, Any] = {}
    service_app = object()

    def build_service(config_path: Path, *, component: str) -> tuple[Any, object]:
        assert component == "web"
        selected = production_module.load_production_config(config_path)
        replacement_payload = json.loads(config_path.read_text(encoding="utf-8"))
        replacement_payload["web_host"] = "127.0.0.9"
        replacement_payload["web_port"] = 9999
        replacement = config_path.with_name("production-replaced.json")
        replacement.write_text(json.dumps(replacement_payload), encoding="utf-8")
        replacement.chmod(0o600)
        replacement.replace(config_path)
        return selected, service_app

    monkeypatch.setattr(
        production_module,
        "create_owned_production_service",
        build_service,
        raising=False,
    )

    def runner(app: object, **kwargs: Any) -> None:
        captured.update(
            app=app,
            config=os.environ.get("SIGNET_PRODUCTION_CONFIG"),
            **kwargs,
        )

    monkeypatch.delenv("SIGNET_PRODUCTION_CONFIG", raising=False)
    args = _parser().parse_args(["production", "serve-web", "--config", str(config)])

    assert run_setup_command(args, runner=runner) == 0
    assert captured["app"] is service_app
    assert captured["factory"] is False
    assert captured["config"] is None
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8790
    assert "SIGNET_PRODUCTION_CONFIG" not in os.environ


def test_completed_setup_rollback_creates_backup_first(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    platform = FakePlatform()
    apply_args = _parser().parse_args(
        [
            "setup",
            "--root",
            str(root),
            "--origin",
            "https://private.example.test",
            "--owner",
            "user:owner",
            "--profile",
            "personal",
            "--executable",
            str(_installed_test_executable(tmp_path)),
            "--yes",
        ]
    )
    assert run_setup_command(apply_args, platform=platform, output=lambda _: None) == 0

    events: list[str] = []

    class FakeOperations:
        def uninstall(self, *, purge: bool = False) -> dict[str, object]:
            assert purge is True
            events.extend(["backup", "rollback"])
            return {
                "setup_status": "rolled_back",
                "purged": True,
                "backup": str(root / "backups" / "before-rollback.signet-backup"),
            }

    output: list[str] = []
    rollback_args = _parser().parse_args(["setup", "--root", str(root), "--rollback", "--yes"])
    assert (
        run_setup_command(
            rollback_args,
            platform=FakePlatform(),
            operations_factory=lambda *_args, **_kwargs: FakeOperations(),
            output=output.append,
        )
        == 0
    )
    document = json.loads(output[-1])
    assert document["setup_status"] == "rolled_back"
    assert document["backup"].endswith("before-rollback.signet-backup")
    assert events == ["backup", "rollback"]
