from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from signet.app import _parser
from signet.setup_cli import _discover_hermes_profiles, run_setup_command
from signet.setup_platform import render_production_config
from signet.setup_state import SETUP_STEPS, SetupSpec


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


def test_profile_discovery_includes_the_hermes_default_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    (home / ".hermes" / "profiles" / "work").mkdir(parents=True)
    (home / ".hermes" / "config.yaml").write_text("model: test/model\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))

    assert _discover_hermes_profiles() == ["default", "work"]


@pytest.mark.parametrize(
    "command",
    ["setup", "manage", "status", "doctor", "backup", "restore", "upgrade", "uninstall"],
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
    assert not root.exists()


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
            "/opt/signet/bin/signet",
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
            "/opt/signet/bin/signet",
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
            "/opt/signet/bin/signet",
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
            "/opt/signet/bin/signet",
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
            "/opt/signet/bin/signet",
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

    class Operations:
        def status(self) -> dict[str, str]:
            calls.append(("status", None))
            return {"status": "completed"}

        def doctor(self) -> dict[str, bool]:
            calls.append(("doctor", None))
            return {"healthy": True}

        def backup(self, destination: Path | None = None) -> Path:
            calls.append(("backup", destination))
            return tmp_path / "backup.signet-backup"

        def restore(self, bundle: Path) -> object:
            calls.append(("restore", bundle))
            return type(
                "Restored",
                (),
                {
                    "root": tmp_path / "restore",
                    "database_path": tmp_path / "restore" / "signet.sqlite3",
                },
            )()

        def upgrade(self) -> dict[str, int]:
            calls.append(("upgrade", None))
            return {"schema_version": 1}

        def uninstall(self, *, purge: bool = False) -> dict[str, bool]:
            calls.append(("uninstall", purge))
            return {"purged": purge}

    def factory(root: Path, platform: Any) -> Operations:
        del root, platform
        return Operations()

    output: list[str] = []
    parser = _parser()
    commands = (
        ["status", "--root", str(tmp_path)],
        ["doctor", "--root", str(tmp_path)],
        ["backup", "--root", str(tmp_path)],
        ["restore", "--root", str(tmp_path), str(tmp_path / "bundle")],
        ["upgrade", "--root", str(tmp_path), "--yes"],
        ["uninstall", "--root", str(tmp_path), "--yes"],
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
        "backup",
        "restore",
        "upgrade",
        "uninstall",
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
            "/opt/signet/bin/signet",
        ]
    )

    with pytest.raises(ValueError, match="confirmation"):
        run_setup_command(
            args,
            output=lambda _: None,
            input_fn=lambda _: "no",
            platform=FakePlatform(),
        )


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

    def runner(app: str, **kwargs: Any) -> None:
        captured.update(app=app, config=os.environ["SIGNET_PRODUCTION_CONFIG"], **kwargs)

    monkeypatch.delenv("SIGNET_PRODUCTION_CONFIG", raising=False)
    args = _parser().parse_args(["production", "serve-web", "--config", str(config)])

    assert run_setup_command(args, runner=runner) == 0
    assert captured["app"] == "signet.production:create_production_web_app_from_environment"
    assert captured["factory"] is True
    assert captured["config"] == str(config)
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
            "/opt/signet/bin/signet",
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
