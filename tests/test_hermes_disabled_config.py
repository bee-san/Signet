from __future__ import annotations

import os
import runpy
import stat
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy" / "hermes" / "configure-disabled-profile.py"
EXAMPLE = ROOT / "deploy" / "hermes" / "disabled-profile.mcp.yaml.example"
RAW_TOKEN = "sgt_abcdefghijklmnop.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"  # nosec B105
SEEDED_ENV = (
    "# Per-profile secrets for this Hermes profile.\n"
    "# API keys and tokens set here override the shell environment.\n"
    "# Behavioral settings belong in config.yaml, not here.\n"
)


def private_write(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def profile_files(
    tmp_path: Path,
    *,
    profile_name: str = "signet-disabled",
    env_content: str = SEEDED_ENV,
) -> tuple[Path, Path, Path]:
    profile = tmp_path / profile_name
    profile.mkdir(mode=0o700)
    config = profile / "config.yaml"
    env_file = profile / ".env"
    fragment = profile / "signet-disabled.mcp.yaml"
    private_write(config, "")
    private_write(env_file, env_content)
    private_write(fragment, EXAMPLE.read_text(encoding="utf-8"))
    return config, env_file, fragment


def invoke(
    config: Path,
    env_file: Path,
    fragment: Path,
    *,
    profile_name: str = "signet-disabled",
    token: str = RAW_TOKEN,
    extra: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603
        [
            sys.executable,
            str(HELPER),
            "--profile",
            profile_name,
            "--config",
            str(config),
            "--env-file",
            str(env_file),
            "--fragment",
            str(fragment),
            *extra,
        ],
        input=f"{token}\n",
        text=True,
        capture_output=True,
        check=False,
    )


def load(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def assert_secret_free(result: subprocess.CompletedProcess[str], token: str = RAW_TOKEN) -> None:
    if token:
        assert token not in result.stdout
        assert token not in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "env_content",
    ["", SEEDED_ENV],
    ids=["hermes-016-empty", "hermes-018-seeded"],
)
def test_helper_configures_supported_profile_without_disclosing_token(
    tmp_path: Path,
    env_content: str,
) -> None:
    config, env_file, fragment = profile_files(tmp_path, env_content=env_content)

    result = invoke(config, env_file, fragment)

    assert result.returncode == 0, result.stderr
    assert_secret_free(result)
    assert result.stdout == (
        "Configured one downstream-disabled Signet MCP route in the dedicated profile.\n"
    )
    assert load(config)["mcp_servers"] == load(fragment)["mcp_servers"]
    assert RAW_TOKEN not in config.read_text(encoding="utf-8")
    assert "${SIGNET_DISABLED_MCP_CALLER_TOKEN}" in config.read_text(encoding="utf-8")
    assert env_file.read_text(encoding="utf-8") == (
        env_content + f"SIGNET_DISABLED_MCP_CALLER_TOKEN={RAW_TOKEN}\n"
    )
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert not list(config.parent.glob(".*.signet-demo-*"))

    repeated = invoke(config, env_file, fragment)
    assert repeated.returncode == 0, repeated.stderr
    assert_secret_free(repeated)
    assert env_file.read_text(encoding="utf-8").count("SIGNET_DISABLED_MCP_CALLER_TOKEN=") == 1


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"url": "http://localhost:8789/mcp/approvals"}, "unexpected MCP URL"),
        ({"url": "http://127.0.0.1:8799/mcp/approvals"}, "unexpected MCP URL"),
        ({"url": "http://127.0.0.1:08789/mcp/approvals"}, "unexpected MCP URL"),
        ({"url": "http://127.0.0.1:8789/mcp/approvals?"}, "unexpected MCP URL"),
        ({"sampling": {"enabled": True}}, "weakens the required MCP controls"),
        (
            {"headers": {"Authorization": "Bearer raw-token"}},
            "weakens the required MCP controls",
        ),
        ({"supports_parallel_tool_calls": True}, "weakens the required MCP controls"),
        ({"unknown": False}, "weakens the required MCP controls"),
    ],
)
def test_helper_rejects_weakened_fragment_without_changing_profile(
    tmp_path: Path,
    mutation: dict[str, Any],
    message: str,
) -> None:
    config, env_file, fragment = profile_files(tmp_path)
    document = load(fragment)
    document["mcp_servers"]["signet_disabled_approvals"].update(mutation)
    private_write(fragment, yaml.safe_dump(document, sort_keys=False))
    before_config = config.read_bytes()
    before_env = env_file.read_bytes()

    result = invoke(config, env_file, fragment)

    assert result.returncode == 1
    assert message in result.stderr
    assert_secret_free(result)
    assert config.read_bytes() == before_config
    assert env_file.read_bytes() == before_env


def test_helper_rejects_extra_server_and_duplicate_yaml(tmp_path: Path) -> None:
    config, env_file, fragment = profile_files(tmp_path)
    document = load(fragment)
    document["mcp_servers"]["fastmail"] = {"url": "http://127.0.0.1:8789/mcp/fastmail"}
    private_write(fragment, yaml.safe_dump(document, sort_keys=False))
    extra = invoke(config, env_file, fragment)
    assert extra.returncode == 1
    assert "unexpected server set" in extra.stderr
    assert_secret_free(extra)

    private_write(fragment, "mcp_servers: {}\nmcp_servers: {}\n")
    duplicate = invoke(config, env_file, fragment)
    assert duplicate.returncode == 1
    assert "not valid unique-key YAML" in duplicate.stderr
    assert_secret_free(duplicate)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "fake:" + RAW_TOKEN,
        "Bearer " + RAW_TOKEN,
        "sgt_short.invalid",
        RAW_TOKEN + "x",
        RAW_TOKEN + "\r",
        RAW_TOKEN + "\nsecond-line",
        "\N{SNOWMAN}",
        "\x00",
    ],
)
def test_helper_rejects_nonexact_token_without_writing(
    tmp_path: Path,
    token: str,
) -> None:
    config, env_file, fragment = profile_files(tmp_path)
    before_config = config.read_bytes()
    before_env = env_file.read_bytes()

    result = invoke(config, env_file, fragment, token=token)

    assert result.returncode == 1
    assert_secret_free(result, token=token)
    assert config.read_bytes() == before_config
    assert env_file.read_bytes() == before_env


@pytest.mark.parametrize(
    "env_content",
    [
        "MODEL_API_KEY=not-read-or-disclosed\n",
        "SIGNET_DISABLED_MCP_CALLER_TOKEN=wrong\n",
        f"export SIGNET_DISABLED_MCP_CALLER_TOKEN={RAW_TOKEN}\n",
        f" SIGNET_DISABLED_MCP_CALLER_TOKEN = {RAW_TOKEN}\n",
        (
            f"SIGNET_DISABLED_MCP_CALLER_TOKEN={RAW_TOKEN}\n"
            f"SIGNET_DISABLED_MCP_CALLER_TOKEN={RAW_TOKEN}\n"
        ),
    ],
)
def test_helper_rejects_nonblank_or_ambiguous_environment_without_disclosure(
    tmp_path: Path,
    env_content: str,
) -> None:
    config, env_file, fragment = profile_files(tmp_path, env_content=env_content)
    before_config = config.read_bytes()
    before_env = env_file.read_bytes()

    result = invoke(config, env_file, fragment)

    assert result.returncode == 1
    assert_secret_free(result)
    assert "not-read-or-disclosed" not in result.stderr
    assert config.read_bytes() == before_config
    assert env_file.read_bytes() == before_env


def test_helper_refuses_existing_routes_wrong_profile_and_unsafe_files(tmp_path: Path) -> None:
    config, env_file, fragment = profile_files(tmp_path)
    private_write(config, "mcp_servers:\n  existing: {url: https://example.invalid/mcp}\n")
    configured = invoke(config, env_file, fragment)
    assert configured.returncode == 1
    assert "already contains MCP servers" in configured.stderr
    assert_secret_free(configured)

    private_write(config, "model: existing-model\n")
    nonblank = invoke(config, env_file, fragment)
    assert nonblank.returncode == 1
    assert "profile config is not blank" in nonblank.stderr
    assert_secret_free(nonblank)

    private_write(config, "")
    wrong_profile = invoke(config, env_file, fragment, profile_name="another-profile")
    assert wrong_profile.returncode == 1
    assert "selected Hermes profile" in wrong_profile.stderr
    assert_secret_free(wrong_profile)

    fragment.chmod(0o644)
    unsafe = invoke(config, env_file, fragment)
    assert unsafe.returncode == 1
    assert "mode 0600" in unsafe.stderr
    assert_secret_free(unsafe)

    fragment.chmod(0o400)
    readonly = invoke(config, env_file, fragment)
    assert readonly.returncode == 1
    assert "mode 0600" in readonly.stderr
    assert_secret_free(readonly)


def test_helper_refuses_symlink_hardlink_and_noncanonical_paths(tmp_path: Path) -> None:
    config, env_file, fragment = profile_files(tmp_path)
    fragment.unlink()
    fragment.symlink_to(EXAMPLE)
    linked = invoke(config, env_file, fragment)
    assert linked.returncode == 1
    assert "canonical and contain no symlinks" in linked.stderr
    assert_secret_free(linked)

    fragment.unlink()
    private_write(fragment, EXAMPLE.read_text(encoding="utf-8"))
    hardlink = tmp_path / "profile-config-hardlink"
    os.link(config, hardlink)
    multiplied = invoke(config, env_file, fragment)
    assert multiplied.returncode == 1
    assert "exactly one filesystem link" in multiplied.stderr
    assert_secret_free(multiplied)

    relative = subprocess.run(  # nosec B603
        [
            sys.executable,
            str(HELPER),
            "--profile",
            "signet-disabled",
            "--config",
            "config.yaml",
            "--env-file",
            str(env_file),
            "--fragment",
            str(fragment),
        ],
        input=f"{RAW_TOKEN}\n",
        text=True,
        capture_output=True,
        check=False,
    )
    assert relative.returncode == 1
    assert "path must be absolute" in relative.stderr
    assert_secret_free(relative)


def test_helper_compare_before_replace_refuses_concurrent_profile_change(
    tmp_path: Path,
) -> None:
    config, env_file, _ = profile_files(tmp_path)
    namespace = runpy.run_path(str(HELPER))
    read_private_file = namespace["_read_private_file"]
    commit_profile_files = namespace["_commit_profile_files"]
    configuration_error = namespace["ConfigurationError"]
    config_snapshot = read_private_file(
        config,
        label="profile config",
        maximum=namespace["MAX_CONFIG_BYTES"],
    )
    env_snapshot = read_private_file(
        env_file,
        label="profile environment",
        maximum=namespace["MAX_ENV_BYTES"],
    )
    private_write(config, "model: concurrent-update\n")

    with pytest.raises(configuration_error, match="changed during configuration"):
        commit_profile_files(
            config_file=config_snapshot,
            config_content=b"mcp_servers: {}\n",
            env_file=env_snapshot,
            env_content=env_snapshot.value,
        )

    assert load(config)["model"] == "concurrent-update"


def test_helper_refuses_interactive_token_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    namespace = runpy.run_path(str(HELPER))
    read_token = namespace["_read_token"]
    configuration_error = namespace["ConfigurationError"]

    class InteractiveInput:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(sys, "stdin", InteractiveInput())
    with pytest.raises(configuration_error, match="must be piped on stdin"):
        read_token()
