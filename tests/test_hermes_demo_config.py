from __future__ import annotations

import os
import stat
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy" / "hermes" / "configure-demo-profile.py"
EXAMPLE = ROOT / "deploy" / "hermes" / "demo-profile.mcp.yaml.example"
FAKE_TOKEN = (  # nosec B105
    "fake:sgt_abcdefghijklmnop.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
)


def private_write(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def profile_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    profile = tmp_path / "signet-demo"
    profile.mkdir(mode=0o700)
    config = profile / "config.yaml"
    env_file = profile / ".env"
    fragment = profile / "signet-demo.mcp.yaml"
    private_write(config, "model: fake-model\nmcp_servers: {}\n")
    private_write(env_file, "# Blank disposable profile.\n")
    private_write(fragment, EXAMPLE.read_text(encoding="utf-8"))
    return config, env_file, fragment


def invoke(
    config: Path,
    env_file: Path,
    fragment: Path,
    *,
    token: str = FAKE_TOKEN,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603
        [
            sys.executable,
            str(HELPER),
            "--config",
            str(config),
            "--env-file",
            str(env_file),
            "--fragment",
            str(fragment),
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


def test_helper_structurally_merges_blank_profile_without_disclosing_token(
    tmp_path: Path,
) -> None:
    config, env_file, fragment = profile_files(tmp_path)

    result = invoke(config, env_file, fragment)

    assert result.returncode == 0, result.stderr
    assert FAKE_TOKEN not in result.stdout
    assert FAKE_TOKEN not in result.stderr
    assert "3 fake-only Signet MCP routes" in result.stdout
    merged = load(config)
    assert merged["model"] == "fake-model"
    assert merged["mcp_servers"] == load(fragment)["mcp_servers"]
    assert env_file.read_text(encoding="utf-8").endswith(
        f"SIGNET_DEMO_MCP_CALLER_TOKEN={FAKE_TOKEN}\n"
    )
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert not list(config.parent.glob(".*.signet-demo-*"))


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"url": "http://localhost:8789/mcp/fastmail"}, "non-loopback MCP URL"),
        ({"sampling": {"enabled": True}}, "weakens the required MCP controls"),
        (
            {"headers": {"Authorization": "Bearer fake:raw-token"}},
            "weakens the required MCP controls",
        ),
        ({"supports_parallel_tool_calls": True}, "weakens the required MCP controls"),
    ],
)
def test_helper_rejects_weakened_fragment_without_changing_profile(
    tmp_path: Path,
    mutation: dict[str, Any],
    message: str,
) -> None:
    config, env_file, fragment = profile_files(tmp_path)
    document = load(fragment)
    document["mcp_servers"]["signet_demo_fastmail"].update(mutation)
    private_write(fragment, yaml.safe_dump(document, sort_keys=False))
    before_config = config.read_bytes()
    before_env = env_file.read_bytes()

    result = invoke(config, env_file, fragment)

    assert result.returncode == 1
    assert message in result.stderr
    assert FAKE_TOKEN not in result.stderr
    assert config.read_bytes() == before_config
    assert env_file.read_bytes() == before_env


@pytest.mark.parametrize(
    "token",
    ["", "live-token", "sgt_production-shaped.token", "fake:has whitespace", "0" * 6],
)
def test_helper_rejects_nonfake_or_ambiguous_token_without_writing(
    tmp_path: Path,
    token: str,
) -> None:
    config, env_file, fragment = profile_files(tmp_path)
    before_config = config.read_bytes()
    before_env = env_file.read_bytes()

    result = invoke(config, env_file, fragment, token=token)

    assert result.returncode == 1
    if token:
        assert token not in result.stderr
    assert config.read_bytes() == before_config
    assert env_file.read_bytes() == before_env


def test_helper_refuses_nonblank_or_preconfigured_profile(tmp_path: Path) -> None:
    config, env_file, fragment = profile_files(tmp_path)
    private_write(config, "mcp_servers:\n  existing: {url: https://example.invalid/mcp}\n")
    configured = invoke(config, env_file, fragment)
    assert configured.returncode == 1
    assert "already contains MCP servers" in configured.stderr

    private_write(config, "mcp_servers: {}\n")
    private_write(env_file, "MODEL_API_KEY=not-read-or-disclosed\n")
    credentialed = invoke(config, env_file, fragment)
    assert credentialed.returncode == 1
    assert "environment is not blank" in credentialed.stderr
    assert "not-read-or-disclosed" not in credentialed.stderr


def test_helper_refuses_unsafe_mode_symlink_and_duplicate_yaml(tmp_path: Path) -> None:
    config, env_file, fragment = profile_files(tmp_path)
    fragment.chmod(0o644)
    unsafe = invoke(config, env_file, fragment)
    assert unsafe.returncode == 1
    assert "mode 0600" in unsafe.stderr

    fragment.unlink()
    fragment.symlink_to(EXAMPLE)
    linked = invoke(config, env_file, fragment)
    assert linked.returncode == 1
    assert "must not be a symlink" in linked.stderr

    fragment.unlink()
    private_write(fragment, "mcp_servers: {}\nmcp_servers: {}\n")
    duplicate = invoke(config, env_file, fragment)
    assert duplicate.returncode == 1
    assert "valid unique-key YAML" in duplicate.stderr


def test_helper_refuses_multiply_linked_profile_file(tmp_path: Path) -> None:
    config, env_file, fragment = profile_files(tmp_path)
    hardlink = tmp_path / "profile-config-hardlink"
    os.link(config, hardlink)

    result = invoke(config, env_file, fragment)

    assert result.returncode == 1
    assert "exactly one filesystem link" in result.stderr


def test_helper_refuses_profile_directory_with_untrusted_identity_or_mode(
    tmp_path: Path,
) -> None:
    config, env_file, fragment = profile_files(tmp_path)
    wrong = tmp_path / "not-signet-demo"
    config.parent.rename(wrong)
    mismatched = invoke(wrong / config.name, wrong / env_file.name, wrong / fragment.name)
    assert mismatched.returncode == 1
    assert "disposable signet-demo profile" in mismatched.stderr

    wrong.rename(config.parent)
    os.chmod(config.parent, 0o722)  # nosec B103
    writable = invoke(config, env_file, fragment)
    assert writable.returncode == 1
    assert "must not be group/world writable" in writable.stderr
