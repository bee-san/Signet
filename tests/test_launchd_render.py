from __future__ import annotations

import os
import plistlib
import runpy
import stat
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "deploy" / "launchd" / "render-disabled-plists.py"


def deployment_paths(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    checkout = tmp_path / "checkout"
    checkout.mkdir(mode=0o755)
    executable = checkout / "signet"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    executable.chmod(0o700)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    config = private / "disabled.json"
    config.write_text("{}\n", encoding="ascii")
    config.chmod(0o600)
    logs = private / "logs"
    logs.mkdir(mode=0o700)
    output = private / "rendered"
    output.mkdir(mode=0o700)
    return executable, config, checkout, logs, output


def invoke(
    executable: Path,
    config: Path,
    checkout: Path,
    logs: Path,
    output: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603
        [
            sys.executable,
            str(RENDERER),
            "--signet-executable",
            str(executable),
            "--config",
            str(config),
            "--working-directory",
            str(checkout),
            "--logs-directory",
            str(logs),
            "--output-directory",
            str(output),
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def test_renderer_creates_exact_private_inert_plists(tmp_path: Path) -> None:
    executable, config, checkout, logs, output = deployment_paths(tmp_path)

    result = invoke(executable, config, checkout, logs, output)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "Rendered two inactive mode-0600 launchd plists for review.\n"
    assert result.stderr == ""
    expected = {
        "mcp": ("ai.hermes.signet.mcp.plist", "serve-mcp"),
        "web": ("ai.hermes.signet.web.plist", "serve-web"),
    }
    for service, (name, command) in expected.items():
        path = output / name
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        document = plistlib.loads(path.read_bytes())
        assert document["Label"] == f"ai.hermes.signet.{service}"
        assert document["ProgramArguments"] == [
            str(executable),
            "deployment",
            command,
            "--config",
            str(config),
        ]
        assert document["WorkingDirectory"] == str(checkout)
        assert document["StandardOutPath"] == str(logs / f"{service}.log")
        assert document["StandardErrorPath"] == str(logs / f"{service}-error.log")
        assert document["RunAtLoad"] is True
        assert document["KeepAlive"] is True
        assert b"/ABSOLUTE/PATH/" not in path.read_bytes()


def test_renderer_refuses_overwrite_and_preserves_first_render(tmp_path: Path) -> None:
    paths = deployment_paths(tmp_path)
    first = invoke(*paths)
    assert first.returncode == 0, first.stderr
    output = paths[-1]
    before = {path.name: path.read_bytes() for path in output.iterdir()}

    second = invoke(*paths)

    assert second.returncode == 1
    assert "output already exists" in second.stderr
    assert "Traceback" not in second.stderr
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before


@pytest.mark.parametrize(
    ("selected", "mode", "message"),
    [
        ("config", 0o644, "exact mode 0600"),
        ("logs", 0o755, "exact mode 0700"),
        ("output", 0o755, "exact mode 0700"),
        ("checkout", 0o777, "must not be group/world writable"),
        ("executable", 0o600, "must be executable"),
    ],
)
def test_renderer_rejects_unsafe_modes(
    tmp_path: Path,
    selected: str,
    mode: int,
    message: str,
) -> None:
    executable, config, checkout, logs, output = deployment_paths(tmp_path)
    paths = {
        "executable": executable,
        "config": config,
        "checkout": checkout,
        "logs": logs,
        "output": output,
    }
    paths[selected].chmod(mode)

    result = invoke(executable, config, checkout, logs, output)

    assert result.returncode == 1
    assert message in result.stderr
    assert "Traceback" not in result.stderr
    assert not list(output.glob("*.plist"))


def test_renderer_rejects_symlink_and_hardlinked_input(tmp_path: Path) -> None:
    executable, config, checkout, logs, output = deployment_paths(tmp_path)
    linked_config = tmp_path / "linked-config"
    linked_config.symlink_to(config)
    symlinked = invoke(executable, linked_config, checkout, logs, output)
    assert symlinked.returncode == 1
    assert "canonical and contain no symlinks" in symlinked.stderr
    assert not list(output.glob("*.plist"))

    hardlink = tmp_path / "hardlink"
    os.link(config, hardlink)
    multiplied = invoke(executable, config, checkout, logs, output)
    assert multiplied.returncode == 1
    assert "single-link regular file" in multiplied.stderr
    assert not list(output.glob("*.plist"))


def test_template_validator_rejects_any_shape_drift() -> None:
    namespace = runpy.run_path(str(RENDERER))
    validate = namespace["_validate_template"]
    render_error = namespace["RenderError"]
    template = plistlib.loads(
        (ROOT / "deploy" / "launchd" / "ai.hermes.signet.mcp.plist.example").read_bytes()
    )
    template["EnvironmentVariables"]["SECRET"] = "unexpected"

    with pytest.raises(render_error, match="reviewed disabled shape"):
        validate(template, service="mcp")


def test_renderer_cleans_outputs_when_directory_fsync_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = runpy.run_path(str(RENDERER))
    write_outputs = namespace["_write_outputs"]
    render_error = namespace["RenderError"]
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    calls = 0
    real_fsync = os.fsync

    def fail_directory_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError("injected directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    with pytest.raises(render_error, match="could not be created safely"):
        write_outputs(output, {"one.plist": b"one", "two.plist": b"two"})

    assert not list(output.iterdir())
