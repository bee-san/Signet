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
    with pytest.raises(render_error, match="publication durability is unknown"):
        write_outputs(output, {"one.plist": b"one", "two.plist": b"two"})

    assert not list(output.iterdir())


def test_renderer_cleans_identity_bound_output_after_fchmod_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = runpy.run_path(str(RENDERER))
    write_outputs = namespace["_write_outputs"]
    render_error = namespace["RenderError"]
    output = tmp_path / "output"
    output.mkdir(mode=0o700)

    def fail_fchmod(descriptor: int, mode: int) -> None:
        del descriptor, mode
        raise OSError("injected fchmod failure with a path")

    monkeypatch.setattr(os, "fchmod", fail_fchmod)
    with pytest.raises(render_error, match="could not be created safely") as captured:
        write_outputs(output, {"one.plist": b"one"})

    assert "injected" not in str(captured.value)
    assert str(tmp_path) not in str(captured.value)
    assert not list(output.iterdir())


@pytest.mark.parametrize(
    ("regular_fstat", "cleanup_confirmed"),
    ((1, False), (2, True)),
    ids=("before-identity", "after-identity"),
)
def test_renderer_contains_created_output_fstat_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    regular_fstat: int,
    cleanup_confirmed: bool,
) -> None:
    namespace = runpy.run_path(str(RENDERER))
    write_outputs = namespace["_write_outputs"]
    render_error = namespace["RenderError"]
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    real_fstat = os.fstat
    regular_calls = 0

    def fail_selected_fstat(descriptor: int) -> os.stat_result:
        nonlocal regular_calls
        metadata = real_fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode):
            regular_calls += 1
            if regular_calls == regular_fstat:
                raise OSError("injected fstat failure")
        return metadata

    monkeypatch.setattr(os, "fstat", fail_selected_fstat)
    with pytest.raises(render_error) as captured:
        write_outputs(output, {"one.plist": b"one"})

    assert "Traceback" not in str(captured.value)
    assert "injected" not in str(captured.value)
    remaining = list(output.iterdir())
    if cleanup_confirmed:
        assert "could not be created safely" in str(captured.value)
        assert remaining == []
    else:
        assert "cleanup could not be confirmed" in str(captured.value)
        assert len(remaining) == 1
        assert remaining[0].read_bytes() == b""


def test_renderer_reports_checked_unlink_failure_and_preserves_for_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = runpy.run_path(str(RENDERER))
    write_outputs = namespace["_write_outputs"]
    render_error = namespace["RenderError"]
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    real_fsync = os.fsync
    fsync_calls = 0

    def fail_file_fsync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 1:
            raise OSError("injected file fsync failure")
        real_fsync(descriptor)

    def fail_unlink(path: str | bytes, *args: object, **kwargs: object) -> None:
        del path, args, kwargs
        raise OSError("injected unlink failure")

    monkeypatch.setattr(os, "fsync", fail_file_fsync)
    monkeypatch.setattr(os, "unlink", fail_unlink)
    with pytest.raises(render_error, match="cleanup could not be confirmed") as captured:
        write_outputs(output, {"one.plist": b"one"})

    assert "injected" not in str(captured.value)
    assert [path.read_bytes() for path in output.iterdir()] == [b"one"]


@pytest.mark.parametrize(
    ("failed_close", "message", "outputs_remain"),
    (
        (1, "output cleanup could not be confirmed", False),
        (3, "published and synced", True),
    ),
    ids=("file-close", "directory-close"),
)
def test_renderer_contains_close_failures_with_inspect_before_retry_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_close: int,
    message: str,
    outputs_remain: bool,
) -> None:
    namespace = runpy.run_path(str(RENDERER))
    write_outputs = namespace["_write_outputs"]
    render_error = namespace["RenderError"]
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    real_close = os.close
    close_calls = 0

    def fail_selected_close(descriptor: int) -> None:
        nonlocal close_calls
        close_calls += 1
        if close_calls == failed_close:
            real_close(descriptor)
            raise OSError("injected close failure")
        real_close(descriptor)

    monkeypatch.setattr(os, "close", fail_selected_close)
    with pytest.raises(render_error) as captured:
        write_outputs(output, {"one.plist": b"one", "two.plist": b"two"})

    assert message in str(captured.value)
    assert "injected" not in str(captured.value)
    assert bool(list(output.iterdir())) is outputs_remain
