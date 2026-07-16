from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from signet.reviewed_process import (
    _TEST_ONLY_SCRIPT_CAPABILITY,
    ReviewedProcessError,
    VerifiedPrivateDirectory,
    descriptor_path,
    open_verified_executable,
)


def _write_script(path: Path, marker: str) -> str:
    path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{marker}'\n", encoding="utf-8")
    path.chmod(0o700)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_verified_snapshot_executes_reviewed_bytes_after_atomic_path_replacement(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider-mcp"
    expected_sha256 = _write_script(executable, "reviewed")
    snapshot_root = tmp_path / "snapshots"
    descriptor = open_verified_executable(
        executable,
        expected_sha256=expected_sha256,
        snapshot_root=snapshot_root,
        _test_capability=_TEST_ONLY_SCRIPT_CAPABILITY,
    )
    try:
        replacement = tmp_path / "replacement"
        _write_script(replacement, "replacement")
        replacement.replace(executable)
        completed = subprocess.run(
            [descriptor_path(descriptor)],
            check=True,
            capture_output=True,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            pass_fds=(descriptor,),
            text=True,
        )
        assert completed.stdout == "reviewed\n"
        assert os.fstat(descriptor).st_nlink == 0
        assert list(snapshot_root.iterdir()) == []
    finally:
        os.close(descriptor)


def test_verified_snapshot_rejects_symlinked_source(tmp_path: Path) -> None:
    executable = tmp_path / "provider-real"
    expected_sha256 = _write_script(executable, "reviewed")
    symlink = tmp_path / "provider-mcp"
    symlink.symlink_to(executable)
    with pytest.raises(ReviewedProcessError, match="executable_unavailable"):
        open_verified_executable(
            symlink,
            expected_sha256=expected_sha256,
            snapshot_root=tmp_path / "snapshots",
        )


def test_verified_snapshot_rejects_digest_drift_without_leaving_a_file(tmp_path: Path) -> None:
    executable = tmp_path / "provider-mcp"
    _write_script(executable, "unreviewed")
    snapshot_root = tmp_path / "snapshots"
    with pytest.raises(ReviewedProcessError, match="executable_digest_mismatch"):
        open_verified_executable(
            executable,
            expected_sha256="0" * 64,
            snapshot_root=snapshot_root,
            _test_capability=_TEST_ONLY_SCRIPT_CAPABILITY,
        )
    assert list(snapshot_root.iterdir()) == []


def test_verified_snapshot_rejects_scripts_without_explicit_test_flag(tmp_path: Path) -> None:
    executable = tmp_path / "provider-mcp"
    expected_sha256 = _write_script(executable, "reviewed")
    with pytest.raises(ReviewedProcessError, match="executable_format_unreviewed"):
        open_verified_executable(
            executable,
            expected_sha256=expected_sha256,
            snapshot_root=tmp_path / "snapshots",
        )


def test_verified_snapshot_rejects_symlinked_snapshot_root(tmp_path: Path) -> None:
    executable = tmp_path / "provider-mcp"
    expected_sha256 = _write_script(executable, "reviewed")
    real_root = tmp_path / "real-snapshots"
    real_root.mkdir(mode=0o700)
    symlink = tmp_path / "snapshots"
    symlink.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(ReviewedProcessError, match="snapshot_root"):
        open_verified_executable(
            executable,
            expected_sha256=expected_sha256,
            snapshot_root=symlink,
            _test_capability=_TEST_ONLY_SCRIPT_CAPABILITY,
        )
    assert list(real_root.iterdir()) == []


def test_verified_snapshot_rejects_group_writable_source(tmp_path: Path) -> None:
    executable = tmp_path / "provider-mcp"
    expected_sha256 = _write_script(executable, "reviewed")
    executable.chmod(0o720)

    with pytest.raises(ReviewedProcessError, match="executable_permissions_unsafe"):
        open_verified_executable(
            executable,
            expected_sha256=expected_sha256,
            snapshot_root=tmp_path / "snapshots",
            _test_capability=_TEST_ONLY_SCRIPT_CAPABILITY,
        )


def test_verified_snapshot_closes_source_when_initial_fstat_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "provider-mcp"
    digest = _write_script(executable, "reviewed")
    opened: list[int] = []
    real_open = os.open
    real_fstat = os.fstat

    def track_open(*args: Any, **kwargs: Any) -> int:
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def fail_source_fstat(descriptor: int) -> os.stat_result:
        if opened and descriptor == opened[0]:
            raise OSError("injected source fstat failure")
        return real_fstat(descriptor)

    monkeypatch.setattr("signet.reviewed_process.os.open", track_open)
    monkeypatch.setattr("signet.reviewed_process.os.fstat", fail_source_fstat)

    with pytest.raises(ReviewedProcessError, match="executable_unavailable"):
        open_verified_executable(
            executable,
            expected_sha256=digest,
            snapshot_root=tmp_path / "snapshots",
            _test_capability=_TEST_ONLY_SCRIPT_CAPABILITY,
        )

    assert len(opened) == 1
    with pytest.raises(OSError):
        real_fstat(opened[0])


def test_verified_snapshot_closes_root_and_source_when_root_fstat_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "provider-mcp"
    digest = _write_script(executable, "reviewed")
    opened: list[int] = []
    real_open = os.open
    real_fstat = os.fstat

    def track_open(*args: Any, **kwargs: Any) -> int:
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def fail_root_fstat(descriptor: int) -> os.stat_result:
        if len(opened) >= 2 and descriptor == opened[1]:
            raise OSError("injected root fstat failure")
        return real_fstat(descriptor)

    monkeypatch.setattr("signet.reviewed_process.os.open", track_open)
    monkeypatch.setattr("signet.reviewed_process.os.fstat", fail_root_fstat)

    with pytest.raises(ReviewedProcessError, match="snapshot_root_unavailable"):
        open_verified_executable(
            executable,
            expected_sha256=digest,
            snapshot_root=tmp_path / "snapshots",
            _test_capability=_TEST_ONLY_SCRIPT_CAPABILITY,
        )

    assert len(opened) == 2
    for descriptor in opened:
        with pytest.raises(OSError):
            real_fstat(descriptor)


@pytest.mark.parametrize("mode", [0o750, 0o770, 0o707])
def test_private_working_directory_rejects_non_private_modes(tmp_path: Path, mode: int) -> None:
    working_directory = tmp_path / "working"
    working_directory.mkdir(mode=mode)
    working_directory.chmod(mode)

    with pytest.raises(ReviewedProcessError, match="working_directory_unsafe"):
        VerifiedPrivateDirectory.open(working_directory)


def test_private_working_directory_rejects_relative_missing_and_symlinked_paths(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    symlink = tmp_path / "linked"
    symlink.symlink_to(private, target_is_directory=True)

    for invalid in (Path("relative"), tmp_path / "missing", symlink):
        with pytest.raises(ReviewedProcessError, match="working_directory"):
            VerifiedPrivateDirectory.open(invalid)


def test_private_working_directory_rejects_foreign_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    working_directory = tmp_path / "working"
    working_directory.mkdir(mode=0o700)
    monkeypatch.setattr(os, "geteuid", lambda: working_directory.stat().st_uid + 1)

    with pytest.raises(ReviewedProcessError, match="working_directory_unsafe"):
        VerifiedPrivateDirectory.open(working_directory)


def test_private_working_directory_detects_path_swap_and_keeps_bound_inode(
    tmp_path: Path,
) -> None:
    working_directory = tmp_path / "working"
    working_directory.mkdir(mode=0o700)
    original = tmp_path / "original"

    with VerifiedPrivateDirectory.open(working_directory) as opened:
        bound_path = opened.reverify()
        working_directory.rename(original)
        working_directory.mkdir(mode=0o700)
        with pytest.raises(ReviewedProcessError, match="working_directory_changed"):
            opened.reverify()

        completed = subprocess.run(
            ["/usr/bin/touch", "bound-inode"],
            cwd=bound_path,
            pass_fds=(opened.descriptor,),
            check=True,
        )
        assert completed.returncode == 0

    assert (original / "bound-inode").is_file()
    assert not (working_directory / "bound-inode").exists()


def test_private_working_directory_closes_descriptor_when_initial_recheck_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    working_directory = tmp_path / "working"
    working_directory.mkdir(mode=0o700)
    opened_descriptor = -1

    def fail_recheck(directory: VerifiedPrivateDirectory) -> str:
        nonlocal opened_descriptor
        opened_descriptor = directory.descriptor
        raise ReviewedProcessError("working_directory_changed")

    monkeypatch.setattr(VerifiedPrivateDirectory, "reverify", fail_recheck)

    with pytest.raises(ReviewedProcessError, match="working_directory_changed"):
        VerifiedPrivateDirectory.open(working_directory)

    assert opened_descriptor >= 0
    with pytest.raises(OSError):
        os.fstat(opened_descriptor)
