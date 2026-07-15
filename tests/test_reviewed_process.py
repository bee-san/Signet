from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from signet.reviewed_process import (
    ReviewedProcessError,
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
        test_only_allow_script=True,
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
            test_only_allow_script=True,
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
            test_only_allow_script=True,
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
            test_only_allow_script=True,
        )
    assert list(real_root.iterdir()) == []
