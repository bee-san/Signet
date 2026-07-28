from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

import signet.setup_platform as setup_platform
from signet.private_paths import PrivatePathError
from signet.setup_platform import ProductionSetupPlatform
from signet.setup_state import SetupError


def _executable(path: Path, *, mode: int = 0o700) -> Path:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(b"#!/bin/sh\nexit 0\n")
    path.chmod(mode)
    return path


def _candidates(
    monkeypatch: pytest.MonkeyPatch,
    *paths: Path,
) -> None:
    monkeypatch.setattr(
        setup_platform,
        "_REVIEWED_COMMAND_CANDIDATES",
        {"systemctl": tuple(paths)},
    )
    monkeypatch.setattr(setup_platform, "_REVIEWED_COMMAND_OWNER_UID", os.geteuid())


def test_reviewed_command_uses_first_safe_absolute_candidate_not_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostile = _executable(tmp_path / "hostile" / "systemctl")
    target = _executable(tmp_path / "private" / "systemctl")
    linked = tmp_path / "linked-systemctl"
    linked.symlink_to(hostile)
    _candidates(monkeypatch, linked, target)
    monkeypatch.setenv("PATH", str(hostile.parent))

    command = ProductionSetupPlatform._reviewed_command(["systemctl", "--user", "daemon-reload"])

    assert command == [str(target), "--user", "daemon-reload"]
    assert Path(command[0]).is_absolute()


@pytest.mark.parametrize("symlinked_ancestor", [False, True])
def test_reviewed_command_fails_closed_on_symlinked_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    symlinked_ancestor: bool,
) -> None:
    real = _executable(tmp_path / "real" / "systemctl")
    if symlinked_ancestor:
        linked_parent = tmp_path / "linked-parent"
        linked_parent.symlink_to(real.parent, target_is_directory=True)
        candidate = linked_parent / real.name
    else:
        candidate = tmp_path / "linked-systemctl"
        candidate.symlink_to(real)
    _candidates(monkeypatch, candidate)

    with pytest.raises(SetupError, match="unavailable or unsafe"):
        ProductionSetupPlatform._reviewed_command(["systemctl", "--user", "status"])


@pytest.mark.parametrize("mode", [0o600, 0o720, 0o702])
def test_reviewed_command_rejects_unsafe_final_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: int,
) -> None:
    target = _executable(tmp_path / "private" / "systemctl", mode=mode)
    _candidates(monkeypatch, target)

    with pytest.raises(SetupError, match="unavailable or unsafe"):
        ProductionSetupPlatform._reviewed_command(["systemctl", "--user", "status"])


def test_reviewed_command_rejects_nonsticky_writable_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writable = tmp_path / "writable"
    target = _executable(writable / "systemctl")
    writable.chmod(0o777)
    _candidates(monkeypatch, target)
    try:
        with pytest.raises(SetupError, match="unavailable or unsafe"):
            ProductionSetupPlatform._reviewed_command(["systemctl", "--user", "status"])
    finally:
        writable.chmod(0o700)


def test_reviewed_command_accepts_current_owned_child_below_sticky_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sticky = tmp_path / "sticky"
    sticky.mkdir(mode=0o700)
    target = _executable(sticky / "private" / "systemctl")
    sticky.chmod(0o1777)
    _candidates(monkeypatch, target)
    try:
        assert ProductionSetupPlatform._reviewed_command(["systemctl", "--user", "status"])[
            0
        ] == str(target)
    finally:
        sticky.chmod(0o700)


def test_reviewed_command_rejects_foreign_owned_final_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _executable(tmp_path / "private" / "systemctl")
    _candidates(monkeypatch, target)
    real_fstat = setup_platform.os.fstat

    def foreign_file_owner(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return metadata
        values = list(metadata)
        values[stat.ST_UID] = os.geteuid() + 1
        return os.stat_result(values)

    monkeypatch.setattr(setup_platform.os, "fstat", foreign_file_owner)

    with pytest.raises(SetupError, match="unavailable or unsafe"):
        ProductionSetupPlatform._reviewed_command(["systemctl", "--user", "status"])


def test_reviewed_command_rejects_hard_linked_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _executable(tmp_path / "private" / "systemctl")
    os.link(target, tmp_path / "private" / "second-name")
    _candidates(monkeypatch, target)

    with pytest.raises(SetupError, match="unavailable or unsafe"):
        ProductionSetupPlatform._reviewed_command(["systemctl", "--user", "status"])


def test_reviewed_command_rejects_granting_acl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _executable(tmp_path / "private" / "systemctl")
    _candidates(monkeypatch, target)

    def reject_file_acl(descriptor: int) -> None:
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise PrivatePathError("granting ACL")

    monkeypatch.setattr(setup_platform, "require_no_acl_grants", reject_file_acl)

    with pytest.raises(SetupError, match="unavailable or unsafe"):
        ProductionSetupPlatform._reviewed_command(["systemctl", "--user", "status"])


def test_reviewed_command_rejects_final_name_replacement_during_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _executable(tmp_path / "private" / "systemctl")
    _candidates(monkeypatch, target)
    real_access = setup_platform.os.access
    replaced = False

    def replace_before_access(
        path: os.PathLike[str] | str,
        mode: int,
        *,
        dir_fd: int | None = None,
        effective_ids: bool = False,
        follow_symlinks: bool = True,
    ) -> bool:
        nonlocal replaced
        if not replaced:
            replaced = True
            target.unlink()
            _executable(target)
        return real_access(
            path,
            mode,
            dir_fd=dir_fd,
            effective_ids=effective_ids,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(setup_platform.os, "access", replace_before_access)

    with pytest.raises(SetupError, match="unavailable or unsafe"):
        ProductionSetupPlatform._reviewed_command(["systemctl", "--user", "status"])


def test_run_command_rejects_a_current_user_owned_executable_before_the_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.geteuid() == 0:
        pytest.skip("requires a non-root test user")
    target = _executable(tmp_path / "private" / "systemctl")
    monkeypatch.setattr(
        setup_platform,
        "_REVIEWED_COMMAND_CANDIDATES",
        {"systemctl": (target,)},
    )
    called = False

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal called
        del command, kwargs
        called = True
        return subprocess.CompletedProcess([], 0, "", "")

    with pytest.raises(SetupError, match="unavailable or unsafe"):
        ProductionSetupPlatform(command_runner=run)._run_command(
            ["systemctl", "--user", "status"],
            text=True,
            capture_output=True,
            check=False,
        )

    assert called is False
