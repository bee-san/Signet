from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from signet.private_paths import (
    PrivatePathError,
    ensure_owned_directory,
    ensure_private_directory,
)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_private_directory_is_created_with_exact_private_mode(tmp_path: Path) -> None:
    selected = tmp_path / "new" / "private"

    resolved = ensure_private_directory(selected)

    assert resolved == selected.resolve()
    assert mode(selected) == 0o700


@pytest.mark.parametrize("unsafe_mode", [0o770, 0o777, 0o1777])
def test_existing_unsafe_directory_is_refused_without_chmod(
    tmp_path: Path,
    unsafe_mode: int,
) -> None:
    selected = tmp_path / "unsafe"
    selected.mkdir()
    selected.chmod(unsafe_mode)

    with pytest.raises(PrivatePathError, match="owned safe"):
        ensure_private_directory(selected)

    assert mode(selected) == unsafe_mode


def test_symlinked_directory_or_parent_is_refused(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    direct_link = tmp_path / "link"
    direct_link.symlink_to(private, target_is_directory=True)

    with pytest.raises(PrivatePathError):
        ensure_private_directory(direct_link)

    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(private, target_is_directory=True)
    with pytest.raises(PrivatePathError):
        ensure_private_directory(parent_link / "child")


def test_owned_output_parent_keeps_existing_mode_and_refuses_writers(
    tmp_path: Path,
) -> None:
    selected = tmp_path / "output"
    selected.mkdir(mode=0o755)
    os.chmod(selected, 0o755)

    assert ensure_owned_directory(selected) == selected.resolve()
    assert mode(selected) == 0o755

    os.chmod(selected, 0o775)
    with pytest.raises(PrivatePathError):
        ensure_owned_directory(selected)
    assert mode(selected) == 0o775
