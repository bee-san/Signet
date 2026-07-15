"""Descriptor-verified directory setup without mutating caller-owned paths."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class PrivatePathError(RuntimeError):
    pass


def ensure_private_directory(path: Path) -> Path:
    """Create a private directory or require an existing exact mode-0700 path."""

    return _ensure_directory(Path(path), private=True)


def ensure_owned_directory(path: Path) -> Path:
    """Create a private directory or accept an owned, non-writable parent."""

    return _ensure_directory(Path(path), private=False)


def _ensure_directory(path: Path, *, private: bool) -> Path:
    selected = path.expanduser().absolute()
    created = False
    try:
        selected.lstat()
    except FileNotFoundError:
        try:
            selected.mkdir(mode=0o700, parents=True)
            created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise PrivatePathError("directory could not be created safely") from exc
    except OSError as exc:
        raise PrivatePathError("directory could not be inspected safely") from exc

    descriptor: int | None = None
    try:
        before = selected.lstat()
        resolved = selected.resolve(strict=True)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(selected, flags)
        opened = os.fstat(descriptor)
        if created:
            os.fchmod(descriptor, 0o700)
            opened = os.fstat(descriptor)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise PrivatePathError("directory could not be opened safely") from exc

    try:
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        mode = stat.S_IMODE(opened.st_mode)
        unsafe_mode = mode != 0o700 if private else bool(mode & 0o022)
        if (
            resolved != selected
            or not stat.S_ISDIR(before.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_uid != current_uid
            or unsafe_mode
        ):
            raise PrivatePathError("directory is not an owned safe directory")
        return resolved
    finally:
        os.close(descriptor)
