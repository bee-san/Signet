#!/usr/bin/env python3
"""Validate stable private paths and bounded recursive profile trees."""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path

from signet.private_paths import (
    PrivatePathError,
    require_no_acl_grants,
    require_owned_directory_identity,
    require_private_directory_identity,
    revalidate_directory_identity,
)

_PRIVATE_TREE_MAX_DEPTH = 16
_PRIVATE_TREE_MAX_ENTRIES = 1024
_PRIVATE_TREE_MAX_BYTES = 64 * 1024 * 1024


class ValidationError(RuntimeError):
    pass


class _PrivateTreeState:
    __slots__ = ("entries", "root_device", "total_bytes", "visited_directories")

    def __init__(self, *, root_device: int) -> None:
        self.root_device = root_device
        self.entries = 0
        self.total_bytes = 0
        self.visited_directories: set[tuple[int, int]] = set()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate one canonical owned directory, private direct-child files, "
            "or a bounded recursive private tree."
        )
    )
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--private-file", type=Path, action="append", default=[])
    parser.add_argument(
        "--private-tree",
        action="store_true",
        help="recursively require a bounded mode-0700/0600 private tree",
    )
    args = parser.parse_args(argv)

    try:
        _validate(
            args.directory,
            tuple(args.private_file),
            private_tree=args.private_tree,
        )
    except (OSError, PrivatePathError, ValidationError, ValueError) as exc:
        parser.exit(1, f"error: private path validation failed: {exc}\n")
    return 0


def _validate(
    directory: Path,
    private_files: tuple[Path, ...],
    *,
    private_tree: bool = False,
) -> None:
    if (
        not directory.is_absolute()
        or ".." in directory.parts
        or any("\x00" in component for component in directory.parts)
    ):
        raise ValidationError("directory must be an absolute canonical path")
    if private_tree:
        identity = require_private_directory_identity(directory)
    else:
        identity = require_owned_directory_identity(directory)
    if identity.path != directory:
        raise ValidationError("directory must be canonical and contain no symlinks")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    descriptor = os.open(identity.path, flags)
    try:
        opened_parent = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            identity.device,
            identity.inode,
        ):
            raise ValidationError("directory identity changed")
        for path in private_files:
            _validate_private_file(path, parent=identity.path, parent_fd=descriptor)
        if private_tree:
            _validate_private_tree(descriptor, root_device=identity.device)
    finally:
        os.close(descriptor)
    revalidate_directory_identity(identity, private=private_tree)


def _validate_private_file(path: Path, *, parent: Path, parent_fd: int) -> None:
    try:
        os.fsencode(path)
    except (OSError, ValueError) as exc:
        raise ValidationError("private file path contains an invalid component") from exc
    if (
        not path.is_absolute()
        or ".." in path.parts
        or any("\x00" in component for component in path.parts)
        or path.parent != parent
    ):
        raise ValidationError("private files must be canonical direct children")
    before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if not _is_safe_private_file_snapshot(before, current_uid=current_uid):
        raise ValidationError("private file ownership, mode, link, or type is unsafe")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path.name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    finally:
        os.close(descriptor)
    safe_snapshots = all(
        _is_safe_private_file_snapshot(metadata, current_uid=current_uid)
        for metadata in (before, opened, after)
    )
    stable_identity = all(
        (metadata.st_dev, metadata.st_ino) == (opened.st_dev, opened.st_ino)
        for metadata in (before, after)
    )
    if not safe_snapshots or not stable_identity:
        raise ValidationError("private file ownership, mode, link, or identity is unsafe")


def _is_safe_private_file_snapshot(metadata: os.stat_result, *, current_uid: int) -> bool:
    return bool(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == current_uid
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == 0o600
    )


def _validate_private_tree(descriptor: int, *, root_device: int) -> None:
    root = os.fstat(descriptor)
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if not _is_safe_private_directory_snapshot(
        root,
        current_uid=current_uid,
        root_device=root_device,
    ):
        raise ValidationError("private tree root is unsafe")
    state = _PrivateTreeState(root_device=root_device)
    state.visited_directories.add((root.st_dev, root.st_ino))
    _validate_private_tree_directory(
        descriptor,
        depth=0,
        current_uid=current_uid,
        state=state,
    )


def _validate_private_tree_directory(
    descriptor: int,
    *,
    depth: int,
    current_uid: int,
    state: _PrivateTreeState,
) -> None:
    observed: dict[str, tuple[int, ...]] = {}
    with os.scandir(descriptor) as iterator:
        for entry in iterator:
            state.entries += 1
            if state.entries > _PRIVATE_TREE_MAX_ENTRIES:
                raise ValidationError("private tree contains too many entries")
            entry_depth = depth + 1
            if entry_depth > _PRIVATE_TREE_MAX_DEPTH:
                raise ValidationError("private tree is too deep")
            name = entry.name
            before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                after = _validate_private_tree_child_directory(
                    descriptor,
                    name,
                    before=before,
                    depth=entry_depth,
                    current_uid=current_uid,
                    state=state,
                )
            elif stat.S_ISREG(before.st_mode):
                after = _validate_private_tree_child_file(
                    descriptor,
                    name,
                    before=before,
                    current_uid=current_uid,
                    state=state,
                )
            else:
                raise ValidationError("private tree contains a special file or link")
            if name in observed:
                raise ValidationError("private tree contains duplicate entries")
            observed[name] = _private_tree_signature(after)

    current: dict[str, tuple[int, ...]] = {}
    with os.scandir(descriptor) as iterator:
        for entry in iterator:
            if len(current) >= _PRIVATE_TREE_MAX_ENTRIES:
                raise ValidationError("private tree contains too many entries")
            metadata = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
            if not (
                _is_safe_private_directory_snapshot(
                    metadata,
                    current_uid=current_uid,
                    root_device=state.root_device,
                )
                or _is_safe_private_file_snapshot(metadata, current_uid=current_uid)
                and metadata.st_dev == state.root_device
            ):
                raise ValidationError("private tree entry changed or became unsafe")
            current[entry.name] = _private_tree_signature(metadata)
    if current != observed:
        raise ValidationError("private tree contents changed during validation")


def _validate_private_tree_child_directory(
    parent_descriptor: int,
    name: str,
    *,
    before: os.stat_result,
    depth: int,
    current_uid: int,
    state: _PrivateTreeState,
) -> os.stat_result:
    if not _is_safe_private_directory_snapshot(
        before,
        current_uid=current_uid,
        root_device=state.root_device,
    ):
        raise ValidationError("private tree directory is unsafe")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    child_descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        opened = os.fstat(child_descriptor)
        require_no_acl_grants(child_descriptor)
        after_open = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not all(
            _is_safe_private_directory_snapshot(
                metadata,
                current_uid=current_uid,
                root_device=state.root_device,
            )
            for metadata in (before, opened, after_open)
        ) or not _same_identity(before, opened, after_open):
            raise ValidationError("private tree directory identity is unsafe")
        identity = (opened.st_dev, opened.st_ino)
        if identity in state.visited_directories:
            raise ValidationError("private tree contains a repeated directory")
        state.visited_directories.add(identity)
        _validate_private_tree_directory(
            child_descriptor,
            depth=depth,
            current_uid=current_uid,
            state=state,
        )
        after_walk = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not _is_safe_private_directory_snapshot(
            after_walk,
            current_uid=current_uid,
            root_device=state.root_device,
        ) or not _same_identity(opened, after_walk):
            raise ValidationError("private tree directory changed during validation")
        return after_walk
    finally:
        os.close(child_descriptor)


def _validate_private_tree_child_file(
    parent_descriptor: int,
    name: str,
    *,
    before: os.stat_result,
    current_uid: int,
    state: _PrivateTreeState,
) -> os.stat_result:
    if not _is_safe_private_file_snapshot(before, current_uid=current_uid) or (
        before.st_dev != state.root_device
    ):
        raise ValidationError("private tree file is unsafe")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    child_descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        opened = os.fstat(child_descriptor)
        require_no_acl_grants(child_descriptor)
        after = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    finally:
        os.close(child_descriptor)
    if not all(
        _is_safe_private_file_snapshot(metadata, current_uid=current_uid)
        and metadata.st_dev == state.root_device
        for metadata in (before, opened, after)
    ) or not _same_identity(before, opened, after):
        raise ValidationError("private tree file identity is unsafe")
    if not (before.st_size == opened.st_size == after.st_size):
        raise ValidationError("private tree file size changed during validation")
    state.total_bytes += opened.st_size
    if state.total_bytes > _PRIVATE_TREE_MAX_BYTES:
        raise ValidationError("private tree contains too much data")
    return after


def _is_safe_private_directory_snapshot(
    metadata: os.stat_result,
    *,
    current_uid: int,
    root_device: int,
) -> bool:
    return bool(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == current_uid
        and metadata.st_dev == root_device
        and stat.S_IMODE(metadata.st_mode) == 0o700
    )


def _same_identity(*snapshots: os.stat_result) -> bool:
    first = snapshots[0]
    return all(
        (metadata.st_dev, metadata.st_ino) == (first.st_dev, first.st_ino)
        for metadata in snapshots[1:]
    )


def _private_tree_signature(metadata: os.stat_result) -> tuple[int, ...]:
    file_size = metadata.st_size if stat.S_ISREG(metadata.st_mode) else 0
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_nlink,
        file_size,
    )


if __name__ == "__main__":
    raise SystemExit(main())
