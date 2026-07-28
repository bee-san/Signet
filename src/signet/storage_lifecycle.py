"""Bounded maintenance for setup-owned logs and disposable cache files."""

from __future__ import annotations

import os
import secrets
import shutil
import stat
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from signet.private_paths import (
    DirectoryIdentity,
    PrivatePathError,
    require_private_directory_identity,
    revalidate_directory_identity,
)


class StoragePolicyError(RuntimeError):
    """Raised when an owned storage boundary is unsafe or cannot be enforced."""


LOG_FILE_BYTES = 25 * 1024**2
LOGS_HARD_BYTES = 512 * 1024**2
CACHE_HARD_BYTES = 1024**3
DATABASE_HARD_BYTES = 1024**3
ATTACHMENTS_HARD_BYTES = 8 * 1024**3
BACKUPS_HARD_BYTES = 8 * 1024**3
STAGING_HARD_BYTES = 50 * 1024**2
MINIMUM_FREE_BYTES = 1024**3 + 100 * 1024**2 + LOG_FILE_BYTES


@dataclass(frozen=True, slots=True)
class StorageMaintenance:
    root: Path
    data_dir: Path | None = None
    attachment_roots: tuple[Path, ...] = ()
    log_file_bytes: int = LOG_FILE_BYTES
    logs_hard_bytes: int = LOGS_HARD_BYTES
    cache_hard_bytes: int = CACHE_HARD_BYTES
    database_hard_bytes: int = DATABASE_HARD_BYTES
    attachments_hard_bytes: int = ATTACHMENTS_HARD_BYTES
    minimum_free_bytes: int = MINIMUM_FREE_BYTES
    disk_usage_provider: Callable[[Path], Any] = shutil.disk_usage

    def __post_init__(self) -> None:
        for value in (
            self.log_file_bytes,
            self.logs_hard_bytes,
            self.cache_hard_bytes,
            self.database_hard_bytes,
            self.attachments_hard_bytes,
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError("storage maintenance limits must be positive integers")
        if (
            not isinstance(self.minimum_free_bytes, int)
            or isinstance(self.minimum_free_bytes, bool)
            or self.minimum_free_bytes < 0
        ):
            raise ValueError("the storage write reserve must be a non-negative integer")
        if not isinstance(self.attachment_roots, tuple):
            raise TypeError("attachment roots must be an immutable tuple")
        if self.logs_hard_bytes < self.log_file_bytes:
            raise ValueError("the log hard limit must fit one bounded log file")

    def run_once(self) -> dict[str, Any]:
        """Enforce hard owned limits without deleting database or recovery artifacts."""

        logs = self.root / "logs"
        cache = self.root / "cache"
        checked_roots = [logs, cache]
        checked_identities: list[DirectoryIdentity] = []
        database_bytes: int | None = None
        attachments_bytes: int | None = None
        try:
            logs_identity = require_private_directory_identity(logs)
            cache_identity = require_private_directory_identity(cache)
            checked_identities.extend((logs_identity, cache_identity))
            rotated = self._rotate_logs(logs)
            logs_bytes = self._owned_file_usage(logs)
            if logs_bytes > self.logs_hard_bytes:
                raise StoragePolicyError("owned logs exceed their hard storage limit")
            pruned = self._prune_cache(cache)
            cache_bytes = self._owned_file_usage(cache)
            if cache_bytes > self.cache_hard_bytes:
                raise StoragePolicyError("owned cache exceeds its hard storage limit")
            if self.data_dir is not None:
                data_identity = require_private_directory_identity(self.data_dir)
                checked_roots.append(self.data_dir)
                checked_identities.append(data_identity)
                database_bytes = self._owned_file_usage(self.data_dir)
                if database_bytes > self.database_hard_bytes:
                    raise StoragePolicyError("owned database exceeds its hard storage limit")
            if self.attachment_roots:
                attachments_bytes = 0
                for attachment_root in self.attachment_roots:
                    attachment_identity = require_private_directory_identity(attachment_root)
                    checked_roots.append(attachment_root)
                    checked_identities.append(attachment_identity)
                    attachments_bytes += self._owned_file_usage(attachment_root)
                if attachments_bytes > self.attachments_hard_bytes:
                    raise StoragePolicyError("owned attachments exceed their hard storage limit")
            identity_keys = {(identity.device, identity.inode) for identity in checked_identities}
            if len(identity_keys) != len(checked_identities):
                raise StoragePolicyError("owned storage roots resolve to the same directory")
            for checked_root in checked_roots:
                usage = self.disk_usage_provider(checked_root)
                if int(usage.free) < self.minimum_free_bytes:
                    raise StoragePolicyError("owned storage write reserve is exhausted")
            for identity in checked_identities:
                revalidate_directory_identity(identity, private=True)
        except StoragePolicyError:
            raise
        except (OSError, PrivatePathError) as exc:
            raise StoragePolicyError("owned storage maintenance failed safely") from exc
        return {
            "logs_bytes": logs_bytes,
            "cache_bytes": cache_bytes,
            "rotated_logs": rotated,
            "pruned_cache_files": pruned,
            "database_bytes": database_bytes,
            "attachments_bytes": attachments_bytes,
        }

    def _rotate_logs(self, logs: Path) -> int:
        rotated = 0
        for path in sorted(logs.iterdir(), key=lambda item: item.name):
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise StoragePolicyError("owned log directory contains a symbolic link")
            if not stat.S_ISREG(metadata.st_mode) or not path.name.endswith(".log"):
                continue
            self._require_private_file(metadata, label="log")
            if metadata.st_size <= self.log_file_bytes:
                continue
            self._copy_truncate(path, metadata)
            rotated += 1
        return rotated

    def _copy_truncate(self, path: Path, expected: os.stat_result) -> None:
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        source_fd = -1
        temporary_fd = -1
        temporary_name = f".{path.name}.rotate-{secrets.token_hex(8)}"
        rotated_name = f"{path.name}.1"
        try:
            source_fd = os.open(
                path.name,
                os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
            current = os.fstat(source_fd)
            if (current.st_dev, current.st_ino, current.st_size) != (
                expected.st_dev,
                expected.st_ino,
                expected.st_size,
            ):
                raise StoragePolicyError("owned log changed before rotation")
            self._require_private_file(current, label="log")
            start = max(0, current.st_size - self.log_file_bytes)
            retained = os.pread(source_fd, self.log_file_bytes, start)
            temporary_fd = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=directory_fd,
            )
            view = memoryview(retained)
            while view:
                written = os.write(temporary_fd, view)
                if written <= 0:
                    raise OSError("short rotated log write")
                view = view[written:]
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = -1
            try:
                previous = os.stat(rotated_name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                self._require_private_file(previous, label="rotated log")
                os.unlink(rotated_name, dir_fd=directory_fd)
            os.replace(
                temporary_name,
                rotated_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
            os.ftruncate(source_fd, 0)
            os.fsync(source_fd)
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            if source_fd >= 0:
                os.close(source_fd)
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=directory_fd)
            os.close(directory_fd)

    def _prune_cache(self, cache: Path) -> int:
        files: list[tuple[int, str, Path, int, int]] = []
        total = 0
        for path in cache.rglob("*"):
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise StoragePolicyError("owned cache contains a symbolic link")
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise StoragePolicyError("owned cache contains an unsupported entry")
            self._require_private_file(metadata, label="cache")
            files.append((metadata.st_mtime_ns, str(path), path, metadata.st_size, metadata.st_ino))
            total += metadata.st_size
        pruned = 0
        for _mtime, _name, path, size, inode in sorted(files):
            if total <= self.cache_hard_bytes:
                break
            current = path.lstat()
            if current.st_ino != inode or current.st_size != size:
                raise StoragePolicyError("owned cache changed before pruning")
            path.unlink()
            total -= size
            pruned += 1
        return pruned

    @staticmethod
    def _owned_file_usage(root: Path) -> int:
        total = 0
        for path in root.rglob("*"):
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise StoragePolicyError("owned storage contains a symbolic link")
            if stat.S_ISREG(metadata.st_mode):
                StorageMaintenance._require_private_file(metadata, label="storage")
                total += metadata.st_size
            elif not stat.S_ISDIR(metadata.st_mode):
                raise StoragePolicyError("owned storage contains an unsupported entry")
        return total

    @staticmethod
    def _require_private_file(metadata: os.stat_result, *, label: str) -> None:
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != current_uid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise StoragePolicyError(f"owned {label} file is unsafe")
