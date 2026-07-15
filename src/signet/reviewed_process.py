"""Verified executable snapshots for reviewed local process boundaries."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_NATIVE_EXECUTABLE_MAGICS = frozenset(
    {
        b"\x7fELF",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
    }
)


class ReviewedProcessError(RuntimeError):
    """A secret-free failure while preparing a reviewed executable."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


DirectoryIdentity = tuple[int, int]


@dataclass(slots=True)
class VerifiedPrivateDirectory:
    """An exact private directory held open across a process spawn."""

    path: Path
    descriptor: int
    identity: DirectoryIdentity

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        expected_identity: DirectoryIdentity | None = None,
    ) -> VerifiedPrivateDirectory:
        selected = Path(path)
        if (
            not selected.is_absolute()
            or not hasattr(os, "O_DIRECTORY")
            or not hasattr(os, "O_NOFOLLOW")
        ):
            raise ReviewedProcessError("working_directory_unsafe")
        descriptor = -1
        try:
            before = selected.lstat()
            resolved = selected.resolve(strict=True)
            descriptor = os.open(
                selected,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            opened = os.fstat(descriptor)
        except (OSError, RuntimeError) as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise ReviewedProcessError("working_directory_unavailable") from exc

        identity = (opened.st_dev, opened.st_ino)
        if (
            resolved != selected
            or not stat.S_ISDIR(before.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or (before.st_dev, before.st_ino) != identity
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
            or expected_identity is not None
            and identity != expected_identity
        ):
            os.close(descriptor)
            raise ReviewedProcessError("working_directory_unsafe")

        result = cls(path=selected, descriptor=descriptor, identity=identity)
        result.reverify()
        return result

    def reverify(self) -> str:
        """Recheck the pathname and descriptor, then return the bound fd path."""

        try:
            current = self.path.lstat()
            resolved = self.path.resolve(strict=True)
            opened = os.fstat(self.descriptor)
        except (OSError, RuntimeError) as exc:
            raise ReviewedProcessError("working_directory_changed") from exc
        if (
            resolved != self.path
            or not stat.S_ISDIR(current.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or (current.st_dev, current.st_ino) != self.identity
            or (opened.st_dev, opened.st_ino) != self.identity
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise ReviewedProcessError("working_directory_changed")
        return descriptor_path(self.descriptor)

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def detach(self) -> int:
        descriptor = self.descriptor
        if descriptor < 0:
            raise ReviewedProcessError("working_directory_unavailable")
        self.descriptor = -1
        return descriptor

    def __enter__(self) -> VerifiedPrivateDirectory:
        return self

    def __exit__(self, *ignored: object) -> None:
        del ignored
        self.close()


class _TestOnlyScriptCapability:
    __slots__ = ()


# Tests inject this opaque in-memory capability directly. It is intentionally
# absent from every serializable runtime configuration model.
_TEST_ONLY_SCRIPT_CAPABILITY = _TestOnlyScriptCapability()


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _write_all(descriptor: int, value: bytes) -> None:
    remaining = memoryview(value)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("executable snapshot write made no progress")
        remaining = remaining[written:]


def _hash_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _open_private_root(root: Path) -> int:
    if not root.is_absolute() or not hasattr(os, "O_NOFOLLOW"):
        raise ReviewedProcessError("snapshot_root_unsafe")
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        before = root.lstat()
        resolved = root.resolve(strict=True)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        descriptor = os.open(root, flags)
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise ReviewedProcessError("snapshot_root_unavailable") from exc
    if (
        resolved != root
        or not stat.S_ISDIR(before.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or opened.st_uid != os.geteuid()
        or opened.st_mode & 0o077
    ):
        os.close(descriptor)
        raise ReviewedProcessError("snapshot_root_unsafe")
    return descriptor


def _is_reviewed_format(leading: bytes, *, test_capability: object | None) -> bool:
    return leading in _NATIVE_EXECUTABLE_MAGICS or (
        test_capability is _TEST_ONLY_SCRIPT_CAPABILITY and leading.startswith(b"#!")
    )


def open_verified_executable(
    source: Path,
    *,
    expected_sha256: str,
    snapshot_root: Path,
    _test_capability: object | None = None,
) -> int:
    """Copy, verify, unlink, and return a read-only descriptor for exact execution."""

    if not hasattr(os, "O_NOFOLLOW"):
        raise ReviewedProcessError("executable_platform_unsupported")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        source_descriptor = os.open(source, flags)
        source_before = os.fstat(source_descriptor)
    except OSError as exc:
        raise ReviewedProcessError("executable_unavailable") from exc

    root_descriptor = -1
    writer = -1
    snapshot_descriptor = -1
    snapshot_name: str | None = None
    try:
        if not stat.S_ISREG(source_before.st_mode) or source_before.st_mode & 0o111 == 0:
            raise ReviewedProcessError("executable_not_runnable")
        if source_before.st_uid not in {0, os.geteuid()} or source_before.st_mode & 0o022:
            raise ReviewedProcessError("executable_permissions_unsafe")
        root_descriptor = _open_private_root(snapshot_root)
        for _ in range(4):
            candidate = f".signet-exec-{secrets.token_hex(18)}"
            try:
                writer = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                    0o600,
                    dir_fd=root_descriptor,
                )
            except FileExistsError:
                continue
            snapshot_name = candidate
            break
        if writer < 0 or snapshot_name is None:
            raise ReviewedProcessError("snapshot_create_failed")

        digest = hashlib.sha256()
        copied = 0
        leading = b""
        try:
            while chunk := os.read(source_descriptor, 1024 * 1024):
                copied += len(chunk)
                if copied > _MAX_EXECUTABLE_BYTES:
                    raise ReviewedProcessError("executable_too_large")
                if len(leading) < 4:
                    leading = (leading + chunk)[:4]
                digest.update(chunk)
                _write_all(writer, chunk)
        except OSError as exc:
            raise ReviewedProcessError("executable_read_failed") from exc
        source_after = os.fstat(source_descriptor)
        if _identity(source_before) != _identity(source_after) or copied != source_before.st_size:
            raise ReviewedProcessError("executable_changed")
        if not _is_reviewed_format(leading, test_capability=_test_capability):
            raise ReviewedProcessError("executable_format_unreviewed")
        actual_sha256 = digest.hexdigest()
        if actual_sha256 != expected_sha256:
            raise ReviewedProcessError("executable_digest_mismatch")

        os.fsync(writer)
        os.fchmod(writer, 0o500)
        os.close(writer)
        writer = -1
        snapshot_descriptor = os.open(snapshot_name, flags, dir_fd=root_descriptor)
        snapshot_metadata = os.fstat(snapshot_descriptor)
        if (
            not stat.S_ISREG(snapshot_metadata.st_mode)
            or snapshot_metadata.st_size != copied
            or snapshot_metadata.st_nlink != 1
            or _hash_descriptor(snapshot_descriptor) != actual_sha256
        ):
            raise ReviewedProcessError("snapshot_integrity_failed")
        os.unlink(snapshot_name, dir_fd=root_descriptor)
        snapshot_name = None
        os.fsync(root_descriptor)
        if os.fstat(snapshot_descriptor).st_nlink != 0:
            raise ReviewedProcessError("snapshot_unlink_failed")
        os.lseek(snapshot_descriptor, 0, os.SEEK_SET)
        result = snapshot_descriptor
        snapshot_descriptor = -1
        return result
    finally:
        if writer >= 0:
            os.close(writer)
        if snapshot_descriptor >= 0:
            os.close(snapshot_descriptor)
        if snapshot_name is not None and root_descriptor >= 0:
            with suppress(OSError):
                os.unlink(snapshot_name, dir_fd=root_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        os.close(source_descriptor)


def descriptor_path(descriptor: int) -> str:
    """Return an executable descriptor path supported by the current POSIX host."""

    for root in ("/proc/self/fd", "/dev/fd"):
        if Path(root).is_dir():
            return f"{root}/{descriptor}"
    raise ReviewedProcessError("executable_platform_unsupported")
