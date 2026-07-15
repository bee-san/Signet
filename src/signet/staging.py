"""Filesystem confinement primitives for local virtualized objects."""

from __future__ import annotations

import fcntl
import hashlib
import json
import mimetypes
import os
import re
import secrets
import shutil
import stat
import time
from collections.abc import Collection, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any


class StagingPathError(ValueError):
    """Raised when a requested staging path violates confinement rules."""


def confined_staging_path(root: Path, relative_path: str) -> Path:
    """Return a path below ``root`` while rejecting traversal and link aliases."""
    requested = PurePath(relative_path)
    if not relative_path or requested.is_absolute() or ".." in requested.parts:
        raise StagingPathError("staging paths must be relative descendants")

    resolved_root = root.resolve()
    candidate = (resolved_root / relative_path).resolve(strict=False)
    try:
        candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise StagingPathError("staging path escapes the configured root") from exc

    current = resolved_root
    for part in requested.parts:
        current /= part
        if current.is_symlink():
            raise StagingPathError("symbolic links are forbidden in staging paths")

    if candidate.exists() and os.stat(candidate, follow_symlinks=False).st_nlink != 1:
        raise StagingPathError("hard-linked staging files are forbidden")
    return candidate


class StagingError(ValueError):
    """Raised when a file cannot be staged or resolved safely."""


@dataclass(frozen=True, slots=True)
class StagedFile:
    opaque_id: str
    adapter: str
    account: str
    filename: str
    declared_mime: str
    detected_mime: str
    size: int
    sha256: str
    path: Path
    created_at: int = 0


_OPAQUE_ID_RE = re.compile(r"stg_[A-Za-z0-9_]{20,64}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_METADATA_KEYS = {
    "format",
    "opaque_id",
    "adapter",
    "account",
    "filename",
    "declared_mime",
    "detected_mime",
    "size",
    "sha256",
    "created_at",
}
_CHUNK_SIZE = 1024 * 1024
_METADATA_LIMIT = 64 * 1024


def _validate_filename(filename: str) -> str:
    if not filename or filename in {".", ".."}:
        raise StagingError("filename is required")
    if filename != Path(filename).name or "/" in filename or "\\" in filename:
        raise StagingError("filename must not contain a path")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in filename):
        raise StagingError("filename contains control characters")
    try:
        encoded = filename.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise StagingError("filename is not valid UTF-8") from exc
    if len(encoded) > 255:
        raise StagingError("filename is too long")
    return filename


def _validate_bounded_text(value: str, *, name: str, maximum: int = 512) -> str:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise StagingError(f"{name} is invalid") from exc
    if (
        not value
        or len(encoded) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise StagingError(f"{name} is invalid")
    return value


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise StagingError("this platform cannot safely open staged files")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _readonly_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise StagingError("this platform cannot safely open staged files")
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _entry_exists(name: str, *, directory_fd: int) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def open_confined_readonly(
    root: Path,
    path: Path,
    *,
    expected_root_identity: tuple[int, int] | None = None,
) -> int:
    """Open a regular file below ``root`` without following any path component.

    The returned descriptor is positioned at byte zero and belongs to the caller.
    ``root`` must already be an absolute canonical path.  Callers that retain a
    configured root across operations can pin its device/inode with
    ``expected_root_identity`` so replacing the root fails closed.
    """
    root = Path(root)
    path = Path(path)
    if not root.is_absolute() or not path.is_absolute() or ".." in path.parts:
        raise StagingError("file path is not a confined absolute descendant")
    normalized = Path(os.path.abspath(path))
    try:
        relative = normalized.relative_to(root)
    except ValueError as exc:
        raise StagingError("file is outside the configured root") from exc
    if not relative.parts:
        raise StagingError("file path does not identify a regular file")

    try:
        root_fd = os.open(root, _directory_flags())
    except OSError as exc:
        raise StagingError("configured root is unavailable") from exc
    directory_fd = root_fd
    try:
        root_metadata = os.fstat(root_fd)
        if not stat.S_ISDIR(root_metadata.st_mode) or (
            expected_root_identity is not None
            and _identity(root_metadata) != expected_root_identity
        ):
            raise StagingError("configured root changed after initialization")
        for component in relative.parts[:-1]:
            try:
                next_fd = os.open(component, _directory_flags(), dir_fd=directory_fd)
            except OSError as exc:
                raise StagingError("file path contains an unsafe directory") from exc
            if directory_fd != root_fd:
                os.close(directory_fd)
            directory_fd = next_fd
            if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
                raise StagingError("file path contains a non-directory component")
        try:
            descriptor = os.open(relative.parts[-1], _readonly_flags(), dir_fd=directory_fd)
        except OSError as exc:
            raise StagingError("file could not be opened safely") from exc
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            os.close(descriptor)
            raise StagingError("file is not a single-link regular file")
        return descriptor
    finally:
        if directory_fd != root_fd:
            os.close(directory_fd)
        os.close(root_fd)


def hash_verified_descriptor(descriptor: int, *, maximum_bytes: int) -> tuple[int, str]:
    """Hash an open regular file and reject mutation during the read."""
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise StagingError("file is not a single-link regular file")
    if before.st_size < 0 or before.st_size > maximum_bytes:
        raise StagingError("file exceeds the configured size limit")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while chunk := os.read(descriptor, _CHUNK_SIZE):
        total += len(chunk)
        if total > maximum_bytes:
            raise StagingError("file exceeds the configured size limit")
        digest.update(chunk)
    after = os.fstat(descriptor)
    if _signature(before) != _signature(after) or total != before.st_size:
        raise StagingError("file changed while it was read")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return total, digest.hexdigest()


def read_verified_descriptor(descriptor: int, *, maximum_bytes: int) -> bytes:
    """Read an open regular file into immutable bytes, detecting concurrent changes."""
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise StagingError("file is not a single-link regular file")
    if before.st_size < 0 or before.st_size > maximum_bytes:
        raise StagingError("file exceeds the configured size limit")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while chunk := os.read(descriptor, min(_CHUNK_SIZE, maximum_bytes + 1 - total)):
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum_bytes:
            raise StagingError("file exceeds the configured size limit")
    after = os.fstat(descriptor)
    if _signature(before) != _signature(after) or total != before.st_size:
        raise StagingError("file changed while it was read")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(chunks)


class StagingStore:
    """Copy reviewed sources into a private, durable gateway-owned root."""

    def __init__(
        self,
        root: Path,
        *,
        allowed_source_roots: tuple[Path, ...] = (),
        max_file_bytes: int = 25 * 1024 * 1024,
        max_total_bytes: int = 50 * 1024 * 1024,
        minimum_free_bytes: int = 100 * 1024 * 1024,
    ) -> None:
        if max_file_bytes < 0 or max_total_bytes < 0 or minimum_free_bytes < 0:
            raise ValueError("staging capacity limits must be non-negative")
        requested_root = Path(root).absolute()
        if requested_root.is_symlink():
            raise StagingError("staging root must not be a symbolic link")
        requested_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = requested_root.resolve(strict=True)
        os.chmod(self.root, 0o700)
        root_fd = os.open(self.root, _directory_flags())
        try:
            root_metadata = os.fstat(root_fd)
            if not stat.S_ISDIR(root_metadata.st_mode):
                raise StagingError("staging root is not a directory")
            self._root_identity = _identity(root_metadata)
        finally:
            os.close(root_fd)

        metadata_root = self.root / ".metadata"
        if metadata_root.is_symlink():
            raise StagingError("staging metadata root must not be a symbolic link")
        metadata_root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(metadata_root, 0o700)
        self._metadata_root = metadata_root
        metadata_fd = os.open(metadata_root, _directory_flags())
        try:
            self._metadata_identity = _identity(os.fstat(metadata_fd))
            os.fsync(metadata_fd)
        finally:
            os.close(metadata_fd)
        self._fsync_root()

        source_roots: list[Path] = []
        source_identities: list[tuple[int, int]] = []
        for source_root in allowed_source_roots:
            canonical = Path(source_root).resolve(strict=True)
            descriptor = os.open(canonical, _directory_flags())
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISDIR(metadata.st_mode):
                    raise StagingError("allowed source root is not a directory")
                source_roots.append(canonical)
                source_identities.append(_identity(metadata))
            finally:
                os.close(descriptor)
        self.allowed_source_roots = tuple(source_roots)
        self._source_root_identities = tuple(source_identities)
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.minimum_free_bytes = minimum_free_bytes

        root_fd = self._open_root()
        try:
            lock_fd = os.open(
                ".staging.lock",
                os.O_RDWR
                | os.O_CREAT
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=root_fd,
            )
            try:
                lock_metadata = os.fstat(lock_fd)
                if not stat.S_ISREG(lock_metadata.st_mode) or lock_metadata.st_nlink != 1:
                    raise StagingError("staging lock is unsafe")
                self._lock_identity = _identity(lock_metadata)
            finally:
                os.close(lock_fd)
            os.fsync(root_fd)
        finally:
            os.close(root_fd)

    def _open_root(self) -> int:
        try:
            descriptor = os.open(self.root, _directory_flags())
        except OSError as exc:
            raise StagingError("staging root is unavailable") from exc
        if _identity(os.fstat(descriptor)) != self._root_identity:
            os.close(descriptor)
            raise StagingError("staging root changed after initialization")
        return descriptor

    def _open_metadata_root(self) -> int:
        try:
            descriptor = os.open(self._metadata_root, _directory_flags())
        except OSError as exc:
            raise StagingError("staging metadata root is unavailable") from exc
        if _identity(os.fstat(descriptor)) != self._metadata_identity:
            os.close(descriptor)
            raise StagingError("staging metadata root changed after initialization")
        return descriptor

    @contextmanager
    def _locked(self) -> Iterator[None]:
        root_fd = self._open_root()
        try:
            try:
                lock_fd = os.open(".staging.lock", _readonly_flags(), dir_fd=root_fd)
            except OSError as exc:
                raise StagingError("staging lock is unavailable") from exc
            try:
                metadata = os.fstat(lock_fd)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or _identity(metadata) != self._lock_identity
                ):
                    raise StagingError("staging lock is unsafe")
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(lock_fd)
        finally:
            os.close(root_fd)

    def _fsync_root(self) -> None:
        descriptor = self._open_root()
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _open_source(self, source: Path) -> int:
        source = Path(source)
        if ".." in source.parts:
            raise StagingError("source path traversal is forbidden")
        candidate = Path(os.path.abspath(source))
        for root, identity in zip(
            self.allowed_source_roots, self._source_root_identities, strict=True
        ):
            try:
                candidate.relative_to(root)
            except ValueError:
                continue
            try:
                return open_confined_readonly(
                    root,
                    candidate,
                    expected_root_identity=identity,
                )
            except StagingError as exc:
                raise StagingError("source could not be opened safely") from exc
        raise StagingError("source is outside the reviewed staging roots")

    def _durable_content_bytes(self) -> int:
        root_fd = self._open_root()
        try:
            total = 0
            for name in os.listdir(root_fd):
                if not (name.startswith("stg_") or name.startswith(".stg_")):
                    continue
                metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise StagingError("staging root contains an unsafe content entry")
                total += metadata.st_size
            return total
        finally:
            os.close(root_fd)

    def _check_capacity(self, incoming: int) -> None:
        if incoming < 0 or incoming > self.max_file_bytes:
            raise StagingError("file exceeds the configured size limit")
        if self._durable_content_bytes() + incoming > self.max_total_bytes:
            raise StagingError("staging total exceeds the configured limit")
        if shutil.disk_usage(self.root).free - incoming < self.minimum_free_bytes:
            raise StagingError("insufficient disk headroom")

    @staticmethod
    def _metadata_document(record: StagedFile) -> bytes:
        document = {
            "format": 1,
            "opaque_id": record.opaque_id,
            "adapter": record.adapter,
            "account": record.account,
            "filename": record.filename,
            "declared_mime": record.declared_mime,
            "detected_mime": record.detected_mime,
            "size": record.size,
            "sha256": record.sha256,
            "created_at": record.created_at,
        }
        encoded = json.dumps(
            document,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        return encoded.encode("utf-8")

    def _write_metadata(self, record: StagedFile) -> None:
        metadata_fd = self._open_metadata_root()
        temporary_name = f".{record.opaque_id}.tmp"
        final_name = f"{record.opaque_id}.json"
        descriptor: int | None = None
        temporary_created = False
        published = False
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=metadata_fd,
            )
            temporary_created = True
            _write_all(descriptor, self._metadata_document(record))
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.rename(
                temporary_name,
                final_name,
                src_dir_fd=metadata_fd,
                dst_dir_fd=metadata_fd,
            )
            temporary_created = False
            published = True
            os.fsync(metadata_fd)
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            if temporary_created:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=metadata_fd)
            if published:
                with suppress(FileNotFoundError):
                    os.unlink(final_name, dir_fd=metadata_fd)
                os.fsync(metadata_fd)
            raise
        finally:
            os.close(metadata_fd)

    def stage_path(
        self,
        source: Path,
        *,
        adapter: str,
        account: str,
        filename: str,
        declared_mime: str,
    ) -> StagedFile:
        filename = _validate_filename(filename)
        adapter = _validate_bounded_text(adapter, name="adapter")
        account = _validate_bounded_text(account, name="account")
        declared_mime = _validate_bounded_text(
            declared_mime, name="declared MIME type", maximum=255
        )
        source_fd = self._open_source(Path(source))
        output_fd: int | None = None
        root_fd: int | None = None
        opaque_id = f"stg_{secrets.token_urlsafe(18).replace('-', '_')}"
        temporary_name = f".{opaque_id}.tmp"
        temporary_created = False
        published = False
        metadata_published = False
        try:
            source_metadata = os.fstat(source_fd)
            if not stat.S_ISREG(source_metadata.st_mode) or source_metadata.st_nlink != 1:
                raise StagingError("source must be a single-link regular file")
            with self._locked():
                self._check_capacity(source_metadata.st_size)
                root_fd = self._open_root()
                metadata_fd = self._open_metadata_root()
                try:
                    if _entry_exists(opaque_id, directory_fd=root_fd) or _entry_exists(
                        f"{opaque_id}.json", directory_fd=metadata_fd
                    ):
                        raise StagingError("generated staged object identifier already exists")
                finally:
                    os.close(metadata_fd)
                output_fd = os.open(
                    temporary_name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=root_fd,
                )
                temporary_created = True
                source_digest = hashlib.sha256()
                total = 0
                while chunk := os.read(source_fd, _CHUNK_SIZE):
                    total += len(chunk)
                    if total > self.max_file_bytes:
                        raise StagingError("file exceeds the configured size limit")
                    source_digest.update(chunk)
                    _write_all(output_fd, chunk)
                source_after = os.fstat(source_fd)
                if _signature(source_metadata) != _signature(source_after) or (
                    total != source_metadata.st_size
                ):
                    raise StagingError("source changed while it was copied")
                os.fsync(output_fd)
                copied_size, copied_hash = hash_verified_descriptor(
                    output_fd,
                    maximum_bytes=self.max_file_bytes,
                )
                if copied_size != total or copied_hash != source_digest.hexdigest():
                    raise StagingError("staged copy failed integrity verification")
                os.close(output_fd)
                output_fd = None
                os.rename(
                    temporary_name,
                    opaque_id,
                    src_dir_fd=root_fd,
                    dst_dir_fd=root_fd,
                )
                temporary_created = False
                published = True
                os.fsync(root_fd)
                detected = mimetypes.guess_type(filename)[0] or "application/octet-stream"
                record = StagedFile(
                    opaque_id=opaque_id,
                    adapter=adapter,
                    account=account,
                    filename=filename,
                    declared_mime=declared_mime,
                    detected_mime=detected,
                    size=total,
                    sha256=copied_hash,
                    path=self.root / opaque_id,
                    created_at=int(time.time()),
                )
                self._write_metadata(record)
                metadata_published = True
                return record
        except BaseException:
            if output_fd is not None:
                os.close(output_fd)
            if root_fd is None:
                root_fd = self._open_root()
            try:
                if temporary_created:
                    with suppress(FileNotFoundError):
                        os.unlink(temporary_name, dir_fd=root_fd)
                if published and not metadata_published:
                    with suppress(FileNotFoundError):
                        os.unlink(opaque_id, dir_fd=root_fd)
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
                root_fd = None
            raise
        finally:
            if root_fd is not None:
                os.close(root_fd)
            os.close(source_fd)

    def _load_record(self, opaque_id: str) -> StagedFile:
        if not _OPAQUE_ID_RE.fullmatch(opaque_id):
            raise StagingError("staged object was not found in this scope")
        path = self._metadata_root / f"{opaque_id}.json"
        try:
            descriptor = open_confined_readonly(
                self._metadata_root,
                path,
                expected_root_identity=self._metadata_identity,
            )
        except StagingError as exc:
            raise StagingError("staged object was not found in this scope") from exc
        try:
            raw = read_verified_descriptor(descriptor, maximum_bytes=_METADATA_LIMIT)
        finally:
            os.close(descriptor)
        try:
            value: Any = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StagingError("staged object metadata is invalid") from exc
        if not isinstance(value, dict) or set(value) != _METADATA_KEYS or value.get("format") != 1:
            raise StagingError("staged object metadata is invalid")
        fields = (
            "opaque_id",
            "adapter",
            "account",
            "filename",
            "declared_mime",
            "detected_mime",
            "sha256",
        )
        if any(not isinstance(value.get(field), str) for field in fields):
            raise StagingError("staged object metadata is invalid")
        size = value.get("size")
        created_at = value.get("created_at")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > self.max_file_bytes
            or isinstance(created_at, bool)
            or not isinstance(created_at, int)
            or created_at < 0
            or value["opaque_id"] != opaque_id
            or not _SHA256_RE.fullmatch(value["sha256"])
        ):
            raise StagingError("staged object metadata is invalid")
        try:
            return StagedFile(
                opaque_id=opaque_id,
                adapter=_validate_bounded_text(value["adapter"], name="adapter"),
                account=_validate_bounded_text(value["account"], name="account"),
                filename=_validate_filename(value["filename"]),
                declared_mime=_validate_bounded_text(
                    value["declared_mime"], name="declared MIME type", maximum=255
                ),
                detected_mime=_validate_bounded_text(
                    value["detected_mime"], name="detected MIME type", maximum=255
                ),
                size=size,
                sha256=value["sha256"],
                path=self.root / opaque_id,
                created_at=created_at,
            )
        except StagingError as exc:
            raise StagingError("staged object metadata is invalid") from exc

    def _scoped_record(self, opaque_id: str, *, adapter: str, account: str) -> StagedFile:
        record = self._load_record(opaque_id)
        if record.adapter != adapter or record.account != account:
            raise StagingError("staged object was not found in this scope")
        return record

    def _open_record(self, record: StagedFile) -> int:
        return open_confined_readonly(
            self.root,
            record.path,
            expected_root_identity=self._root_identity,
        )

    def resolve(self, opaque_id: str, *, adapter: str, account: str) -> StagedFile:
        with self._locked():
            record = self._scoped_record(opaque_id, adapter=adapter, account=account)
            descriptor = self._open_record(record)
            try:
                size, digest = hash_verified_descriptor(
                    descriptor,
                    maximum_bytes=self.max_file_bytes,
                )
            finally:
                os.close(descriptor)
            if size != record.size or digest != record.sha256:
                raise StagingError("staged object failed integrity verification")
            return record

    def read_verified(
        self,
        opaque_id: str,
        *,
        adapter: str,
        account: str,
    ) -> tuple[StagedFile, bytes]:
        """Return metadata and byte-identical content from one verified descriptor."""
        with self._locked():
            record = self._scoped_record(opaque_id, adapter=adapter, account=account)
            descriptor = self._open_record(record)
            try:
                content = read_verified_descriptor(
                    descriptor,
                    maximum_bytes=self.max_file_bytes,
                )
            finally:
                os.close(descriptor)
            if len(content) != record.size or hashlib.sha256(content).hexdigest() != record.sha256:
                raise StagingError("staged object failed integrity verification")
            return record, content

    def purge(
        self,
        opaque_id: str,
        *,
        adapter: str | None = None,
        account: str | None = None,
    ) -> None:
        if not _OPAQUE_ID_RE.fullmatch(opaque_id):
            return
        with self._locked():
            if adapter is not None or account is not None:
                if adapter is None or account is None:
                    raise ValueError("adapter and account must be supplied together")
                self._scoped_record(opaque_id, adapter=adapter, account=account)
            root_fd = self._open_root()
            metadata_fd = self._open_metadata_root()
            try:
                for descriptor, name in (
                    (root_fd, opaque_id),
                    (metadata_fd, f"{opaque_id}.json"),
                ):
                    with suppress(FileNotFoundError):
                        os.unlink(name, dir_fd=descriptor)
                os.fsync(root_fd)
                os.fsync(metadata_fd)
            finally:
                os.close(metadata_fd)
                os.close(root_fd)

    def purge_verified(
        self,
        opaque_id: str,
        *,
        expected_path: Path,
        expected_size: int,
        expected_sha256: str,
        missing_ok: bool = False,
    ) -> None:
        """Unlink one DB-owned object and sidecar after confined integrity checks.

        ``missing_ok`` exists for the narrow crash-recovery case where filesystem
        unlink completed before the owning SQLite transaction committed.
        """

        if not _OPAQUE_ID_RE.fullmatch(opaque_id):
            raise StagingError("staged object identifier is invalid")
        candidate = Path(expected_path)
        if not candidate.is_absolute() or candidate != self.root / opaque_id:
            raise StagingError("staged object path is outside the private root")
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
            or expected_size > self.max_file_bytes
            or not isinstance(expected_sha256, str)
            or _SHA256_RE.fullmatch(expected_sha256) is None
            or not isinstance(missing_ok, bool)
        ):
            raise ValueError("staged object purge expectation is invalid")

        with self._locked():
            root_fd = self._open_root()
            metadata_fd = self._open_metadata_root()
            content_fd: int | None = None
            content_present = False
            metadata_present = False
            try:
                try:
                    content_fd = os.open(opaque_id, _readonly_flags(), dir_fd=root_fd)
                except FileNotFoundError:
                    if not missing_ok:
                        raise StagingError("staged object is unavailable") from None
                except OSError as exc:
                    raise StagingError("staged object is unsafe") from exc
                else:
                    content_present = True
                    opened = os.fstat(content_fd)
                    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                        raise StagingError("staged object is unsafe")
                    size, digest = hash_verified_descriptor(
                        content_fd,
                        maximum_bytes=self.max_file_bytes,
                    )
                    if size != expected_size or digest != expected_sha256:
                        raise StagingError("staged object failed purge integrity verification")
                    named = os.stat(opaque_id, dir_fd=root_fd, follow_symlinks=False)
                    if (
                        not stat.S_ISREG(named.st_mode)
                        or named.st_nlink != 1
                        or _identity(named) != _identity(opened)
                    ):
                        raise StagingError("staged object changed before purge")

                metadata_name = f"{opaque_id}.json"
                try:
                    metadata = os.stat(
                        metadata_name,
                        dir_fd=metadata_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    raise StagingError("staged object metadata is unsafe") from exc
                else:
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                        raise StagingError("staged object metadata is unsafe")
                    metadata_present = True

                if content_present:
                    os.unlink(opaque_id, dir_fd=root_fd)
                if metadata_present:
                    os.unlink(metadata_name, dir_fd=metadata_fd)
                os.fsync(root_fd)
                os.fsync(metadata_fd)
            finally:
                if content_fd is not None:
                    os.close(content_fd)
                os.close(metadata_fd)
                os.close(root_fd)

    def sweep_orphans(
        self,
        *,
        protected_ids: Collection[str] = (),
        minimum_age_seconds: int = 300,
        now: int | None = None,
    ) -> int:
        """Remove only aged unpublished files, never catalogued or protected objects."""
        if minimum_age_seconds < 0:
            raise ValueError("orphan sweep grace period must be non-negative")
        protected = {value for value in protected_ids if _OPAQUE_ID_RE.fullmatch(value)}
        cutoff = (int(time.time()) if now is None else now) - minimum_age_seconds
        removed = 0
        with self._locked():
            root_fd = self._open_root()
            metadata_fd = self._open_metadata_root()
            try:
                metadata_names = set(os.listdir(metadata_fd))
                catalogued = {
                    name.removesuffix(".json")
                    for name in metadata_names
                    if name.endswith(".json")
                    and _OPAQUE_ID_RE.fullmatch(name.removesuffix(".json"))
                }
                for name in os.listdir(root_fd):
                    opaque_id: str | None = None
                    if _OPAQUE_ID_RE.fullmatch(name):
                        opaque_id = name
                    elif name.startswith(".stg_") and name.endswith(".tmp"):
                        candidate = name[1:-4]
                        if _OPAQUE_ID_RE.fullmatch(candidate):
                            opaque_id = candidate
                    if opaque_id is None or opaque_id in catalogued or opaque_id in protected:
                        continue
                    metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                    if (
                        stat.S_ISREG(metadata.st_mode)
                        and metadata.st_nlink == 1
                        and int(metadata.st_mtime) <= cutoff
                    ):
                        os.unlink(name, dir_fd=root_fd)
                        removed += 1
                for name in metadata_names:
                    if not (name.startswith(".stg_") and name.endswith(".tmp")):
                        continue
                    metadata = os.stat(name, dir_fd=metadata_fd, follow_symlinks=False)
                    if (
                        stat.S_ISREG(metadata.st_mode)
                        and metadata.st_nlink == 1
                        and int(metadata.st_mtime) <= cutoff
                    ):
                        os.unlink(name, dir_fd=metadata_fd)
                        removed += 1
                if removed:
                    os.fsync(root_fd)
                    os.fsync(metadata_fd)
            finally:
                os.close(metadata_fd)
                os.close(root_fd)
        return removed


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("staged file write made no progress")
        view = view[written:]
