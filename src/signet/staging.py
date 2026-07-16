"""Filesystem confinement primitives for local virtualized objects."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import time
from collections.abc import Collection, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any

import puremagic

from signet.attachment_crypto import (
    ATTACHMENT_ENVELOPE_FORMAT,
    AttachmentCipher,
    AttachmentContext,
    AttachmentEnvelopeError,
)
from signet.db import Database, IntegrityError
from signet.private_paths import (
    PrivatePathError,
    ensure_private_directory,
    require_no_acl_grants,
)


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


@dataclass(frozen=True, slots=True, repr=False)
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
    envelope_format: str = ATTACHMENT_ENVELOPE_FORMAT
    envelope_size: int = 0
    envelope_sha256: str = ""
    encryption_key_ref: str = ""
    detection_source: str = "content_signature_v1"

    def __repr__(self) -> str:
        return (
            "StagedFile(opaque_id=<redacted>, adapter=<redacted>, account=<redacted>, "
            "filename=<redacted>, content=<redacted>, encryption_key_ref=<redacted>)"
        )


_OPAQUE_ID_RE = re.compile(r"stg_[A-Za-z0-9_]{20,64}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_METADATA_V2_KEYS = {
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
    "envelope_format",
    "envelope_size",
    "envelope_sha256",
    "encryption_key_ref",
}
_METADATA_KEYS = {*_METADATA_V2_KEYS, "detection_source"}
_CHUNK_SIZE = 1024 * 1024
_METADATA_LIMIT = 64 * 1024
_CONTENT_SNIFF_LIMIT = 64 * 1024


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


def _detected_content_mime(content: bytes) -> str:
    """Return a bounded best-effort content signature, never a filename guess."""

    sample = content[:_CONTENT_SNIFF_LIMIT]
    if not sample:
        return "application/octet-stream"
    try:
        detected = puremagic.from_string(sample, mime=True)
    except puremagic.PureError:
        detected = None
    if isinstance(detected, str) and detected and len(detected) <= 255:
        return detected
    try:
        decoded = sample.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return "application/octet-stream"
    if decoded and all(
        character in "\t\n\r" or (ord(character) >= 32 and ord(character) != 127)
        for character in decoded
    ):
        return "text/plain"
    return "application/octet-stream"


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
    return _hash_stable_descriptor(
        descriptor,
        maximum_bytes=maximum_bytes,
        allowed_link_counts=frozenset({1}),
    )


def _hash_stable_descriptor(
    descriptor: int,
    *,
    maximum_bytes: int,
    allowed_link_counts: Collection[int],
) -> tuple[int, str]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink not in allowed_link_counts:
        raise StagingError("file is not a regular file with the expected link state")
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
        database: Database,
        cipher: AttachmentCipher,
        allowed_source_roots: tuple[Path, ...] = (),
        max_file_bytes: int = 25 * 1024 * 1024,
        max_total_bytes: int = 50 * 1024 * 1024,
        minimum_free_bytes: int = 100 * 1024 * 1024,
    ) -> None:
        if not isinstance(database, Database):
            raise TypeError("staging database is required")
        if not isinstance(cipher, AttachmentCipher):
            raise TypeError("staging attachment cipher is required")
        if max_file_bytes < 0 or max_total_bytes < 0 or minimum_free_bytes < 0:
            raise ValueError("staging capacity limits must be non-negative")
        if max_file_bytes > cipher.max_plaintext_bytes:
            raise ValueError("staging file limit exceeds the attachment cipher limit")
        self.database = database
        self._cipher = cipher
        requested_root = Path(root).absolute()
        try:
            self.root = ensure_private_directory(requested_root)
        except PrivatePathError as exc:
            raise StagingError("staging root must be an owned mode-0700 directory") from exc
        root_fd = os.open(self.root, _directory_flags())
        try:
            root_metadata = os.fstat(root_fd)
            if not stat.S_ISDIR(root_metadata.st_mode):
                raise StagingError("staging root is not a directory")
            self._root_identity = _identity(root_metadata)
        finally:
            os.close(root_fd)

        metadata_root = self.root / ".metadata"
        try:
            self._metadata_root = ensure_private_directory(metadata_root)
        except PrivatePathError as exc:
            raise StagingError(
                "staging metadata root must be an owned mode-0700 directory"
            ) from exc
        metadata_root = self._metadata_root
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
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=root_fd,
            )
            try:
                lock_metadata = os.fstat(lock_fd)
                current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
                if (
                    not stat.S_ISREG(lock_metadata.st_mode)
                    or lock_metadata.st_uid != current_uid
                    or lock_metadata.st_nlink != 1
                ):
                    raise StagingError("staging lock is unsafe")
                os.fchmod(lock_fd, 0o600)
                try:
                    require_no_acl_grants(lock_fd)
                except PrivatePathError as exc:
                    raise StagingError("staging lock is unsafe") from exc
                lock_metadata = os.fstat(lock_fd)
                if stat.S_IMODE(lock_metadata.st_mode) != 0o600:
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
        envelope_size = self._cipher.envelope_size(incoming)
        if self._durable_content_bytes() + envelope_size > self.max_total_bytes:
            raise StagingError("staging total exceeds the configured limit")
        if shutil.disk_usage(self.root).free - envelope_size < self.minimum_free_bytes:
            raise StagingError("insufficient disk headroom")

    @staticmethod
    def _metadata_document(record: StagedFile, *, format_version: int = 3) -> bytes:
        if format_version not in {2, 3}:
            raise ValueError("staged object metadata format is unsupported")
        document = {
            "format": format_version,
            "opaque_id": record.opaque_id,
            "adapter": record.adapter,
            "account": record.account,
            "filename": record.filename,
            "declared_mime": record.declared_mime,
            "detected_mime": record.detected_mime,
            "size": record.size,
            "sha256": record.sha256,
            "created_at": record.created_at,
            "envelope_format": record.envelope_format,
            "envelope_size": record.envelope_size,
            "envelope_sha256": record.envelope_sha256,
            "encryption_key_ref": record.encryption_key_ref,
        }
        if format_version == 3:
            document["detection_source"] = record.detection_source
        encoded = json.dumps(
            document,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        return encoded.encode("utf-8")

    @classmethod
    def metadata_document(cls, record: StagedFile, *, format_version: int = 3) -> bytes:
        """Serialize one validated sidecar for backup restoration."""

        if not isinstance(record, StagedFile):
            raise TypeError("staged object metadata record is invalid")
        return cls._metadata_document(record, format_version=format_version)

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

    def _insert_catalog(self, record: StagedFile) -> None:
        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO staged_objects(
                        attachment_id, adapter, account, filename, declared_mime,
                        detected_mime, detection_source, size_bytes, sha256, storage_path,
                        envelope_format, envelope_size, envelope_sha256,
                        encryption_key_ref, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.opaque_id,
                        record.adapter,
                        record.account,
                        record.filename,
                        record.declared_mime,
                        record.detected_mime,
                        record.detection_source,
                        record.size,
                        record.sha256,
                        str(record.path),
                        record.envelope_format,
                        record.envelope_size,
                        record.envelope_sha256,
                        record.encryption_key_ref,
                        record.created_at,
                    ),
                )
        except IntegrityError as exc:
            raise StagingError("staged object catalog registration failed") from exc

    def _catalog_record(self, opaque_id: str) -> StagedFile:
        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT attachment_id, adapter, account, filename, declared_mime,
                       detected_mime, detection_source, size_bytes, sha256, storage_path,
                       envelope_format, envelope_size, envelope_sha256,
                       encryption_key_ref, created_at, purged_at, key_destroyed_at
                FROM staged_objects WHERE attachment_id = ?
                """,
                (opaque_id,),
            ).fetchone()
        if (
            row is None
            or row["storage_path"] is None
            or row["purged_at"] is not None
            or row["key_destroyed_at"] is not None
            or not isinstance(row["encryption_key_ref"], str)
        ):
            raise StagingError("staged object was not found in this scope")
        return StagedFile(
            opaque_id=str(row["attachment_id"]),
            adapter=str(row["adapter"]),
            account=str(row["account"]),
            filename=str(row["filename"]),
            declared_mime=str(row["declared_mime"]),
            detected_mime=str(row["detected_mime"]),
            size=int(row["size_bytes"]),
            sha256=str(row["sha256"]),
            path=Path(str(row["storage_path"])),
            created_at=int(row["created_at"]),
            envelope_format=str(row["envelope_format"]),
            envelope_size=int(row["envelope_size"]),
            envelope_sha256=str(row["envelope_sha256"]),
            encryption_key_ref=str(row["encryption_key_ref"]),
            detection_source=str(row["detection_source"]),
        )

    @staticmethod
    def _same_record(left: StagedFile, right: StagedFile) -> bool:
        return left == right

    @staticmethod
    def _context(record: StagedFile) -> AttachmentContext:
        return AttachmentContext(
            opaque_id=record.opaque_id,
            adapter=record.adapter,
            account=record.account,
            filename=record.filename,
            declared_mime=record.declared_mime,
            detected_mime=record.detected_mime,
            size=record.size,
            sha256=record.sha256,
            created_at=record.created_at,
        )

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
        catalog_published = False
        try:
            source_metadata = os.fstat(source_fd)
            if not stat.S_ISREG(source_metadata.st_mode) or source_metadata.st_nlink != 1:
                raise StagingError("source must be a single-link regular file")
            with self._locked():
                self._check_capacity(source_metadata.st_size)
                plaintext = read_verified_descriptor(
                    source_fd,
                    maximum_bytes=self.max_file_bytes,
                )
                plaintext_hash = hashlib.sha256(plaintext).hexdigest()
                detected = _detected_content_mime(plaintext)
                created_at = int(time.time())
                context = AttachmentContext(
                    opaque_id=opaque_id,
                    adapter=adapter,
                    account=account,
                    filename=filename,
                    declared_mime=declared_mime,
                    detected_mime=detected,
                    size=len(plaintext),
                    sha256=plaintext_hash,
                    created_at=created_at,
                )
                try:
                    envelope = self._cipher.encrypt(plaintext, context=context)
                except AttachmentEnvelopeError as exc:
                    raise StagingError("staged object encryption failed") from exc
                finally:
                    del plaintext
                envelope_hash = hashlib.sha256(envelope).hexdigest()
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
                _write_all(output_fd, envelope)
                os.fsync(output_fd)
                copied_size, copied_hash = hash_verified_descriptor(
                    output_fd,
                    maximum_bytes=self._cipher.maximum_envelope_bytes,
                )
                if copied_size != len(envelope) or copied_hash != envelope_hash:
                    raise StagingError("encrypted staged copy failed integrity verification")
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
                record = StagedFile(
                    opaque_id=opaque_id,
                    adapter=adapter,
                    account=account,
                    filename=filename,
                    declared_mime=declared_mime,
                    detected_mime=detected,
                    size=context.size,
                    sha256=context.sha256,
                    path=self.root / opaque_id,
                    created_at=created_at,
                    envelope_size=copied_size,
                    envelope_sha256=copied_hash,
                    encryption_key_ref=self._cipher.key_reference,
                )
                self._write_metadata(record)
                metadata_published = True
                self._insert_catalog(record)
                catalog_published = True
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
                if published and not catalog_published:
                    with suppress(FileNotFoundError):
                        os.unlink(opaque_id, dir_fd=root_fd)
                if metadata_published and not catalog_published:
                    metadata_fd = self._open_metadata_root()
                    try:
                        with suppress(FileNotFoundError):
                            os.unlink(f"{opaque_id}.json", dir_fd=metadata_fd)
                        os.fsync(metadata_fd)
                    finally:
                        os.close(metadata_fd)
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
        if not isinstance(value, dict):
            raise StagingError("staged object metadata is invalid")
        metadata_format = value.get("format")
        expected_keys = _METADATA_V2_KEYS if metadata_format == 2 else _METADATA_KEYS
        if metadata_format not in {2, 3} or set(value) != expected_keys:
            raise StagingError("staged object metadata is invalid")
        fields = (
            "opaque_id",
            "adapter",
            "account",
            "filename",
            "declared_mime",
            "detected_mime",
            "sha256",
            "envelope_format",
            "envelope_sha256",
            "encryption_key_ref",
        )
        if any(not isinstance(value.get(field), str) for field in fields):
            raise StagingError("staged object metadata is invalid")
        detection_source = (
            "legacy_filename_unverified" if metadata_format == 2 else value.get("detection_source")
        )
        size = value.get("size")
        created_at = value.get("created_at")
        envelope_size = value.get("envelope_size")
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
            or value["envelope_format"] != ATTACHMENT_ENVELOPE_FORMAT
            or isinstance(envelope_size, bool)
            or not isinstance(envelope_size, int)
            or envelope_size != self._cipher.envelope_size(size)
            or not _SHA256_RE.fullmatch(value["envelope_sha256"])
            or value["encryption_key_ref"] != self._cipher.key_reference
            or detection_source not in {"legacy_filename_unverified", "content_signature_v1"}
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
                envelope_format=value["envelope_format"],
                envelope_size=envelope_size,
                envelope_sha256=value["envelope_sha256"],
                encryption_key_ref=value["encryption_key_ref"],
                detection_source=detection_source,
            )
        except StagingError as exc:
            raise StagingError("staged object metadata is invalid") from exc

    def _scoped_record(self, opaque_id: str, *, adapter: str, account: str) -> StagedFile:
        record = self._load_record(opaque_id)
        catalog = self._catalog_record(opaque_id)
        if not self._same_record(record, catalog):
            raise StagingError("staged object catalog failed integrity verification")
        if record.adapter != adapter or record.account != account:
            raise StagingError("staged object was not found in this scope")
        return catalog

    def _open_record(self, record: StagedFile) -> int:
        return open_confined_readonly(
            self.root,
            record.path,
            expected_root_identity=self._root_identity,
        )

    def _read_plaintext(self, record: StagedFile) -> bytes:
        descriptor = self._open_record(record)
        try:
            envelope = read_verified_descriptor(
                descriptor,
                maximum_bytes=self._cipher.maximum_envelope_bytes,
            )
        finally:
            os.close(descriptor)
        return self.authenticate_envelope(record, envelope)

    def authenticate_envelope(self, record: StagedFile, envelope: bytes) -> bytes:
        """Authenticate externally copied envelope bytes against catalog metadata."""

        if not isinstance(record, StagedFile) or not isinstance(envelope, bytes):
            raise TypeError("staged object envelope verification input is invalid")
        if (
            record.envelope_format != ATTACHMENT_ENVELOPE_FORMAT
            or len(envelope) != record.envelope_size
            or not hmac.compare_digest(hashlib.sha256(envelope).hexdigest(), record.envelope_sha256)
        ):
            raise StagingError("staged object envelope failed integrity verification")
        try:
            return self._cipher.decrypt(
                envelope,
                context=self._context(record),
                key_reference=record.encryption_key_ref,
            )
        except AttachmentEnvelopeError as exc:
            raise StagingError("staged object failed authenticated decryption") from exc

    def resolve(self, opaque_id: str, *, adapter: str, account: str) -> StagedFile:
        with self._locked():
            record = self._scoped_record(opaque_id, adapter=adapter, account=account)
            plaintext = self._read_plaintext(record)
            if len(plaintext) != record.size or not hmac.compare_digest(
                hashlib.sha256(plaintext).hexdigest(), record.sha256
            ):
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
            content = self._read_plaintext(record)
            if len(content) != record.size or not hmac.compare_digest(
                hashlib.sha256(content).hexdigest(), record.sha256
            ):
                raise StagingError("staged object failed integrity verification")
            return record, content

    @contextmanager
    def plaintext_descriptor(
        self,
        opaque_id: str,
        *,
        adapter: str,
        account: str,
        expected_size: int,
        expected_sha256: str,
    ) -> Iterator[tuple[StagedFile, int]]:
        """Yield approved plaintext only through a mode-0600 anonymous descriptor."""

        with self._locked():
            record = self._scoped_record(opaque_id, adapter=adapter, account=account)
            if record.size != expected_size or not hmac.compare_digest(
                record.sha256, expected_sha256
            ):
                raise StagingError("staged object no longer matches approved metadata")
            plaintext = self._read_plaintext(record)
        with tempfile.TemporaryFile(mode="w+b", dir=self.root) as temporary:
            os.fchmod(temporary.fileno(), 0o600)
            metadata = os.fstat(temporary.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 0:
                raise StagingError("platform did not create an anonymous plaintext file")
            _write_all(temporary.fileno(), plaintext)
            del plaintext
            os.fsync(temporary.fileno())
            size, digest = _hash_stable_descriptor(
                temporary.fileno(),
                maximum_bytes=self.max_file_bytes,
                allowed_link_counts=frozenset({0}),
            )
            if size != record.size or not hmac.compare_digest(digest, record.sha256):
                raise StagingError("plaintext descriptor failed integrity verification")
            yield record, temporary.fileno()

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
            with self.database.transaction() as connection:
                catalog = connection.execute(
                    """
                    SELECT adapter, account, consumed_request_id, storage_path, purged_at
                    FROM staged_objects WHERE attachment_id = ?
                    """,
                    (opaque_id,),
                ).fetchone()
                if catalog is None or catalog["purged_at"] is not None:
                    return
                if (
                    adapter is not None
                    and account is not None
                    and (catalog["adapter"] != adapter or catalog["account"] != account)
                ):
                    raise StagingError("staged object was not found in this scope")
                if catalog["consumed_request_id"] is not None:
                    raise StagingError("a consumed staged object requires retention-owned purge")
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
                updated = connection.execute(
                    """
                    UPDATE staged_objects SET storage_path = NULL, purged_at = ?
                    WHERE attachment_id = ? AND consumed_request_id IS NULL
                      AND storage_path = ? AND purged_at IS NULL
                    """,
                    (int(time.time()), opaque_id, catalog["storage_path"]),
                ).rowcount
            if updated != 1:
                raise StagingError("staged object catalog changed during purge")

    def purge_verified(
        self,
        opaque_id: str,
        *,
        expected_path: Path,
        expected_size: int,
        expected_sha256: str,
        purged_at: int,
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
            or isinstance(purged_at, bool)
            or not isinstance(purged_at, int)
            or purged_at < 0
            or not isinstance(missing_ok, bool)
        ):
            raise ValueError("staged object purge expectation is invalid")

        with self._locked():
            with self.database.read() as connection:
                row = connection.execute(
                    """
                    SELECT attachment_id, adapter, account, filename, declared_mime,
                           detected_mime, size_bytes, sha256, storage_path,
                           envelope_format, envelope_size, envelope_sha256,
                           encryption_key_ref, created_at, purged_at
                    FROM staged_objects WHERE attachment_id = ?
                    """,
                    (opaque_id,),
                ).fetchone()
            if row is None:
                raise StagingError("staged object catalog entry is unavailable")
            if row["purged_at"] is not None:
                if missing_ok and row["storage_path"] is None:
                    return
                raise StagingError("staged object was already purged")
            record = StagedFile(
                opaque_id=str(row["attachment_id"]),
                adapter=str(row["adapter"]),
                account=str(row["account"]),
                filename=str(row["filename"]),
                declared_mime=str(row["declared_mime"]),
                detected_mime=str(row["detected_mime"]),
                size=int(row["size_bytes"]),
                sha256=str(row["sha256"]),
                path=Path(str(row["storage_path"])),
                created_at=int(row["created_at"]),
                envelope_format=str(row["envelope_format"]),
                envelope_size=int(row["envelope_size"]),
                envelope_sha256=str(row["envelope_sha256"]),
                encryption_key_ref=str(row["encryption_key_ref"]),
            )
            if (
                record.path != candidate
                or record.size != expected_size
                or not hmac.compare_digest(record.sha256, expected_sha256)
                or record.envelope_format != ATTACHMENT_ENVELOPE_FORMAT
                or record.encryption_key_ref != self._cipher.key_reference
            ):
                raise StagingError("staged object catalog does not match purge expectation")
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
                    envelope = read_verified_descriptor(
                        content_fd,
                        maximum_bytes=self._cipher.maximum_envelope_bytes,
                    )
                    if len(envelope) != record.envelope_size or not hmac.compare_digest(
                        hashlib.sha256(envelope).hexdigest(),
                        record.envelope_sha256,
                    ):
                        raise StagingError("staged object failed purge integrity verification")
                    try:
                        plaintext = self._cipher.decrypt(
                            envelope,
                            context=self._context(record),
                            key_reference=record.encryption_key_ref,
                        )
                    except AttachmentEnvelopeError as exc:
                        raise StagingError(
                            "staged object failed purge integrity verification"
                        ) from exc
                    if len(plaintext) != expected_size or not hmac.compare_digest(
                        hashlib.sha256(plaintext).hexdigest(), expected_sha256
                    ):
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
            with self.database.transaction() as connection:
                updated = connection.execute(
                    """
                    UPDATE staged_objects SET storage_path = NULL, purged_at = ?
                    WHERE attachment_id = ? AND storage_path = ? AND purged_at IS NULL
                      AND size_bytes = ? AND sha256 = ?
                      AND envelope_size = ? AND envelope_sha256 = ?
                    """,
                    (
                        purged_at,
                        opaque_id,
                        str(candidate),
                        expected_size,
                        expected_sha256,
                        record.envelope_size,
                        record.envelope_sha256,
                    ),
                ).rowcount
            if updated != 1:
                raise StagingError("staged object catalog changed during purge")

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
