"""Filesystem confinement primitives for local virtualized objects."""

from __future__ import annotations

import hashlib
import mimetypes
import os
import secrets
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePath


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


def _validate_filename(filename: str) -> str:
    if not filename or filename in {".", ".."}:
        raise StagingError("filename is required")
    if filename != Path(filename).name or "/" in filename or "\\" in filename:
        raise StagingError("filename must not contain a path")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in filename):
        raise StagingError("filename contains control characters")
    if len(filename.encode("utf-8")) > 255:
        raise StagingError("filename is too long")
    return filename


class StagingStore:
    """Copy reviewed sources into a private, immutable gateway-owned root."""

    def __init__(
        self,
        root: Path,
        *,
        allowed_source_roots: tuple[Path, ...] = (),
        max_file_bytes: int = 25 * 1024 * 1024,
        max_total_bytes: int = 50 * 1024 * 1024,
        minimum_free_bytes: int = 100 * 1024 * 1024,
    ) -> None:
        self.root = root.resolve()
        self.allowed_source_roots = tuple(path.resolve() for path in allowed_source_roots)
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.minimum_free_bytes = minimum_free_bytes
        self._records: dict[str, StagedFile] = {}
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)

    def _check_capacity(self, incoming: int) -> None:
        if incoming < 0 or incoming > self.max_file_bytes:
            raise StagingError("file exceeds the configured size limit")
        current = sum(record.size for record in self._records.values())
        if current + incoming > self.max_total_bytes:
            raise StagingError("staging total exceeds the configured limit")
        if shutil.disk_usage(self.root).free - incoming < self.minimum_free_bytes:
            raise StagingError("insufficient disk headroom")

    def _source_allowed(self, source: Path) -> bool:
        try:
            resolved_parent = source.parent.resolve(strict=True)
        except OSError:
            return False
        return any(
            resolved_parent == root or root in resolved_parent.parents
            for root in self.allowed_source_roots
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
        if not adapter or not account:
            raise StagingError("adapter and account scope are required")
        source = Path(source)
        if not self._source_allowed(source):
            raise StagingError("source is outside the reviewed staging roots")
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise StagingError("source must be a single-link regular file")
        self._check_capacity(before.st_size)

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        source_fd = os.open(source, flags)
        opaque_id = f"stg_{secrets.token_urlsafe(18).replace('-', '_')}"
        temp_path = self.root / f".{opaque_id}.tmp"
        final_path = self.root / opaque_id
        output_fd: int | None = None
        try:
            opened = os.fstat(source_fd)
            if (opened.st_dev, opened.st_ino, opened.st_size) != (
                before.st_dev,
                before.st_ino,
                before.st_size,
            ):
                raise StagingError("source changed during validation")
            output_fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            digest = hashlib.sha256()
            total = 0
            while chunk := os.read(source_fd, 1024 * 1024):
                total += len(chunk)
                if total > self.max_file_bytes:
                    raise StagingError("file exceeds the configured size limit")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(output_fd, view)
                    view = view[written:]
            after = os.fstat(source_fd)
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            ):
                raise StagingError("source changed while it was copied")
            os.fsync(output_fd)
            os.close(output_fd)
            output_fd = None
            os.replace(temp_path, final_path)
            directory_fd = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            detected = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            record = StagedFile(
                opaque_id=opaque_id,
                adapter=adapter,
                account=account,
                filename=filename,
                declared_mime=declared_mime,
                detected_mime=detected,
                size=total,
                sha256=digest.hexdigest(),
                path=final_path,
            )
            self._records[opaque_id] = record
            return record
        except Exception:
            if output_fd is not None:
                os.close(output_fd)
            temp_path.unlink(missing_ok=True)
            final_path.unlink(missing_ok=True)
            raise
        finally:
            os.close(source_fd)

    def resolve(self, opaque_id: str, *, adapter: str, account: str) -> StagedFile:
        record = self._records.get(opaque_id)
        if record is None or record.adapter != adapter or record.account != account:
            raise StagingError("staged object was not found in this scope")
        try:
            resolved = record.path.resolve(strict=True)
        except OSError as exc:
            raise StagingError("staged object is unavailable") from exc
        if resolved.parent != self.root:
            raise StagingError("staged object escaped the staging root")
        metadata = resolved.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise StagingError("staged object is not an immutable regular file")
        digest = hashlib.sha256()
        with resolved.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        if metadata.st_size != record.size or digest.hexdigest() != record.sha256:
            raise StagingError("staged object failed integrity verification")
        return record

    def purge(self, opaque_id: str) -> None:
        record = self._records.pop(opaque_id, None)
        if record is not None:
            record.path.unlink(missing_ok=True)

    def sweep_orphans(self) -> int:
        referenced = {record.path.name for record in self._records.values()}
        removed = 0
        for path in self.root.iterdir():
            if path.name not in referenced:
                path.unlink(missing_ok=True)
                removed += 1
        return removed
