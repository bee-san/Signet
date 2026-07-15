"""Encrypted SQLite and attachment backup bundles."""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import shutil
import stat
import tempfile
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from signet.db import Database

MAGIC = b"SIGNET-BACKUP-V1\n"


class BackupError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class RestoredBundle:
    root: Path
    database_path: Path
    attachments_root: Path
    manifest: dict[str, Any]


class BackupBundleManager:
    """Create encrypted bundles and restore them only into a staging path."""

    def __init__(
        self,
        database: Database,
        *,
        staging_root: Path,
        encryption_key: bytes,
        max_bundle_bytes: int = 512 * 1024 * 1024,
    ) -> None:
        if len(encryption_key) != 32:
            raise ValueError("backup encryption key must be exactly 32 bytes")
        if max_bundle_bytes <= 0:
            raise ValueError("maximum bundle size must be positive")
        self.database = database
        self.staging_root = staging_root.resolve()
        self._encryption_key = bytes(encryption_key)
        self.max_bundle_bytes = max_bundle_bytes

    def __repr__(self) -> str:
        return f"BackupBundleManager(database={self.database.path!s}, encryption_key=<redacted>)"

    def create(self, destination: Path, *, created_at: int | None = None) -> Path:
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(destination.parent, 0o700)
        if destination.exists() or destination.is_symlink():
            raise BackupError("backup destination already exists")
        workspace = Path(tempfile.mkdtemp(prefix=".signet-backup-", dir=destination.parent))
        os.chmod(workspace, 0o700)
        try:
            snapshot = self.database.create_snapshot(workspace / "approvals.sqlite3")
            attachments_dir = workspace / "attachments"
            attachments_dir.mkdir(mode=0o700)
            attachment_manifest = self._copy_attachments(attachments_dir)
            with self.database.read() as connection:
                schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                key_references = sorted(
                    {
                        row[0]
                        for row in connection.execute(
                            """
                            SELECT encryption_key_ref FROM payload_versions
                            WHERE encryption_key_ref IS NOT NULL
                            """
                        )
                    }
                )
            manifest = {
                "format": 1,
                "schema_version": schema_version,
                "created_at": created_at if created_at is not None else int(time.time()),
                "database_sha256": _file_hash(snapshot),
                "attachments": attachment_manifest,
                "key_references": key_references,
            }
            manifest_path = workspace / "manifest.json"
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            os.chmod(manifest_path, 0o600)
            archive = _archive_workspace(workspace, manifest)
            nonce = secrets.token_bytes(12)
            ciphertext = AESGCM(self._encryption_key).encrypt(nonce, archive, MAGIC)
            if len(ciphertext) + len(MAGIC) + len(nonce) > self.max_bundle_bytes:
                raise BackupError("encrypted backup exceeds the configured size limit")
            temporary = destination.with_name(f".{destination.name}.partial")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                _write_all(descriptor, MAGIC + nonce + ciphertext)
                os.fsync(descriptor)
            except BaseException:
                os.close(descriptor)
                temporary.unlink(missing_ok=True)
                raise
            else:
                os.close(descriptor)
            os.replace(temporary, destination)
            _fsync_directory(destination.parent)
            return destination
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def restore(self, bundle: Path, destination_root: Path) -> RestoredBundle:
        bundle = Path(bundle)
        if not bundle.is_file() or bundle.is_symlink():
            raise BackupError("backup bundle is not a regular file")
        if bundle.stat().st_size > self.max_bundle_bytes:
            raise BackupError("backup bundle exceeds the configured size limit")
        raw = bundle.read_bytes()
        if not raw.startswith(MAGIC) or len(raw) <= len(MAGIC) + 12:
            raise BackupError("backup bundle header is invalid")
        nonce = raw[len(MAGIC) : len(MAGIC) + 12]
        try:
            archive = AESGCM(self._encryption_key).decrypt(nonce, raw[len(MAGIC) + 12 :], MAGIC)
        except InvalidTag as exc:
            raise BackupError("backup authentication failed") from exc

        destination_root = Path(destination_root)
        if destination_root.exists() or destination_root.is_symlink():
            raise BackupError("restore destination must not already exist")
        destination_root.mkdir(parents=True, mode=0o700)
        try:
            with zipfile.ZipFile(io.BytesIO(archive), mode="r") as zipped:
                _extract_archive(zipped, destination_root)
            manifest_path = destination_root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict) or manifest.get("format") != 1:
                raise BackupError("backup manifest format is unsupported")
            database_path = destination_root / "approvals.sqlite3"
            if _file_hash(database_path) != manifest.get("database_sha256"):
                raise BackupError("backup database hash does not match the manifest")
            Database.verify_snapshot(database_path)
            self._verify_restored_attachments(destination_root, database_path, manifest)
            return RestoredBundle(
                root=destination_root,
                database_path=database_path,
                attachments_root=destination_root / "attachments",
                manifest=manifest,
            )
        except BaseException:
            shutil.rmtree(destination_root, ignore_errors=True)
            raise

    def create_pre_migration_callback(
        self, backup_directory: Path
    ) -> Callable[[Database, int], None]:
        backup_directory = Path(backup_directory)

        def backup(database: Database, current_version: int) -> None:
            if database.path.resolve() != self.database.path.resolve():
                raise BackupError("pre-migration callback received an unexpected database")
            timestamp = int(time.time())
            destination = backup_directory / (
                f"pre-migration-v{current_version}-{timestamp}.signet-backup"
            )
            self.create(destination, created_at=timestamp)
            staged = backup_directory / f".verify-{timestamp}"
            restored = self.restore(destination, staged)
            if restored.manifest.get("schema_version") != current_version:
                shutil.rmtree(staged, ignore_errors=True)
                raise BackupError("pre-migration backup schema version is inconsistent")
            shutil.rmtree(staged, ignore_errors=True)

        return backup

    def _copy_attachments(self, destination: Path) -> list[dict[str, Any]]:
        with self.database.read() as connection:
            rows = connection.execute(
                """
                SELECT attachment_id, request_id, version, payload_hash,
                       size_bytes, sha256, storage_path
                FROM attachments WHERE storage_path IS NOT NULL AND purged_at IS NULL
                ORDER BY request_id, version, attachment_id
                """
            ).fetchall()
        manifest: list[dict[str, Any]] = []
        for index, row in enumerate(rows):
            source = Path(row["storage_path"])
            try:
                resolved = source.resolve(strict=True)
            except OSError as exc:
                raise BackupError("a referenced attachment is unavailable") from exc
            if self.staging_root != resolved.parent and self.staging_root not in resolved.parents:
                raise BackupError("an attachment is outside the gateway staging root")
            metadata = resolved.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise BackupError("an attachment is not a single-link regular file")
            digest = _file_hash(resolved)
            if metadata.st_size != row["size_bytes"] or digest != row["sha256"]:
                raise BackupError("an attachment failed backup integrity verification")
            archive_name = f"attachments/{index:08d}.bin"
            target = destination / f"{index:08d}.bin"
            with resolved.open("rb") as source_handle, target.open("xb") as target_handle:
                os.chmod(target, 0o600)
                shutil.copyfileobj(source_handle, target_handle, 1024 * 1024)
                target_handle.flush()
                os.fsync(target_handle.fileno())
            manifest.append(
                {
                    "attachment_id": row["attachment_id"],
                    "request_id": row["request_id"],
                    "version": row["version"],
                    "payload_hash": row["payload_hash"],
                    "size_bytes": row["size_bytes"],
                    "sha256": digest,
                    "archive_path": archive_name,
                }
            )
        _fsync_directory(destination)
        return manifest

    @staticmethod
    def _verify_restored_attachments(
        destination: Path,
        database_path: Path,
        manifest: dict[str, Any],
    ) -> None:
        attachments = manifest.get("attachments")
        if not isinstance(attachments, list):
            raise BackupError("backup attachment manifest is invalid")
        expected: dict[tuple[str, str, int], dict[str, Any]] = {}
        for item in attachments:
            if not isinstance(item, dict):
                raise BackupError("backup attachment manifest is invalid")
            attachment_id = item.get("attachment_id")
            request_id = item.get("request_id")
            version = item.get("version")
            if (
                not isinstance(attachment_id, str)
                or not isinstance(request_id, str)
                or not isinstance(version, int)
            ):
                raise BackupError("backup attachment identity is invalid")
            key = (attachment_id, request_id, version)
            expected[key] = item

        import sqlite3

        connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                """
                SELECT attachment_id, request_id, version, payload_hash,
                       size_bytes, sha256 FROM attachments
                WHERE storage_path IS NOT NULL AND purged_at IS NULL
                """
            ).fetchall()
            key_refs = sorted(
                {
                    row[0]
                    for row in connection.execute(
                        """
                        SELECT encryption_key_ref FROM payload_versions
                        WHERE encryption_key_ref IS NOT NULL
                        """
                    )
                }
            )
        finally:
            connection.close()
        if key_refs != manifest.get("key_references"):
            raise BackupError("backup key-reference manifest is inconsistent")
        if len(rows) != len(expected):
            raise BackupError("backup attachment manifest is incomplete")
        for row in rows:
            key = (row["attachment_id"], row["request_id"], row["version"])
            item = expected.get(key)
            if item is None:
                raise BackupError("backup attachment manifest is incomplete")
            archive_path = item.get("archive_path")
            path = destination / str(archive_path)
            if (
                row["payload_hash"] != item.get("payload_hash")
                or row["size_bytes"] != item.get("size_bytes")
                or row["sha256"] != item.get("sha256")
                or not path.is_file()
                or path.stat().st_size != row["size_bytes"]
                or _file_hash(path) != row["sha256"]
            ):
                raise BackupError("a restored attachment failed integrity verification")


def _archive_workspace(workspace: Path, manifest: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_STORED) as zipped:
        zipped.write(workspace / "approvals.sqlite3", "approvals.sqlite3")
        for item in manifest["attachments"]:
            zipped.write(workspace / item["archive_path"], item["archive_path"])
        zipped.write(workspace / "manifest.json", "manifest.json")
    return buffer.getvalue()


def _extract_archive(zipped: zipfile.ZipFile, destination: Path) -> None:
    allowed_roots = {"approvals.sqlite3", "manifest.json", "attachments"}
    total = 0
    for info in zipped.infolist():
        path = PurePosixPath(info.filename)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise BackupError("backup archive contains an unsafe path")
        if path.parts[0] not in allowed_roots:
            raise BackupError("backup archive contains an unexpected member")
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise BackupError("backup archive contains a symbolic link")
        total += info.file_size
        if total > 2 * 1024 * 1024 * 1024:
            raise BackupError("restored backup exceeds the extraction limit")
        target = destination.joinpath(*path.parts)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if info.is_dir():
            continue
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with zipped.open(info, "r") as source:
                while chunk := source.read(1024 * 1024):
                    _write_all(descriptor, chunk)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
