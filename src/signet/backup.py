"""Encrypted SQLite and attachment backup bundles."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from signet.db import Database
from signet.retention import BackupPins, RetentionError
from signet.staging import (
    StagedFile,
    StagingError,
    StagingStore,
    hash_verified_descriptor,
    open_confined_readonly,
    read_verified_descriptor,
)

MAGIC = b"SIGNET-BACKUP-V1\n"
_OPAQUE_ID_RE = re.compile(r"stg_[A-Za-z0-9_]{20,64}\Z")


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
        staging: StagingStore,
        encryption_key: bytes,
        max_bundle_bytes: int = 512 * 1024 * 1024,
        backup_pins: BackupPins | None = None,
    ) -> None:
        if len(encryption_key) != 32:
            raise ValueError("backup encryption key must be exactly 32 bytes")
        if max_bundle_bytes <= 0:
            raise ValueError("maximum bundle size must be positive")
        if not isinstance(staging, StagingStore) or staging.database.path.resolve() != (
            database.path.resolve()
        ):
            raise ValueError("backup staging store must use the backup database")
        self.database = database
        self.staging = staging
        self.staging_root = staging.root
        self._staging_root_identity: tuple[int, int] | None = None
        try:
            metadata = self.staging_root.stat()
        except OSError:
            pass
        else:
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("backup staging root must be a directory")
            self._staging_root_identity = (metadata.st_dev, metadata.st_ino)
        self._encryption_key = bytes(encryption_key)
        self.max_bundle_bytes = max_bundle_bytes
        self._backup_pins = backup_pins or BackupPins(database)

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
        pin_time = int(time.time())
        try:
            try:
                pins = self._backup_pins.acquire(now=pin_time)
            except RetentionError as exc:
                raise BackupError("backup could not acquire consistent attachment pins") from exc
            try:
                snapshot = self.database.create_snapshot(workspace / "approvals.sqlite3")
                try:
                    self._backup_pins.release_snapshot_pins(snapshot, now=pin_time)
                except (OSError, sqlite3.Error) as exc:
                    raise BackupError("backup snapshot pins could not be finalized") from exc
                attachments_dir = workspace / "attachments"
                attachments_dir.mkdir(mode=0o700)
                attachment_manifest = self._copy_attachments(snapshot, attachments_dir)
                with _snapshot_connection(snapshot) as connection:
                    schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                    key_references = sorted(
                        {
                            row[0]
                            for row in connection.execute(
                                """
                                SELECT encryption_key_ref FROM payload_versions
                                WHERE encryption_key_ref IS NOT NULL
                                UNION
                                SELECT encryption_key_ref FROM staged_objects
                                WHERE encryption_key_ref IS NOT NULL
                                """
                            )
                        }
                    )
                manifest = {
                    "format": 2,
                    "schema_version": schema_version,
                    "created_at": created_at if created_at is not None else int(time.time()),
                    "database_sha256": _file_hash(snapshot),
                    "attachments": attachment_manifest,
                    "key_references": key_references,
                }
                manifest_path = workspace / "manifest.json"
                manifest_path.write_text(
                    json.dumps(
                        manifest,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
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
                try:
                    self._backup_pins.release(
                        pins,
                        now=max(pin_time, int(time.time())),
                    )
                except RetentionError as exc:
                    raise BackupError("backup attachment pins could not be released") from exc
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def restore(self, bundle: Path, destination_root: Path) -> RestoredBundle:
        bundle = Path(bundle)
        try:
            flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(bundle, flags)
            try:
                raw = read_verified_descriptor(
                    descriptor,
                    maximum_bytes=self.max_bundle_bytes,
                )
            finally:
                os.close(descriptor)
        except (OSError, StagingError) as exc:
            raise BackupError("backup bundle is not a safe bounded regular file") from exc
        if not raw.startswith(MAGIC) or len(raw) <= len(MAGIC) + 12:
            raise BackupError("backup bundle header is invalid")
        nonce = raw[len(MAGIC) : len(MAGIC) + 12]
        try:
            archive = AESGCM(self._encryption_key).decrypt(nonce, raw[len(MAGIC) + 12 :], MAGIC)
        except InvalidTag as exc:
            raise BackupError("backup authentication failed") from exc

        destination_root = Path(destination_root).absolute()
        if destination_root.exists() or destination_root.is_symlink():
            raise BackupError("restore destination must not already exist")
        destination_root.mkdir(parents=True, mode=0o700)
        try:
            with zipfile.ZipFile(io.BytesIO(archive), mode="r") as zipped:
                _extract_archive(zipped, destination_root)
            attachments_root = destination_root / "attachments"
            attachments_root.mkdir(mode=0o700, exist_ok=True)
            os.chmod(attachments_root, 0o700)
            _fsync_directory(attachments_root)
            _fsync_directory(destination_root)
            manifest_path = destination_root / "manifest.json"
            manifest = _read_json_file(manifest_path)
            if not isinstance(manifest, dict) or manifest.get("format") != 2:
                raise BackupError("backup manifest format is unsupported")
            database_path = destination_root / "approvals.sqlite3"
            if _file_hash(database_path) != manifest.get("database_sha256"):
                raise BackupError("backup database hash does not match the manifest")
            Database.verify_snapshot(database_path)
            self._relocate_restored_attachments(destination_root, database_path, manifest)
            Database.verify_snapshot(database_path)
            self._verify_restored_attachments(destination_root, database_path, manifest)
            return RestoredBundle(
                root=destination_root,
                database_path=database_path,
                attachments_root=attachments_root,
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

    def _copy_attachments(
        self,
        snapshot: Path,
        destination: Path,
    ) -> list[dict[str, Any]]:
        with _snapshot_connection(snapshot) as connection:
            mismatches = int(
                connection.execute(
                    """
                    SELECT count(*) FROM attachments AS attachment
                    LEFT JOIN staged_objects AS staged
                      ON staged.attachment_id = attachment.attachment_id
                    WHERE attachment.storage_path IS NOT NULL
                      AND attachment.purged_at IS NULL
                      AND (
                          staged.attachment_id IS NULL OR staged.storage_path IS NULL OR
                          staged.purged_at IS NOT NULL OR
                          staged.filename != attachment.filename OR
                          staged.declared_mime != attachment.mime_type OR
                          staged.size_bytes != attachment.size_bytes OR
                          staged.sha256 != attachment.sha256 OR
                          staged.storage_path != attachment.storage_path
                      )
                    """
                ).fetchone()[0]
            )
            if mismatches:
                raise BackupError("attachment catalog is incomplete or inconsistent")
            rows = connection.execute(
                """
                SELECT staged.* FROM staged_objects AS staged
                WHERE staged.storage_path IS NOT NULL AND staged.purged_at IS NULL
                ORDER BY staged.attachment_id
                """
            ).fetchall()
        metadata_destination = destination / ".metadata"
        metadata_destination.mkdir(mode=0o700)
        manifest: list[dict[str, Any]] = []
        for row in rows:
            record = _record_from_catalog_row(row, root=self.staging_root)
            source = record.path
            try:
                source_descriptor = open_confined_readonly(
                    self.staging_root,
                    source,
                    expected_root_identity=self._staging_root_identity,
                )
            except StagingError as exc:
                raise BackupError("a referenced attachment is unavailable or unsafe") from exc
            archive_name = f"attachments/{record.opaque_id}"
            metadata_archive_name = f"attachments/.metadata/{record.opaque_id}.json"
            target = destination / record.opaque_id
            target_descriptor: int | None = None
            try:
                target_descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
                size, digest = _copy_verified_descriptor(
                    source_descriptor,
                    target_descriptor,
                    maximum_bytes=self.max_bundle_bytes,
                )
                if size != record.envelope_size or digest != record.envelope_sha256:
                    raise BackupError("an attachment failed backup integrity verification")
                os.fsync(target_descriptor)
            finally:
                if target_descriptor is not None:
                    os.close(target_descriptor)
                os.close(source_descriptor)
            target_descriptor = os.open(
                target, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            )
            try:
                copied_envelope = read_verified_descriptor(
                    target_descriptor,
                    maximum_bytes=self.max_bundle_bytes,
                )
            finally:
                os.close(target_descriptor)
            try:
                plaintext = self.staging.authenticate_envelope(record, copied_envelope)
            except StagingError as exc:
                raise BackupError("an attachment failed backup authentication") from exc
            del plaintext
            metadata_target = metadata_destination / f"{record.opaque_id}.json"
            _write_new_file(metadata_target, StagingStore.metadata_document(record))
            manifest.append(
                {
                    "attachment_id": record.opaque_id,
                    "adapter": record.adapter,
                    "account": record.account,
                    "filename": record.filename,
                    "declared_mime": record.declared_mime,
                    "detected_mime": record.detected_mime,
                    "size_bytes": record.size,
                    "sha256": record.sha256,
                    "envelope_format": record.envelope_format,
                    "envelope_size": record.envelope_size,
                    "envelope_sha256": record.envelope_sha256,
                    "encryption_key_ref": record.encryption_key_ref,
                    "created_at": record.created_at,
                    "consumed_request_id": row["consumed_request_id"],
                    "archive_path": archive_name,
                    "metadata_archive_path": metadata_archive_name,
                }
            )
        _fsync_directory(metadata_destination)
        _fsync_directory(destination)
        return manifest

    def _relocate_restored_attachments(
        self,
        destination: Path,
        database_path: Path,
        manifest: dict[str, Any],
    ) -> None:
        expected = _attachment_manifest(manifest)
        connection = sqlite3.connect(str(database_path), isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            rows = connection.execute(
                """
                SELECT staged.* FROM staged_objects AS staged
                WHERE staged.storage_path IS NOT NULL AND staged.purged_at IS NULL
                """
            ).fetchall()
            _require_consistent_attachment_references(connection)
            key_refs = _key_references(connection)
            if key_refs != manifest.get("key_references"):
                raise BackupError("backup key-reference manifest is inconsistent")
            if len(rows) != len(expected):
                raise BackupError("backup attachment manifest is incomplete")
            relocations: list[tuple[StagedFile, Path]] = []
            for row in rows:
                record = _record_from_catalog_row(row)
                item = expected.get(record.opaque_id)
                if item is None:
                    raise BackupError("backup attachment manifest is incomplete")
                path = destination.joinpath(*PurePosixPath(item["archive_path"]).parts)
                restored_record = _record_with_path(record, path)
                if (
                    row["consumed_request_id"] != item["consumed_request_id"]
                    or not _record_matches_manifest(record, item)
                ):
                    raise BackupError("backup attachment manifest is inconsistent")
                self._verify_restored_file(
                    destination,
                    path,
                    record=restored_record,
                )
                metadata_path = destination.joinpath(
                    *PurePosixPath(item["metadata_archive_path"]).parts
                )
                _verify_metadata_file(
                    destination,
                    metadata_path,
                    expected=StagingStore.metadata_document(restored_record),
                )
                relocations.append((record, path))

            connection.execute("BEGIN IMMEDIATE")
            active_count = int(
                connection.execute(
                    """
                    SELECT count(*) FROM staged_objects
                    WHERE storage_path IS NOT NULL AND purged_at IS NULL
                    """
                ).fetchone()[0]
            )
            current_key_refs = _key_references(connection)
            if active_count != len(relocations) or current_key_refs != key_refs:
                raise BackupError("restored database changed during attachment validation")
            for record, restored_path in relocations:
                updated = connection.execute(
                    """
                    UPDATE staged_objects SET storage_path = ?
                    WHERE attachment_id = ? AND storage_path = ? AND purged_at IS NULL
                      AND envelope_size = ? AND envelope_sha256 = ?
                    """,
                    (
                        str(restored_path),
                        record.opaque_id,
                        str(record.path),
                        record.envelope_size,
                        record.envelope_sha256,
                    ),
                )
                if updated.rowcount != 1:
                    raise BackupError("restored staged-object relocation was incomplete")
                references = int(
                    connection.execute(
                        """
                        SELECT count(*) FROM attachments
                        WHERE attachment_id = ? AND storage_path = ? AND purged_at IS NULL
                        """,
                        (record.opaque_id, str(record.path)),
                    ).fetchone()[0]
                )
                updated_references = connection.execute(
                    """
                    UPDATE attachments SET storage_path = ?
                    WHERE attachment_id = ? AND storage_path = ? AND purged_at IS NULL
                    """,
                    (str(restored_path), record.opaque_id, str(record.path)),
                ).rowcount
                if updated_references != references:
                    raise BackupError("restored attachment path relocation was incomplete")
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except BackupError:
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise BackupError("restored attachment path relocation failed") from exc
        finally:
            connection.close()
        _fsync_file(database_path)
        _fsync_directory(database_path.parent)

    def _verify_restored_attachments(
        self,
        destination: Path,
        database_path: Path,
        manifest: dict[str, Any],
    ) -> None:
        expected = _attachment_manifest(manifest)
        connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                """
                SELECT staged.* FROM staged_objects AS staged
                WHERE staged.storage_path IS NOT NULL AND staged.purged_at IS NULL
                """
            ).fetchall()
            _require_consistent_attachment_references(connection)
            key_refs = _key_references(connection)
        finally:
            connection.close()
        if key_refs != manifest.get("key_references"):
            raise BackupError("backup key-reference manifest is inconsistent")
        if len(rows) != len(expected):
            raise BackupError("backup attachment manifest is incomplete")
        for row in rows:
            record = _record_from_catalog_row(row)
            item = expected.get(record.opaque_id)
            if item is None:
                raise BackupError("backup attachment manifest is incomplete")
            path = destination.joinpath(*PurePosixPath(item["archive_path"]).parts)
            if (
                record.path != path
                or row["consumed_request_id"] != item["consumed_request_id"]
                or not _record_matches_manifest(record, item)
            ):
                raise BackupError("a restored attachment failed integrity verification")
            self._verify_restored_file(
                destination,
                path,
                record=record,
            )
            metadata_path = destination.joinpath(
                *PurePosixPath(item["metadata_archive_path"]).parts
            )
            _verify_metadata_file(
                destination,
                metadata_path,
                expected=StagingStore.metadata_document(record),
            )

    def _verify_restored_file(
        self,
        destination: Path,
        path: Path,
        *,
        record: StagedFile,
    ) -> None:
        try:
            descriptor = open_confined_readonly(destination, path)
            try:
                envelope = read_verified_descriptor(
                    descriptor, maximum_bytes=self.max_bundle_bytes
                )
            finally:
                os.close(descriptor)
        except StagingError as exc:
            raise BackupError("a restored attachment is unavailable or unsafe") from exc
        try:
            plaintext = self.staging.authenticate_envelope(record, envelope)
        except StagingError as exc:
            raise BackupError("a restored attachment failed integrity verification") from exc
        del plaintext


def _archive_workspace(workspace: Path, manifest: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_STORED) as zipped:
        zipped.write(workspace / "approvals.sqlite3", "approvals.sqlite3")
        for item in manifest["attachments"]:
            zipped.write(workspace / item["archive_path"], item["archive_path"])
            zipped.write(
                workspace / item["metadata_archive_path"],
                item["metadata_archive_path"],
            )
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


@contextmanager
def _snapshot_connection(path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def _attachment_manifest(
    manifest: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    attachments = manifest.get("attachments")
    if not isinstance(attachments, list):
        raise BackupError("backup attachment manifest is invalid")
    expected: dict[str, dict[str, Any]] = {}
    archive_paths: set[str] = set()
    required_keys = {
        "attachment_id",
        "adapter",
        "account",
        "filename",
        "declared_mime",
        "detected_mime",
        "size_bytes",
        "sha256",
        "envelope_format",
        "envelope_size",
        "envelope_sha256",
        "encryption_key_ref",
        "created_at",
        "consumed_request_id",
        "archive_path",
        "metadata_archive_path",
    }
    for item in attachments:
        if not isinstance(item, dict) or set(item) != required_keys:
            raise BackupError("backup attachment manifest is invalid")
        attachment_id = item["attachment_id"]
        size_bytes = item["size_bytes"]
        sha256 = item["sha256"]
        envelope_size = item["envelope_size"]
        envelope_sha256 = item["envelope_sha256"]
        archive_path = item["archive_path"]
        metadata_archive_path = item["metadata_archive_path"]
        if (
            not isinstance(attachment_id, str)
            or _OPAQUE_ID_RE.fullmatch(attachment_id) is None
            or any(
                not _valid_manifest_text(item[field], maximum=maximum)
                for field, maximum in (
                    ("adapter", 512),
                    ("account", 512),
                    ("filename", 255),
                    ("declared_mime", 255),
                    ("detected_mime", 255),
                    ("envelope_format", 128),
                    ("encryption_key_ref", 512),
                )
            )
            or (
                item["consumed_request_id"] is not None
                and not _valid_manifest_text(item["consumed_request_id"], maximum=512)
            )
            or isinstance(size_bytes, bool)
            or not isinstance(size_bytes, int)
            or size_bytes < 0
            or not _valid_hash(sha256)
            or isinstance(envelope_size, bool)
            or not isinstance(envelope_size, int)
            or envelope_size <= 0
            or not _valid_hash(envelope_sha256)
            or isinstance(item["created_at"], bool)
            or not isinstance(item["created_at"], int)
            or item["created_at"] < 0
            or not isinstance(archive_path, str)
            or not isinstance(metadata_archive_path, str)
        ):
            raise BackupError("backup attachment manifest is invalid")
        archive = PurePosixPath(archive_path)
        metadata_archive = PurePosixPath(metadata_archive_path)
        if (
            len(archive.parts) != 2
            or archive.parts[0] != "attachments"
            or archive.parts[1] != attachment_id
            or metadata_archive.parts
            != ("attachments", ".metadata", f"{attachment_id}.json")
        ):
            raise BackupError("backup attachment archive path is invalid")
        if (
            attachment_id in expected
            or archive_path in archive_paths
            or metadata_archive_path in archive_paths
        ):
            raise BackupError("backup attachment manifest contains duplicates")
        expected[attachment_id] = item
        archive_paths.update((archive_path, metadata_archive_path))
    return expected


def _record_from_catalog_row(
    row: Any,
    *,
    root: Path | None = None,
) -> StagedFile:
    values = {
        "attachment_id": row["attachment_id"],
        "adapter": row["adapter"],
        "account": row["account"],
        "filename": row["filename"],
        "declared_mime": row["declared_mime"],
        "detected_mime": row["detected_mime"],
        "size_bytes": row["size_bytes"],
        "sha256": row["sha256"],
        "storage_path": row["storage_path"],
        "envelope_format": row["envelope_format"],
        "envelope_size": row["envelope_size"],
        "envelope_sha256": row["envelope_sha256"],
        "encryption_key_ref": row["encryption_key_ref"],
        "created_at": row["created_at"],
    }
    if (
        not isinstance(values["attachment_id"], str)
        or _OPAQUE_ID_RE.fullmatch(values["attachment_id"]) is None
        or any(
            not _valid_manifest_text(values[field], maximum=maximum)
            for field, maximum in (
                ("adapter", 512),
                ("account", 512),
                ("filename", 255),
                ("declared_mime", 255),
                ("detected_mime", 255),
                ("envelope_format", 128),
                ("encryption_key_ref", 512),
            )
        )
        or isinstance(values["size_bytes"], bool)
        or not isinstance(values["size_bytes"], int)
        or values["size_bytes"] < 0
        or not _valid_hash(values["sha256"])
        or not isinstance(values["storage_path"], str)
        or not values["storage_path"]
        or isinstance(values["envelope_size"], bool)
        or not isinstance(values["envelope_size"], int)
        or values["envelope_size"] <= 0
        or not _valid_hash(values["envelope_sha256"])
        or isinstance(values["created_at"], bool)
        or not isinstance(values["created_at"], int)
        or values["created_at"] < 0
    ):
        raise BackupError("staged object catalog is invalid")
    path = Path(values["storage_path"])
    if not path.is_absolute() or (root is not None and path.parent != root):
        raise BackupError("staged object catalog path is invalid")
    return StagedFile(
        opaque_id=values["attachment_id"],
        adapter=values["adapter"],
        account=values["account"],
        filename=values["filename"],
        declared_mime=values["declared_mime"],
        detected_mime=values["detected_mime"],
        size=values["size_bytes"],
        sha256=values["sha256"],
        path=path,
        created_at=values["created_at"],
        envelope_format=values["envelope_format"],
        envelope_size=values["envelope_size"],
        envelope_sha256=values["envelope_sha256"],
        encryption_key_ref=values["encryption_key_ref"],
    )


def _record_with_path(record: StagedFile, path: Path) -> StagedFile:
    return StagedFile(
        opaque_id=record.opaque_id,
        adapter=record.adapter,
        account=record.account,
        filename=record.filename,
        declared_mime=record.declared_mime,
        detected_mime=record.detected_mime,
        size=record.size,
        sha256=record.sha256,
        path=path,
        created_at=record.created_at,
        envelope_format=record.envelope_format,
        envelope_size=record.envelope_size,
        envelope_sha256=record.envelope_sha256,
        encryption_key_ref=record.encryption_key_ref,
    )


def _record_matches_manifest(record: StagedFile, item: dict[str, Any]) -> bool:
    return all(
        (
            record.opaque_id == item["attachment_id"],
            record.adapter == item["adapter"],
            record.account == item["account"],
            record.filename == item["filename"],
            record.declared_mime == item["declared_mime"],
            record.detected_mime == item["detected_mime"],
            record.size == item["size_bytes"],
            record.sha256 == item["sha256"],
            record.envelope_format == item["envelope_format"],
            record.envelope_size == item["envelope_size"],
            record.envelope_sha256 == item["envelope_sha256"],
            record.encryption_key_ref == item["encryption_key_ref"],
            record.created_at == item["created_at"],
        )
    )


def _key_references(connection: Any) -> list[str]:
    return sorted(
        {
            str(row[0])
            for row in connection.execute(
                """
                SELECT encryption_key_ref FROM payload_versions
                WHERE encryption_key_ref IS NOT NULL
                UNION
                SELECT encryption_key_ref FROM staged_objects
                WHERE encryption_key_ref IS NOT NULL
                """
            )
        }
    )


def _require_consistent_attachment_references(connection: Any) -> None:
    mismatch = connection.execute(
        """
        SELECT 1 FROM attachments AS attachment
        LEFT JOIN staged_objects AS staged
          ON staged.attachment_id = attachment.attachment_id
        WHERE attachment.storage_path IS NOT NULL AND attachment.purged_at IS NULL
          AND (
              staged.attachment_id IS NULL OR staged.storage_path IS NULL OR
              staged.purged_at IS NOT NULL OR
              staged.filename != attachment.filename OR
              staged.declared_mime != attachment.mime_type OR
              staged.size_bytes != attachment.size_bytes OR
              staged.sha256 != attachment.sha256 OR
              staged.storage_path != attachment.storage_path
          )
        LIMIT 1
        """
    ).fetchone()
    if mismatch is not None:
        raise BackupError("attachment catalog is incomplete or inconsistent")


def _verify_metadata_file(root: Path, path: Path, *, expected: bytes) -> None:
    try:
        descriptor = open_confined_readonly(root, path)
        try:
            actual = read_verified_descriptor(descriptor, maximum_bytes=64 * 1024)
        finally:
            os.close(descriptor)
    except StagingError as exc:
        raise BackupError("restored attachment metadata is unavailable or unsafe") from exc
    if not hmac.compare_digest(actual, expected):
        raise BackupError("restored attachment metadata failed integrity verification")


def _valid_manifest_text(value: object, *, maximum: int) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    return len(encoded) <= maximum and not any(
        ord(character) < 32 or ord(character) == 127 for character in value
    )


def _valid_hash(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _file_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _copy_verified_descriptor(
    source: int,
    target: int,
    *,
    maximum_bytes: int,
) -> tuple[int, str]:
    before = os.fstat(source)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > maximum_bytes
    ):
        raise BackupError("an attachment is not a safe bounded regular file")
    os.lseek(source, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while chunk := os.read(source, 1024 * 1024):
        total += len(chunk)
        if total > maximum_bytes:
            raise BackupError("an attachment exceeds the backup size limit")
        digest.update(chunk)
        _write_all(target, chunk)
    after = os.fstat(source)
    if _file_signature(before) != _file_signature(after) or total != before.st_size:
        raise BackupError("an attachment changed while it was backed up")
    return total, digest.hexdigest()


def _file_hash(path: Path) -> str:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            _, digest = hash_verified_descriptor(
                descriptor,
                maximum_bytes=2 * 1024 * 1024 * 1024,
            )
            return digest
        finally:
            os.close(descriptor)
    except (OSError, StagingError) as exc:
        raise BackupError("backup file could not be hashed safely") from exc


def _read_json_file(path: Path) -> Any:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            raw = read_verified_descriptor(descriptor, maximum_bytes=4 * 1024 * 1024)
        finally:
            os.close(descriptor)
        return json.loads(raw.decode("utf-8"))
    except (OSError, StagingError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError("backup manifest is invalid") from exc


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("backup file write made no progress")
        view = view[written:]


def _write_new_file(path: Path, data: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
