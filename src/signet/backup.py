"""Encrypted SQLite and attachment backup bundles."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from signet.db import (
    DATABASE_OPERATOR_RECOVERY_NOTES,
    Database,
    DatabaseRecoveryNoteCarrier,
    MigrationBackupReceipt,
)
from signet.private_paths import (
    DirectoryIdentity,
    PrivatePathError,
    capture_owned_directory_identity,
    ensure_owned_directory,
    ensure_private_directory,
    harden_private_directory_descendant,
    harden_private_directory_identity,
    require_no_acl_grants,
    require_owned_directory_identity,
    require_private_directory_identity,
    revalidate_directory_identity,
)
from signet.retention import BackupPins, RetentionError
from signet.staging import (
    StagedFile,
    StagingError,
    StagingStore,
    hash_verified_descriptor,
    open_confined_readonly,
    read_verified_descriptor,
)

MAGIC = b"SIGNET-BACKUP-V2\n"
_BACKUP_CHUNK_BYTES = 4 * 1024 * 1024
_BACKUP_HEADER_BYTES = len(MAGIC) + 12 + 8 + 4
_AEAD_TAG_BYTES = 16
_RECORD_LENGTH_BYTES = 4
_OPAQUE_ID_RE = re.compile(r"stg_[A-Za-z0-9_]{20,64}\Z")
_PRIVATE_ARTIFACT_CLEANUP_NOTE = "One or more private backup artifacts could not be removed safely."
_RMTREE_AVOIDS_SYMLINK_ATTACKS = bool(getattr(shutil.rmtree, "avoids_symlink_attacks", False))


class BackupError(RuntimeError):
    pass


class _OperatorVisibleBackupError(BackupError, DatabaseRecoveryNoteCarrier):
    def operator_message(self) -> str:
        parts = [str(self)]
        for note in getattr(self, "__notes__", ()):
            if note == _PRIVATE_ARTIFACT_CLEANUP_NOTE or note in DATABASE_OPERATOR_RECOVERY_NOTES:
                parts.append(note)
        return " ".join(parts)


class BackupPublicationUnknown(_OperatorVisibleBackupError):
    """A destination may exist, but durable publication was not confirmed."""


class BackupPublishedWithWarnings(_OperatorVisibleBackupError):
    """The destination is durable, but required post-publication work failed."""


class BackupRetentionStateUnknown(_OperatorVisibleBackupError):
    """No destination was published, but retention-pin state needs recovery."""


class BackupCleanupStateUnknown(_OperatorVisibleBackupError):
    """No destination was published, but private cleanup needs recovery."""


@dataclass(frozen=True, slots=True)
class RestoredBundle:
    root: Path
    database_path: Path
    attachments_root: Path
    manifest: dict[str, Any]
    root_identity: DirectoryIdentity
    parent_identity: DirectoryIdentity


@dataclass(frozen=True, slots=True)
class _BackupFileIdentity:
    device: int
    inode: int
    owner_uid: int
    size: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> _BackupFileIdentity:
        return cls(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            owner_uid=metadata.st_uid,
            size=metadata.st_size,
        )

    def same_object(self, metadata: os.stat_result) -> bool:
        return (self.device, self.inode, self.owner_uid) == (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
        )


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
        requested = _absolute_backup_path(
            destination,
            message="backup destination path is unavailable or unsafe",
        )
        try:
            parent = ensure_owned_directory(requested.parent)
            parent_identity = require_owned_directory_identity(parent)
        except PrivatePathError as exc:
            raise BackupError("backup parent must be owned and not writable by others") from exc
        destination = parent / requested.name
        if destination.exists() or destination.is_symlink():
            raise BackupError("backup destination already exists")
        workspace, workspace_identity = _create_backup_workspace(parent_identity)
        temporary: Path | None = None
        temporary_identity: _BackupFileIdentity | None = None
        publication_observed = False
        publication_durable = False
        operation_error: BaseException | None = None
        pin_time = int(time.time())
        try:
            try:
                pins = self._backup_pins.acquire(now=pin_time)
            except RetentionError as exc:
                raise BackupError("backup could not acquire consistent retention pins") from exc
            except BaseException as exc:
                raise BackupRetentionStateUnknown(
                    "backup was not published because retention pin acquisition could not be "
                    "confirmed; inspect retention state before retrying"
                ) from exc
            pin_operation_error: BaseException | None = None
            try:
                snapshot = self.database.create_snapshot(workspace / "approvals.sqlite3")
                try:
                    self._backup_pins.release_snapshot_pins(snapshot, now=pin_time)
                except (OSError, sqlite3.Error) as exc:
                    raise BackupError("backup snapshot pins could not be finalized") from exc
                attachments_dir = workspace / "attachments"
                attachments_dir.mkdir(mode=0o700)
                _harden_private_directory(attachments_dir)
                attachment_manifest = self._copy_attachments(snapshot, attachments_dir)
                with _snapshot_connection(snapshot) as connection:
                    schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                    key_references = _key_references(connection)
                manifest = {
                    "format": 2,
                    "schema_version": schema_version,
                    "created_at": created_at if created_at is not None else int(time.time()),
                    "database_sha256": _file_hash(snapshot),
                    "attachments": attachment_manifest,
                    "key_references": key_references,
                }
                manifest_path = workspace / "manifest.json"
                _write_new_file(
                    manifest_path,
                    json.dumps(
                        manifest,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8"),
                )
                members = _archive_members(workspace, manifest)
                projected_archive_size = _projected_zip_size(members)
                if _encrypted_bundle_size(projected_archive_size) > self.max_bundle_bytes:
                    raise BackupError("encrypted backup exceeds the configured size limit")
                temporary = destination.with_name(
                    f".{destination.name}.partial-{secrets.token_urlsafe(12)}"
                )
                with tempfile.TemporaryFile(mode="w+b", dir=workspace) as archive:
                    _archive_workspace(archive, members)
                    archive_size = archive.seek(0, os.SEEK_END)
                    if _encrypted_bundle_size(archive_size) > self.max_bundle_bytes:
                        raise BackupError("encrypted backup exceeds the configured size limit")
                    archive.seek(0)
                    try:
                        temporary_identity = _encrypt_archive_to_path(
                            archive,
                            archive_size=archive_size,
                            destination=temporary,
                            encryption_key=self._encryption_key,
                        )
                    except FileExistsError as exc:
                        raise BackupError("backup temporary destination already exists") from exc
                _require_unchanged_backup_directory(parent_identity)
                _require_private_backup_file(temporary, expected=temporary_identity)
                if destination.exists() or destination.is_symlink():
                    raise BackupError("backup destination already exists")
            except BaseException as exc:
                pin_operation_error = exc
                raise
            finally:
                try:
                    self._backup_pins.release(
                        pins,
                        now=max(pin_time, int(time.time())),
                    )
                except BaseException as exc:
                    if pin_operation_error is not None:
                        failure = BackupRetentionStateUnknown(
                            "backup was not published because backup construction failed and "
                            "retention pin release could not be confirmed; inspect retention "
                            "state before retrying"
                        )
                        if isinstance(pin_operation_error, BackupCleanupStateUnknown) or any(
                            note == _PRIVATE_ARTIFACT_CLEANUP_NOTE
                            for note in getattr(pin_operation_error, "__notes__", ())
                        ):
                            failure.add_note(_PRIVATE_ARTIFACT_CLEANUP_NOTE)
                        raise failure from pin_operation_error
                    raise BackupRetentionStateUnknown(
                        "backup was not published because retention pin release could not be "
                        "confirmed; inspect retention state before retrying"
                    ) from exc

            _require_unchanged_backup_directory(parent_identity)
            _require_private_backup_file(temporary, expected=temporary_identity)
            if destination.exists() or destination.is_symlink():
                raise BackupError("backup destination already exists")
            try:
                _rename_backup_no_replace(temporary, destination)
                publication_observed = True
            except BaseException as exc:
                try:
                    _require_private_backup_file(temporary, expected=temporary_identity)
                except BackupError:
                    publication_observed = True
                    raise _backup_publication_unknown() from exc
                if isinstance(exc, FileExistsError):
                    raise BackupError("backup destination already exists") from exc
                raise
            try:
                published_identity = _require_private_backup_file(
                    destination,
                    expected=temporary_identity,
                )
                if published_identity != temporary_identity:
                    raise BackupError("published backup file identity changed")
                _require_unchanged_backup_directory(parent_identity)
                _fsync_directory(parent)
                _require_unchanged_backup_directory(parent_identity)
                _require_private_backup_file(destination, expected=published_identity)
            except BaseException as exc:
                raise _backup_publication_unknown() from exc
            publication_durable = True
            return destination
        except BaseException as exc:
            operation_error = exc
            raise
        finally:
            cleanup_errors: list[BaseException] = []
            if (
                temporary is not None
                and temporary_identity is not None
                and not publication_observed
            ):
                try:
                    _cleanup_backup_temporary_file(
                        temporary,
                        identity=temporary_identity,
                        parent_identity=parent_identity,
                    )
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            try:
                _cleanup_backup_workspace(
                    workspace,
                    parent_identity=parent_identity,
                    workspace_identity=workspace_identity,
                )
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
            if cleanup_errors:
                if operation_error is not None:
                    if isinstance(operation_error, _OperatorVisibleBackupError):
                        operation_error.add_note(_PRIVATE_ARTIFACT_CLEANUP_NOTE)
                    else:
                        raise BackupCleanupStateUnknown(
                            "backup was not published, but private backup artifact cleanup "
                            "could not be confirmed; inspect the backup parent before continuing"
                        ) from cleanup_errors[0]
                elif publication_durable:
                    raise BackupPublishedWithWarnings(
                        "backup was published durably, but private backup artifacts could not "
                        "be removed; inspect the backup parent before continuing"
                    ) from cleanup_errors[0]
                elif publication_observed:
                    raise _backup_publication_unknown() from cleanup_errors[0]
                else:
                    raise BackupCleanupStateUnknown(
                        "backup was not published, but private backup artifact cleanup could "
                        "not be confirmed; inspect the backup parent before continuing"
                    ) from cleanup_errors[0]

    def restore(self, bundle: Path, destination_root: Path) -> RestoredBundle:
        bundle = _absolute_backup_path(
            bundle,
            message="backup bundle path is unavailable or unsafe",
        )
        destination_root = _absolute_backup_path(
            destination_root,
            message="backup restore destination path is unavailable or unsafe",
        )
        try:
            flags = (
                os.O_RDONLY
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            descriptor = os.open(bundle, flags)
        except OSError as exc:
            raise BackupError("backup bundle is not a safe bounded regular file") from exc

        restored: RestoredBundle | None = None
        try:
            with tempfile.TemporaryFile(mode="w+b") as archive:
                _decrypt_bundle_to_archive(
                    descriptor,
                    archive,
                    encryption_key=self._encryption_key,
                    maximum_bytes=self.max_bundle_bytes,
                )
                archive.seek(0)
                restored = self._restore_archive(archive, destination_root)
        except BaseException as operation_error:
            try:
                os.close(descriptor)
            except BaseException:
                operation_error.add_note(
                    "The backup bundle descriptor close outcome could not be confirmed."
                )
            if restored is not None:
                try:
                    remove_private_tree_checked(
                        restored.root,
                        parent_identity=restored.parent_identity,
                        tree_identity=restored.root_identity,
                    )
                except BaseException as cleanup_error:
                    raise BackupCleanupStateUnknown(
                        "backup restore did not complete, and private restore-tree cleanup could "
                        "not be confirmed; inspect the restore parent before continuing"
                    ) from cleanup_error
            if isinstance(operation_error, OSError):
                raise BackupError("backup restore did not complete safely") from operation_error
            raise

        try:
            os.close(descriptor)
        except BaseException as close_error:
            if restored is not None:
                try:
                    remove_private_tree_checked(
                        restored.root,
                        parent_identity=restored.parent_identity,
                        tree_identity=restored.root_identity,
                    )
                except BaseException as cleanup_error:
                    raise BackupCleanupStateUnknown(
                        "backup restore did not complete after a bundle descriptor close failure, "
                        "and private restore-tree cleanup could not be confirmed; inspect the "
                        "restore parent before continuing"
                    ) from cleanup_error
            raise BackupError(
                "backup restore did not complete because the bundle descriptor close outcome "
                "could not be confirmed"
            ) from close_error
        if restored is None:  # pragma: no cover - guarded by the restore implementation
            raise BackupError("backup restore did not produce a verified restore tree")
        return restored

    def _restore_archive(
        self,
        archive: BinaryIO,
        destination_root: Path,
    ) -> RestoredBundle:
        destination_root = _absolute_backup_path(
            destination_root,
            message="backup restore destination path is unavailable or unsafe",
        )
        destination_root, parent_identity, root_identity = _create_restore_root(destination_root)
        try:
            with zipfile.ZipFile(archive, mode="r") as zipped:
                _extract_archive(zipped, destination_root)
            attachments_root = destination_root / "attachments"
            try:
                ensure_private_directory(attachments_root)
            except PrivatePathError as exc:
                raise BackupError("restored attachment directory is unsafe") from exc
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
            with Database(database_path).read_only() as connection:
                snapshot_schema_version = int(
                    connection.execute("PRAGMA user_version").fetchone()[0]
                )
            if manifest.get("schema_version") != snapshot_schema_version:
                raise BackupError("backup manifest schema version differs from the snapshot")
            self._relocate_restored_attachments(destination_root, database_path, manifest)
            Database.verify_snapshot(database_path)
            self._verify_restored_attachments(destination_root, database_path, manifest)
            current_root = require_private_directory_identity(destination_root)
            if not root_identity.same_object(current_root):
                raise BackupError("private restore tree identity changed")
            _fsync_directory(destination_root)
            parent = revalidate_directory_identity(parent_identity, private=False)
            _fsync_directory(parent)
            revalidate_directory_identity(parent_identity, private=False)
            current_root = require_private_directory_identity(destination_root)
            if not root_identity.same_object(current_root):
                raise BackupError("private restore tree identity changed")
            return RestoredBundle(
                root=destination_root,
                database_path=database_path,
                attachments_root=attachments_root,
                manifest=manifest,
                root_identity=root_identity,
                parent_identity=parent_identity,
            )
        except BaseException:
            try:
                remove_private_tree_checked(
                    destination_root,
                    parent_identity=parent_identity,
                    tree_identity=root_identity,
                )
            except BaseException as cleanup_error:
                raise BackupCleanupStateUnknown(
                    "backup restore did not complete, but private restore-tree cleanup could "
                    "not be confirmed; inspect the restore parent before continuing"
                ) from cleanup_error
            raise

    def create_pre_migration_callback(
        self, backup_directory: Path
    ) -> Callable[[Database, int], MigrationBackupReceipt]:
        backup_directory = Path(backup_directory)

        def backup(database: Database, current_version: int) -> MigrationBackupReceipt:
            if database.path.resolve() != self.database.path.resolve():
                raise BackupError("pre-migration callback received an unexpected database")
            timestamp = int(time.time())
            destination = backup_directory / (
                f"pre-migration-v{current_version}-{timestamp}.signet-backup"
            )
            self.create(destination, created_at=timestamp)
            staged = backup_directory / f".verify-{timestamp}"
            restored: RestoredBundle | None = None
            verification_error: BaseException | None = None
            try:
                restored = self.restore(destination, staged)
                if restored.manifest.get("schema_version") != current_version:
                    raise BackupError("pre-migration backup schema version is inconsistent")
            except BaseException as exc:
                verification_error = exc
            if restored is not None:
                try:
                    remove_private_tree_checked(
                        restored.root,
                        parent_identity=restored.parent_identity,
                        tree_identity=restored.root_identity,
                    )
                except BaseException as cleanup_error:
                    if verification_error is not None:
                        raise BackupPublishedWithWarnings(
                            "pre-migration backup was published durably, but verification did not "
                            "complete "
                            "and private verification-tree cleanup could not be confirmed; "
                            "do not migrate or recreate the backup; inspect the backup parent "
                            "before continuing"
                        ) from cleanup_error
                    raise BackupPublishedWithWarnings(
                        "pre-migration backup was published durably, but private "
                        "verification-tree cleanup could not be confirmed; inspect the backup "
                        "parent before continuing"
                    ) from cleanup_error
            if verification_error is not None:
                if isinstance(verification_error, BackupCleanupStateUnknown):
                    raise BackupPublishedWithWarnings(
                        "pre-migration backup was published durably, but verification did not "
                        "complete and private verification-tree cleanup could not be confirmed; "
                        "do not migrate or recreate the backup; inspect the backup parent before "
                        "continuing"
                    ) from verification_error
                raise BackupPublishedWithWarnings(
                    "pre-migration backup was published durably, but verification did not "
                    "complete; do not migrate or recreate the backup; inspect the published "
                    "bundle before continuing"
                ) from verification_error
            return MigrationBackupReceipt(
                database_path=database.path,
                source_schema_version=current_version,
                artifact_path=destination.absolute(),
                artifact_sha256=_file_hash(destination),
                verified_restore_schema_version=current_version,
            )

        return backup

    def _copy_attachments(
        self,
        snapshot: Path,
        destination: Path,
    ) -> list[dict[str, Any]]:
        with _snapshot_connection(snapshot) as connection:
            if not _table_has_column(connection, "staged_objects", "attachment_id"):
                legacy_attachments = int(
                    connection.execute(
                        """
                        SELECT count(*) FROM attachments
                        WHERE storage_path IS NOT NULL AND purged_at IS NULL
                        """
                    ).fetchone()[0]
                )
                if legacy_attachments:
                    raise BackupError(
                        "legacy unencrypted attachments must be migrated before backup"
                    )
                rows = []
            else:
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
        _harden_private_directory(metadata_destination)
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
                target_descriptor = _open_new_private_file(target)
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
                    "detection_source": record.detection_source,
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
            rows = _active_staged_rows(connection)
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
                if row["consumed_request_id"] != item[
                    "consumed_request_id"
                ] or not _record_matches_manifest(record, item):
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
                    expected=StagingStore.metadata_document(
                        restored_record,
                        format_version=(3 if "detection_source" in item else 2),
                    ),
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
            rows = _active_staged_rows(connection)
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
                expected=StagingStore.metadata_document(
                    record,
                    format_version=(3 if "detection_source" in item else 2),
                ),
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
                envelope = read_verified_descriptor(descriptor, maximum_bytes=self.max_bundle_bytes)
            finally:
                os.close(descriptor)
        except StagingError as exc:
            raise BackupError("a restored attachment is unavailable or unsafe") from exc
        try:
            plaintext = self.staging.authenticate_envelope(record, envelope)
        except StagingError as exc:
            raise BackupError("a restored attachment failed integrity verification") from exc
        del plaintext


def _archive_members(
    workspace: Path,
    manifest: dict[str, Any],
) -> tuple[tuple[Path, str], ...]:
    members: list[tuple[Path, str]] = [(workspace / "approvals.sqlite3", "approvals.sqlite3")]
    for item in manifest["attachments"]:
        members.append((workspace / item["archive_path"], item["archive_path"]))
        members.append(
            (
                workspace / item["metadata_archive_path"],
                item["metadata_archive_path"],
            )
        )
    members.append((workspace / "manifest.json", "manifest.json"))
    return tuple(members)


def _projected_zip_size(members: tuple[tuple[Path, str], ...]) -> int:
    total = 22
    for path, archive_name in members:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise BackupError("backup archive source is not a safe regular file")
        name_bytes = archive_name.encode("utf-8")
        if len(name_bytes) > 65_535 or metadata.st_size >= 2**32 or total >= 2**32:
            raise BackupError("backup archive exceeds the supported ZIP size")
        total += metadata.st_size + 30 + len(name_bytes) + 46 + len(name_bytes)
    return total


def _archive_workspace(
    archive: BinaryIO,
    members: tuple[tuple[Path, str], ...],
) -> None:
    with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_STORED) as zipped:
        for path, archive_name in members:
            zipped.write(path, archive_name)
    archive.flush()


def _encrypted_bundle_size(archive_size: int) -> int:
    if archive_size <= 0:
        return _BACKUP_HEADER_BYTES
    chunks = (archive_size + _BACKUP_CHUNK_BYTES - 1) // _BACKUP_CHUNK_BYTES
    return _BACKUP_HEADER_BYTES + archive_size + chunks * (_RECORD_LENGTH_BYTES + _AEAD_TAG_BYTES)


def _encrypt_archive_to_path(
    archive: BinaryIO,
    *,
    archive_size: int,
    destination: Path,
    encryption_key: bytes,
) -> _BackupFileIdentity:
    seed = secrets.token_bytes(12)
    header = MAGIC + seed + archive_size.to_bytes(8, "big") + _BACKUP_CHUNK_BYTES.to_bytes(4, "big")
    descriptor: int | None = None
    created_identity: _BackupFileIdentity | None = None
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        created_metadata = os.fstat(descriptor)
        _require_owned_backup_metadata(created_metadata)
        created_identity = _BackupFileIdentity.from_stat(created_metadata)
        os.fchmod(descriptor, 0o600)
        try:
            require_no_acl_grants(descriptor)
        except PrivatePathError as exc:
            raise BackupError("backup temporary file inherited an unsafe granting ACL") from exc
        created_metadata = os.fstat(descriptor)
        _require_private_backup_metadata(created_metadata)
        _write_all(descriptor, header)
        cipher = AESGCM(encryption_key)
        remaining = archive_size
        index = 0
        while remaining:
            plaintext_length = min(remaining, _BACKUP_CHUNK_BYTES)
            plaintext = _read_stream_exact(archive, plaintext_length)
            ciphertext = cipher.encrypt(
                _chunk_nonce(seed, index),
                plaintext,
                _chunk_aad(header, index, plaintext_length),
            )
            _write_all(descriptor, len(ciphertext).to_bytes(4, "big") + ciphertext)
            remaining -= plaintext_length
            index += 1
        if archive.read(1):
            raise BackupError("backup archive changed while it was encrypted")
        os.fsync(descriptor)
        completed = os.fstat(descriptor)
        _require_private_backup_metadata(completed)
        completed_identity = _BackupFileIdentity.from_stat(completed)
        os.close(descriptor)
        descriptor = None
        return _require_private_backup_file(destination, expected=completed_identity)
    except BaseException as operation_error:
        cleanup_failed = False
        if descriptor is not None:
            if created_identity is None:
                try:
                    created_identity = _BackupFileIdentity.from_stat(os.fstat(descriptor))
                except BaseException:
                    cleanup_failed = True
            try:
                os.close(descriptor)
            except BaseException:
                cleanup_failed = True
        if created_identity is not None and not _unlink_backup_file_if_same(
            destination, created_identity
        ):
            cleanup_failed = True
        if cleanup_failed:
            raise BackupCleanupStateUnknown(
                "backup was not published, but private backup temporary-file cleanup could not "
                "be confirmed; inspect the backup parent before continuing"
            ) from operation_error
        raise


def _rename_backup_no_replace(source: Path, destination: Path) -> None:
    try:
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "linux":
            function = cast(Any, getattr(library, "renameat2", None))
            if function is None:
                raise BackupError("atomic no-replace backup publication is unavailable")
            function.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            arguments = (-100, os.fsencode(source), -100, os.fsencode(destination), 1)
        elif sys.platform == "darwin":
            function = cast(Any, getattr(library, "renamex_np", None))
            if function is None:
                raise BackupError("atomic no-replace backup publication is unavailable")
            function.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
            arguments = (os.fsencode(source), os.fsencode(destination), 0x00000004)
        else:
            raise BackupError("atomic no-replace backup publication is unavailable")
    except (OSError, ValueError) as exc:
        raise BackupError("atomic no-replace backup publication is unavailable") from exc

    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    if function(*arguments) != 0:
        error = ctypes.get_errno() or errno.EIO
        failure = OSError(error, os.strerror(error), destination)
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), destination)
        raise BackupError("atomic no-replace backup publication failed") from failure


def _require_owned_backup_metadata(metadata: os.stat_result) -> None:
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != current_uid
    ):
        raise BackupError("backup temporary file changed or became unsafe")


def _require_private_backup_metadata(metadata: os.stat_result) -> None:
    _require_owned_backup_metadata(metadata)
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise BackupError("backup temporary file changed or became unsafe")


def _require_private_backup_file(
    path: Path,
    *,
    expected: _BackupFileIdentity | None = None,
) -> _BackupFileIdentity:
    descriptor: int | None = None
    try:
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        after = path.lstat()
    except (OSError, PrivatePathError, ValueError) as exc:
        raise BackupError("backup temporary file changed or became unsafe") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    _require_private_backup_metadata(before)
    _require_private_backup_metadata(opened)
    _require_private_backup_metadata(after)
    observed = _BackupFileIdentity.from_stat(opened)
    if (
        not observed.same_object(before)
        or not observed.same_object(after)
        or before.st_size != observed.size
        or after.st_size != observed.size
        or (
            expected is not None
            and (not expected.same_object(opened) or expected.size != observed.size)
        )
    ):
        raise BackupError("backup temporary file changed or became unsafe")
    return observed


def _require_unchanged_backup_directory(identity: DirectoryIdentity) -> Path:
    try:
        return revalidate_directory_identity(identity, private=False)
    except PrivatePathError as exc:
        raise BackupError("backup parent changed or became unsafe") from exc


def _backup_publication_unknown() -> BackupPublicationUnknown:
    return BackupPublicationUnknown(
        "backup creation outcome is unknown because durable publication could not be "
        "confirmed; inspect the destination before retrying"
    )


def _unlink_backup_file_if_same(path: Path, identity: _BackupFileIdentity) -> bool:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or not identity.same_object(metadata):
            return False
        path.unlink()
        return True
    except OSError:
        return False


def _cleanup_backup_temporary_file(
    path: Path,
    *,
    identity: _BackupFileIdentity,
    parent_identity: DirectoryIdentity,
) -> None:
    try:
        parent = revalidate_directory_identity(parent_identity, private=False)
        _require_private_backup_file(path, expected=identity)
    except (BackupError, PrivatePathError) as exc:
        raise BackupError(
            "backup temporary file changed; refusing to remove a replacement"
        ) from exc
    if not _unlink_backup_file_if_same(path, identity):
        raise BackupError("backup temporary file could not be removed safely")
    try:
        _fsync_directory(parent)
        revalidate_directory_identity(parent_identity, private=False)
    except (OSError, PrivatePathError) as exc:
        raise BackupError("backup temporary file removal could not be confirmed durably") from exc


def _cleanup_backup_workspace(
    workspace: Path,
    *,
    parent_identity: DirectoryIdentity,
    workspace_identity: DirectoryIdentity | None,
) -> None:
    remove_private_tree_checked(
        workspace,
        parent_identity=parent_identity,
        tree_identity=workspace_identity,
    )


def remove_private_tree_checked(
    tree: Path,
    *,
    parent_identity: DirectoryIdentity,
    tree_identity: DirectoryIdentity | None,
) -> None:
    """Remove exactly one captured private tree and confirm durable absence."""

    if tree_identity is None:
        raise BackupError("private tree identity is unavailable for safe cleanup")
    try:
        parent = revalidate_directory_identity(parent_identity, private=False)
        metadata = tree.lstat()
    except FileNotFoundError:
        try:
            _fsync_directory(parent)
            revalidate_directory_identity(parent_identity, private=False)
        except (OSError, PrivatePathError) as exc:
            raise BackupError("private tree absence could not be confirmed durably") from exc
        return
    except (OSError, PrivatePathError, ValueError) as exc:
        raise BackupError("private tree could not be inspected for safe cleanup") from exc
    if not stat.S_ISDIR(metadata.st_mode) or (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
    ) != (
        tree_identity.device,
        tree_identity.inode,
        tree_identity.owner_uid,
    ):
        raise BackupError("private tree changed; refusing to remove a replacement")
    try:
        if not _RMTREE_AVOIDS_SYMLINK_ATTACKS:
            raise BackupError("symlink-safe private tree removal is unavailable")
        _chmod_captured_directory_for_cleanup(tree_identity)
        _remove_private_tree_with_repairs(tree, tree_identity)
        try:
            tree.lstat()
        except FileNotFoundError:
            pass
        else:
            raise BackupError("private tree still exists after cleanup")
        _fsync_directory(parent)
        revalidate_directory_identity(parent_identity, private=False)
    except (OSError, PrivatePathError) as exc:
        raise BackupError("private tree could not be removed durably") from exc


def _remove_private_tree_with_repairs(
    tree: Path,
    tree_identity: DirectoryIdentity,
) -> None:
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    repaired: set[Path] = set()
    while True:
        try:
            shutil.rmtree(tree)
            return
        except PermissionError as exc:
            if exc.filename is None or len(repaired) >= 64:
                raise
            blocked = Path(exc.filename).absolute()
            if blocked in repaired or not blocked.is_relative_to(tree):
                raise
            relative = blocked.relative_to(tree)
            if not relative.parts:
                hardened = harden_private_directory_identity(tree_identity)
            else:
                hardened = harden_private_directory_descendant(tree_identity, relative)
            if hardened.owner_uid != current_uid:
                raise
            repaired.add(blocked)


def _chmod_captured_directory_for_cleanup(
    identity: DirectoryIdentity,
) -> None:
    try:
        hardened = harden_private_directory_identity(identity)
        if not identity.same_object(hardened):
            raise BackupError("private tree changed; refusing to harden a replacement")
    except PrivatePathError as exc:
        raise BackupError("private tree could not be hardened safely") from exc


def _create_backup_workspace(
    parent_identity: DirectoryIdentity,
) -> tuple[Path, DirectoryIdentity]:
    parent = _require_unchanged_backup_directory(parent_identity)
    for _attempt in range(8):
        workspace = parent / f".signet-backup-{secrets.token_urlsafe(12)}"
        workspace_identity: DirectoryIdentity | None = None
        created = False
        try:
            os.mkdir(workspace, 0o700)
            created = True
            workspace_identity = _capture_backup_workspace_identity(workspace)
            private_workspace = _harden_private_directory(
                workspace,
                expected=workspace_identity,
            )
            if not workspace_identity.same_object(private_workspace):
                raise PrivatePathError("backup workspace identity changed")
            _require_unchanged_backup_directory(parent_identity)
            return workspace, private_workspace
        except FileExistsError:
            if not created:
                continue
            failure: BaseException = BackupError("backup workspace creation was interrupted")
        except BaseException as exc:
            failure = exc
            if not created:
                raise BackupCleanupStateUnknown(
                    "backup was not published, and backup workspace creation cleanup could not "
                    "be confirmed; inspect the backup parent before continuing"
                ) from failure
        if created:
            try:
                _cleanup_backup_workspace(
                    workspace,
                    parent_identity=parent_identity,
                    workspace_identity=workspace_identity,
                )
            except BaseException as cleanup_error:
                raise BackupCleanupStateUnknown(
                    "backup was not published, but private backup workspace cleanup could not "
                    "be confirmed; inspect the backup parent before continuing"
                ) from cleanup_error
        raise BackupError("backup workspace could not be secured") from failure
    raise BackupError("a unique private backup workspace could not be created")


def _create_restore_root(
    destination: Path,
) -> tuple[Path, DirectoryIdentity, DirectoryIdentity]:
    try:
        parent = ensure_owned_directory(destination.parent)
        parent_identity = require_owned_directory_identity(parent)
    except (OSError, PrivatePathError, ValueError) as exc:
        raise BackupError("restore parent is unavailable or unsafe") from exc
    if destination.exists() or destination.is_symlink():
        raise BackupError("restore destination must not already exist")
    root_identity: DirectoryIdentity | None = None
    created = False
    try:
        os.mkdir(destination, 0o700)
        created = True
        root_identity = _capture_backup_workspace_identity(destination)
        private_root = _harden_private_directory(destination, expected=root_identity)
        if not root_identity.same_object(private_root):
            raise PrivatePathError("restore destination identity changed")
        _require_unchanged_backup_directory(parent_identity)
        _fsync_directory(parent)
        _require_unchanged_backup_directory(parent_identity)
        return destination, parent_identity, private_root
    except FileExistsError as exc:
        if not created:
            raise BackupError("restore destination must not already exist") from exc
        failure: BaseException = exc
    except BaseException as exc:
        failure = exc
        if not created:
            raise BackupCleanupStateUnknown(
                "backup restore did not complete, and restore-tree creation cleanup could not "
                "be confirmed; inspect the restore parent before continuing"
            ) from failure
    if created:
        try:
            remove_private_tree_checked(
                destination,
                parent_identity=parent_identity,
                tree_identity=root_identity,
            )
        except BaseException as cleanup_error:
            raise BackupCleanupStateUnknown(
                "backup restore did not complete, but private restore-tree cleanup could not be "
                "confirmed; inspect the restore parent before continuing"
            ) from cleanup_error
    raise BackupError("restore destination could not be created privately") from failure


def _capture_backup_workspace_identity(workspace: Path) -> DirectoryIdentity:
    try:
        return capture_owned_directory_identity(workspace)
    except PrivatePathError as exc:
        raise BackupError("backup workspace could not be inspected safely") from exc


def _harden_private_directory(
    path: Path,
    *,
    expected: DirectoryIdentity | None = None,
) -> DirectoryIdentity:
    before = expected or _capture_backup_workspace_identity(path)
    try:
        hardened = harden_private_directory_identity(before)
        private = require_private_directory_identity(path)
    except (OSError, PrivatePathError) as exc:
        raise BackupError("private backup directory could not be hardened safely") from exc
    if not before.same_object(hardened) or not before.same_object(private):
        raise BackupError("private backup directory identity changed")
    return private


def _decrypt_bundle_to_archive(
    descriptor: int,
    archive: BinaryIO,
    *,
    encryption_key: bytes,
    maximum_bytes: int,
) -> None:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < _BACKUP_HEADER_BYTES
        or before.st_size > maximum_bytes
    ):
        raise BackupError("backup bundle is not a safe bounded regular file")
    os.lseek(descriptor, 0, os.SEEK_SET)
    header = _read_descriptor_exact(descriptor, _BACKUP_HEADER_BYTES)
    if not header.startswith(MAGIC):
        raise BackupError("backup bundle header is invalid")
    offset = len(MAGIC)
    seed = header[offset : offset + 12]
    archive_size = int.from_bytes(header[offset + 12 : offset + 20], "big")
    chunk_size = int.from_bytes(header[offset + 20 : offset + 24], "big")
    if (
        chunk_size != _BACKUP_CHUNK_BYTES
        or archive_size <= 0
        or _encrypted_bundle_size(archive_size) != before.st_size
    ):
        raise BackupError("backup bundle header is invalid")

    cipher = AESGCM(encryption_key)
    remaining = archive_size
    index = 0
    try:
        while remaining:
            plaintext_length = min(remaining, _BACKUP_CHUNK_BYTES)
            ciphertext_length = int.from_bytes(
                _read_descriptor_exact(descriptor, _RECORD_LENGTH_BYTES), "big"
            )
            if ciphertext_length != plaintext_length + _AEAD_TAG_BYTES:
                raise BackupError("backup bundle record is invalid")
            ciphertext = _read_descriptor_exact(descriptor, ciphertext_length)
            plaintext = cipher.decrypt(
                _chunk_nonce(seed, index),
                ciphertext,
                _chunk_aad(header, index, plaintext_length),
            )
            _write_stream_all(archive, plaintext)
            remaining -= plaintext_length
            index += 1
    except InvalidTag as exc:
        raise BackupError("backup authentication failed") from exc
    if os.read(descriptor, 1):
        raise BackupError("backup bundle has trailing data")
    after = os.fstat(descriptor)
    if _file_signature(before) != _file_signature(after):
        raise BackupError("backup bundle changed while it was read")
    archive.flush()


def _chunk_nonce(seed: bytes, index: int) -> bytes:
    if index < 0 or index > 0xFFFFFFFF:
        raise BackupError("backup contains too many chunks")
    tail = int.from_bytes(seed[8:], "big") ^ index
    return seed[:8] + tail.to_bytes(4, "big")


def _chunk_aad(header: bytes, index: int, plaintext_length: int) -> bytes:
    return header + index.to_bytes(4, "big") + plaintext_length.to_bytes(4, "big")


def _read_stream_exact(stream: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise BackupError("backup archive ended unexpectedly")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_descriptor_exact(descriptor: int, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            raise BackupError("backup bundle is truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_stream_all(stream: BinaryIO, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = stream.write(view)
        if written is None or written <= 0:
            raise BackupError("backup archive write made no progress")
        view = view[written:]


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
        current = destination
        for component in path.parts[:-1]:
            current = current / component
            _harden_private_directory(current)
        if info.is_dir():
            continue
        descriptor = _open_new_private_file(target)
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
    legacy_required_keys = {
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
    required_keys = {*legacy_required_keys, "detection_source"}
    for item in attachments:
        if not isinstance(item, dict) or set(item) not in (
            legacy_required_keys,
            required_keys,
        ):
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
            or item.get("detection_source", "legacy_filename_unverified")
            not in {"legacy_filename_unverified", "content_signature_v1"}
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
            or metadata_archive.parts != ("attachments", ".metadata", f"{attachment_id}.json")
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
    available_columns = frozenset(row.keys())
    values = {
        "attachment_id": row["attachment_id"],
        "adapter": row["adapter"],
        "account": row["account"],
        "filename": row["filename"],
        "declared_mime": row["declared_mime"],
        "detected_mime": row["detected_mime"],
        "detection_source": (
            row["detection_source"]
            if "detection_source" in available_columns
            else "legacy_filename_unverified"
        ),
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
        or values["detection_source"] not in {"legacy_filename_unverified", "content_signature_v1"}
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
        detection_source=values["detection_source"],
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
        detection_source=record.detection_source,
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
            record.detection_source == item.get("detection_source", "legacy_filename_unverified"),
            record.size == item["size_bytes"],
            record.sha256 == item["sha256"],
            record.envelope_format == item["envelope_format"],
            record.envelope_size == item["envelope_size"],
            record.envelope_sha256 == item["envelope_sha256"],
            record.encryption_key_ref == item["encryption_key_ref"],
            record.created_at == item["created_at"],
        )
    )


def _table_has_column(connection: Any, table: str, column: str) -> bool:
    if table not in {"payload_versions", "staged_objects", "web_action_drafts"}:
        raise ValueError("unsupported backup catalog table")
    return any(str(row[1]) == column for row in connection.execute(f"PRAGMA table_info({table})"))


def _active_staged_rows(connection: Any) -> list[Any]:
    if not _table_has_column(connection, "staged_objects", "attachment_id"):
        active_legacy_attachments = int(
            connection.execute(
                """
                SELECT count(*) FROM attachments
                WHERE storage_path IS NOT NULL AND purged_at IS NULL
                """
            ).fetchone()[0]
        )
        if active_legacy_attachments:
            raise BackupError("legacy unencrypted attachments must be migrated before backup")
        return []
    return list(
        connection.execute(
            """
            SELECT staged.* FROM staged_objects AS staged
            WHERE staged.storage_path IS NOT NULL AND staged.purged_at IS NULL
            """
        ).fetchall()
    )


def _key_references(connection: Any) -> list[str]:
    references: set[str] = set()
    queries = (
        (
            "payload_versions",
            "encryption_key_ref",
            "SELECT encryption_key_ref FROM payload_versions WHERE encryption_key_ref IS NOT NULL",
        ),
        (
            "staged_objects",
            "encryption_key_ref",
            "SELECT encryption_key_ref FROM staged_objects WHERE encryption_key_ref IS NOT NULL",
        ),
        (
            "web_action_drafts",
            "edit_encryption_key_ref",
            "SELECT edit_encryption_key_ref FROM web_action_drafts "
            "WHERE edit_encryption_key_ref IS NOT NULL",
        ),
    )
    for table, column, query in queries:
        if not _table_has_column(connection, table, column):
            continue
        references.update(str(row[0]) for row in connection.execute(query))
    return sorted(references)


def _require_consistent_attachment_references(connection: Any) -> None:
    if not _table_has_column(connection, "staged_objects", "attachment_id"):
        return
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
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
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
    descriptor = _open_new_private_file(path)
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_new_private_file(path: Path) -> int:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        _require_owned_backup_metadata(os.fstat(descriptor))
        os.fchmod(descriptor, 0o600)
        require_no_acl_grants(descriptor)
        _require_private_backup_metadata(os.fstat(descriptor))
        return descriptor
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        raise


def _absolute_backup_path(path: Path, *, message: str) -> Path:
    try:
        selected = Path(path).expanduser().absolute()
        encoded = os.fsencode(selected)
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        raise BackupError(message) from exc
    if b"\x00" in encoded or selected.name in {"", ".", ".."}:
        raise BackupError(message)
    return selected


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
