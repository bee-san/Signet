from __future__ import annotations

import errno
import json
import os
import sqlite3
import stat
import tempfile
import time
import zipfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import BinaryIO

import pytest

import signet.backup as backup_module
import signet.private_paths as private_paths_module
from signet.backup import (
    BackupBundleManager,
    BackupCleanupStateUnknown,
    BackupError,
    BackupPublicationUnknown,
    BackupPublishedWithWarnings,
    BackupRetentionStateUnknown,
    RestoredBundle,
)
from signet.db import Database
from signet.models import AttachmentReference, EnqueueRequest, RequestState
from signet.private_paths import (
    DirectoryIdentity,
    PrivatePathError,
    require_owned_directory_identity,
    require_private_directory_identity,
)
from signet.retention import RetentionError, RetentionManager, RetentionMatrix
from signet.staging import StagedFile, StagingStore
from signet.state_machine import ApprovalStateMachine
from tests.attachment_fixtures import (
    FAKE_ATTACHMENT_KEY_REF,
    attachment_cipher,
)
from tests.migration_helpers import (
    downgrade_auth_credentials_before_schema_16,
    downgrade_auth_credentials_before_schema_17,
)

PAYLOAD_KEY_REF = "keychain://Signet/payload-backupfixture"


def _request(staged: StagedFile, *, request_id: str = "backupfixture") -> EnqueueRequest:
    return EnqueueRequest(
        request_id=request_id,
        downstream_alias="fastmail",
        tool_name="send_email",
        policy_mode="approval",
        origin_namespace="profile:test",
        encrypted_payload=b"encrypted-private-payload",
        payload_hash="a" * 64,
        payload_fingerprint=f"fingerprint-{request_id}",
        pending_result=b'{"status":"pending_approval"}',
        created_at=100,
        expires_at=200,
        policy_version="policy-1",
        adapter_version="adapter-1",
        schema_version="schema-1",
        editor_actor="caller:profile:test",
        encryption_key_ref=PAYLOAD_KEY_REF,
        attachments=(
            AttachmentReference(
                attachment_id=staged.opaque_id,
                filename=staged.filename,
                mime_type=staged.declared_mime,
                size_bytes=staged.size,
                sha256=staged.sha256,
                storage_path=str(staged.path),
            ),
        ),
    )


def _fixture(
    tmp_path: Path,
    *,
    content: bytes = b"sensitive attachment bytes",
    request_id: str = "backupfixture",
) -> tuple[Database, StagingStore, StagedFile]:
    database = Database(tmp_path / "live" / "approvals.sqlite3")
    database.initialize()
    source_root = tmp_path / "sources"
    source_root.mkdir()
    source = source_root / "sensitive-name.txt"
    source.write_bytes(content)
    staging = StagingStore(
        tmp_path / "staging",
        database=database,
        cipher=attachment_cipher(),
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    staged = staging.stage_path(
        source,
        adapter="fastmail",
        account="primary",
        filename="sensitive-name.txt",
        declared_mime="text/plain",
    )
    ApprovalStateMachine(database).enqueue(_request(staged, request_id=request_id))
    return database, staging, staged


def _manager(
    database: Database,
    staging: StagingStore,
    *,
    key: bytes = b"k" * 32,
) -> BackupBundleManager:
    return BackupBundleManager(database, staging=staging, encryption_key=key)


def test_legacy_key_reference_inventory_tolerates_unencrypted_staged_schema() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE payload_versions(encryption_key_ref TEXT)")
        connection.execute("CREATE TABLE staged_objects(attachment_id TEXT PRIMARY KEY)")
        connection.execute(
            "INSERT INTO payload_versions(encryption_key_ref) VALUES (?)",
            (PAYLOAD_KEY_REF,),
        )

        assert backup_module._key_references(connection) == [PAYLOAD_KEY_REF]
    finally:
        connection.close()


def _restored_store(restored: RestoredBundle) -> StagingStore:
    database = Database(restored.database_path)
    database.initialize()
    return StagingStore(
        restored.attachments_root,
        database=database,
        cipher=attachment_cipher(),
        minimum_free_bytes=0,
    )


def _rewrite_encrypted_archive(
    bundle: Path,
    destination: Path,
    mutator: Callable[[dict[str, bytes]], None],
) -> Path:
    with tempfile.TemporaryFile(mode="w+b") as archive:
        descriptor = os.open(bundle, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            backup_module._decrypt_bundle_to_archive(
                descriptor,
                archive,
                encryption_key=b"k" * 32,
                maximum_bytes=512 * 1024 * 1024,
            )
        finally:
            os.close(descriptor)
        archive.seek(0)
        with zipfile.ZipFile(archive, mode="r") as zipped:
            members = {info.filename: zipped.read(info) for info in zipped.infolist()}

    mutator(members)
    with tempfile.TemporaryFile(mode="w+b") as rewritten:
        with zipfile.ZipFile(rewritten, mode="w", compression=zipfile.ZIP_STORED) as zipped:
            for name, content in members.items():
                zipped.writestr(name, content)
        archive_size = rewritten.seek(0, os.SEEK_END)
        rewritten.seek(0)
        backup_module._encrypt_archive_to_path(
            rewritten,
            archive_size=archive_size,
            destination=destination,
            encryption_key=b"k" * 32,
        )
    return destination


def _downgrade_catalog_to_schema_12(database: Database) -> None:
    with database.transaction() as connection:
        connection.execute("DROP TABLE browser_enrollment_authorizations")
        connection.execute("DROP TABLE auth_factor_challenges")
        connection.execute("DROP TABLE auth_factor_events")
        connection.execute("DROP TABLE auth_factors")
        downgrade_auth_credentials_before_schema_17(connection)
        downgrade_auth_credentials_before_schema_16(connection)
        connection.execute("DROP TABLE attachment_metadata_privacy_maintenance")
        connection.execute("DROP TRIGGER IF EXISTS request_events_structured_reason_insert")
        connection.execute("DROP TRIGGER IF EXISTS web_action_drafts_structured_reason_insert")
        connection.execute("DROP TRIGGER staged_objects_immutable_context")
        connection.execute("ALTER TABLE staged_objects DROP COLUMN detection_source")
        connection.execute(
            """
            CREATE TRIGGER staged_objects_immutable_context
            BEFORE UPDATE OF
                attachment_id, adapter, account, filename, declared_mime, detected_mime,
                size_bytes, sha256, envelope_format, envelope_size, envelope_sha256,
                created_at, consumed_request_id, consumed_at
            ON staged_objects
            FOR EACH ROW
            WHEN
                OLD.attachment_id IS NOT NEW.attachment_id OR
                OLD.adapter IS NOT NEW.adapter OR
                OLD.account IS NOT NEW.account OR
                OLD.filename IS NOT NEW.filename OR
                OLD.declared_mime IS NOT NEW.declared_mime OR
                OLD.detected_mime IS NOT NEW.detected_mime OR
                OLD.size_bytes IS NOT NEW.size_bytes OR
                OLD.sha256 IS NOT NEW.sha256 OR
                OLD.envelope_format IS NOT NEW.envelope_format OR
                OLD.envelope_size IS NOT NEW.envelope_size OR
                OLD.envelope_sha256 IS NOT NEW.envelope_sha256 OR
                OLD.created_at IS NOT NEW.created_at OR
                NOT (
                    (OLD.consumed_request_id IS NEW.consumed_request_id AND
                     OLD.consumed_at IS NEW.consumed_at) OR
                    (OLD.consumed_request_id IS NULL AND OLD.consumed_at IS NULL AND
                     NEW.consumed_request_id IS NOT NULL AND NEW.consumed_at IS NOT NULL)
                )
            BEGIN
                SELECT RAISE(ABORT, 'staged object immutable context changed');
            END
            """
        )
        connection.execute("DROP TABLE browser_totp_enrollments")
        connection.execute("DROP TABLE auth_registration_challenges")
        connection.execute("DROP TABLE browser_bootstrap_state")
        connection.execute("DROP TABLE connector_effect_review_drafts")
        connection.execute("DROP TABLE connector_effect_review_challenges")
        connection.execute("DROP TABLE connector_effect_reviews")
        connection.execute("DROP TABLE connector_effect_evidence")
        connection.execute("DROP TABLE connector_tool_state")
        connection.execute("DROP TABLE connector_discovered_tools")
        connection.execute("DROP TABLE connector_discovery_runs")
        connection.execute("DROP TABLE connector_active")
        connection.execute("DROP TABLE connector_configurations")
        connection.execute("DROP TABLE plugin_tool_mappings")
        connection.execute("DROP TABLE plugin_active")
        connection.execute("DROP TABLE plugin_manifests")
        connection.execute("DROP TABLE production_secret_references")
        connection.execute("DROP TABLE production_services")
        connection.execute("DROP TABLE production_connectors")
        connection.execute("DROP TABLE production_users")
        connection.execute("DROP TABLE production_setup_state")
        connection.execute("DROP TABLE privacy_maintenance")
        connection.execute("DELETE FROM schema_meta WHERE migration_id > 12")
        connection.execute("PRAGMA user_version = 12")


def test_encrypted_bundle_restores_catalogued_envelopes_and_key_manifest(
    tmp_path: Path,
) -> None:
    database, staging, staged = _fixture(tmp_path)
    manager = _manager(database, staging)

    bundle = manager.create(tmp_path / "backups" / "backup.signet", created_at=123)
    encrypted = bundle.read_bytes()
    assert b"sensitive attachment bytes" not in encrypted
    assert b"sensitive-name.txt" not in encrypted
    assert b"keychain://" not in encrypted

    restored = manager.restore(bundle, tmp_path / "restored")
    assert restored.manifest["format"] == 2
    assert restored.manifest["created_at"] == 123
    assert restored.manifest["key_references"] == sorted([FAKE_ATTACHMENT_KEY_REF, PAYLOAD_KEY_REF])
    restored_envelope = restored.attachments_root / staged.opaque_id
    assert b"sensitive attachment bytes" not in restored_envelope.read_bytes()
    assert (restored.attachments_root / ".metadata" / f"{staged.opaque_id}.json").is_file()

    restarted = _restored_store(restored)
    record, plaintext = restarted.read_verified(
        staged.opaque_id,
        adapter="fastmail",
        account="primary",
    )
    assert plaintext == b"sensitive attachment bytes"
    assert record.path == restored_envelope
    with restarted.database.read() as connection:
        attachment_path = connection.execute(
            "SELECT storage_path FROM attachments WHERE attachment_id = ?",
            (staged.opaque_id,),
        ).fetchone()[0]
        catalog_path = connection.execute(
            "SELECT storage_path FROM staged_objects WHERE attachment_id = ?",
            (staged.opaque_id,),
        ).fetchone()[0]
        restored_active_pins = connection.execute(
            """
            SELECT count(*) FROM purge_jobs
            WHERE intent = 'backup_pin' AND completed_at IS NULL
            """
        ).fetchone()[0]
    assert attachment_path == catalog_path == str(restored_envelope)
    assert restored_active_pins == 0
    with database.read() as connection:
        live_pins = connection.execute(
            "SELECT started_at, completed_at FROM purge_jobs WHERE intent = 'backup_pin'"
        ).fetchall()
    assert len(live_pins) == 1
    assert live_pins[0]["started_at"] is not None
    assert live_pins[0]["completed_at"] is not None


def test_restore_rejects_manifest_schema_that_differs_from_the_snapshot(
    tmp_path: Path,
) -> None:
    database, staging, _ = _fixture(tmp_path)
    manager = _manager(database, staging)
    current = manager.create(tmp_path / "current.signet")

    def change_schema_version(members: dict[str, bytes]) -> None:
        manifest = json.loads(members["manifest.json"])
        manifest["schema_version"] += 1
        members["manifest.json"] = json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    mismatched = _rewrite_encrypted_archive(
        current,
        tmp_path / "schema-mismatch.signet",
        change_schema_version,
    )

    with pytest.raises(BackupError, match="schema version"):
        manager.restore(mismatched, tmp_path / "schema-mismatch-restore")
    assert not (tmp_path / "schema-mismatch-restore").exists()


def test_backup_publication_never_replaces_a_destination_created_during_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"publication race fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "race.signet"
    original_publish = backup_module._rename_backup_no_replace
    raced_identity: tuple[int, int] | None = None

    def create_destination_then_publish(source: Path, target: Path) -> None:
        nonlocal raced_identity
        target.write_bytes(b"racing writer owns this destination")
        target.chmod(0o600)
        metadata = target.stat()
        raced_identity = (metadata.st_dev, metadata.st_ino)
        original_publish(source, target)

    monkeypatch.setattr(
        backup_module,
        "_rename_backup_no_replace",
        create_destination_then_publish,
    )

    with pytest.raises(BackupError, match="destination already exists"):
        manager.create(destination)

    assert raced_identity is not None
    assert destination.read_bytes() == b"racing writer owns this destination"
    metadata = destination.stat()
    assert (metadata.st_dev, metadata.st_ino) == raced_identity
    assert tuple(tmp_path.glob(".race.signet.partial-*")) == ()
    assert tuple(tmp_path.glob(".signet-backup-*")) == ()


def test_concurrent_backup_publication_has_exactly_one_non_overwriting_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"concurrent publication fixture")
    managers = {
        "first": _manager(database, staging, key=b"1" * 32),
        "second": _manager(database, staging, key=b"2" * 32),
    }
    destination = tmp_path / "concurrent.signet"
    publication_barrier = Barrier(2)
    original_publish = backup_module._rename_backup_no_replace

    def publish_together(source: Path, target: Path) -> None:
        publication_barrier.wait(timeout=10)
        original_publish(source, target)

    monkeypatch.setattr(backup_module, "_rename_backup_no_replace", publish_together)

    def create(label: str) -> tuple[str, Path | BackupError]:
        try:
            return label, managers[label].create(destination)
        except BackupError as exc:
            return label, exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(create, managers))

    winners = [(label, result) for label, result in results if isinstance(result, Path)]
    losers = [(label, result) for label, result in results if isinstance(result, BackupError)]
    assert len(winners) == len(losers) == 1
    assert winners[0][1] == destination
    assert str(losers[0][1]) == "backup destination already exists"
    winning_manager = managers[winners[0][0]]
    losing_manager = managers[losers[0][0]]
    restored = winning_manager.restore(destination, tmp_path / "winner-restored")
    assert restored.manifest["format"] == 2
    with pytest.raises(BackupError, match="authentication"):
        losing_manager.restore(destination, tmp_path / "loser-restored")
    assert tuple(tmp_path.glob(".concurrent.signet.partial-*")) == ()
    assert tuple(tmp_path.glob(".signet-backup-*")) == ()


def test_backup_workspace_interrupt_after_mkdir_is_retained_without_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"workspace interrupt fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "workspace-interrupt.signet"
    original_mkdir = backup_module.os.mkdir
    interrupted = False

    def mkdir_then_interrupt(
        path: Path, mode: int = 0o777, *args: object, **kwargs: object
    ) -> None:
        nonlocal interrupted
        original_mkdir(path, mode, *args, **kwargs)
        if Path(path).name.startswith(".signet-backup-"):
            interrupted = True
            raise KeyboardInterrupt

    monkeypatch.setattr(backup_module.os, "mkdir", mkdir_then_interrupt)

    with pytest.raises(
        BackupCleanupStateUnknown,
        match="workspace creation cleanup could not be confirmed",
    ):
        manager.create(destination)

    assert interrupted
    assert not destination.exists()
    workspaces = tuple(tmp_path.glob(".signet-backup-*"))
    assert len(workspaces) == 1
    backup_module.shutil.rmtree(workspaces[0])


def test_backup_workspace_preserves_replacement_when_mkdir_outcome_is_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"workspace replacement boundary")
    manager = _manager(database, staging)
    destination = tmp_path / "workspace-uncaptured.signet"
    original_mkdir = backup_module.os.mkdir
    displaced = tmp_path / "workspace-created-before-interrupt"
    replacement: Path | None = None

    def replace_then_interrupt(
        path: Path,
        mode: int = 0o777,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal replacement
        original_mkdir(path, mode, *args, **kwargs)
        selected = Path(path)
        if selected.name.startswith(".signet-backup-"):
            selected.rename(displaced)
            original_mkdir(selected, 0o700)
            (selected / "replacement-marker").write_text("preserve\n", encoding="utf-8")
            selected.chmod(0o500)
            replacement = selected
            raise KeyboardInterrupt

    monkeypatch.setattr(backup_module.os, "mkdir", replace_then_interrupt)

    with pytest.raises(
        BackupCleanupStateUnknown,
        match="workspace creation cleanup could not be confirmed",
    ):
        manager.create(destination)

    assert replacement is not None
    assert (replacement / "replacement-marker").read_text(encoding="utf-8") == "preserve\n"
    assert stat.S_IMODE(replacement.stat().st_mode) == 0o500
    replacement.chmod(0o700)
    backup_module.shutil.rmtree(replacement)
    backup_module.shutil.rmtree(displaced)


def test_backup_workspace_descriptor_hardening_failure_is_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"workspace chmod fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "workspace-chmod.signet"
    original_harden = backup_module._harden_private_directory

    def fail_workspace_hardening(
        path: Path,
        *,
        expected: DirectoryIdentity | None = None,
    ) -> DirectoryIdentity:
        if Path(path).name.startswith(".signet-backup-"):
            raise OSError("injected workspace descriptor-hardening failure")
        return original_harden(path, expected=expected)

    monkeypatch.setattr(
        backup_module,
        "_harden_private_directory",
        fail_workspace_hardening,
    )

    with pytest.raises(BackupError, match="workspace could not be secured"):
        manager.create(destination)

    assert not destination.exists()
    assert tuple(tmp_path.glob(".signet-backup-*")) == ()


def test_backup_create_and_restore_harden_every_artifact_under_restrictive_umask(
    tmp_path: Path,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"restrictive umask fixture")
    manager = _manager(database, staging)
    bundle = tmp_path / "restrictive-umask.signet"
    restored_root = tmp_path / "restrictive-umask-restored"
    previous_umask = os.umask(0o777)
    try:
        assert manager.create(bundle, created_at=238) == bundle
        restored = manager.restore(bundle, restored_root)
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(bundle.stat().st_mode) == 0o600
    for path in restored.root.rglob("*"):
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == (0o700 if path.is_dir() else 0o600), path
    assert tuple(tmp_path.glob(".signet-backup-*")) == ()


def test_interrupt_between_private_subdirectory_mkdir_and_hardening_is_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"subdirectory interrupt fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "subdirectory-interrupt.signet"
    original_harden = backup_module._harden_private_directory
    interrupted = False

    def interrupt_first_attachments_hardening(
        path: Path,
        *,
        expected: DirectoryIdentity | None = None,
    ) -> object:
        nonlocal interrupted
        if path.name == "attachments" and path.parent.name.startswith(".signet-backup-"):
            interrupted = True
            raise KeyboardInterrupt
        return original_harden(path, expected=expected)

    monkeypatch.setattr(
        backup_module,
        "_harden_private_directory",
        interrupt_first_attachments_hardening,
    )
    previous_umask = os.umask(0o777)
    try:
        with pytest.raises(KeyboardInterrupt):
            manager.create(destination)
    finally:
        os.umask(previous_umask)

    assert interrupted
    assert not destination.exists()
    assert tuple(tmp_path.glob(".signet-backup-*")) == ()


def test_backup_reports_unknown_outcome_and_preserves_publish_on_parent_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"durability fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "fsync-unknown.signet"
    original_fsync = backup_module._fsync_directory

    def fail_parent_fsync(path: Path) -> None:
        if path == tmp_path and destination.exists():
            raise OSError("injected parent fsync failure")
        original_fsync(path)

    monkeypatch.setattr(backup_module, "_fsync_directory", fail_parent_fsync)

    with pytest.raises(
        BackupPublicationUnknown,
        match="outcome is unknown.*durable publication",
    ):
        manager.create(destination, created_at=234)

    assert destination.is_file()
    monkeypatch.setattr(backup_module, "_fsync_directory", original_fsync)
    assert (
        manager.restore(destination, tmp_path / "fsync-unknown-restored").manifest["created_at"]
        == 234
    )
    assert tuple(tmp_path.glob(".fsync-unknown.signet.partial-*")) == ()


@pytest.mark.parametrize(
    "release_failure",
    (
        RetentionError("injected retention failure"),
        sqlite3.OperationalError("injected sqlite release failure"),
        KeyboardInterrupt(),
    ),
    ids=("retention", "sqlite", "interrupt"),
)
def test_retention_pin_release_uncertainty_prevents_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    release_failure: BaseException,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"pin release boundary fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "pin-release-failure.signet"
    publication_calls: list[tuple[Path, Path]] = []

    def fail_pin_release(_pins: object, *, now: int) -> None:
        del now
        raise release_failure

    def record_publication(source: Path, target: Path) -> None:
        publication_calls.append((source, target))

    monkeypatch.setattr(manager._backup_pins, "release", fail_pin_release)
    monkeypatch.setattr(backup_module, "_rename_backup_no_replace", record_publication)

    with pytest.raises(
        BackupRetentionStateUnknown,
        match="was not published.*release could not be confirmed",
    ) as caught:
        manager.create(destination, created_at=235)

    assert caught.value.__cause__ is release_failure
    assert publication_calls == []
    assert not destination.exists()
    assert tuple(tmp_path.glob(".pin-release-failure.signet.partial-*")) == ()
    assert tuple(tmp_path.glob(".signet-backup-*")) == ()


@pytest.mark.parametrize(
    "acquire_failure",
    (
        sqlite3.OperationalError("injected sqlite acquire failure"),
        KeyboardInterrupt(),
    ),
    ids=("sqlite", "interrupt"),
)
def test_retention_pin_acquisition_uncertainty_is_prepublication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    acquire_failure: BaseException,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"pin acquire boundary fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "pin-acquire-failure.signet"

    def fail_pin_acquire(*, now: int) -> object:
        del now
        raise acquire_failure

    monkeypatch.setattr(manager._backup_pins, "acquire", fail_pin_acquire)

    with pytest.raises(
        BackupRetentionStateUnknown,
        match="was not published.*acquisition could not be confirmed",
    ) as caught:
        manager.create(destination)

    assert caught.value.__cause__ is acquire_failure
    assert not destination.exists()
    assert tuple(tmp_path.glob(".signet-backup-*")) == ()


def test_construction_and_pin_release_failure_reports_fixed_prepublication_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"combined prepublication fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "combined-prepublication.signet"
    construction_failure = BackupError("injected construction failure")

    def fail_pin_release(_pins: object, *, now: int) -> None:
        del now
        raise sqlite3.OperationalError("injected sqlite release failure")

    monkeypatch.setattr(
        backup_module,
        "_archive_workspace",
        lambda *_args: (_ for _ in ()).throw(construction_failure),
    )
    monkeypatch.setattr(manager._backup_pins, "release", fail_pin_release)

    with pytest.raises(
        BackupRetentionStateUnknown,
        match="was not published.*construction failed.*release could not be confirmed",
    ) as caught:
        manager.create(destination, created_at=236)

    assert caught.value.__cause__ is construction_failure
    assert not destination.exists()
    assert tuple(tmp_path.glob(".signet-backup-*")) == ()


def test_construction_cleanup_and_pin_release_uncertainty_report_both_states(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"combined recovery fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "combined-recovery.signet"
    original_rmtree = backup_module.shutil.rmtree

    def fail_construction(*_args: object) -> None:
        raise BackupError("injected private construction failure")

    def fail_pin_release(_pins: object, *, now: int) -> None:
        del now
        raise sqlite3.OperationalError("injected private release failure")

    def retain_workspace(path: Path) -> None:
        if path.name.startswith(".signet-backup-"):
            raise OSError("injected private cleanup failure")
        original_rmtree(path)

    monkeypatch.setattr(backup_module, "_archive_workspace", fail_construction)
    monkeypatch.setattr(manager._backup_pins, "release", fail_pin_release)
    monkeypatch.setattr(backup_module.shutil, "rmtree", retain_workspace)

    with pytest.raises(BackupRetentionStateUnknown) as caught:
        manager.create(destination)

    message = caught.value.operator_message()
    assert "retention pin release could not be confirmed" in message
    assert "private backup artifacts could not be removed safely" in message.lower()
    assert "injected" not in message
    assert not destination.exists()
    workspaces = tuple(tmp_path.glob(".signet-backup-*"))
    assert len(workspaces) == 1
    monkeypatch.setattr(backup_module.shutil, "rmtree", original_rmtree)
    original_rmtree(workspaces[0])


def test_inner_construction_cleanup_and_pin_release_report_both_states(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"inner combined recovery fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "inner-combined-recovery.signet"
    construction_failure = BackupCleanupStateUnknown(
        "backup was not published, but temporary-file cleanup could not be confirmed"
    )

    def fail_encryption(*_args: object, **_kwargs: object) -> object:
        raise construction_failure

    def fail_pin_release(_pins: object, *, now: int) -> None:
        del now
        raise sqlite3.OperationalError("injected private release failure")

    monkeypatch.setattr(backup_module, "_encrypt_archive_to_path", fail_encryption)
    monkeypatch.setattr(manager._backup_pins, "release", fail_pin_release)

    with pytest.raises(BackupRetentionStateUnknown) as caught:
        manager.create(destination)

    message = caught.value.operator_message()
    assert "retention pin release could not be confirmed" in message
    assert "private backup artifacts could not be removed safely" in message.lower()
    assert "injected" not in message
    assert caught.value.__cause__ is construction_failure


def test_retention_pins_are_released_before_atomic_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"pin ordering fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "pin-order.signet"
    events: list[str] = []
    original_release = manager._backup_pins.release
    original_publish = backup_module._rename_backup_no_replace

    def release_before_publish(pins: object, *, now: int) -> None:
        events.append("pins_released")
        original_release(pins, now=now)  # type: ignore[arg-type]

    def publish_after_release(source: Path, target: Path) -> None:
        events.append("publication_started")
        original_publish(source, target)

    monkeypatch.setattr(manager._backup_pins, "release", release_before_publish)
    monkeypatch.setattr(backup_module, "_rename_backup_no_replace", publish_after_release)

    assert manager.create(destination, created_at=237) == destination
    assert events == ["pins_released", "publication_started"]


def test_backup_reports_unknown_outcome_when_interrupted_immediately_after_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"interrupted publication fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "interrupted.signet"
    original_publish = backup_module._rename_backup_no_replace

    def publish_then_interrupt(source: Path, target: Path) -> None:
        original_publish(source, target)
        raise KeyboardInterrupt

    monkeypatch.setattr(backup_module, "_rename_backup_no_replace", publish_then_interrupt)

    with pytest.raises(
        BackupPublicationUnknown,
        match="outcome is unknown.*durable publication",
    ):
        manager.create(destination, created_at=345)

    assert destination.is_file()
    assert (
        manager.restore(destination, tmp_path / "interrupted-restored").manifest["created_at"]
        == 345
    )
    assert tuple(tmp_path.glob(".interrupted.signet.partial-*")) == ()


def test_backup_temporary_collision_is_preserved_and_never_published(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"temporary collision fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "collision.signet"
    temporary = tmp_path / ".collision.signet.partial-fixed"
    temporary.write_bytes(b"pre-existing temporary path")
    temporary.chmod(0o600)
    identity = temporary.stat().st_ino
    monkeypatch.setattr(backup_module.secrets, "token_urlsafe", lambda _size: "fixed")

    with pytest.raises(BackupError, match="temporary destination already exists"):
        manager.create(destination)

    assert not destination.exists()
    assert temporary.read_bytes() == b"pre-existing temporary path"
    assert temporary.stat().st_ino == identity
    assert tuple(tmp_path.glob(".signet-backup-*")) == ()


def test_backup_temporary_is_removed_when_file_hardening_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "fchmod-failure.partial"

    def fail_fchmod(_descriptor: int, _mode: int) -> None:
        raise OSError("injected fchmod failure")

    monkeypatch.setattr(backup_module.os, "fchmod", fail_fchmod)
    with tempfile.TemporaryFile(mode="w+b") as archive:
        archive.write(b"bounded archive bytes")
        archive.seek(0)
        with pytest.raises(OSError, match="injected fchmod failure"):
            backup_module._encrypt_archive_to_path(
                archive,
                archive_size=len(b"bounded archive bytes"),
                destination=destination,
                encryption_key=b"k" * 32,
            )

    assert not destination.exists()


def test_backup_temporary_fstat_failure_reports_retained_private_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "fstat-failure.partial"

    def fail_fstat(_descriptor: int) -> os.stat_result:
        raise OSError("injected fstat failure")

    monkeypatch.setattr(backup_module.os, "fstat", fail_fstat)
    with tempfile.TemporaryFile(mode="w+b") as archive:
        archive.write(b"bounded archive bytes")
        archive.seek(0)
        with pytest.raises(
            BackupCleanupStateUnknown,
            match="was not published.*temporary-file cleanup could not be confirmed",
        ):
            backup_module._encrypt_archive_to_path(
                archive,
                archive_size=len(b"bounded archive bytes"),
                destination=destination,
                encryption_key=b"k" * 32,
            )

    assert destination.is_file()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    destination.unlink()


def test_backup_temporary_is_removed_when_acl_hardening_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "acl-failure.partial"

    def reject_acl(_descriptor: int) -> None:
        raise PrivatePathError("injected granting ACL")

    monkeypatch.setattr(backup_module, "require_no_acl_grants", reject_acl)
    with tempfile.TemporaryFile(mode="w+b") as archive:
        archive.write(b"bounded archive bytes")
        archive.seek(0)
        with pytest.raises(BackupError, match="unsafe granting ACL"):
            backup_module._encrypt_archive_to_path(
                archive,
                archive_size=len(b"bounded archive bytes"),
                destination=destination,
                encryption_key=b"k" * 32,
            )

    assert not destination.exists()


def test_backup_reports_workspace_cleanup_failure_after_durable_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"workspace cleanup fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "cleanup-failure.signet"
    original_rmtree = backup_module.shutil.rmtree

    def fail_rmtree(_path: Path) -> None:
        raise OSError("injected workspace cleanup failure")

    monkeypatch.setattr(backup_module.shutil, "rmtree", fail_rmtree)
    with pytest.raises(
        BackupPublishedWithWarnings,
        match="published durably.*artifacts could not be removed",
    ):
        manager.create(destination, created_at=456)

    workspaces = tuple(tmp_path.glob(".signet-backup-*"))
    assert len(workspaces) == 1
    assert (workspaces[0] / "approvals.sqlite3").is_file()
    monkeypatch.setattr(backup_module.shutil, "rmtree", original_rmtree)
    assert (
        manager.restore(destination, tmp_path / "cleanup-failure-restored").manifest["created_at"]
        == 456
    )
    original_rmtree(workspaces[0])


def test_workspace_replacement_is_preserved_without_masking_unknown_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"workspace replacement fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "workspace-replacement.signet"
    displaced = tmp_path / "displaced-workspace"
    workspace: Path | None = None
    original_archive = backup_module._archive_workspace
    original_publish = backup_module._rename_backup_no_replace

    def capture_workspace(
        archive: BinaryIO,
        members: tuple[tuple[Path, str], ...],
    ) -> None:
        nonlocal workspace
        workspace = members[0][0].parent
        original_archive(archive, members)

    def publish_then_replace_workspace(source: Path, target: Path) -> None:
        original_publish(source, target)
        assert workspace is not None
        workspace.rename(displaced)
        workspace.mkdir(mode=0o700)
        marker = workspace / "replacement-marker"
        marker.write_text("preserve replacement\n", encoding="utf-8")
        marker.chmod(0o600)
        raise KeyboardInterrupt

    monkeypatch.setattr(backup_module, "_archive_workspace", capture_workspace)
    monkeypatch.setattr(
        backup_module,
        "_rename_backup_no_replace",
        publish_then_replace_workspace,
    )

    with pytest.raises(BackupError, match="outcome is unknown.*durable publication") as caught:
        manager.create(destination, created_at=567)

    assert workspace is not None
    assert (workspace / "replacement-marker").read_text(encoding="utf-8") == (
        "preserve replacement\n"
    )
    assert (displaced / "approvals.sqlite3").is_file()
    assert any(
        "backup artifacts could not be removed safely" in note
        for note in getattr(caught.value, "__notes__", ())
    )
    assert (
        manager.restore(destination, tmp_path / "workspace-replacement-restored").manifest[
            "created_at"
        ]
        == 567
    )


@pytest.mark.parametrize("replacement_kind", ["symlink", "directory"])
def test_cleanup_root_descriptor_hardening_never_mutates_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    parent_identity = require_owned_directory_identity(tmp_path.resolve(strict=True))
    tree = tmp_path / f"captured-{replacement_kind}"
    tree.mkdir(mode=0o700)
    (tree / "private").write_text("private\n", encoding="utf-8")
    tree_identity = require_private_directory_identity(tree)
    displaced = tmp_path / f"displaced-{replacement_kind}"
    outside = tmp_path / f"outside-{replacement_kind}"
    outside.mkdir(mode=0o700)
    (outside / "outside-marker").write_text("outside\n", encoding="utf-8")
    outside.chmod(0o500)
    original_fchmod = private_paths_module._fchmod_identity_descriptor
    swapped = False

    def swap_before_descriptor_chmod(descriptor: int, mode: int) -> None:
        nonlocal swapped
        metadata = os.fstat(descriptor)
        if not swapped and (metadata.st_dev, metadata.st_ino) == (
            tree_identity.device,
            tree_identity.inode,
        ):
            swapped = True
            tree.rename(displaced)
            if replacement_kind == "symlink":
                tree.symlink_to(outside, target_is_directory=True)
            else:
                tree.mkdir(mode=0o700)
                (tree / "replacement-marker").write_text("replacement\n", encoding="utf-8")
                tree.chmod(0o500)
        original_fchmod(descriptor, mode)

    monkeypatch.setattr(
        private_paths_module,
        "_fchmod_identity_descriptor",
        swap_before_descriptor_chmod,
    )

    with pytest.raises(BackupError, match="hardened safely|identity changed"):
        backup_module.remove_private_tree_checked(
            tree,
            parent_identity=parent_identity,
            tree_identity=tree_identity,
        )

    assert swapped
    assert (outside / "outside-marker").read_text(encoding="utf-8") == "outside\n"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o500
    if replacement_kind == "symlink":
        assert tree.is_symlink()
        tree.unlink()
    else:
        assert (tree / "replacement-marker").read_text(encoding="utf-8") == "replacement\n"
        assert stat.S_IMODE(tree.stat().st_mode) == 0o500
        tree.chmod(0o700)
        backup_module.shutil.rmtree(tree)
    backup_module.shutil.rmtree(displaced)
    outside.chmod(0o700)
    backup_module.shutil.rmtree(outside)


def test_cleanup_nested_descriptor_hardening_never_follows_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_identity = require_owned_directory_identity(tmp_path.resolve(strict=True))
    tree = tmp_path / "captured-tree"
    child = tree / "blocked"
    tree.mkdir(mode=0o700)
    child.mkdir(mode=0o700)
    (child / "private").write_text("private\n", encoding="utf-8")
    child_identity = require_private_directory_identity(child)
    tree_identity = require_private_directory_identity(tree)
    child.chmod(0o000)
    displaced = tree / "displaced-blocked"
    outside = tmp_path / "outside-nested"
    outside.mkdir(mode=0o700)
    (outside / "outside-marker").write_text("outside\n", encoding="utf-8")
    outside.chmod(0o500)
    original_fchmod = private_paths_module._fchmod_identity_descriptor
    original_rmtree = backup_module.shutil.rmtree
    swapped = False

    def report_blocked(_path: Path) -> None:
        raise PermissionError(errno.EACCES, "injected blocked directory", str(child))

    def swap_before_descriptor_chmod(descriptor: int, mode: int) -> None:
        nonlocal swapped
        metadata = os.fstat(descriptor)
        if not swapped and (metadata.st_dev, metadata.st_ino) == (
            child_identity.device,
            child_identity.inode,
        ):
            swapped = True
            child.rename(displaced)
            child.symlink_to(outside, target_is_directory=True)
        original_fchmod(descriptor, mode)

    monkeypatch.setattr(backup_module.shutil, "rmtree", report_blocked)
    monkeypatch.setattr(
        private_paths_module,
        "_fchmod_identity_descriptor",
        swap_before_descriptor_chmod,
    )

    with pytest.raises(BackupError):
        backup_module.remove_private_tree_checked(
            tree,
            parent_identity=parent_identity,
            tree_identity=tree_identity,
        )

    assert swapped
    assert child.is_symlink()
    assert (outside / "outside-marker").read_text(encoding="utf-8") == "outside\n"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o500
    child.unlink()
    displaced.chmod(0o700)
    original_rmtree(tree)
    outside.chmod(0o700)
    original_rmtree(outside)


def test_partial_cleanup_failure_has_fixed_prepublication_operator_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"partial cleanup fixture")
    manager = _manager(database, staging)
    destination = tmp_path / "partial-cleanup.signet"

    def fail_before_publish(_source: Path, _target: Path) -> None:
        raise BackupError("injected pre-publication failure")

    monkeypatch.setattr(backup_module, "_rename_backup_no_replace", fail_before_publish)
    monkeypatch.setattr(backup_module, "_unlink_backup_file_if_same", lambda *_args: False)

    with pytest.raises(
        BackupCleanupStateUnknown,
        match="was not published.*artifact cleanup could not be confirmed",
    ) as caught:
        manager.create(destination)

    assert "injected pre-publication failure" not in caught.value.operator_message()
    assert not destination.exists()
    assert len(tuple(tmp_path.glob(".partial-cleanup.signet.partial-*"))) == 1
    assert tuple(tmp_path.glob(".signet-backup-*")) == ()


def test_bundle_tamper_and_wrong_backup_key_fail_before_restore(tmp_path: Path) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"fixture")
    manager = _manager(database, staging)
    bundle = manager.create(tmp_path / "backup.signet")
    tampered = tmp_path / "tampered.signet"
    raw = bytearray(bundle.read_bytes())
    raw[-1] ^= 1
    tampered.write_bytes(raw)

    with pytest.raises(BackupError, match="authentication"):
        manager.restore(tampered, tmp_path / "tampered-restore")
    wrong = _manager(database, staging, key=b"w" * 32)
    with pytest.raises(BackupError, match="authentication"):
        wrong.restore(bundle, tmp_path / "wrong-restore")


def test_restore_failure_reports_identity_checked_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"restore cleanup fixture")
    manager = _manager(database, staging)
    bundle = manager.create(tmp_path / "restore-cleanup.signet")
    destination = tmp_path / "retained-restore"
    original_rmtree = backup_module.shutil.rmtree

    def fail_after_private_extract(_archive: object, root: Path) -> None:
        retained = root / "retained-private-content"
        retained.write_bytes(b"private restored bytes")
        retained.chmod(0o600)
        raise BackupError("injected restore validation failure")

    def retain_restore_tree(path: Path) -> None:
        if path == destination:
            raise OSError("injected restore cleanup failure")
        original_rmtree(path)

    monkeypatch.setattr(backup_module, "_extract_archive", fail_after_private_extract)
    monkeypatch.setattr(backup_module.shutil, "rmtree", retain_restore_tree)

    with pytest.raises(
        BackupCleanupStateUnknown,
        match="restore did not complete.*cleanup could not be confirmed",
    ) as caught:
        manager.restore(bundle, destination)

    assert "injected" not in caught.value.operator_message()
    assert (destination / "retained-private-content").read_bytes() == b"private restored bytes"
    monkeypatch.setattr(backup_module.shutil, "rmtree", original_rmtree)
    original_rmtree(destination)


def test_restore_preserves_replacement_when_mkdir_outcome_is_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"restore replacement boundary")
    manager = _manager(database, staging)
    bundle = manager.create(tmp_path / "restore-replacement.signet")
    destination = tmp_path / "uncaptured-restore"
    displaced = tmp_path / "restore-created-before-interrupt"
    original_mkdir = backup_module.os.mkdir

    def replace_then_interrupt(
        path: Path,
        mode: int = 0o777,
        *args: object,
        **kwargs: object,
    ) -> None:
        original_mkdir(path, mode, *args, **kwargs)
        selected = Path(path)
        if selected == destination:
            selected.rename(displaced)
            original_mkdir(selected, 0o700)
            (selected / "replacement-marker").write_text("preserve\n", encoding="utf-8")
            selected.chmod(0o500)
            raise KeyboardInterrupt

    monkeypatch.setattr(backup_module.os, "mkdir", replace_then_interrupt)

    with pytest.raises(
        BackupCleanupStateUnknown,
        match="restore-tree creation cleanup could not be confirmed",
    ):
        manager.restore(bundle, destination)

    assert (destination / "replacement-marker").read_text(encoding="utf-8") == "preserve\n"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o500
    destination.chmod(0o700)
    backup_module.shutil.rmtree(destination)
    backup_module.shutil.rmtree(displaced)


def test_restore_descriptor_close_failure_removes_completed_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"restore close fixture")
    manager = _manager(database, staging)
    bundle = manager.create(tmp_path / "restore-close.signet")
    destination = tmp_path / "restore-close-destination"
    original_open = backup_module.os.open
    original_close = backup_module.os.close
    bundle_descriptor: int | None = None
    bundle_close_failed = False

    def track_bundle_open(path: Path, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal bundle_descriptor
        descriptor = original_open(path, flags, *args, **kwargs)
        if Path(path) == bundle:
            bundle_descriptor = descriptor
        return descriptor

    def close_then_report_failure(descriptor: int) -> None:
        nonlocal bundle_close_failed
        if descriptor == bundle_descriptor and not bundle_close_failed:
            bundle_close_failed = True
            original_close(descriptor)
            raise OSError("injected bundle close failure")
        original_close(descriptor)

    monkeypatch.setattr(backup_module.os, "open", track_bundle_open)
    monkeypatch.setattr(backup_module.os, "close", close_then_report_failure)

    with pytest.raises(BackupError, match="restore did not complete.*descriptor close"):
        manager.restore(bundle, destination)

    assert bundle_descriptor is not None
    assert bundle_close_failed
    assert not destination.exists()


def test_restore_archive_context_exit_failure_removes_completed_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"archive exit fixture")
    manager = _manager(database, staging)
    bundle = manager.create(tmp_path / "archive-exit.signet")
    destination = tmp_path / "archive-exit-destination"
    original_temporary_file = backup_module.tempfile.TemporaryFile

    class ExitFailure:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.file = original_temporary_file(*args, **kwargs)

        def __enter__(self) -> BinaryIO:
            return self.file

        def __exit__(self, *_args: object) -> None:
            self.file.close()
            raise OSError("injected private archive close failure")

    monkeypatch.setattr(backup_module.tempfile, "TemporaryFile", ExitFailure)

    with pytest.raises(BackupError, match="restore did not complete safely") as caught:
        manager.restore(bundle, destination)

    assert "injected" not in str(caught.value)
    assert not destination.exists()


def test_restore_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"fifo fixture")
    manager = _manager(database, staging)
    fifo = tmp_path / "not-a-bundle.fifo"
    os.mkfifo(fifo, mode=0o600)
    started = time.monotonic()

    with pytest.raises(BackupError, match="safe bounded regular file"):
        manager.restore(fifo, tmp_path / "fifo-destination")

    assert time.monotonic() - started < 1.0
    assert not (tmp_path / "fifo-destination").exists()


def test_backup_paths_map_unexpandable_home_to_controlled_errors(tmp_path: Path) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"bounded path fixture")
    manager = _manager(database, staging)
    selected = Path("~signet-user-that-must-not-exist-7f43d5/private.signet")

    with pytest.raises(BackupError, match="destination path is unavailable or unsafe"):
        manager.create(selected)
    with pytest.raises(BackupError, match="bundle path is unavailable or unsafe"):
        manager.restore(selected, tmp_path / "unreachable")

    assert not (tmp_path / "unreachable").exists()


def test_restore_rejects_valid_but_mismatched_manifest_detection_source(
    tmp_path: Path,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"signature-detected fixture")
    manager = _manager(database, staging)
    bundle = manager.create(tmp_path / "backup.signet")

    def change_provenance(members: dict[str, bytes]) -> None:
        manifest = json.loads(members["manifest.json"])
        assert manifest["attachments"][0]["detection_source"] == "content_signature_v1"
        manifest["attachments"][0]["detection_source"] = "legacy_filename_unverified"
        members["manifest.json"] = json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    rewritten = _rewrite_encrypted_archive(
        bundle,
        tmp_path / "validly-encrypted-tampered-manifest.signet",
        change_provenance,
    )

    with pytest.raises(BackupError, match="manifest is inconsistent"):
        manager.restore(rewritten, tmp_path / "tampered-restore")
    assert not (tmp_path / "tampered-restore").exists()


def test_schema_12_format_2_backup_restores_and_upgrades_legacy_provenance(
    tmp_path: Path,
) -> None:
    database, staging, staged = _fixture(
        tmp_path,
        content=b"legacy filename-era attachment",
    )
    _downgrade_catalog_to_schema_12(database)
    manager = _manager(database, staging)
    current_bundle = manager.create(tmp_path / "schema-12-current-writer.signet")

    def convert_to_legacy_bundle(members: dict[str, bytes]) -> None:
        manifest = json.loads(members["manifest.json"])
        assert manifest["schema_version"] == 12
        item = manifest["attachments"][0]
        assert item.pop("detection_source") == "legacy_filename_unverified"
        metadata_path = item["metadata_archive_path"]
        metadata = json.loads(members[metadata_path])
        assert metadata["format"] == 3
        assert metadata.pop("detection_source") == "legacy_filename_unverified"
        metadata["format"] = 2
        members[metadata_path] = json.dumps(
            metadata,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        members["manifest.json"] = json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    legacy_bundle = _rewrite_encrypted_archive(
        current_bundle,
        tmp_path / "schema-12-format-2.signet",
        convert_to_legacy_bundle,
    )
    restored = manager.restore(legacy_bundle, tmp_path / "legacy-restored")
    restored_item = restored.manifest["attachments"][0]
    assert "detection_source" not in restored_item
    restored_metadata = json.loads(
        (restored.attachments_root / ".metadata" / f"{staged.opaque_id}.json").read_text(
            encoding="utf-8"
        )
    )
    assert restored_metadata["format"] == 2
    assert "detection_source" not in restored_metadata

    restored_database = Database(restored.database_path)
    restored_staging = StagingStore(
        restored.attachments_root,
        database=restored_database,
        cipher=attachment_cipher(),
        minimum_free_bytes=0,
    )
    restored_manager = _manager(restored_database, restored_staging)
    migration_backups = tmp_path / "restore-migration-backups"
    migration_backups.mkdir(mode=0o700)
    restored_database.initialize(
        pre_migration_backup=restored_manager.create_pre_migration_callback(migration_backups)
    )

    migrated_record, plaintext = restored_staging.read_verified(
        staged.opaque_id,
        adapter="fastmail",
        account="primary",
    )
    assert plaintext == b"legacy filename-era attachment"
    assert migrated_record.detection_source == "legacy_filename_unverified"
    assert len(tuple(migration_backups.glob("pre-migration-v12-*.signet-backup"))) == 1


def test_backup_preflights_limit_before_archive_or_aead_allocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"bounded fixture")
    manager = BackupBundleManager(
        database,
        staging=staging,
        encryption_key=b"k" * 32,
        max_bundle_bytes=256,
    )

    def archive_must_not_run(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("archive allocation ran before size preflight")

    monkeypatch.setattr(backup_module, "_archive_workspace", archive_must_not_run)

    with pytest.raises(BackupError, match="size limit"):
        manager.create(tmp_path / "too-small.signet")


def test_pre_migration_backup_reports_retained_private_verification_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"pre-migration cleanup fixture")
    manager = _manager(database, staging)
    backup_directory = tmp_path / "pre-migration-cleanup"
    backup_directory.mkdir(mode=0o700)
    with database.read() as connection:
        current_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    original_rmtree = backup_module.shutil.rmtree

    def retain_verification_tree(path: Path) -> None:
        if path.name.startswith(".verify-"):
            raise OSError("injected verification cleanup failure")
        original_rmtree(path)

    monkeypatch.setattr(backup_module.shutil, "rmtree", retain_verification_tree)

    with pytest.raises(
        BackupPublishedWithWarnings,
        match="published durably.*verification-tree cleanup could not be confirmed",
    ) as caught:
        manager.create_pre_migration_callback(backup_directory)(database, current_version)

    assert "injected" not in caught.value.operator_message()
    bundles = tuple(backup_directory.glob("pre-migration-*.signet-backup"))
    verification_trees = tuple(backup_directory.glob(".verify-*"))
    assert len(bundles) == len(verification_trees) == 1
    assert (
        manager.restore(bundles[0], tmp_path / "pre-migration-restored").manifest["schema_version"]
        == current_version
    )
    monkeypatch.setattr(backup_module.shutil, "rmtree", original_rmtree)
    original_rmtree(verification_trees[0])


def test_pre_migration_post_publish_restore_failure_is_operator_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"verification failure fixture")
    manager = _manager(database, staging)
    backup_directory = tmp_path / "post-publish-restore-failure"
    backup_directory.mkdir(mode=0o700)
    with database.read() as connection:
        current_version = int(connection.execute("PRAGMA user_version").fetchone()[0])

    def fail_verification_restore(_bundle: Path, _destination: Path) -> RestoredBundle:
        raise BackupError("injected private verification failure")

    monkeypatch.setattr(manager, "restore", fail_verification_restore)

    with pytest.raises(
        BackupPublishedWithWarnings,
        match="published durably.*verification did not complete.*do not migrate",
    ) as caught:
        manager.create_pre_migration_callback(backup_directory)(database, current_version)

    assert "injected" not in caught.value.operator_message()
    assert len(tuple(backup_directory.glob("pre-migration-*.signet-backup"))) == 1


def test_pre_migration_schema_mismatch_is_operator_visible_and_cleans_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, _ = _fixture(tmp_path, content=b"schema mismatch fixture")
    manager = _manager(database, staging)
    backup_directory = tmp_path / "post-publish-schema-mismatch"
    backup_directory.mkdir(mode=0o700)
    with database.read() as connection:
        current_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    original_restore = manager.restore

    def restore_with_wrong_schema(bundle: Path, destination: Path) -> RestoredBundle:
        restored = original_restore(bundle, destination)
        restored.manifest["schema_version"] = current_version + 1
        return restored

    monkeypatch.setattr(manager, "restore", restore_with_wrong_schema)

    with pytest.raises(
        BackupPublishedWithWarnings,
        match="published durably.*verification did not complete.*do not migrate",
    ) as caught:
        manager.create_pre_migration_callback(backup_directory)(database, current_version)

    assert "inconsistent" not in caught.value.operator_message()
    assert len(tuple(backup_directory.glob("pre-migration-*.signet-backup"))) == 1
    assert tuple(backup_directory.glob(".verify-*")) == ()


def test_chunked_backup_round_trip_crosses_aead_chunk_boundary(tmp_path: Path) -> None:
    content = b"x" * (backup_module._BACKUP_CHUNK_BYTES + 1_024)
    database, staging, staged = _fixture(tmp_path, content=content)
    manager = _manager(database, staging)

    bundle = manager.create(tmp_path / "chunked.signet")
    assert bundle.read_bytes().startswith(backup_module.MAGIC)
    restored = manager.restore(bundle, tmp_path / "chunked-restored")
    _, plaintext = _restored_store(restored).read_verified(
        staged.opaque_id,
        adapter="fastmail",
        account="primary",
    )
    assert plaintext == content


def test_backup_preserves_unconsumed_virtual_staging_objects(tmp_path: Path) -> None:
    database = Database(tmp_path / "live" / "approvals.sqlite3")
    database.initialize()
    source_root = tmp_path / "sources"
    source_root.mkdir()
    source = source_root / "draft.bin"
    source.write_bytes(b"local virtual object")
    staging = StagingStore(
        tmp_path / "staging",
        database=database,
        cipher=attachment_cipher(),
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    staged = staging.stage_path(
        source,
        adapter="fastmail",
        account="primary",
        filename="draft.bin",
        declared_mime="application/octet-stream",
    )

    manager = _manager(database, staging)
    restored = manager.restore(
        manager.create(tmp_path / "backup.signet"),
        tmp_path / "restored",
    )
    restarted = _restored_store(restored)
    _, plaintext = restarted.read_verified(
        staged.opaque_id,
        adapter="fastmail",
        account="primary",
    )
    assert plaintext == b"local virtual object"
    with restarted.database.read() as connection:
        owner = connection.execute(
            "SELECT consumed_request_id FROM staged_objects WHERE attachment_id = ?",
            (staged.opaque_id,),
        ).fetchone()[0]
    assert owner is None


def test_backup_rejects_changed_envelope_and_releases_pin(tmp_path: Path) -> None:
    database, staging, staged = _fixture(tmp_path, content=b"original")
    staged.path.write_bytes(b"changed ciphertext")
    manager = _manager(database, staging)

    with pytest.raises(BackupError, match="integrity"):
        manager.create(tmp_path / "backup.signet")
    with database.read() as connection:
        pins = connection.execute(
            "SELECT completed_at FROM purge_jobs WHERE intent = 'backup_pin'"
        ).fetchall()
    assert len(pins) == 1 and pins[0]["completed_at"] is not None


def test_manager_repr_redacts_backup_and_attachment_keys(tmp_path: Path) -> None:
    database, staging, _ = _fixture(tmp_path)
    manager = _manager(
        database,
        staging,
        key=b"private-key-material-32-bytes!!!!"[:32],
    )
    representation = repr(manager)
    assert "private-key" not in representation
    assert "fake-attachment" not in representation


def test_backup_catalog_rows_are_read_from_the_sqlite_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, staged = _fixture(tmp_path, content=b"snapshot-owned bytes")
    original_snapshot = database.create_snapshot

    def snapshot_then_change_live_database(destination: Path) -> Path:
        snapshot = original_snapshot(destination)
        changed_path = tmp_path / "missing-after-snapshot"
        with database.transaction() as connection:
            connection.execute(
                "UPDATE staged_objects SET storage_path = ? WHERE attachment_id = ?",
                (str(changed_path), staged.opaque_id),
            )
            connection.execute(
                "UPDATE attachments SET storage_path = ? WHERE attachment_id = ?",
                (str(changed_path), staged.opaque_id),
            )
        return snapshot

    monkeypatch.setattr(database, "create_snapshot", snapshot_then_change_live_database)
    manager = _manager(database, staging)

    bundle = manager.create(tmp_path / "backup.signet")
    restored = manager.restore(bundle, tmp_path / "restored")
    _, plaintext = _restored_store(restored).read_verified(
        staged.opaque_id,
        adapter="fastmail",
        account="primary",
    )
    assert plaintext == b"snapshot-owned bytes"


def test_backup_rejects_symlink_replacement_of_snapshot_envelope(tmp_path: Path) -> None:
    database, staging, staged = _fixture(tmp_path, content=b"approved")
    outside = tmp_path / "outside"
    outside.write_bytes(staged.path.read_bytes())
    staged.path.unlink()
    staged.path.symlink_to(outside)

    with pytest.raises(BackupError, match="unsafe"):
        _manager(database, staging).create(tmp_path / "backup.signet")


def test_backup_pin_prevents_purge_between_snapshot_and_envelope_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, staging, staged = _fixture(
        tmp_path,
        content=b"fake consistently backed up bytes",
        request_id="backup-pin-race",
    )
    with database.transaction() as connection:
        connection.execute(
            """
            UPDATE approval_requests SET state = 'denied', completed_at = 100
            WHERE request_id = 'backup-pin-race'
            """
        )
    attachments: dict[RequestState, int | None] = dict.fromkeys(RequestState)
    attachments.update(
        {
            RequestState.SUCCEEDED: 0,
            RequestState.FAILED: 2 * 24 * 60 * 60,
            RequestState.DENIED: 0,
            RequestState.EXPIRED: 24 * 60 * 60,
            RequestState.CANCELLED: 24 * 60 * 60,
        }
    )
    payloads: dict[RequestState, int | None] = dict.fromkeys(RequestState)
    payloads.update(
        {
            RequestState.SUCCEEDED: 24 * 60 * 60,
            RequestState.FAILED: 24 * 60 * 60,
            RequestState.DENIED: 24 * 60 * 60,
            RequestState.EXPIRED: 24 * 60 * 60,
            RequestState.CANCELLED: 24 * 60 * 60,
        }
    )
    retention = RetentionManager(
        database,
        staging,
        matrix=RetentionMatrix(attachments, payloads),
    )
    manager = _manager(database, staging)
    copy_attachments = manager._copy_attachments

    def copy_while_purge_is_due(snapshot: Path, destination: Path) -> list[dict[str, object]]:
        report = retention.run_due(now=100)
        assert report.claimed == 0
        assert staged.path.exists()
        return copy_attachments(snapshot, destination)

    monkeypatch.setattr(manager, "_copy_attachments", copy_while_purge_is_due)
    bundle = manager.create(tmp_path / "backup.signet", created_at=100)
    assert staged.path.exists()

    assert retention.run_due(now=100).completed == 1
    assert not staged.path.exists()
    restored = manager.restore(bundle, tmp_path / "restored-race")
    _, plaintext = _restored_store(restored).read_verified(
        staged.opaque_id,
        adapter="fastmail",
        account="primary",
    )
    assert plaintext == b"fake consistently backed up bytes"
