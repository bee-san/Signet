from __future__ import annotations

from pathlib import Path

import pytest

import signet.backup as backup_module
from signet.backup import BackupBundleManager, BackupError, RestoredBundle
from signet.db import Database
from signet.models import AttachmentReference, EnqueueRequest, RequestState
from signet.retention import RetentionManager, RetentionMatrix
from signet.staging import StagedFile, StagingStore
from signet.state_machine import ApprovalStateMachine
from tests.attachment_fixtures import (
    FAKE_ATTACHMENT_KEY_REF,
    attachment_cipher,
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


def _restored_store(restored: RestoredBundle) -> StagingStore:
    database = Database(restored.database_path)
    database.initialize()
    return StagingStore(
        restored.attachments_root,
        database=database,
        cipher=attachment_cipher(),
        minimum_free_bytes=0,
    )


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
