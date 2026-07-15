from __future__ import annotations

from pathlib import Path

import pytest

from signet.backup import BackupBundleManager, BackupError
from signet.db import Database
from signet.models import AttachmentReference, EnqueueRequest, RequestState
from signet.retention import RetentionManager, RetentionMatrix
from signet.staging import StagingStore
from signet.state_machine import ApprovalStateMachine


def _request(path: Path, digest: str) -> EnqueueRequest:
    return EnqueueRequest(
        request_id="backupfixture",
        downstream_alias="fastmail",
        tool_name="send_email",
        policy_mode="approval",
        origin_namespace="profile:test",
        encrypted_payload=b"encrypted-private-payload",
        payload_hash="a" * 64,
        payload_fingerprint="fingerprint",
        pending_result=b'{"status":"pending_approval"}',
        created_at=100,
        expires_at=200,
        policy_version="policy-1",
        adapter_version="adapter-1",
        schema_version="schema-1",
        editor_actor="caller:profile:test",
        encryption_key_ref="keychain://Signet/payload-backupfixture",
        attachments=(
            AttachmentReference(
                "stg_backup",
                "sensitive-name.txt",
                "text/plain",
                path.stat().st_size,
                digest,
                str(path),
            ),
        ),
    )


def test_encrypted_bundle_restores_database_attachments_and_key_manifest(
    tmp_path: Path,
) -> None:
    import hashlib

    staging = tmp_path / "staging"
    staging.mkdir()
    attachment = staging / "stg_backup"
    attachment.write_bytes(b"sensitive attachment bytes")
    digest = hashlib.sha256(attachment.read_bytes()).hexdigest()
    database = Database(tmp_path / "live" / "approvals.sqlite3")
    database.initialize()
    ApprovalStateMachine(database).enqueue(_request(attachment, digest))
    manager = BackupBundleManager(database, staging_root=staging, encryption_key=b"k" * 32)

    bundle = manager.create(tmp_path / "backups" / "backup.signet", created_at=123)
    encrypted = bundle.read_bytes()
    assert b"sensitive attachment bytes" not in encrypted
    assert b"sensitive-name.txt" not in encrypted
    assert b"keychain://" not in encrypted
    restored = manager.restore(bundle, tmp_path / "restored")
    assert restored.manifest["created_at"] == 123
    assert restored.manifest["key_references"] == ["keychain://Signet/payload-backupfixture"]
    assert (restored.attachments_root / "00000000.bin").read_bytes() == (
        b"sensitive attachment bytes"
    )
    restored_database = Database(restored.database_path)
    restored_database.initialize()
    assert ApprovalStateMachine(restored_database).get_request("backupfixture")["state"] == (
        "pending_approval"
    )
    with restored_database.read() as connection:
        restored_path = connection.execute(
            "SELECT storage_path FROM attachments WHERE attachment_id = 'stg_backup'"
        ).fetchone()[0]
        restored_active_pins = connection.execute(
            """
            SELECT count(*) FROM purge_jobs
            WHERE intent = 'backup_pin' AND completed_at IS NULL
            """
        ).fetchone()[0]
    with database.read() as connection:
        live_pins = connection.execute(
            "SELECT started_at, completed_at FROM purge_jobs WHERE intent = 'backup_pin'"
        ).fetchall()
    assert restored_path == str(restored.attachments_root / "00000000.bin")
    assert restored_path != str(attachment)
    assert restored_active_pins == 0
    assert len(live_pins) == 1
    assert live_pins[0]["started_at"] is not None
    assert live_pins[0]["completed_at"] is not None


def test_bundle_tamper_and_wrong_key_fail_before_restore(tmp_path: Path) -> None:
    import hashlib

    staging = tmp_path / "staging"
    staging.mkdir()
    attachment = staging / "stg_backup"
    attachment.write_bytes(b"fixture")
    database = Database(tmp_path / "live" / "approvals.sqlite3")
    database.initialize()
    ApprovalStateMachine(database).enqueue(
        _request(attachment, hashlib.sha256(b"fixture").hexdigest())
    )
    manager = BackupBundleManager(database, staging_root=staging, encryption_key=b"k" * 32)
    bundle = manager.create(tmp_path / "backup.signet")
    tampered = tmp_path / "tampered.signet"
    raw = bytearray(bundle.read_bytes())
    raw[-1] ^= 1
    tampered.write_bytes(raw)
    with pytest.raises(BackupError, match="authentication"):
        manager.restore(tampered, tmp_path / "tampered-restore")
    wrong = BackupBundleManager(database, staging_root=staging, encryption_key=b"w" * 32)
    with pytest.raises(BackupError, match="authentication"):
        wrong.restore(bundle, tmp_path / "wrong-restore")


def test_backup_rejects_changed_attachment(tmp_path: Path) -> None:
    import hashlib

    staging = tmp_path / "staging"
    staging.mkdir()
    attachment = staging / "stg_backup"
    attachment.write_bytes(b"original")
    database = Database(tmp_path / "live" / "approvals.sqlite3")
    database.initialize()
    request = _request(attachment, hashlib.sha256(b"original").hexdigest())
    ApprovalStateMachine(database).enqueue(request)
    attachment.write_bytes(b"changed!")
    manager = BackupBundleManager(database, staging_root=staging, encryption_key=b"k" * 32)
    with pytest.raises(BackupError, match="integrity"):
        manager.create(tmp_path / "backup.signet")
    with database.read() as connection:
        pins = connection.execute(
            "SELECT completed_at FROM purge_jobs WHERE intent = 'backup_pin'"
        ).fetchall()
    assert len(pins) == 1 and pins[0]["completed_at"] is not None


def test_manager_repr_redacts_key(tmp_path: Path) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    manager = BackupBundleManager(
        database,
        staging_root=tmp_path,
        encryption_key=b"private-key-material-32-bytes!!!!"[:32],
    )
    assert "private-key" not in repr(manager)


def test_backup_attachment_rows_are_read_from_the_sqlite_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hashlib

    staging = tmp_path / "staging"
    staging.mkdir()
    attachment = staging / "stg_backup"
    attachment.write_bytes(b"snapshot-owned bytes")
    database = Database(tmp_path / "live" / "approvals.sqlite3")
    database.initialize()
    ApprovalStateMachine(database).enqueue(
        _request(attachment, hashlib.sha256(b"snapshot-owned bytes").hexdigest())
    )
    original_snapshot = database.create_snapshot

    def snapshot_then_change_live_database(destination: Path) -> Path:
        snapshot = original_snapshot(destination)
        with database.transaction() as connection:
            connection.execute(
                "UPDATE attachments SET storage_path = ? WHERE attachment_id = 'stg_backup'",
                (str(tmp_path / "missing-after-snapshot"),),
            )
        return snapshot

    monkeypatch.setattr(database, "create_snapshot", snapshot_then_change_live_database)
    manager = BackupBundleManager(database, staging_root=staging, encryption_key=b"k" * 32)

    bundle = manager.create(tmp_path / "backup.signet")
    restored = manager.restore(bundle, tmp_path / "restored")

    assert (restored.attachments_root / "00000000.bin").read_bytes() == (
        b"snapshot-owned bytes"
    )


def test_backup_rejects_symlink_replacement_of_snapshot_attachment(tmp_path: Path) -> None:
    import hashlib

    staging = tmp_path / "staging"
    staging.mkdir()
    attachment = staging / "stg_backup"
    attachment.write_bytes(b"approved")
    database = Database(tmp_path / "live" / "approvals.sqlite3")
    database.initialize()
    ApprovalStateMachine(database).enqueue(
        _request(attachment, hashlib.sha256(b"approved").hexdigest())
    )
    outside = tmp_path / "outside"
    outside.write_bytes(b"approved")
    attachment.unlink()
    attachment.symlink_to(outside)
    manager = BackupBundleManager(database, staging_root=staging, encryption_key=b"k" * 32)

    with pytest.raises(BackupError, match="unsafe"):
        manager.create(tmp_path / "backup.signet")


def test_backup_pin_prevents_purge_between_snapshot_and_attachment_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    source = source_root / "fake.txt"
    source.write_bytes(b"fake consistently backed up bytes")
    staging = StagingStore(
        tmp_path / "staging",
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    staged = staging.stage_path(
        source,
        adapter="fake-adapter",
        account="fake-account",
        filename="fake.txt",
        declared_mime="text/plain",
    )
    database = Database(tmp_path / "live" / "approvals.sqlite3")
    database.initialize()
    digest = "d" * 64
    ApprovalStateMachine(database).enqueue(
        EnqueueRequest(
            request_id="backup-pin-race",
            downstream_alias="fake-service",
            tool_name="fake_write",
            policy_mode="approval",
            origin_namespace="profile:fake",
            encrypted_payload=b"fake encrypted payload",
            payload_hash=digest,
            payload_fingerprint="fake-backup-race-fingerprint",
            pending_result=b'{"status":"pending_approval"}',
            created_at=10,
            expires_at=10_000,
            policy_version="policy-fake",
            adapter_version="adapter-fake",
            schema_version="schema-fake",
            editor_actor="caller:profile:fake",
            attachments=(
                AttachmentReference(
                    staged.opaque_id,
                    staged.filename,
                    staged.declared_mime,
                    staged.size,
                    staged.sha256,
                    str(staged.path),
                ),
            ),
        )
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
    manager = BackupBundleManager(
        database,
        staging_root=staging.root,
        encryption_key=b"k" * 32,
    )
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
    assert (restored.attachments_root / "00000000.bin").read_bytes() == (
        b"fake consistently backed up bytes"
    )
