from __future__ import annotations

from pathlib import Path

import pytest

from signet.backup import BackupBundleManager, BackupError
from signet.db import Database
from signet.models import AttachmentReference, EnqueueRequest
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


def test_manager_repr_redacts_key(tmp_path: Path) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    manager = BackupBundleManager(
        database,
        staging_root=tmp_path,
        encryption_key=b"private-key-material-32-bytes!!!!"[:32],
    )
    assert "private-key" not in repr(manager)
