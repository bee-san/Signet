from __future__ import annotations

from pathlib import Path
from typing import Any

from signet.attachment_crypto import AttachmentCipher
from signet.credential_broker import Secret
from signet.db import Database
from signet.models import AttachmentReference
from signet.staging import StagingStore

FAKE_ATTACHMENT_MASTER = "fake-attachment-master-key-material-32-bytes"
FAKE_ATTACHMENT_KEY_REF = "keychain://Signet/fake-attachments"


def attachment_cipher(*, key_reference: str = FAKE_ATTACHMENT_KEY_REF) -> AttachmentCipher:
    return AttachmentCipher(
        Secret(FAKE_ATTACHMENT_MASTER),
        key_reference,
        max_plaintext_bytes=100 * 1024 * 1024,
    )


def staging_store(root: Path, **kwargs: Any) -> StagingStore:
    root = Path(root)
    database = Database(root.parent / f".{root.name}-catalog.sqlite3")
    database.initialize()
    return StagingStore(
        root,
        database=database,
        cipher=attachment_cipher(),
        **kwargs,
    )


def register_catalog_attachment(
    database: Database,
    *,
    attachment_id: str,
    storage_path: str,
    filename: str = "fixture.txt",
    mime_type: str = "text/plain",
    size_bytes: int = 7,
    sha256: str = "b" * 64,
    created_at: int = 100,
    adapter: str = "fastmail",
) -> AttachmentReference:
    envelope_size = attachment_cipher().envelope_size(size_bytes)
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO staged_objects(
                attachment_id, adapter, account, filename, declared_mime,
                detected_mime, size_bytes, sha256, storage_path,
                envelope_format, envelope_size, envelope_sha256,
                encryption_key_ref, created_at
            ) VALUES (?, ?, 'fake-account', ?, ?, ?, ?, ?, ?,
                      'signet-attachment-aes256-gcm-envelope-v1', ?, ?, ?, ?)
            """,
            (
                attachment_id,
                adapter,
                filename,
                mime_type,
                mime_type,
                size_bytes,
                sha256,
                storage_path,
                envelope_size,
                "c" * 64,
                FAKE_ATTACHMENT_KEY_REF,
                created_at,
            ),
        )
    return AttachmentReference(
        attachment_id=attachment_id,
        filename=filename,
        mime_type=mime_type,
        size_bytes=size_bytes,
        sha256=sha256,
        storage_path=storage_path,
    )
