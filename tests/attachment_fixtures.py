from __future__ import annotations

from pathlib import Path
from typing import Any

from signet.attachment_crypto import AttachmentCipher
from signet.credential_broker import Secret
from signet.db import Database
from signet.staging import StagingStore

FAKE_ATTACHMENT_MASTER = "fake-attachment-master-key-material-32-bytes"
FAKE_ATTACHMENT_KEY_REF = "keychain://Signet/fake-attachments"


def attachment_cipher(
    *, key_reference: str = FAKE_ATTACHMENT_KEY_REF
) -> AttachmentCipher:
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
