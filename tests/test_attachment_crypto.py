from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from signet.attachment_crypto import (
    AttachmentCipher,
    AttachmentContext,
    AttachmentDecryptionError,
    AttachmentEncryptionError,
    AttachmentEnvelopeConfigurationError,
)
from signet.credential_broker import Secret

MASTER = "fake-attachment-crypto-master-key-material"
KEY_REF = "keychain://Signet/fake-attachment-test"
PLAINTEXT = b"fake private attachment bytes\x00\xff"


def cipher(*, master: str = MASTER, maximum: int = 4096) -> AttachmentCipher:
    return AttachmentCipher(Secret(master), KEY_REF, max_plaintext_bytes=maximum)


def context() -> AttachmentContext:
    return AttachmentContext(
        opaque_id="stg_" + "a" * 20,
        adapter="fastmail",
        account="primary",
        filename="private.txt",
        declared_mime="text/plain",
        detected_mime="text/plain",
        size=len(PLAINTEXT),
        sha256=hashlib.sha256(PLAINTEXT).hexdigest(),
        created_at=123,
    )


def test_attachment_envelopes_are_random_authenticated_and_plaintext_free() -> None:
    selected = cipher()
    first = selected.encrypt(PLAINTEXT, context=context())
    second = selected.encrypt(PLAINTEXT, context=context())

    assert first != second
    assert PLAINTEXT not in first
    assert len(first) == selected.envelope_size(len(PLAINTEXT))
    assert selected.decrypt(first, context=context(), key_reference=KEY_REF) == PLAINTEXT
    assert selected.decrypt(second, context=context(), key_reference=KEY_REF) == PLAINTEXT
    assert "fake-attachment" not in repr(selected)
    assert "private.txt" not in repr(context())


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("opaque_id", "stg_" + "b" * 20),
        ("adapter", "whatsapp"),
        ("account", "secondary"),
        ("filename", "other.txt"),
        ("declared_mime", "application/octet-stream"),
        ("detected_mime", "application/octet-stream"),
        ("size", len(PLAINTEXT) + 1),
        ("sha256", "b" * 64),
        ("created_at", 124),
    ],
)
def test_decryption_rejects_every_changed_immutable_context(
    field: str, replacement: object
) -> None:
    selected = cipher()
    envelope = selected.encrypt(PLAINTEXT, context=context())

    with pytest.raises(AttachmentDecryptionError, match="does not match its context"):
        selected.decrypt(
            envelope,
            context=replace(context(), **{field: replacement}),
            key_reference=KEY_REF,
        )


@pytest.mark.parametrize("mutation", ["header", "ciphertext", "truncate", "append"])
def test_decryption_strictly_rejects_envelope_tamper(mutation: str) -> None:
    selected = cipher()
    changed = bytearray(selected.encrypt(PLAINTEXT, context=context()))
    if mutation == "header":
        changed[0] ^= 1
    elif mutation == "ciphertext":
        changed[-1] ^= 1
    elif mutation == "truncate":
        changed.pop()
    else:
        changed.append(0)

    with pytest.raises(AttachmentDecryptionError, match="does not match its context"):
        selected.decrypt(bytes(changed), context=context(), key_reference=KEY_REF)


def test_wrong_key_reference_and_master_are_indistinguishable_from_tamper() -> None:
    envelope = cipher().encrypt(PLAINTEXT, context=context())
    for selected, reference in (
        (cipher(), "keychain://Signet/other"),
        (cipher(master="different-fake-attachment-master-key-material"), KEY_REF),
    ):
        with pytest.raises(AttachmentDecryptionError, match="does not match its context"):
            selected.decrypt(envelope, context=context(), key_reference=reference)


def test_encryption_checks_plaintext_hash_and_bounds_before_writing() -> None:
    selected = cipher(maximum=len(PLAINTEXT))
    with pytest.raises(AttachmentEncryptionError, match="does not match"):
        selected.encrypt(PLAINTEXT, context=replace(context(), sha256="f" * 64))
    with pytest.raises(AttachmentEncryptionError, match="exceeds"):
        cipher(maximum=1).encrypt(PLAINTEXT, context=context())


def test_attachment_cipher_rejects_weak_or_invalid_configuration() -> None:
    with pytest.raises(AttachmentEnvelopeConfigurationError, match="between 32"):
        AttachmentCipher(Secret("short"), KEY_REF)
    with pytest.raises(AttachmentEnvelopeConfigurationError, match="reference"):
        AttachmentCipher(Secret(MASTER), "bad\nreference")
    with pytest.raises(AttachmentEnvelopeConfigurationError, match="size"):
        AttachmentCipher(Secret(MASTER), KEY_REF, max_plaintext_bytes=0)


def test_context_rejects_controls_before_encryption() -> None:
    with pytest.raises(AttachmentEncryptionError, match="context"):
        cipher().encrypt(PLAINTEXT, context=replace(context(), filename="bad\nname"))
