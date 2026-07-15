from __future__ import annotations

import hashlib
import struct

import pytest

from signet.credential_broker import Secret
from signet.crypto import (
    PayloadCipher,
    PayloadDecryptionError,
    PayloadEncryptionError,
    PayloadEnvelopeConfigurationError,
)

FAKE_MASTER = "fake-payload-master-key-material-0001"
FAKE_KEY_REFERENCE = "keychain://Signet/fake-payload-test-key"
REQUEST_ID = "req_CryptoFixture01"
PLAINTEXT = b'{"fake":"canonical payload"}'
PAYLOAD_HASH = hashlib.sha256(PLAINTEXT).hexdigest()


def cipher(*, master: str = FAKE_MASTER, maximum: int = 4096) -> PayloadCipher:
    return PayloadCipher(
        Secret(master),
        FAKE_KEY_REFERENCE,
        max_plaintext_bytes=maximum,
    )


def decrypt(
    selected: PayloadCipher,
    envelope: bytes,
    *,
    key_reference: str | None = FAKE_KEY_REFERENCE,
    request_id: str = REQUEST_ID,
    version: int = 1,
    payload_hash: str = PAYLOAD_HASH,
) -> bytes:
    return selected.decrypt(
        envelope,
        key_reference=key_reference,
        request_id=request_id,
        version=version,
        payload_hash=payload_hash,
    )


def test_envelope_uses_fresh_key_and_independent_aes_gcm_nonces() -> None:
    selected = cipher()
    first = selected.encrypt(
        PLAINTEXT,
        request_id=REQUEST_ID,
        version=1,
        payload_hash=PAYLOAD_HASH,
    )
    second = selected.encrypt(
        PLAINTEXT,
        request_id=REQUEST_ID,
        version=1,
        payload_hash=PAYLOAD_HASH,
    )

    header = struct.Struct(">8sBBBBHI")
    _, _, _, wrapping_size, payload_size, wrapped_size, _ = header.unpack_from(first)
    wrapping_start = header.size
    payload_start = wrapping_start + wrapping_size
    wrapped_start = payload_start + payload_size

    assert first != second
    assert PLAINTEXT not in first
    assert first[wrapping_start:payload_start] != first[payload_start:wrapped_start]
    assert first[wrapped_start : wrapped_start + wrapped_size] != second[
        wrapped_start : wrapped_start + wrapped_size
    ]
    assert decrypt(selected, first) == PLAINTEXT
    assert decrypt(selected, second) == PLAINTEXT


@pytest.mark.parametrize(
    ("overrides", "alternate_cipher"),
    [
        ({"request_id": "req_OtherFixture02"}, None),
        ({"version": 2}, None),
        ({"payload_hash": "b" * 64}, None),
        ({"key_reference": "keychain://Signet/fake-other-key"}, None),
        ({"key_reference": "keychain://Signet/fake-non-ascii-\u00e9"}, None),
        ({"key_reference": None}, None),
        ({}, cipher(master="different-fake-master-key-material-02")),
    ],
)
def test_decryption_rejects_every_wrong_immutable_binding(
    overrides: dict[str, object], alternate_cipher: PayloadCipher | None
) -> None:
    selected = cipher()
    envelope = selected.encrypt(
        PLAINTEXT,
        request_id=REQUEST_ID,
        version=1,
        payload_hash=PAYLOAD_HASH,
    )
    decryptor = alternate_cipher or selected
    context: dict[str, object] = {
        "key_reference": FAKE_KEY_REFERENCE,
        "request_id": REQUEST_ID,
        "version": 1,
        "payload_hash": PAYLOAD_HASH,
    }
    context.update(overrides)

    with pytest.raises(PayloadDecryptionError) as raised:
        decryptor.decrypt(envelope, **context)  # type: ignore[arg-type]

    assert str(raised.value) == "encrypted payload is invalid or does not match its context"
    assert raised.value.__cause__ is None


@pytest.mark.parametrize("mutation", ["body", "magic", "truncate", "trailing", "length"])
def test_decryption_strictly_rejects_tamper_and_bad_framing(mutation: str) -> None:
    selected = cipher()
    original = selected.encrypt(
        PLAINTEXT,
        request_id=REQUEST_ID,
        version=1,
        payload_hash=PAYLOAD_HASH,
    )
    changed = bytearray(original)
    if mutation == "body":
        changed[-1] ^= 1
    elif mutation == "magic":
        changed[0] ^= 1
    elif mutation == "truncate":
        changed = changed[:-1]
    elif mutation == "trailing":
        changed.extend(b"x")
    else:
        struct.pack_into(">I", changed, 14, len(changed))

    with pytest.raises(PayloadDecryptionError):
        decrypt(selected, bytes(changed))


def test_decryption_rejects_oversized_input_before_crypto() -> None:
    selected = cipher(maximum=32)
    oversized = b"x" * (selected.max_envelope_bytes + 1)

    with pytest.raises(PayloadDecryptionError):
        decrypt(selected, oversized)


def test_encryption_requires_the_exact_plaintext_hash_and_size_bound() -> None:
    selected = cipher(maximum=len(PLAINTEXT))
    with pytest.raises(PayloadEncryptionError, match="hash"):
        selected.encrypt(
            PLAINTEXT,
            request_id=REQUEST_ID,
            version=1,
            payload_hash="b" * 64,
        )
    with pytest.raises(PayloadEncryptionError, match="limit"):
        selected.encrypt(
            PLAINTEXT + b"x",
            request_id=REQUEST_ID,
            version=1,
            payload_hash=hashlib.sha256(PLAINTEXT + b"x").hexdigest(),
        )


def test_cipher_configuration_and_representations_never_disclose_key_material() -> None:
    selected = cipher()
    representation = repr(selected)
    assert FAKE_MASTER not in representation
    assert FAKE_KEY_REFERENCE not in representation
    assert representation.count("<redacted>") == 2
    with pytest.raises(AttributeError):
        selected.max_plaintext_bytes = 10_000  # type: ignore[misc]

    with pytest.raises(PayloadEnvelopeConfigurationError) as raised:
        PayloadCipher(Secret("too-short"), FAKE_KEY_REFERENCE)
    assert "too-short" not in str(raised.value)
    assert FAKE_KEY_REFERENCE not in str(raised.value)
