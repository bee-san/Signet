"""Authenticated envelope encryption for immutable canonical request payloads.

The database stores the returned opaque bytes and the key reference separately.
Neither the master secret nor any authenticated request metadata is serialized
into the envelope.  A fresh data-encryption key is generated for every call and
is wrapped with the configured master key using an independent AES-GCM nonce.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from signet.canonical import canonical_json
from signet.credential_broker import Secret

__all__ = [
    "AESGCMEnvelopeCipher",
    "ENVELOPE_FORMAT",
    "PayloadCipher",
    "PayloadDecryptionError",
    "PayloadEncryptionError",
    "PayloadEnvelopeConfigurationError",
    "PayloadEnvelopeError",
]


ENVELOPE_FORMAT = "signet-aes256-gcm-envelope-v1"
_MAGIC = b"SGNTENC1"
_FORMAT_VERSION = 1
_FLAGS = 0
_NONCE_SIZE = 12
_DATA_KEY_SIZE = 32
_GCM_TAG_SIZE = 16
_WRAPPED_KEY_SIZE = _DATA_KEY_SIZE + _GCM_TAG_SIZE
_HEADER = struct.Struct(">8sBBBBHI")
_REQUEST_ID_RE = re.compile(r"^req_[A-Za-z0-9]+$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_MAX_CONTEXT_TEXT_BYTES = 512
_MASTER_KEY_INFO = b"signet/payload-master-key/v1"
_MASTER_KEY_SALT = b"Signet payload encryption master key"
_WRAP_AAD_DOMAIN = b"signet/payload-envelope/wrapped-key/v1\x00"
_PAYLOAD_AAD_DOMAIN = b"signet/payload-envelope/ciphertext/v1\x00"


class PayloadEnvelopeError(RuntimeError):
    """Base class for payload envelope failures with privacy-safe messages."""


class PayloadEnvelopeConfigurationError(ValueError):
    """The payload cipher was configured with unusable key material."""


class PayloadEncryptionError(PayloadEnvelopeError):
    """A canonical payload could not be encrypted."""


class PayloadDecryptionError(PayloadEnvelopeError):
    """An envelope was malformed, tampered with, or bound to other metadata."""


@dataclass(frozen=True, slots=True, repr=False)
class _ParsedEnvelope:
    wrapping_nonce: bytes
    payload_nonce: bytes
    wrapped_key: bytes
    ciphertext: bytes


class PayloadCipher:
    """AES-256-GCM payload encryptor and delivery ``PayloadDecryptor``.

    ``master_secret`` is treated as high-entropy input key material and expanded
    to an AES-256 wrapping key with a domain-separated HKDF.  Deployments should
    generate it from at least 32 random bytes and keep it behind ``Secret``; the
    constructor rejects short or unusually large values without echoing them.
    """

    __slots__ = ("__master_key", "__key_reference", "__max_plaintext_bytes")

    def __init__(
        self,
        master_secret: Secret,
        key_reference: str,
        *,
        max_plaintext_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        if not isinstance(master_secret, Secret):
            raise PayloadEnvelopeConfigurationError("master key must be supplied as Secret")
        if not _valid_key_reference(key_reference):
            raise PayloadEnvelopeConfigurationError("payload key reference is invalid")
        if (
            not isinstance(max_plaintext_bytes, int)
            or isinstance(max_plaintext_bytes, bool)
            or max_plaintext_bytes <= 0
            or max_plaintext_bytes > 64 * 1024 * 1024
        ):
            raise PayloadEnvelopeConfigurationError("payload size limit is invalid")

        try:
            raw_secret = master_secret.reveal().encode("utf-8", errors="strict")
        except (AttributeError, UnicodeError):
            raise PayloadEnvelopeConfigurationError("master key material is invalid") from None
        if len(raw_secret) < 32 or len(raw_secret) > 4096:
            raise PayloadEnvelopeConfigurationError(
                "master key material must contain between 32 and 4096 bytes"
            )

        self.__master_key = HKDF(
            algorithm=hashes.SHA256(),
            length=_DATA_KEY_SIZE,
            salt=_MASTER_KEY_SALT,
            info=_MASTER_KEY_INFO,
        ).derive(raw_secret)
        self.__key_reference = key_reference
        self.__max_plaintext_bytes = max_plaintext_bytes

    @property
    def key_reference(self) -> str:
        """Return the opaque reference that must be persisted beside the envelope."""

        return self.__key_reference

    @property
    def max_plaintext_bytes(self) -> int:
        return self.__max_plaintext_bytes

    @property
    def max_envelope_bytes(self) -> int:
        return (
            _HEADER.size
            + (2 * _NONCE_SIZE)
            + _WRAPPED_KEY_SIZE
            + self.max_plaintext_bytes
            + _GCM_TAG_SIZE
        )

    def __repr__(self) -> str:
        return (
            "PayloadCipher(master_secret=<redacted>, key_reference=<redacted>, "
            f"max_plaintext_bytes={self.max_plaintext_bytes})"
        )

    def encrypt(
        self,
        plaintext: bytes,
        *,
        request_id: str,
        version: int,
        payload_hash: str,
    ) -> bytes:
        """Encrypt bytes under a fresh data key bound to immutable row identity."""

        if not isinstance(plaintext, bytes):
            raise PayloadEncryptionError("canonical payload must be bytes")
        if len(plaintext) > self.max_plaintext_bytes:
            raise PayloadEncryptionError("canonical payload exceeds the encryption limit")
        try:
            metadata_aad = _metadata_aad(
                request_id=request_id,
                version=version,
                payload_hash=payload_hash,
                key_reference=self.__key_reference,
            )
        except ValueError:
            raise PayloadEncryptionError("payload encryption context is invalid") from None

        actual_hash = hashlib.sha256(plaintext).hexdigest()
        if not hmac.compare_digest(actual_hash, payload_hash):
            raise PayloadEncryptionError("canonical payload hash does not match its context")

        data_key = AESGCM.generate_key(bit_length=256)
        wrapping_nonce = secrets.token_bytes(_NONCE_SIZE)
        payload_nonce = secrets.token_bytes(_NONCE_SIZE)
        for _ in range(8):
            if not hmac.compare_digest(wrapping_nonce, payload_nonce):
                break
            payload_nonce = secrets.token_bytes(_NONCE_SIZE)
        else:  # pragma: no cover - requires a broken operating-system CSPRNG
            raise PayloadEncryptionError("secure nonce generation failed")

        try:
            wrapped_key = AESGCM(self.__master_key).encrypt(
                wrapping_nonce,
                data_key,
                _WRAP_AAD_DOMAIN + metadata_aad,
            )
            ciphertext = AESGCM(data_key).encrypt(
                payload_nonce,
                plaintext,
                _PAYLOAD_AAD_DOMAIN + metadata_aad,
            )
        except Exception:
            raise PayloadEncryptionError("canonical payload encryption failed") from None
        if len(wrapped_key) != _WRAPPED_KEY_SIZE:
            raise PayloadEncryptionError("canonical payload encryption failed")

        header = _HEADER.pack(
            _MAGIC,
            _FORMAT_VERSION,
            _FLAGS,
            _NONCE_SIZE,
            _NONCE_SIZE,
            len(wrapped_key),
            len(ciphertext),
        )
        envelope = header + wrapping_nonce + payload_nonce + wrapped_key + ciphertext
        if len(envelope) > self.max_envelope_bytes:  # pragma: no cover - arithmetic invariant
            raise PayloadEncryptionError("encrypted payload exceeds the envelope limit")
        return envelope

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        key_reference: str | None,
        request_id: str,
        version: int,
        payload_hash: str,
    ) -> bytes:
        """Authenticate and decrypt one immutable payload version.

        Every corrupt-envelope and context-mismatch path intentionally has the
        same public failure text.  Callers must not receive request data, key
        references, hashes, parser offsets, or cryptographic backend details.
        """

        failure = "encrypted payload is invalid or does not match its context"
        if not isinstance(ciphertext, bytes):
            raise PayloadDecryptionError(failure)
        if (
            not isinstance(key_reference, str)
            or not _valid_key_reference(key_reference)
            or not hmac.compare_digest(key_reference, self.__key_reference)
        ):
            raise PayloadDecryptionError(failure)
        try:
            metadata_aad = _metadata_aad(
                request_id=request_id,
                version=version,
                payload_hash=payload_hash,
                key_reference=key_reference,
            )
            parsed = self._parse(ciphertext)
            data_key = AESGCM(self.__master_key).decrypt(
                parsed.wrapping_nonce,
                parsed.wrapped_key,
                _WRAP_AAD_DOMAIN + metadata_aad,
            )
            if len(data_key) != _DATA_KEY_SIZE:
                raise InvalidTag
            plaintext = AESGCM(data_key).decrypt(
                parsed.payload_nonce,
                parsed.ciphertext,
                _PAYLOAD_AAD_DOMAIN + metadata_aad,
            )
        except (InvalidTag, OverflowError, struct.error, TypeError, ValueError):
            raise PayloadDecryptionError(failure) from None

        if len(plaintext) > self.max_plaintext_bytes:
            raise PayloadDecryptionError(failure)
        actual_hash = hashlib.sha256(plaintext).hexdigest()
        if not hmac.compare_digest(actual_hash, payload_hash):
            raise PayloadDecryptionError(failure)
        return plaintext

    def _parse(self, envelope: bytes) -> _ParsedEnvelope:
        if len(envelope) < _HEADER.size or len(envelope) > self.max_envelope_bytes:
            raise ValueError("invalid envelope")
        (
            magic,
            format_version,
            flags,
            wrapping_nonce_size,
            payload_nonce_size,
            wrapped_key_size,
            ciphertext_size,
        ) = _HEADER.unpack_from(envelope)
        if (
            magic != _MAGIC
            or format_version != _FORMAT_VERSION
            or flags != _FLAGS
            or wrapping_nonce_size != _NONCE_SIZE
            or payload_nonce_size != _NONCE_SIZE
            or wrapped_key_size != _WRAPPED_KEY_SIZE
            or ciphertext_size < _GCM_TAG_SIZE
            or ciphertext_size > self.max_plaintext_bytes + _GCM_TAG_SIZE
        ):
            raise ValueError("invalid envelope")

        expected_size = (
            _HEADER.size
            + wrapping_nonce_size
            + payload_nonce_size
            + wrapped_key_size
            + ciphertext_size
        )
        if expected_size != len(envelope):
            raise ValueError("invalid envelope")

        cursor = _HEADER.size
        wrapping_nonce = envelope[cursor : cursor + wrapping_nonce_size]
        cursor += wrapping_nonce_size
        payload_nonce = envelope[cursor : cursor + payload_nonce_size]
        cursor += payload_nonce_size
        wrapped_key = envelope[cursor : cursor + wrapped_key_size]
        cursor += wrapped_key_size
        return _ParsedEnvelope(
            wrapping_nonce=wrapping_nonce,
            payload_nonce=payload_nonce,
            wrapped_key=wrapped_key,
            ciphertext=envelope[cursor:],
        )


AESGCMEnvelopeCipher = PayloadCipher


def _metadata_aad(
    *,
    request_id: str,
    version: int,
    payload_hash: str,
    key_reference: str,
) -> bytes:
    if (
        not isinstance(request_id, str)
        or len(request_id) > 128
        or not _REQUEST_ID_RE.fullmatch(request_id)
    ):
        raise ValueError("invalid request identity")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version < 1
        or version > (2**63 - 1)
    ):
        raise ValueError("invalid payload version")
    if not isinstance(payload_hash, str) or not _SHA256_RE.fullmatch(payload_hash):
        raise ValueError("invalid payload hash")
    if not _valid_key_reference(key_reference):
        raise ValueError("invalid key reference")
    return canonical_json(
        {
            "format": ENVELOPE_FORMAT,
            "key_reference": key_reference,
            "payload_hash": payload_hash,
            "request_id": request_id,
            "version": version,
        }
    )


def _valid_key_reference(value: object) -> bool:
    if not isinstance(value, str) or not value or value.strip() != value:
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    return encoded.isascii() and len(encoded) <= _MAX_CONTEXT_TEXT_BYTES and not any(
        character < 0x20 or character == 0x7F for character in encoded
    )
