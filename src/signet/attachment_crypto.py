"""Authenticated envelope encryption for gateway-owned staged objects."""

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
    "ATTACHMENT_ENVELOPE_FORMAT",
    "AttachmentCipher",
    "AttachmentContext",
    "AttachmentDecryptionError",
    "AttachmentEncryptionError",
    "AttachmentEnvelopeConfigurationError",
    "AttachmentEnvelopeError",
]


ATTACHMENT_ENVELOPE_FORMAT = "signet-attachment-aes256-gcm-envelope-v1"
_MAGIC = b"SGNTATT1"
_FORMAT_VERSION = 1
_FLAGS = 0
_NONCE_SIZE = 12
_DATA_KEY_SIZE = 32
_GCM_TAG_SIZE = 16
_WRAPPED_KEY_SIZE = _DATA_KEY_SIZE + _GCM_TAG_SIZE
_HEADER = struct.Struct(">8sBBBBHI")
_OPAQUE_ID_RE = re.compile(r"stg_[A-Za-z0-9_]{20,64}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MASTER_KEY_INFO = b"signet/attachment-master-key/v1"
_MASTER_KEY_SALT = b"Signet attachment encryption master key"
_WRAP_AAD_DOMAIN = b"signet/attachment-envelope/wrapped-key/v1\x00"
_CONTENT_AAD_DOMAIN = b"signet/attachment-envelope/content/v1\x00"


class AttachmentEnvelopeError(RuntimeError):
    """Base class for privacy-safe attachment envelope failures."""


class AttachmentEnvelopeConfigurationError(ValueError):
    """The attachment cipher was configured with unusable key material."""


class AttachmentEncryptionError(AttachmentEnvelopeError):
    """Attachment plaintext could not be encrypted."""


class AttachmentDecryptionError(AttachmentEnvelopeError):
    """An attachment envelope or its immutable context did not authenticate."""


@dataclass(frozen=True, slots=True)
class AttachmentContext:
    """Immutable metadata authenticated with one staged object's bytes."""

    opaque_id: str
    adapter: str
    account: str
    filename: str
    declared_mime: str
    detected_mime: str
    size: int
    sha256: str
    created_at: int


@dataclass(frozen=True, slots=True, repr=False)
class _ParsedEnvelope:
    wrapping_nonce: bytes
    content_nonce: bytes
    wrapped_key: bytes
    ciphertext: bytes


class AttachmentCipher:
    """Encrypt each staged object under a fresh DEK wrapped by one reviewed key."""

    __slots__ = ("__key_reference", "__master_key", "__max_plaintext_bytes")

    def __init__(
        self,
        master_secret: Secret,
        key_reference: str,
        *,
        max_plaintext_bytes: int = 25 * 1024 * 1024,
    ) -> None:
        if not isinstance(master_secret, Secret):
            raise AttachmentEnvelopeConfigurationError(
                "attachment master key must be supplied as Secret"
            )
        if not _valid_bounded_text(key_reference, maximum=512):
            raise AttachmentEnvelopeConfigurationError(
                "attachment key reference is invalid"
            )
        if (
            isinstance(max_plaintext_bytes, bool)
            or not isinstance(max_plaintext_bytes, int)
            or max_plaintext_bytes <= 0
            or max_plaintext_bytes > 100 * 1024 * 1024
        ):
            raise AttachmentEnvelopeConfigurationError(
                "attachment plaintext size limit is invalid"
            )
        try:
            raw_secret = master_secret.reveal().encode("utf-8", errors="strict")
        except (AttributeError, UnicodeError):
            raise AttachmentEnvelopeConfigurationError(
                "attachment master key material is invalid"
            ) from None
        if len(raw_secret) < 32 or len(raw_secret) > 4096:
            raise AttachmentEnvelopeConfigurationError(
                "attachment master key material must contain between 32 and 4096 bytes"
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
        return self.__key_reference

    @property
    def max_plaintext_bytes(self) -> int:
        return self.__max_plaintext_bytes

    @property
    def maximum_envelope_bytes(self) -> int:
        return self.envelope_size(self.max_plaintext_bytes)

    @staticmethod
    def envelope_size(plaintext_size: int) -> int:
        if isinstance(plaintext_size, bool) or not isinstance(plaintext_size, int):
            raise ValueError("attachment plaintext size is invalid")
        if plaintext_size < 0:
            raise ValueError("attachment plaintext size is invalid")
        return (
            _HEADER.size
            + (2 * _NONCE_SIZE)
            + _WRAPPED_KEY_SIZE
            + plaintext_size
            + _GCM_TAG_SIZE
        )

    def __repr__(self) -> str:
        return (
            "AttachmentCipher(master_secret=<redacted>, key_reference=<redacted>, "
            f"max_plaintext_bytes={self.max_plaintext_bytes})"
        )

    def encrypt(self, plaintext: bytes, *, context: AttachmentContext) -> bytes:
        if not isinstance(plaintext, bytes):
            raise AttachmentEncryptionError("attachment plaintext must be bytes")
        if len(plaintext) > self.max_plaintext_bytes:
            raise AttachmentEncryptionError("attachment exceeds the encryption limit")
        try:
            aad = _context_aad(context, key_reference=self.__key_reference)
        except ValueError:
            raise AttachmentEncryptionError("attachment encryption context is invalid") from None
        if len(plaintext) != context.size or not hmac.compare_digest(
            hashlib.sha256(plaintext).hexdigest(), context.sha256
        ):
            raise AttachmentEncryptionError(
                "attachment plaintext does not match its encryption context"
            )

        data_key = AESGCM.generate_key(bit_length=256)
        wrapping_nonce = secrets.token_bytes(_NONCE_SIZE)
        content_nonce = secrets.token_bytes(_NONCE_SIZE)
        for _ in range(8):
            if not hmac.compare_digest(wrapping_nonce, content_nonce):
                break
            content_nonce = secrets.token_bytes(_NONCE_SIZE)
        else:  # pragma: no cover - requires a broken operating-system CSPRNG
            raise AttachmentEncryptionError("secure nonce generation failed")
        try:
            wrapped_key = AESGCM(self.__master_key).encrypt(
                wrapping_nonce,
                data_key,
                _WRAP_AAD_DOMAIN + aad,
            )
            ciphertext = AESGCM(data_key).encrypt(
                content_nonce,
                plaintext,
                _CONTENT_AAD_DOMAIN + aad,
            )
        except Exception:
            raise AttachmentEncryptionError("attachment encryption failed") from None
        if len(wrapped_key) != _WRAPPED_KEY_SIZE:
            raise AttachmentEncryptionError("attachment encryption failed")
        header = _HEADER.pack(
            _MAGIC,
            _FORMAT_VERSION,
            _FLAGS,
            _NONCE_SIZE,
            _NONCE_SIZE,
            len(wrapped_key),
            len(ciphertext),
        )
        envelope = header + wrapping_nonce + content_nonce + wrapped_key + ciphertext
        if len(envelope) != self.envelope_size(len(plaintext)):
            raise AttachmentEncryptionError("attachment encryption failed")
        return envelope

    def decrypt(
        self,
        envelope: bytes,
        *,
        context: AttachmentContext,
        key_reference: str | None,
    ) -> bytes:
        failure = "encrypted attachment is invalid or does not match its context"
        if not isinstance(envelope, bytes):
            raise AttachmentDecryptionError(failure)
        if (
            not isinstance(key_reference, str)
            or not hmac.compare_digest(key_reference, self.__key_reference)
        ):
            raise AttachmentDecryptionError(failure)
        try:
            aad = _context_aad(context, key_reference=key_reference)
            parsed = self._parse(envelope)
            data_key = AESGCM(self.__master_key).decrypt(
                parsed.wrapping_nonce,
                parsed.wrapped_key,
                _WRAP_AAD_DOMAIN + aad,
            )
            if len(data_key) != _DATA_KEY_SIZE:
                raise InvalidTag
            plaintext = AESGCM(data_key).decrypt(
                parsed.content_nonce,
                parsed.ciphertext,
                _CONTENT_AAD_DOMAIN + aad,
            )
        except (InvalidTag, OverflowError, struct.error, TypeError, ValueError):
            raise AttachmentDecryptionError(failure) from None
        if (
            len(plaintext) != context.size
            or len(plaintext) > self.max_plaintext_bytes
            or not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), context.sha256)
        ):
            raise AttachmentDecryptionError(failure)
        return plaintext

    def _parse(self, envelope: bytes) -> _ParsedEnvelope:
        if len(envelope) < _HEADER.size or len(envelope) > self.maximum_envelope_bytes:
            raise ValueError("invalid envelope")
        (
            magic,
            version,
            flags,
            wrapping_nonce_size,
            content_nonce_size,
            wrapped_key_size,
            ciphertext_size,
        ) = _HEADER.unpack_from(envelope)
        if (
            magic != _MAGIC
            or version != _FORMAT_VERSION
            or flags != _FLAGS
            or wrapping_nonce_size != _NONCE_SIZE
            or content_nonce_size != _NONCE_SIZE
            or wrapped_key_size != _WRAPPED_KEY_SIZE
            or ciphertext_size < _GCM_TAG_SIZE
            or ciphertext_size > self.max_plaintext_bytes + _GCM_TAG_SIZE
        ):
            raise ValueError("invalid envelope")
        expected = (
            _HEADER.size
            + wrapping_nonce_size
            + content_nonce_size
            + wrapped_key_size
            + ciphertext_size
        )
        if len(envelope) != expected:
            raise ValueError("invalid envelope")
        offset = _HEADER.size
        wrapping_nonce = envelope[offset : offset + wrapping_nonce_size]
        offset += wrapping_nonce_size
        content_nonce = envelope[offset : offset + content_nonce_size]
        offset += content_nonce_size
        wrapped_key = envelope[offset : offset + wrapped_key_size]
        offset += wrapped_key_size
        ciphertext = envelope[offset:]
        return _ParsedEnvelope(wrapping_nonce, content_nonce, wrapped_key, ciphertext)


def _context_aad(context: AttachmentContext, *, key_reference: str) -> bytes:
    if not isinstance(context, AttachmentContext):
        raise ValueError("invalid attachment context")
    if not _OPAQUE_ID_RE.fullmatch(context.opaque_id):
        raise ValueError("invalid attachment context")
    for value, maximum in (
        (context.adapter, 512),
        (context.account, 512),
        (context.filename, 255),
        (context.declared_mime, 255),
        (context.detected_mime, 255),
        (key_reference, 512),
    ):
        if not _valid_bounded_text(value, maximum=maximum):
            raise ValueError("invalid attachment context")
    if (
        isinstance(context.size, bool)
        or not isinstance(context.size, int)
        or context.size < 0
        or isinstance(context.created_at, bool)
        or not isinstance(context.created_at, int)
        or context.created_at < 0
        or not _SHA256_RE.fullmatch(context.sha256)
    ):
        raise ValueError("invalid attachment context")
    return canonical_json(
        {
            "format": ATTACHMENT_ENVELOPE_FORMAT,
            "opaque_id": context.opaque_id,
            "adapter": context.adapter,
            "account": context.account,
            "filename": context.filename,
            "declared_mime": context.declared_mime,
            "detected_mime": context.detected_mime,
            "size": context.size,
            "sha256": context.sha256,
            "created_at": context.created_at,
            "key_reference": key_reference,
        }
    )


def _valid_bounded_text(value: object, *, maximum: int) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    return len(encoded) <= maximum and not any(
        ord(character) < 32 or ord(character) == 127 for character in value
    )
