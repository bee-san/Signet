"""Build encrypted, canonical approval requests without mutating durable state."""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from signet.adapters.base import ApprovalAdapter
from signet.canonical import canonical_json, payload_fingerprint
from signet.mcp_mirror import pending_call_result
from signet.models import AttachmentReference, EnqueueRequest

__all__ = ["FrozenRequest", "PayloadEncryptor", "RequestFreezer"]


_REQUEST_ID_RE = re.compile(r"^req_[A-Za-z0-9]+$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_MAX_TEXT_BYTES = 512
_DEFAULT_PENDING_TTL_SECONDS = 7 * 24 * 60 * 60
_MAX_PENDING_TTL_SECONDS = 30 * 24 * 60 * 60
_DEFAULT_MAX_CANONICAL_BYTES = 16 * 1024 * 1024
_PENDING_MESSAGE = (
    "This action requires human approval. Check status with check_approval_status."
)


class PayloadEncryptor(Protocol):
    """Narrow encryption half of the payload cipher used by the freezer."""

    @property
    def key_reference(self) -> str: ...

    def encrypt(
        self,
        plaintext: bytes,
        *,
        request_id: str,
        version: int,
        payload_hash: str,
    ) -> bytes: ...


@dataclass(frozen=True, slots=True, repr=False)
class FrozenRequest:
    """Fully built data awaiting an explicit caller-owned durable enqueue."""

    enqueue_request: EnqueueRequest

    @property
    def request(self) -> EnqueueRequest:
        """Alias for integrations that pass the persistence model directly."""

        return self.enqueue_request

    @property
    def pending(self) -> dict[str, Any]:
        """Return a detached copy of the stable pending value stored for replay."""

        decoded: object = json.loads(self.enqueue_request.pending_result)
        if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
            raise RuntimeError("frozen pending result is invalid")
        return cast(dict[str, Any], decoded)

    @property
    def pending_result(self) -> dict[str, Any]:
        """Return a freshly validated MCP call result for post-commit emission."""

        return pending_call_result(self.pending)

    @property
    def call_result(self) -> dict[str, Any]:
        return self.pending_result

    def __repr__(self) -> str:
        return "FrozenRequest(enqueue_request=<redacted>)"


class RequestFreezer:
    """Canonicalize and encrypt one approval request without enqueueing it.

    The only adapter method invoked here is ``canonicalize``.  No downstream
    client, approval primitive, credential, state machine, or notification sink
    is accepted by this class, keeping creation separate from durable commit and
    all subsequent side effects.
    """

    __slots__ = (
        "_clock",
        "_encryptor",
        "_key_reference",
        "_max_canonical_bytes",
        "_pending_ttl_seconds",
    )

    def __init__(
        self,
        encryptor: PayloadEncryptor,
        *,
        pending_ttl_seconds: int = _DEFAULT_PENDING_TTL_SECONDS,
        max_canonical_bytes: int = _DEFAULT_MAX_CANONICAL_BYTES,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not isinstance(pending_ttl_seconds, int)
            or isinstance(pending_ttl_seconds, bool)
            or pending_ttl_seconds <= 0
            or pending_ttl_seconds > _MAX_PENDING_TTL_SECONDS
        ):
            raise ValueError("pending TTL is outside the supported range")
        if (
            not isinstance(max_canonical_bytes, int)
            or isinstance(max_canonical_bytes, bool)
            or max_canonical_bytes <= 0
            or max_canonical_bytes > 64 * 1024 * 1024
        ):
            raise ValueError("canonical payload size limit is invalid")
        key_reference = getattr(encryptor, "key_reference", None)
        if not _valid_bounded_text(key_reference):
            raise ValueError("payload encryptor key reference is invalid")
        if not callable(getattr(encryptor, "encrypt", None)):
            raise TypeError("payload encryptor does not implement encrypt")
        self._encryptor = encryptor
        self._key_reference = cast(str, key_reference)
        self._pending_ttl_seconds = pending_ttl_seconds
        self._max_canonical_bytes = max_canonical_bytes
        self._clock = clock or _utc_now

    @property
    def pending_ttl_seconds(self) -> int:
        return self._pending_ttl_seconds

    @property
    def max_canonical_bytes(self) -> int:
        return self._max_canonical_bytes

    def __repr__(self) -> str:
        return (
            "RequestFreezer(encryptor=<redacted>, "
            f"pending_ttl_seconds={self.pending_ttl_seconds}, "
            f"max_canonical_bytes={self.max_canonical_bytes})"
        )

    def freeze(
        self,
        adapter: ApprovalAdapter,
        arguments: Mapping[str, Any],
        *,
        origin_namespace: str,
        policy_version: int,
        schema_version: str,
        editor_actor: str,
        idempotency_key: str | None = None,
        retry_of_request_id: str | None = None,
        attachments: Sequence[AttachmentReference] = (),
        staged_file_hashes: Sequence[str] | None = None,
        gateway_internal: bool = False,
        created_at: int | None = None,
    ) -> FrozenRequest:
        """Return immutable enqueue data; the caller remains responsible for commit."""

        downstream_alias = adapter.downstream_alias
        tool_name = adapter.tool_name
        adapter_version = adapter.adapter_version
        self._validate_request_metadata(
            downstream_alias=downstream_alias,
            tool_name=tool_name,
            adapter_version=adapter_version,
            origin_namespace=origin_namespace,
            policy_version=policy_version,
            schema_version=schema_version,
            editor_actor=editor_actor,
            idempotency_key=idempotency_key,
            retry_of_request_id=retry_of_request_id,
            gateway_internal=gateway_internal,
        )
        if not isinstance(arguments, Mapping):
            raise TypeError("adapter arguments must be a mapping")

        frozen_attachments = tuple(attachments)
        _validate_attachments(frozen_attachments)
        attachment_hashes = tuple(attachment.sha256 for attachment in frozen_attachments)
        if staged_file_hashes is None:
            staged_hashes = attachment_hashes
        else:
            staged_hashes = tuple(staged_file_hashes)
            _validate_staged_hashes(staged_hashes)
            if frozen_attachments and staged_hashes != attachment_hashes:
                raise ValueError("staged-file hashes must exactly match attachment order")

        canonical_arguments = adapter.canonicalize(arguments)
        if not isinstance(canonical_arguments, dict):
            raise TypeError("adapter canonicalization must return a JSON object")
        canonical_payload, fingerprint = payload_fingerprint(
            alias=downstream_alias,
            tool=tool_name,
            arguments=canonical_arguments,
            staged_file_hashes=staged_hashes,
            policy_version=policy_version,
            adapter_version=adapter_version,
        )
        if len(canonical_payload) > self.max_canonical_bytes:
            raise ValueError("canonical payload exceeds the freezer limit")

        frozen_at = _utc_timestamp(self._clock()) if created_at is None else created_at
        if (
            not isinstance(frozen_at, int)
            or isinstance(frozen_at, bool)
            or frozen_at < 0
            or frozen_at > (2**63 - 1) - self.pending_ttl_seconds
        ):
            raise ValueError("request creation time is invalid")
        expires_at = frozen_at + self.pending_ttl_seconds
        request_id = _new_request_id()
        pending = {
            "status": "pending_approval",
            "request_id": request_id,
            "expires_at": _rfc3339_utc(expires_at),
            "message": _PENDING_MESSAGE,
        }
        # This validates the exact public shape before any bytes can be persisted.
        pending_call_result(pending)
        encrypted_payload = self._encryptor.encrypt(
            canonical_payload,
            request_id=request_id,
            version=1,
            payload_hash=fingerprint,
        )
        if not isinstance(encrypted_payload, bytes) or not encrypted_payload:
            raise TypeError("payload encryptor returned an invalid envelope")

        enqueue_request = EnqueueRequest(
            request_id=request_id,
            downstream_alias=downstream_alias,
            tool_name=tool_name,
            policy_mode="approval",
            origin_namespace=origin_namespace,
            encrypted_payload=encrypted_payload,
            payload_hash=fingerprint,
            payload_fingerprint=fingerprint,
            pending_result=canonical_json(pending),
            created_at=frozen_at,
            expires_at=expires_at,
            policy_version=str(policy_version),
            adapter_version=adapter_version,
            schema_version=schema_version,
            editor_actor=editor_actor,
            canonical_size=len(canonical_payload),
            encryption_key_ref=self._key_reference,
            idempotency_key=idempotency_key,
            retry_of_request_id=retry_of_request_id,
            gateway_internal=gateway_internal,
            attachments=frozen_attachments,
        )
        return FrozenRequest(enqueue_request=enqueue_request)

    @staticmethod
    def _validate_request_metadata(
        *,
        downstream_alias: str,
        tool_name: str,
        adapter_version: str,
        origin_namespace: str,
        policy_version: int,
        schema_version: str,
        editor_actor: str,
        idempotency_key: str | None,
        retry_of_request_id: str | None,
        gateway_internal: bool,
    ) -> None:
        if not _valid_bounded_text(downstream_alias):
            raise ValueError("adapter downstream alias is invalid")
        if not _valid_bounded_text(tool_name):
            raise ValueError("adapter tool name is invalid")
        if not _valid_bounded_text(adapter_version, maximum=256):
            raise ValueError("adapter version is invalid")
        if not _valid_bounded_text(origin_namespace):
            raise ValueError("origin namespace is invalid")
        if not _valid_bounded_text(schema_version, maximum=256):
            raise ValueError("schema version is invalid")
        if not _valid_bounded_text(editor_actor):
            raise ValueError("editor actor is invalid")
        if (
            not isinstance(policy_version, int)
            or isinstance(policy_version, bool)
            or policy_version < 1
            or policy_version > (2**63 - 1)
        ):
            raise ValueError("policy version is invalid")
        if idempotency_key is not None and not _valid_bounded_text(idempotency_key):
            raise ValueError("idempotency key is invalid")
        if retry_of_request_id is not None and (
            not isinstance(retry_of_request_id, str)
            or len(retry_of_request_id) > 128
            or not _REQUEST_ID_RE.fullmatch(retry_of_request_id)
        ):
            raise ValueError("retry request ID is invalid")
        if not isinstance(gateway_internal, bool):
            raise TypeError("gateway_internal must be a boolean")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_timestamp(value: datetime) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("freezer clock must return a timezone-aware datetime")
    normalized = value.astimezone(UTC)
    timestamp = int(normalized.timestamp())
    if timestamp < 0:
        raise ValueError("freezer clock returned a pre-epoch datetime")
    return timestamp


def _rfc3339_utc(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat().replace("+00:00", "Z")


def _new_request_id() -> str:
    # 144 bits gives a compact alphanumeric identifier with ample collision margin.
    request_id = f"req_{secrets.token_hex(18)}"
    if not _REQUEST_ID_RE.fullmatch(request_id):  # pragma: no cover - stdlib invariant
        raise RuntimeError("secure request ID generation failed")
    return request_id


def _validate_staged_hashes(hashes: tuple[str, ...]) -> None:
    if len(hashes) > 1024 or any(
        not isinstance(value, str) or not _SHA256_RE.fullmatch(value) for value in hashes
    ):
        raise ValueError("staged-file hashes must be lowercase SHA-256 digests")


def _validate_attachments(attachments: tuple[AttachmentReference, ...]) -> None:
    if len(attachments) > 1024:
        raise ValueError("too many attachments")
    identifiers: set[str] = set()
    for attachment in attachments:
        if not isinstance(attachment, AttachmentReference):
            raise TypeError("attachments must be immutable attachment references")
        if (
            not _valid_bounded_text(attachment.attachment_id)
            or attachment.attachment_id in identifiers
            or not _valid_bounded_text(attachment.filename)
            or not _valid_bounded_text(attachment.mime_type)
            or not isinstance(attachment.size_bytes, int)
            or isinstance(attachment.size_bytes, bool)
            or attachment.size_bytes < 0
            or not isinstance(attachment.sha256, str)
            or not _SHA256_RE.fullmatch(attachment.sha256)
            or not _valid_bounded_text(attachment.storage_path, maximum=4096)
            or (
                attachment.purge_after is not None
                and (
                    not isinstance(attachment.purge_after, int)
                    or isinstance(attachment.purge_after, bool)
                    or attachment.purge_after < 0
                )
            )
        ):
            raise ValueError("attachment reference is invalid")
        identifiers.add(attachment.attachment_id)


def _valid_bounded_text(value: object, *, maximum: int = _MAX_TEXT_BYTES) -> bool:
    if not isinstance(value, str) or not value or value.strip() != value:
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    return len(encoded) <= maximum and not any(
        character < 0x20 or character == 0x7F for character in encoded
    )
