"""Fenced downstream delivery orchestration.

The dispatcher owns the narrow path from a durable execution lease to one
provider call.  It authenticates the encrypted, canonical envelope before the
adapter sees it and commits ``dispatch_started`` immediately before entering
the adapter's asynchronous execution method.  After that boundary every
interruption is ambiguous until a read-only reconciliation proves otherwise.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Protocol, cast

from signet.adapters.base import AdapterRequest, ApprovalAdapter, MCPClient, Outcome
from signet.async_support import run_sync_non_abandoning as _run_sync
from signet.canonical import CanonicalizationError, canonical_json
from signet.execution_scope import ExecutionScope, ExecutionScopeResolver
from signet.models import (
    AttachmentReference,
    ExecutionLease,
    ExecutionPhase,
    OutcomeClassification,
    ResultAlias,
)
from signet.safe_metadata import public_safe_metadata
from signet.state_machine import ApprovalStateMachine


class DeliveryError(RuntimeError):
    """Base class for delivery failures that contain no private payload data."""


class FrozenPayloadError(DeliveryError):
    """The stored encrypted envelope failed integrity or contract verification."""


class DeliveryPreparationError(DeliveryError):
    """Delivery failed before the durable downstream-call boundary."""


class PayloadDecryptor(Protocol):
    """Decrypt one payload version using its immutable database identity as AAD."""

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        key_reference: str | None,
        request_id: str,
        version: int,
        payload_hash: str,
    ) -> bytes: ...


@dataclass(frozen=True, slots=True)
class LoadedFrozenRequest:
    """A verified adapter request and the adapter reviewed for its exact envelope."""

    adapter: ApprovalAdapter
    request: AdapterRequest
    adapter_id: str
    adapter_version: str
    execution_scope: ExecutionScope


@dataclass(frozen=True, slots=True)
class DispatchResult:
    request_id: str
    attempt_id: str
    outcome: OutcomeClassification
    safe_metadata: Mapping[str, str | int | bool | None]
    result_aliases: tuple[ResultAlias, ...]
    redispatch: bool


@dataclass(frozen=True, slots=True)
class _PreparedDispatch:
    loaded: LoadedFrozenRequest
    downstream: MCPClient
    payload: Mapping[str, Any]


_ENVELOPE_FIELDS = frozenset(
    {
        "account_ref",
        "adapter_id",
        "adapter_version",
        "alias",
        "arguments",
        "caller_namespace",
        "credential_identity_digest",
        "policy_version",
        "schema_digest",
        "staged_file_hashes",
        "tool",
    }
)
_SAFE_METADATA_FIELDS = (
    "provider_id",
    "message_id",
    "submission_id",
    "thread_id",
    "chat_message_id",
    "status",
    "state",
    "provider_status",
    "reconciled_at",
    "delivered_at",
    "idempotency_key_applied",
)
_ALIAS_FIELDS = frozenset(
    {"provider_id", "message_id", "submission_id", "thread_id", "chat_message_id"}
)


class FrozenRequestLoader:
    """Decrypt and authenticate the exact canonical envelope named by a lease."""

    def __init__(
        self,
        state_machine: ApprovalStateMachine,
        decryptor: PayloadDecryptor,
        adapters: Mapping[tuple[str, str], ApprovalAdapter],
        execution_scopes: ExecutionScopeResolver,
        *,
        max_payload_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        if max_payload_bytes <= 0:
            raise ValueError("maximum payload size must be positive")
        if not adapters:
            raise ValueError("at least one delivery adapter is required")
        if any(
            not alias or not tool or adapter.downstream_alias != alias or adapter.tool_name != tool
            for (alias, tool), adapter in adapters.items()
        ):
            raise ValueError("adapter registry keys must match adapter contracts")
        if not callable(getattr(execution_scopes, "resolve", None)):
            raise ValueError("an execution scope resolver is required")
        self.state_machine = state_machine
        self.decryptor = decryptor
        self._adapters = dict(adapters)
        self._execution_scopes = execution_scopes
        self.max_payload_bytes = max_payload_bytes

    def adapter_for(self, downstream_alias: str, tool_name: str) -> ApprovalAdapter:
        try:
            return self._adapters[(downstream_alias, tool_name)]
        except KeyError as exc:
            raise DeliveryPreparationError(
                "no reviewed adapter matches the frozen request"
            ) from exc

    def load(self, lease: ExecutionLease) -> LoadedFrozenRequest:
        request_row = self.state_machine.get_request(lease.request_id)
        if request_row["current_version"] != lease.version or not _same_text(
            request_row["current_payload_hash"], lease.payload_hash
        ):
            raise FrozenPayloadError("execution lease no longer names the current request version")

        payload_row = self.state_machine.get_payload_version(lease.request_id, lease.version)
        if not _same_text(payload_row["payload_hash"], lease.payload_hash):
            raise FrozenPayloadError("payload row does not match the execution lease")
        if (
            payload_row["encrypted_payload"] is None
            or payload_row["purged_at"] is not None
            or payload_row["key_destroyed_at"] is not None
        ):
            raise FrozenPayloadError("frozen payload is unavailable")
        canonical_size = payload_row["canonical_size"]
        if (
            not isinstance(canonical_size, int)
            or canonical_size < 0
            or canonical_size > self.max_payload_bytes
        ):
            raise FrozenPayloadError("frozen payload size is outside the execution limit")

        ciphertext = bytes(payload_row["encrypted_payload"])
        key_reference = payload_row["encryption_key_ref"]
        if key_reference is not None and not isinstance(key_reference, str):
            raise FrozenPayloadError("payload key reference is invalid")
        try:
            plaintext = self.decryptor.decrypt(
                ciphertext,
                key_reference=key_reference,
                request_id=lease.request_id,
                version=lease.version,
                payload_hash=lease.payload_hash,
            )
        except Exception as exc:
            raise FrozenPayloadError("frozen payload could not be decrypted") from exc
        if not isinstance(plaintext, bytes):
            raise FrozenPayloadError("payload decryptor returned an invalid value")
        if len(plaintext) != canonical_size or len(plaintext) > self.max_payload_bytes:
            raise FrozenPayloadError("decrypted payload size does not match the frozen version")
        digest = hashlib.sha256(plaintext).hexdigest()
        if not hmac.compare_digest(digest, lease.payload_hash):
            raise FrozenPayloadError("decrypted payload hash does not match the frozen version")

        envelope = _parse_canonical_envelope(plaintext)
        alias = envelope["alias"]
        tool = envelope["tool"]
        account_ref = envelope["account_ref"]
        adapter_id = envelope["adapter_id"]
        adapter_version = envelope["adapter_version"]
        caller_namespace = envelope["caller_namespace"]
        credential_identity_digest = envelope["credential_identity_digest"]
        arguments = envelope["arguments"]
        staged_hashes = envelope["staged_file_hashes"]
        policy_version = envelope["policy_version"]
        schema_digest = envelope["schema_digest"]
        if (
            not isinstance(alias, str)
            or alias != request_row["downstream_alias"]
            or not isinstance(tool, str)
            or tool != request_row["tool_name"]
        ):
            raise FrozenPayloadError("canonical envelope targets a different downstream tool")
        if (
            not isinstance(adapter_id, str)
            or not adapter_id
            or not isinstance(adapter_version, str)
            or adapter_version != payload_row["adapter_version"]
        ):
            raise FrozenPayloadError("canonical envelope has a stale adapter identity")
        if not _valid_policy_version(policy_version) or str(policy_version) != str(
            payload_row["policy_version"]
        ):
            raise FrozenPayloadError("canonical envelope has a stale policy version")
        if (
            not isinstance(caller_namespace, str)
            or caller_namespace != request_row["origin_namespace"]
        ):
            raise FrozenPayloadError("canonical envelope has a different caller namespace")
        if not _is_sha256(schema_digest) or not _same_text(
            payload_row["schema_version"], cast(str, schema_digest)
        ):
            raise FrozenPayloadError("canonical envelope has a stale schema digest")
        if not isinstance(account_ref, str) or not _is_sha256(credential_identity_digest):
            raise FrozenPayloadError("canonical envelope execution identity is invalid")
        if not isinstance(arguments, dict):
            raise FrozenPayloadError("canonical envelope arguments are invalid")
        if not isinstance(staged_hashes, list) or any(
            not _is_sha256(item) for item in staged_hashes
        ):
            raise FrozenPayloadError("canonical envelope staged-file hashes are invalid")

        adapter = self.adapter_for(alias, tool)
        if adapter.adapter_id != adapter_id or adapter.adapter_version != adapter_version:
            raise FrozenPayloadError("reviewed adapter identity does not match the frozen envelope")
        frozen_scope = ExecutionScope(
            account_ref=account_ref,
            credential_identity_digest=cast(str, credential_identity_digest),
            schema_digest=cast(str, schema_digest),
        )
        if not self._scope_is_current(adapter, frozen_scope):
            raise FrozenPayloadError("current execution scope does not match the frozen envelope")
        try:
            canonical_arguments = adapter.canonicalize(cast(dict[str, Any], arguments))
            if canonical_json(canonical_arguments) != canonical_json(arguments):
                raise ValueError
            frozen_attachments = adapter.freeze_attachments(canonical_arguments)
            stored_attachments = self.state_machine.get_attachment_references(
                lease.request_id,
                version=lease.version,
                payload_hash=lease.payload_hash,
            )
        except Exception:
            raise FrozenPayloadError(
                "frozen payload attachment snapshot could not be authenticated"
            ) from None
        if tuple(attachment.sha256 for attachment in frozen_attachments) != tuple(
            cast(list[str], staged_hashes)
        ) or _sorted_attachment_identities(frozen_attachments) != _sorted_attachment_identities(
            stored_attachments
        ):
            raise FrozenPayloadError("frozen payload attachment snapshot does not match")
        return LoadedFrozenRequest(
            adapter=adapter,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            execution_scope=frozen_scope,
            request=AdapterRequest(
                request_id=lease.request_id,
                downstream_alias=alias,
                tool_name=tool,
                arguments=canonical_arguments,
                account=account_ref,
                payload_hash=lease.payload_hash,
                version=lease.version,
                idempotency_key=lease.downstream_idempotency_key,
                created_at=datetime.fromtimestamp(payload_row["created_at"], tz=UTC),
            ),
        )

    def require_current_scope(
        self,
        loaded: LoadedFrozenRequest,
        downstream_client: object,
    ) -> None:
        """Recheck runtime identity at the last pre-dispatch boundary."""

        if (
            loaded.adapter.adapter_id != loaded.adapter_id
            or loaded.adapter.adapter_version != loaded.adapter_version
            or not self._scope_is_current(
                loaded.adapter,
                loaded.execution_scope,
                downstream_client,
            )
        ):
            raise FrozenPayloadError("current execution scope changed before dispatch")

    def _scope_is_current(
        self,
        adapter: ApprovalAdapter,
        frozen_scope: ExecutionScope,
        downstream_client: object | None = None,
    ) -> bool:
        try:
            current = self._execution_scopes.resolve(
                adapter.downstream_alias,
                adapter.tool_name,
                adapter,
                downstream_client,
            )
        except Exception:
            return False
        return (
            current.account_ref == frozen_scope.account_ref
            and hmac.compare_digest(
                current.credential_identity_digest,
                frozen_scope.credential_identity_digest,
            )
            and hmac.compare_digest(current.schema_digest, frozen_scope.schema_digest)
        )


def _attachment_identity(
    attachment: AttachmentReference,
) -> tuple[str, str, str, int, str, str]:
    if not isinstance(attachment, AttachmentReference):
        raise FrozenPayloadError("frozen payload attachment snapshot is invalid")
    return (
        attachment.attachment_id,
        attachment.filename,
        attachment.mime_type,
        attachment.size_bytes,
        attachment.sha256,
        attachment.storage_path,
    )


def _sorted_attachment_identities(
    attachments: tuple[AttachmentReference, ...],
) -> tuple[tuple[str, str, str, int, str, str], ...]:
    return tuple(sorted(_attachment_identity(attachment) for attachment in attachments))


class DeliveryDispatcher:
    """Claim and execute one immutable request through its reviewed adapter."""

    def __init__(
        self,
        state_machine: ApprovalStateMachine,
        loader: FrozenRequestLoader,
        downstream_clients: Mapping[str, MCPClient],
        *,
        initial_reconciliation_delay: int = 60,
    ) -> None:
        if initial_reconciliation_delay <= 0:
            raise ValueError("initial reconciliation delay must be positive")
        if any(not alias for alias in downstream_clients):
            raise ValueError("downstream aliases must not be empty")
        self.state_machine = state_machine
        self.loader = loader
        self._downstream_clients = dict(downstream_clients)
        self.initial_reconciliation_delay = initial_reconciliation_delay

    async def dispatch(
        self,
        request_id: str,
        *,
        worker_id: str,
        now: int,
        lease_seconds: int = 30,
    ) -> DispatchResult:
        lease = await _run_sync(
            self._claim_execution,
            request_id,
            worker_id=worker_id,
            now=now,
            lease_seconds=lease_seconds,
        )
        return await self.dispatch_claimed(lease, now=now)

    def _claim_execution(
        self,
        request_id: str,
        *,
        worker_id: str,
        now: int,
        lease_seconds: int,
    ) -> ExecutionLease:
        request = self.state_machine.get_request(request_id)
        adapter = self.loader.adapter_for(request["downstream_alias"], request["tool_name"])
        downstream_key = (
            stable_downstream_idempotency_key(
                request_id,
                version=request["current_version"],
                payload_hash=request["current_payload_hash"],
            )
            if adapter.supports_idempotency
            else None
        )
        return self.state_machine.claim_execution(
            request_id,
            worker_id=worker_id,
            now=now,
            lease_seconds=lease_seconds,
            downstream_idempotency_key=downstream_key,
        )

    async def dispatch_claimed(self, lease: ExecutionLease, *, now: int) -> DispatchResult:
        """Execute an initial or reconciliation-authorized redispatch lease once."""

        try:
            prepared = await _run_sync(self._prepare_dispatch, lease)
        except asyncio.CancelledError:
            await _run_sync(self._record_pre_dispatch_failure, lease, now=now)
            raise
        except Exception as exc:
            await _run_sync(self._record_pre_dispatch_failure, lease, now=now)
            raise DeliveryPreparationError(
                "delivery preparation failed before network I/O"
            ) from exc

        # Commit first, then revalidate the exact client with no await before provider I/O.
        try:
            await _run_sync(self.state_machine.mark_dispatch_started, lease, now=now)
        except asyncio.CancelledError:
            await _run_sync(
                self._record_unknown,
                lease,
                now=now,
                failure_reason="dispatch_cancelled",
            )
            raise
        try:
            self.loader.require_current_scope(prepared.loaded, prepared.downstream)
        except Exception as exc:
            await _run_sync(
                self.state_machine.record_outcome,
                lease,
                classification=OutcomeClassification.DEFINITE_FAILURE,
                now=now,
                failure_reason="execution_scope_changed_before_io",
            )
            raise DeliveryPreparationError(
                "delivery execution scope changed before network I/O"
            ) from exc
        try:
            result_or_error: object = await prepared.loaded.adapter.execute(
                prepared.downstream,
                prepared.payload,
            )
        except asyncio.CancelledError:
            await _run_sync(
                self._record_unknown,
                lease,
                now=now,
                failure_reason="dispatch_cancelled",
            )
            raise
        except Exception as exc:
            result_or_error = exc

        return await _run_sync(
            self._settle_dispatch,
            lease,
            prepared.loaded,
            result_or_error,
            now=now,
        )

    def _prepare_dispatch(self, lease: ExecutionLease) -> _PreparedDispatch:
        loaded = self.loader.load(lease)
        downstream = self._downstream_clients[loaded.request.downstream_alias]
        payload = loaded.adapter.prepare_for_execution(loaded.request)
        self.loader.require_current_scope(loaded, downstream)
        return _PreparedDispatch(loaded=loaded, downstream=downstream, payload=payload)

    def _settle_dispatch(
        self,
        lease: ExecutionLease,
        loaded: LoadedFrozenRequest,
        result_or_error: object,
        *,
        now: int,
    ) -> DispatchResult:
        outcome = _classify(loaded.adapter, result_or_error)
        internal_metadata = (
            standardize_safe_metadata(loaded.adapter, result_or_error)
            if isinstance(result_or_error, Mapping)
            else MappingProxyType({})
        )
        aliases = (
            result_aliases_from_metadata(
                internal_metadata, account_namespace=loaded.request.account
            )
            if outcome is Outcome.SUCCEEDED
            else ()
        )
        metadata = MappingProxyType(public_safe_metadata(internal_metadata))
        classification = _state_classification(outcome)
        kwargs: dict[str, Any] = {
            "classification": classification,
            "now": now,
            "safe_outcome": internal_metadata,
            "result_aliases": aliases,
        }
        if classification is OutcomeClassification.DEFINITE_FAILURE:
            kwargs["failure_reason"] = "downstream_definite_failure"
        elif classification is OutcomeClassification.UNKNOWN:
            kwargs["failure_reason"] = "dispatch_outcome_unknown"
            kwargs["reconciliation_next_at"] = now + self.initial_reconciliation_delay
        self.state_machine.record_outcome(lease, **kwargs)
        return DispatchResult(
            request_id=lease.request_id,
            attempt_id=lease.attempt_id,
            outcome=classification,
            safe_metadata=metadata,
            result_aliases=aliases,
            redispatch=lease.phase is ExecutionPhase.REDISPATCH_PREPARING,
        )

    def _record_pre_dispatch_failure(self, lease: ExecutionLease, *, now: int) -> None:
        self.state_machine.record_pre_dispatch_failure(
            lease,
            now=now,
            failure_reason="delivery_preparation_failed",
        )

    def _record_unknown(self, lease: ExecutionLease, *, now: int, failure_reason: str) -> None:
        self.state_machine.record_outcome(
            lease,
            classification=OutcomeClassification.UNKNOWN,
            now=now,
            failure_reason=failure_reason,
            reconciliation_next_at=now + self.initial_reconciliation_delay,
        )


def stable_downstream_idempotency_key(
    request_id: str,
    *,
    version: int,
    payload_hash: str,
) -> str:
    if not request_id or version < 1 or not _is_sha256(payload_hash):
        raise ValueError("stable idempotency keys require an immutable request version")
    material = f"signet-dispatch\x00{request_id}\x00{version}\x00{payload_hash}".encode()
    return f"sgd_{hashlib.sha256(material).hexdigest()}"


def standardize_safe_metadata(
    adapter: ApprovalAdapter,
    downstream_result: Mapping[str, Any],
) -> Mapping[str, str | int | bool | None]:
    """Keep only the state machine's reviewed scalar metadata vocabulary."""

    try:
        candidate = adapter.safe_result_metadata(downstream_result)
    except Exception:
        return MappingProxyType({})
    if not isinstance(candidate, Mapping):
        return MappingProxyType({})
    safe: dict[str, str | int | bool | None] = {}
    for field in _SAFE_METADATA_FIELDS:
        value = candidate.get(field)
        if field not in candidate or (
            value is not None and not isinstance(value, (str, int, bool))
        ):
            continue
        if isinstance(value, str) and len(value) > 512:
            continue
        proposed = {**safe, field: value}
        try:
            size = len(json.dumps(proposed, ensure_ascii=False, separators=(",", ":")).encode())
        except (TypeError, ValueError):
            continue
        if size <= 4096:
            safe = proposed
    return MappingProxyType(safe)


def result_aliases_from_metadata(
    metadata: Mapping[str, str | int | bool | None],
    *,
    account_namespace: str,
) -> tuple[ResultAlias, ...]:
    if not account_namespace:
        raise ValueError("result aliases require an account namespace")
    aliases: list[ResultAlias] = []
    seen: set[tuple[str, str]] = set()
    for field in _SAFE_METADATA_FIELDS:
        if field not in _ALIAS_FIELDS:
            continue
        value = metadata.get(field)
        if isinstance(value, bool) or value is None:
            continue
        identifier = str(value)
        key = (field, identifier)
        if not identifier or len(identifier) > 512 or key in seen:
            continue
        seen.add(key)
        aliases.append(ResultAlias(account_namespace, field, identifier))
    return tuple(aliases)


def _parse_canonical_envelope(plaintext: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    try:
        decoded = json.loads(plaintext.decode("utf-8"), object_pairs_hook=reject_duplicates)
        if not isinstance(decoded, dict) or set(decoded) != _ENVELOPE_FIELDS:
            raise ValueError("invalid envelope fields")
        if canonical_json(decoded) != plaintext:
            raise ValueError("payload is not canonical JSON")
    except (CanonicalizationError, RecursionError, UnicodeError, ValueError) as exc:
        raise FrozenPayloadError(
            "decrypted payload is not the canonical execution envelope"
        ) from exc
    return cast(dict[str, Any], decoded)


def _classify(adapter: ApprovalAdapter, result_or_error: object) -> Outcome:
    try:
        outcome = adapter.classify_outcome(result_or_error)
    except Exception:
        return Outcome.OUTCOME_UNKNOWN
    if not isinstance(outcome, Outcome):
        return Outcome.OUTCOME_UNKNOWN
    if isinstance(result_or_error, BaseException) and outcome is Outcome.SUCCEEDED:
        return Outcome.OUTCOME_UNKNOWN
    return outcome


def _state_classification(outcome: Outcome) -> OutcomeClassification:
    return {
        Outcome.SUCCEEDED: OutcomeClassification.SUCCEEDED,
        Outcome.DEFINITE_FAILURE: OutcomeClassification.DEFINITE_FAILURE,
        Outcome.OUTCOME_UNKNOWN: OutcomeClassification.UNKNOWN,
    }[outcome]


def _same_text(left: object, right: str) -> bool:
    return isinstance(left, str) and hmac.compare_digest(left, right)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_policy_version(value: object) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool) and value >= 0) or (
        isinstance(value, str) and bool(value) and len(value) <= 256
    )
