"""Persistence-facing models for the approval request lifecycle.

The database stores timestamps as integer Unix seconds.  Callers are expected to
derive payload hashes and encrypted payloads before entering this layer; keeping
those concerns outside the state machine makes its transactional boundaries
explicit and testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

type PolicyMode = Literal[
    "deny",
    "approval",
    "passthrough",
    "virtualize_local",
]


class RequestState(StrEnum):
    RECEIVED = "received"
    VALIDATING = "validating"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ExecutionPhase(StrEnum):
    PREPARING = "preparing"
    DISPATCH_STARTED = "dispatch_started"
    OUTCOME_UNKNOWN = "outcome_unknown"
    REDISPATCH_PREPARING = "redispatch_preparing"
    REDISPATCH_STARTED = "redispatch_started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ConfirmationKind(StrEnum):
    TOTP = "totp"
    WEBAUTHN = "webauthn"


class OutcomeClassification(StrEnum):
    SUCCEEDED = "succeeded"
    DEFINITE_FAILURE = "definite_failure"
    UNKNOWN = "outcome_unknown"


class ReconciliationDecision(StrEnum):
    CONFIRMED_EFFECT = "confirmed_effect"
    CONFIRMED_NO_EFFECT = "confirmed_no_effect"
    INCONCLUSIVE = "inconclusive"


class ReconciliationAction(StrEnum):
    SUCCEEDED = "succeeded"
    REDISPATCH = "redispatch"
    FAILED_NO_EFFECT = "failed_no_effect"
    RESCHEDULED = "rescheduled"
    EXHAUSTED = "exhausted"


@dataclass(frozen=True, slots=True)
class AttachmentReference:
    attachment_id: str
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    storage_path: str
    purge_after: int | None = None


@dataclass(frozen=True, slots=True)
class ResultAlias:
    account_namespace: str
    identifier_kind: str
    downstream_identifier: str


@dataclass(frozen=True, slots=True)
class EnqueueRequest:
    request_id: str
    downstream_alias: str
    tool_name: str
    policy_mode: PolicyMode
    origin_namespace: str
    encrypted_payload: bytes
    payload_hash: str
    payload_fingerprint: str
    pending_result: bytes
    created_at: int
    expires_at: int
    policy_version: str
    adapter_version: str
    schema_version: str
    editor_actor: str
    canonical_size: int | None = None
    encryption_key_ref: str | None = None
    idempotency_key: str | None = None
    retry_of_request_id: str | None = None
    gateway_internal: bool = False
    attachments: tuple[AttachmentReference, ...] = ()


@dataclass(frozen=True, slots=True)
class EnqueueResult:
    request_id: str
    pending_result: bytes
    created: bool


@dataclass(frozen=True, slots=True, repr=False)
class ApprovalConfirmation:
    kind: ConfirmationKind
    use_id: str
    path: Literal["web", "mcp"]
    capability: str
    user_id: str | None = None
    action: str | None = None
    bound_request_id: str | None = None
    bound_version: int | None = None
    bound_payload_hash: str | None = None
    prospective_payload_hash: str | None = None
    session_id: str | None = None
    http_method: str | None = None
    attempt_id: str | None = None
    attempt_scope_keys: tuple[str, ...] = ()
    rate_limit_key: str | None = None
    challenge_id: str | None = None
    credential_id: str | None = None
    credential_user_id: str | None = None
    expected_counter: int | None = None
    new_counter: int | None = None
    device_type: Literal["single_device", "multi_device"] | None = None
    expected_backup_eligible: bool | None = None
    new_backup_eligible: bool | None = None
    previous_backed_up: bool | None = None
    new_backed_up: bool | None = None

    def __repr__(self) -> str:
        return (
            "ApprovalConfirmation("
            f"kind={self.kind!r}, path={self.path!r}, "
            "use_id=<redacted>, capability=<redacted>, binding=<redacted>, "
            "session_id=<redacted>, credential_id=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class ExecutionLease:
    request_id: str
    version: int
    payload_hash: str
    attempt_id: str
    fencing_token: str
    worker_generation: int
    lease_expires_at: int
    phase: ExecutionPhase
    downstream_idempotency_key: str | None


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    action: ReconciliationAction
    reconciliation_count: int
    lease: ExecutionLease | None = None


@dataclass(frozen=True, slots=True)
class RecoverySummary:
    active: tuple[str, ...]
    reclaimable: tuple[str, ...]
    routed_to_reconciliation: tuple[str, ...]


class StateMachineError(RuntimeError):
    """Base class for lifecycle rejections."""


class AdmissionRejected(StateMachineError):
    """A new durable request exceeded a fail-closed admission boundary."""

    _REASONS = frozenset(
        {"payload_limit", "request_rate", "queue_capacity", "storage_headroom"}
    )

    def __init__(self, reason: str) -> None:
        if reason not in self._REASONS:
            raise ValueError("invalid admission rejection reason")
        self.reason = reason
        super().__init__(reason)


class RequestNotFound(StateMachineError):
    pass


class InvalidTransition(StateMachineError):
    pass


class StaleVersion(StateMachineError):
    pass


class RequestExpired(StateMachineError):
    pass


class IdempotencyConflict(StateMachineError):
    pass


class ConfirmationReplay(StateMachineError):
    pass


class InvalidConfirmation(StateMachineError):
    pass


class FenceRejected(StateMachineError):
    pass


class ReconciliationRejected(StateMachineError):
    pass


class ReadOnlyToolViolation(StateMachineError):
    pass
