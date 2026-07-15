"""Transactional approval lifecycle and fenced execution state machine."""

from __future__ import annotations

import hmac
import inspect
import json
import secrets
import shutil
import uuid
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Literal

from .admission import QueueAdmissionLimits, ReviewedToolLimits
from .auth import (
    TOTP_PROOF_DOMAIN,
    WEBAUTHN_PROOF_DOMAIN,
    ActionBinding,
    ProofCapability,
    canonical_user_id,
    totp_proof_claims,
    totp_rate_limit_key,
    webauthn_proof_claims,
)
from .db import Database, IntegrityError
from .models import (
    AdmissionRejected,
    ApprovalConfirmation,
    AttachmentReference,
    ConfirmationKind,
    ConfirmationReplay,
    EnqueueRequest,
    EnqueueResult,
    ExecutionLease,
    ExecutionPhase,
    FenceRejected,
    IdempotencyConflict,
    InvalidConfirmation,
    InvalidTransition,
    OutcomeClassification,
    ReadOnlyToolViolation,
    ReconciliationAction,
    ReconciliationDecision,
    ReconciliationRejected,
    ReconciliationResult,
    RecoverySummary,
    RequestExpired,
    RequestNotFound,
    RequestState,
    ResultAlias,
    StaleVersion,
)
from .notification_outbox import enqueue_notification
from .notifications import NotificationKind, PushMessage
from .safe_metadata import public_safe_metadata

FaultInjector = Callable[[str], None]
TokenFactory = Callable[[], str]

_TERMINAL_STATES = {
    RequestState.SUCCEEDED,
    RequestState.FAILED,
    RequestState.DENIED,
    RequestState.EXPIRED,
    RequestState.CANCELLED,
}


class ApprovalStateMachine:
    """Own all durable lifecycle mutations.

    The public methods deliberately accept explicit versions, hashes, fencing
    tokens, and reconciliation counters.  Those values are the CAS inputs that
    make stale browser tabs, duplicate approvals, and old workers lose without
    changing persistent state.
    """

    def __init__(
        self,
        database: Database,
        *,
        fault_injector: FaultInjector | None = None,
        token_factory: TokenFactory | None = None,
        web_session_idle_timeout: int = 30 * 60,
        capabilities: ProofCapability | None = None,
        notification_user_id: str | None = None,
        admission_limits: QueueAdmissionLimits | None = None,
        free_space_provider: Callable[[str], int] | None = None,
    ) -> None:
        if web_session_idle_timeout <= 0:
            raise ValueError("web session idle timeout must be positive")
        self.database = database
        self._fault_injector = fault_injector
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._web_session_idle_timeout = web_session_idle_timeout
        self._capabilities = capabilities
        self._admission_limits = admission_limits or QueueAdmissionLimits()
        if not isinstance(self._admission_limits, QueueAdmissionLimits):
            raise TypeError("admission_limits must be queue admission limits")
        if free_space_provider is not None and not callable(free_space_provider):
            raise TypeError("free-space provider must be callable")
        self._free_space_provider = free_space_provider or _filesystem_free_bytes
        self._notification_user_id = (
            canonical_user_id(notification_user_id) if notification_user_id is not None else None
        )

    @property
    def notifications_enabled(self) -> bool:
        return self._notification_user_id is not None

    def enqueue(
        self,
        request: EnqueueRequest,
        *,
        reviewed_limits: ReviewedToolLimits | None = None,
    ) -> EnqueueResult:
        """Durably enqueue or replay a caller-scoped invocation.

        The return happens only after the FULL-synchronous transaction context
        has committed.  A fault at ``enqueue:before_commit`` therefore produces
        neither a stored request nor an acknowledgement.
        """

        self._validate_enqueue(request)
        selected_tool_limits = reviewed_limits or ReviewedToolLimits()
        if not isinstance(selected_tool_limits, ReviewedToolLimits):
            raise TypeError("reviewed_limits must be reviewed tool limits")
        replay: EnqueueResult | None = None
        with self.database.transaction() as connection:
            if request.idempotency_key is not None:
                existing = connection.execute(
                    """
                    SELECT request_id, payload_fingerprint, pending_result
                    FROM idempotency_records
                    WHERE origin_namespace = ? AND downstream_alias = ?
                      AND tool_name = ? AND invocation_key = ?
                    """,
                    (
                        request.origin_namespace,
                        request.downstream_alias,
                        request.tool_name,
                        request.idempotency_key,
                    ),
                ).fetchone()
                if existing is not None:
                    if not hmac.compare_digest(
                        existing["payload_fingerprint"],
                        request.payload_fingerprint,
                    ):
                        raise IdempotencyConflict(
                            "the invocation key is already bound to a different payload"
                        )
                    replay = EnqueueResult(
                        request_id=existing["request_id"],
                        pending_result=bytes(existing["pending_result"]),
                        created=False,
                    )

            if replay is None:
                duplicate_warning = 0
                if request.retry_of_request_id is not None:
                    prior = connection.execute(
                        """
                        SELECT state FROM approval_requests WHERE request_id = ?
                        """,
                        (request.retry_of_request_id,),
                    ).fetchone()
                    if prior is None:
                        raise RequestNotFound(request.retry_of_request_id)
                    if prior["state"] not in {
                        RequestState.FAILED.value,
                        RequestState.OUTCOME_UNKNOWN.value,
                    }:
                        raise InvalidTransition(
                            "manual send-again requires a failed or unknown prior request"
                        )
                    duplicate_warning = int(prior["state"] == RequestState.OUTCOME_UNKNOWN.value)

                self._expire_pending_batch(
                    connection,
                    now=request.created_at,
                    limit=self._admission_limits.enqueue_expiry_sweep_limit,
                    actor="system:enqueue-expiry-sweep",
                )
                self._enforce_enqueue_admission(
                    connection,
                    request=request,
                    reviewed_limits=selected_tool_limits,
                )
                self._require_attachment_catalog(connection, request)

                connection.execute(
                    """
                    INSERT INTO approval_requests(
                        request_id, downstream_alias, tool_name, policy_mode,
                        state, current_version, current_payload_hash,
                        origin_namespace, pending_result, retry_of_request_id,
                        gateway_internal, created_at, expires_at,
                        duplicate_warning_required
                    ) VALUES (?, ?, ?, ?, 'pending_approval', 1, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.request_id,
                        request.downstream_alias,
                        request.tool_name,
                        request.policy_mode,
                        request.payload_hash,
                        request.origin_namespace,
                        request.pending_result,
                        request.retry_of_request_id,
                        int(request.gateway_internal),
                        request.created_at,
                        request.expires_at,
                        duplicate_warning,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO payload_versions(
                        request_id, version, encrypted_payload, payload_hash,
                        canonical_size, policy_version, adapter_version,
                        schema_version, editor_actor, created_at,
                        encryption_key_ref
                    ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.request_id,
                        request.encrypted_payload,
                        request.payload_hash,
                        request.canonical_size
                        if request.canonical_size is not None
                        else len(request.encrypted_payload),
                        request.policy_version,
                        request.adapter_version,
                        request.schema_version,
                        request.editor_actor,
                        request.created_at,
                        request.encryption_key_ref,
                    ),
                )
                for attachment in request.attachments:
                    connection.execute(
                        """
                        INSERT INTO attachments(
                            attachment_id, request_id, version, payload_hash, filename,
                            mime_type, size_bytes, sha256, storage_path,
                            created_at, purge_after
                        ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            attachment.attachment_id,
                            request.request_id,
                            request.payload_hash,
                            attachment.filename,
                            attachment.mime_type,
                            attachment.size_bytes,
                            attachment.sha256,
                            attachment.storage_path,
                            request.created_at,
                            attachment.purge_after,
                        ),
                    )
                if request.idempotency_key is not None:
                    connection.execute(
                        """
                        INSERT INTO idempotency_records(
                            origin_namespace, downstream_alias, tool_name,
                            invocation_key, payload_fingerprint, request_id,
                            pending_result, created_at, expires_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            request.origin_namespace,
                            request.downstream_alias,
                            request.tool_name,
                            request.idempotency_key,
                            request.payload_fingerprint,
                            request.request_id,
                            request.pending_result,
                            request.created_at,
                            request.expires_at,
                        ),
                    )
                self._event(
                    connection,
                    request.request_id,
                    request.editor_actor,
                    "pending_enqueued",
                    request.created_at,
                    1,
                    request.payload_hash,
                )
                self._notification(
                    connection,
                    kind=NotificationKind.NEW_PENDING,
                    request_id=request.request_id,
                    service=request.downstream_alias,
                    action=request.tool_name,
                    now=request.created_at,
                    dedupe_key=f"new_pending:{request.request_id}:1",
                )
                self._fault("enqueue:before_commit")

        if replay is not None:
            return replay
        return EnqueueResult(
            request_id=request.request_id,
            pending_result=request.pending_result,
            created=True,
        )

    def get_request(self, request_id: str) -> dict[str, Any]:
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM approval_requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        if row is None:
            raise RequestNotFound(request_id)
        return dict(row)

    def get_payload_version(self, request_id: str, version: int) -> dict[str, Any]:
        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT * FROM payload_versions
                WHERE request_id = ? AND version = ?
                """,
                (request_id, version),
            ).fetchone()
        if row is None:
            raise RequestNotFound(f"{request_id}@{version}")
        return dict(row)

    def get_attachment_references(
        self,
        request_id: str,
        *,
        version: int,
        payload_hash: str,
    ) -> tuple[AttachmentReference, ...]:
        """Load the exact active attachment snapshot for one payload revision."""

        self._validate_hash(payload_hash)
        with self.database.read() as connection:
            payload = connection.execute(
                """
                SELECT 1 FROM payload_versions
                WHERE request_id = ? AND version = ? AND payload_hash = ?
                """,
                (request_id, version, payload_hash),
            ).fetchone()
            if payload is None:
                raise RequestNotFound(f"{request_id}@{version}")
            rows = connection.execute(
                """
                SELECT attachment_id, filename, mime_type, size_bytes, sha256,
                       storage_path, purge_after, purged_at
                FROM attachments
                WHERE request_id = ? AND version = ? AND payload_hash = ?
                ORDER BY attachment_id
                """,
                (request_id, version, payload_hash),
            ).fetchall()
        if any(
            row["purged_at"] is not None or not isinstance(row["storage_path"], str) for row in rows
        ):
            raise InvalidTransition("attachment snapshot is unavailable")
        attachments = tuple(
            AttachmentReference(
                attachment_id=str(row["attachment_id"]),
                filename=str(row["filename"]),
                mime_type=str(row["mime_type"]),
                size_bytes=int(row["size_bytes"]),
                sha256=str(row["sha256"]),
                storage_path=str(row["storage_path"]),
                purge_after=(int(row["purge_after"]) if row["purge_after"] is not None else None),
            )
            for row in rows
        )
        self._validate_attachments(attachments)
        return attachments

    def list_events(self, request_id: str) -> list[dict[str, Any]]:
        with self.database.read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM request_events
                WHERE request_id = ? ORDER BY event_id
                """,
                (request_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def edit(
        self,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        encrypted_payload: bytes,
        payload_hash: str,
        canonical_size: int,
        policy_version: str,
        adapter_version: str,
        schema_version: str,
        editor_actor: str,
        confirmation: ApprovalConfirmation,
        now: int,
        encryption_key_ref: str | None = None,
        attachments: tuple[AttachmentReference, ...] | None = None,
    ) -> int:
        self._validate_hash(payload_hash)
        if not encrypted_payload or canonical_size < 0:
            raise ValueError("an edited payload and non-negative canonical size are required")

        with self.database.transaction() as connection:
            request = self._request_for_update(connection, request_id)
            self._require_current(request, expected_version, expected_payload_hash)
            if request["state"] != RequestState.PENDING_APPROVAL.value:
                raise InvalidTransition(f"cannot edit a request in state {request['state']}")
            if hmac.compare_digest(request["current_payload_hash"], payload_hash):
                raise InvalidTransition("an edit must create a different payload hash")
            self._consume_confirmation(
                connection,
                confirmation,
                action="edit",
                request_id=request_id,
                expected_version=expected_version,
                expected_payload_hash=expected_payload_hash,
                prospective_payload_hash=payload_hash,
                now=now,
            )

            new_version = expected_version + 1
            connection.execute(
                """
                INSERT INTO payload_versions(
                    request_id, version, encrypted_payload, payload_hash,
                    canonical_size, policy_version, adapter_version,
                    schema_version, editor_actor, created_at,
                    encryption_key_ref
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    new_version,
                    encrypted_payload,
                    payload_hash,
                    canonical_size,
                    policy_version,
                    adapter_version,
                    schema_version,
                    editor_actor,
                    now,
                    encryption_key_ref,
                ),
            )
            if attachments is None:
                connection.execute(
                    """
                    INSERT INTO attachments(
                        attachment_id, request_id, version, payload_hash,
                        filename, mime_type, size_bytes, sha256, storage_path,
                        created_at, purge_after, purged_at
                    )
                    SELECT attachment_id, request_id, ?, ?, filename, mime_type,
                           size_bytes, sha256, storage_path, ?, purge_after, purged_at
                    FROM attachments
                    WHERE request_id = ? AND version = ?
                    """,
                    (new_version, payload_hash, now, request_id, expected_version),
                )
            else:
                self._validate_attachments(attachments)
                self._require_attachment_catalog_entries(
                    connection,
                    downstream_alias=str(request["downstream_alias"]),
                    request_id=request_id,
                    attachments=attachments,
                )
                self._insert_attachments(
                    connection,
                    request_id=request_id,
                    version=new_version,
                    payload_hash=payload_hash,
                    attachments=attachments,
                    created_at=now,
                )
            updated = connection.execute(
                """
                UPDATE approval_requests
                SET current_version = ?, current_payload_hash = ?,
                    state = 'pending_approval', approved_at = NULL,
                    execution_started_at = NULL, completed_at = NULL,
                    safe_outcome_json = NULL, failure_reason = NULL,
                    manual_retry_allowed = 0,
                    duplicate_warning_required = 0, revision = revision + 1
                WHERE request_id = ? AND state = 'pending_approval'
                  AND current_version = ? AND current_payload_hash = ?
                """,
                (
                    new_version,
                    payload_hash,
                    request_id,
                    expected_version,
                    expected_payload_hash,
                ),
            ).rowcount
            if updated != 1:
                raise StaleVersion(request_id)
            connection.execute(
                """
                UPDATE approval_challenges
                SET invalidated_at = ?
                WHERE request_id = ? AND invalidated_at IS NULL
                  AND consumed_at IS NULL
                """,
                (now, request_id),
            )
            connection.execute(
                """
                UPDATE auth_challenges SET invalidated_at = ?
                WHERE request_id = ? AND invalidated_at IS NULL
                  AND consumed_at IS NULL
                """,
                (now, request_id),
            )
            connection.execute(
                """
                UPDATE browser_views SET invalidated_at = ?
                WHERE request_id = ? AND invalidated_at IS NULL
                """,
                (now, request_id),
            )
            self._event(
                connection,
                request_id,
                editor_actor,
                "payload_edited",
                now,
                new_version,
                payload_hash,
            )
            self._fault("edit:before_commit")
        return new_version

    def create_challenge(
        self,
        challenge_id: str,
        request_id: str,
        *,
        kind: ConfirmationKind,
        user_id: str,
        action: str,
        challenge: bytes,
        session_id: str,
        http_method: str,
        offered_credential_ids: tuple[str, ...],
        expected_version: int,
        expected_payload_hash: str,
        prospective_payload_hash: str | None = None,
        created_at: int,
        expires_at: int,
    ) -> None:
        if expires_at <= created_at:
            raise ValueError("challenge expiry must be after creation")
        if kind != ConfirmationKind.WEBAUTHN:
            raise ValueError("only WebAuthn uses a server challenge")
        if (
            len(challenge) != 32
            or http_method != "POST"
            or not offered_credential_ids
            or len(offered_credential_ids) > 32
        ):
            raise ValueError("invalid WebAuthn challenge binding")
        if (prospective_payload_hash is not None) != (action == "edit"):
            raise ValueError("prospective hashes are edit-only")
        with self.database.transaction() as connection:
            request = self._request_for_update(connection, request_id)
            self._require_current(request, expected_version, expected_payload_hash)
            if request["state"] != RequestState.PENDING_APPROVAL.value:
                raise InvalidTransition("challenges require a pending request")
            connection.execute(
                """
                INSERT INTO auth_challenges(
                    challenge_id, challenge, user_id, action, request_id,
                    version, current_payload_hash, prospective_payload_hash,
                    session_id, http_method, offered_credential_ids_json,
                    created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge_id,
                    challenge,
                    user_id,
                    action,
                    request_id,
                    expected_version,
                    expected_payload_hash,
                    prospective_payload_hash,
                    session_id,
                    http_method,
                    json.dumps(
                        list(offered_credential_ids),
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ),
                    created_at,
                    expires_at,
                ),
            )

    def create_browser_view(
        self,
        view_id: str,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        created_at: int,
    ) -> None:
        with self.database.transaction() as connection:
            request = self._request_for_update(connection, request_id)
            self._require_current(request, expected_version, expected_payload_hash)
            connection.execute(
                """
                INSERT INTO browser_views(
                    view_id, request_id, version, payload_hash,
                    request_revision, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    view_id,
                    request_id,
                    expected_version,
                    expected_payload_hash,
                    request["revision"],
                    created_at,
                ),
            )

    def browser_view_is_current(self, view_id: str) -> bool:
        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM browser_views AS view
                JOIN approval_requests AS request
                  ON request.request_id = view.request_id
                WHERE view.view_id = ? AND view.invalidated_at IS NULL
                  AND view.version = request.current_version
                  AND view.payload_hash = request.current_payload_hash
                  AND view.request_revision = request.revision
                  AND request.state = 'pending_approval'
                """,
                (view_id,),
            ).fetchone()
        return row is not None

    def approve(
        self,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        confirmation: ApprovalConfirmation,
        actor: str,
        now: int,
    ) -> None:
        with self.database.transaction() as connection:
            request = self._request_for_update(connection, request_id)
            self._require_current(request, expected_version, expected_payload_hash)
            if request["state"] != RequestState.PENDING_APPROVAL.value:
                raise InvalidTransition(f"cannot approve a request in state {request['state']}")
            if now >= request["expires_at"]:
                raise RequestExpired(request_id)
            if request["gateway_internal"] and confirmation.path == "mcp":
                raise InvalidConfirmation("gateway-internal policy changes are web-approval-only")

            self._consume_confirmation(
                connection,
                confirmation,
                action="approve",
                request_id=request_id,
                expected_version=expected_version,
                expected_payload_hash=expected_payload_hash,
                prospective_payload_hash=None,
                now=now,
            )

            updated = connection.execute(
                """
                UPDATE approval_requests
                SET state = 'approved', approved_at = ?, revision = revision + 1
                WHERE request_id = ? AND state = 'pending_approval'
                  AND current_version = ? AND current_payload_hash = ?
                """,
                (now, request_id, expected_version, expected_payload_hash),
            ).rowcount
            if updated != 1:
                raise StaleVersion(request_id)
            connection.execute(
                """
                UPDATE approval_challenges SET invalidated_at = ?
                WHERE request_id = ? AND consumed_at IS NULL
                  AND invalidated_at IS NULL
                """,
                (now, request_id),
            )
            connection.execute(
                """
                UPDATE auth_challenges SET invalidated_at = ?
                WHERE request_id = ? AND consumed_at IS NULL
                  AND invalidated_at IS NULL
                """,
                (now, request_id),
            )
            connection.execute(
                """
                UPDATE browser_views SET invalidated_at = ?
                WHERE request_id = ? AND invalidated_at IS NULL
                """,
                (now, request_id),
            )
            self._event(
                connection,
                request_id,
                actor,
                f"approved_via_{confirmation.path}",
                now,
                expected_version,
                expected_payload_hash,
            )
            if confirmation.path == "mcp":
                self._notification(
                    connection,
                    kind=NotificationKind.MCP_APPROVED,
                    request_id=request_id,
                    service=request["downstream_alias"],
                    action=request["tool_name"],
                    now=now,
                    dedupe_key=f"mcp_approved:{request_id}:{expected_version}",
                )
            self._fault("approve:before_commit")

    def _consume_confirmation(
        self,
        connection: Any,
        confirmation: ApprovalConfirmation,
        *,
        action: str,
        request_id: str,
        expected_version: int,
        expected_payload_hash: str,
        prospective_payload_hash: str | None,
        now: int,
    ) -> None:
        if (
            confirmation.user_id is None
            or confirmation.action != action
            or confirmation.bound_request_id != request_id
            or confirmation.bound_version != expected_version
            or confirmation.bound_payload_hash != expected_payload_hash
            or confirmation.prospective_payload_hash != prospective_payload_hash
        ):
            raise InvalidConfirmation("confirmation action binding does not match")
        self._verify_confirmation_capability(confirmation)
        if confirmation.path == "web":
            if confirmation.session_id is None or confirmation.http_method != "POST":
                raise InvalidConfirmation("web confirmation requires a bound POST session")
            session = connection.execute(
                """
                SELECT 1 FROM web_sessions AS session
                JOIN auth_users AS user ON user.user_id = session.user_id
                WHERE session.session_id = ? AND session.user_id = ?
                  AND session.revoked_at IS NULL AND session.created_at <= ?
                  AND session.last_seen_at + ? > ?
                  AND session.absolute_expires_at > ?
                  AND session.auth_generation = user.auth_generation
                """,
                (
                    confirmation.session_id,
                    confirmation.user_id,
                    now,
                    self._web_session_idle_timeout,
                    now,
                    now,
                ),
            ).fetchone()
            if session is None:
                raise InvalidConfirmation("web session is stale or unavailable")
        elif (
            confirmation.path != "mcp"
            or confirmation.session_id is not None
            or confirmation.http_method != "MCP"
            or action != "approve"
        ):
            raise InvalidConfirmation("MCP confirmation context is invalid")

        if confirmation.kind == ConfirmationKind.WEBAUTHN:
            if confirmation.path != "web" or confirmation.challenge_id is None:
                raise InvalidConfirmation("WebAuthn confirmation requires a web challenge")
            self._consume_webauthn_credential(connection, confirmation, now=now)
            consumed = connection.execute(
                """
                UPDATE auth_challenges SET consumed_at = ?
                WHERE challenge_id = ? AND user_id = ? AND action = ?
                  AND request_id = ? AND version = ?
                  AND current_payload_hash = ?
                  AND prospective_payload_hash IS ?
                  AND session_id = ? AND http_method = 'POST'
                  AND created_at <= ? AND expires_at > ?
                  AND consumed_at IS NULL AND invalidated_at IS NULL
                  AND EXISTS (
                      SELECT 1 FROM json_each(offered_credential_ids_json)
                      WHERE value = ?
                  )
                """,
                (
                    now,
                    confirmation.challenge_id,
                    confirmation.user_id,
                    action,
                    request_id,
                    expected_version,
                    expected_payload_hash,
                    prospective_payload_hash,
                    confirmation.session_id,
                    now,
                    now,
                    confirmation.credential_id,
                ),
            ).rowcount
            if consumed != 1:
                raise InvalidConfirmation("challenge is stale, expired, consumed, or misbound")
            if (
                confirmation.attempt_id is not None
                or confirmation.attempt_scope_keys
                or confirmation.rate_limit_key is not None
            ):
                raise InvalidConfirmation("WebAuthn confirmation contains TOTP attempt state")
        elif any(
            value is not None
            for value in (
                confirmation.challenge_id,
                confirmation.expected_counter,
                confirmation.new_counter,
                confirmation.device_type,
                confirmation.expected_backup_eligible,
                confirmation.new_backup_eligible,
                confirmation.previous_backed_up,
                confirmation.new_backed_up,
            )
        ):
            raise InvalidConfirmation("TOTP confirmation contains WebAuthn state")

        if confirmation.kind == ConfirmationKind.TOTP:
            rate_key = totp_rate_limit_key(confirmation.user_id or "")
            if (
                confirmation.credential_id is None
                or confirmation.credential_user_id != confirmation.user_id
                or confirmation.rate_limit_key != rate_key
                or confirmation.attempt_id is None
                or len(confirmation.attempt_scope_keys) != 2
                or confirmation.attempt_scope_keys[0] != rate_key
                or not confirmation.attempt_scope_keys[1].startswith("auth-source:")
            ):
                raise InvalidConfirmation("TOTP proof state is invalid")
            credential = connection.execute(
                """
                UPDATE auth_credentials SET last_used_at = ?
                WHERE credential_id = ? AND user_id = ? AND kind = 'totp'
                  AND disabled_at IS NULL
                RETURNING credential_id
                """,
                (
                    now,
                    confirmation.credential_id,
                    confirmation.user_id,
                ),
            ).fetchone()
            if credential is None:
                raise InvalidConfirmation("TOTP credential is stale or unavailable")

        try:
            connection.execute(
                """
                INSERT INTO auth_proof_consumptions(
                    kind, use_id, purpose, consumed_at
                ) VALUES (?, ?, 'mutation', ?)
                """,
                (confirmation.kind.value, confirmation.use_id, now),
            )
            connection.execute(
                """
                INSERT INTO confirmation_consumptions(
                    kind, use_id, request_id, version, payload_hash,
                    path, consumed_at, action, user_id, session_id,
                    http_method, prospective_payload_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    confirmation.kind.value,
                    confirmation.use_id,
                    request_id,
                    expected_version,
                    expected_payload_hash,
                    confirmation.path,
                    now,
                    action,
                    confirmation.user_id,
                    confirmation.session_id,
                    confirmation.http_method,
                    prospective_payload_hash,
                ),
            )
        except IntegrityError as exc:
            raise ConfirmationReplay("confirmation was already consumed") from exc

        if confirmation.kind == ConfirmationKind.TOTP:
            if confirmation.attempt_id is None:
                raise InvalidConfirmation("TOTP confirmation attempt is unavailable")
            for scope in confirmation.attempt_scope_keys:
                connection.execute(
                    """
                    DELETE FROM auth_attempts
                    WHERE scope_key = ? AND last_attempt_id = ?
                    """,
                    (scope, confirmation.attempt_id),
                )

    def consume_policy_confirmation(
        self,
        connection: Any,
        confirmation: ApprovalConfirmation,
        *,
        action: str,
        request_id: str,
        expected_version: int,
        expected_payload_hash: str,
        now: int,
    ) -> None:
        """Consume one web-only policy proof in the caller's transaction.

        Policy persistence owns a larger atomic boundary than an ordinary
        request transition.  Keeping proof verification here preserves the
        exact credential/session/replay checks without opening a nested
        transaction.
        """

        if action not in {"promote_approval", "promote_passthrough"}:
            raise InvalidConfirmation("policy confirmation action is invalid")
        if confirmation.path != "web":
            raise InvalidConfirmation("policy changes require web confirmation")
        self._consume_confirmation(
            connection,
            confirmation,
            action=action,
            request_id=request_id,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            prospective_payload_hash=None,
            now=now,
        )

    def _verify_confirmation_capability(
        self,
        confirmation: ApprovalConfirmation,
    ) -> None:
        if self._capabilities is None:
            raise InvalidConfirmation("proof capability verification is unavailable")
        try:
            if confirmation.action is None:
                raise ValueError
            binding = ActionBinding(
                confirmation.action,
                confirmation.bound_request_id,
                confirmation.bound_version,
                confirmation.bound_payload_hash,
                confirmation.prospective_payload_hash,
            )
            if confirmation.kind == ConfirmationKind.TOTP:
                if (
                    confirmation.credential_id is None
                    or confirmation.credential_user_id != confirmation.user_id
                    or confirmation.rate_limit_key is None
                    or confirmation.attempt_id is None
                    or not confirmation.attempt_scope_keys
                ):
                    raise ValueError
                claims = totp_proof_claims(
                    credential_id=confirmation.credential_id,
                    credential_user_id=confirmation.credential_user_id or "",
                    user_id=confirmation.user_id or "",
                    use_id=confirmation.use_id,
                    binding=binding,
                    path=confirmation.path,
                    session_id=confirmation.session_id,
                    http_method=confirmation.http_method or "",
                    rate_limit_key=confirmation.rate_limit_key,
                    attempt_id=confirmation.attempt_id,
                    attempt_scope_keys=confirmation.attempt_scope_keys,
                )
                domain = TOTP_PROOF_DOMAIN
            else:
                credential_id = confirmation.credential_id
                challenge_id = confirmation.challenge_id
                expected_counter = confirmation.expected_counter
                new_counter = confirmation.new_counter
                device_type = confirmation.device_type
                expected_backup_eligible = confirmation.expected_backup_eligible
                new_backup_eligible = confirmation.new_backup_eligible
                previous_backed_up = confirmation.previous_backed_up
                new_backed_up = confirmation.new_backed_up
                if (
                    credential_id is None
                    or confirmation.credential_user_id is None
                    or challenge_id is None
                    or expected_counter is None
                    or new_counter is None
                    or device_type is None
                    or expected_backup_eligible is None
                    or new_backup_eligible is None
                    or previous_backed_up is None
                    or new_backed_up is None
                ):
                    raise ValueError
                claims = webauthn_proof_claims(
                    credential_id=credential_id,
                    credential_user_id=confirmation.credential_user_id or "",
                    user_id=confirmation.user_id or "",
                    challenge_id=challenge_id,
                    use_id=confirmation.use_id,
                    binding=binding,
                    path=confirmation.path,
                    session_id=confirmation.session_id or "",
                    http_method=confirmation.http_method or "",
                    expected_counter=expected_counter,
                    new_counter=new_counter,
                    device_type=device_type,
                    expected_backup_eligible=expected_backup_eligible,
                    new_backup_eligible=new_backup_eligible,
                    previous_backed_up=previous_backed_up,
                    new_backed_up=new_backed_up,
                )
                domain = WEBAUTHN_PROOF_DOMAIN
        except (AssertionError, TypeError, ValueError):
            raise InvalidConfirmation("proof capability claims are invalid") from None
        if not self._capabilities.verify(
            confirmation.capability,
            domain=domain,
            claims=claims,
        ):
            raise InvalidConfirmation("proof capability is invalid")

    @staticmethod
    def _consume_webauthn_credential(
        connection: Any,
        confirmation: ApprovalConfirmation,
        *,
        now: int,
    ) -> None:
        credential_id = confirmation.credential_id
        credential_user_id = confirmation.credential_user_id
        expected_counter = confirmation.expected_counter
        new_counter = confirmation.new_counter
        expected_eligible = confirmation.expected_backup_eligible
        new_eligible = confirmation.new_backup_eligible
        previous_backed_up = confirmation.previous_backed_up
        new_backed_up = confirmation.new_backed_up
        if (
            credential_id is None
            or credential_user_id is None
            or expected_counter is None
            or new_counter is None
            or expected_eligible is None
            or new_eligible is None
            or previous_backed_up is None
            or new_backed_up is None
        ):
            raise InvalidConfirmation("WebAuthn confirmation is missing credential state")
        if credential_user_id != confirmation.user_id:
            raise InvalidConfirmation("WebAuthn credential ownership does not match")
        if expected_counter < 0 or not (
            expected_counter == new_counter == 0 or new_counter > expected_counter
        ):
            raise InvalidConfirmation("WebAuthn signature counter transition is invalid")
        if (
            expected_eligible != new_eligible
            or confirmation.device_type != ("multi_device" if new_eligible else "single_device")
            or (not new_eligible and new_backed_up)
            or (previous_backed_up and not new_backed_up)
        ):
            raise InvalidConfirmation("WebAuthn backup state transition is invalid")

        updated = connection.execute(
            """
            UPDATE auth_credentials
            SET sign_count = ?, backup_eligible = ?, backup_state = ?,
                last_used_at = ?
            WHERE credential_id = ? AND user_id = ? AND kind = 'webauthn'
              AND disabled_at IS NULL AND sign_count = ?
              AND backup_eligible = ? AND backup_state = ?
            """,
            (
                new_counter,
                int(new_eligible),
                int(new_backed_up),
                now,
                credential_id,
                credential_user_id,
                expected_counter,
                int(expected_eligible),
                int(previous_backed_up),
            ),
        ).rowcount
        if updated != 1:
            raise InvalidConfirmation("WebAuthn credential state is stale or unavailable")

    def deny(
        self,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        confirmation: ApprovalConfirmation,
        actor: str,
        now: int,
    ) -> None:
        self._finish_pending(
            request_id,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            state=RequestState.DENIED,
            actor=actor,
            now=now,
            confirmation=confirmation,
            confirmation_action="deny",
        )

    def cancel(
        self,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        confirmation: ApprovalConfirmation,
        actor: str,
        now: int,
    ) -> None:
        self._finish_pending(
            request_id,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            state=RequestState.CANCELLED,
            actor=actor,
            now=now,
            confirmation=confirmation,
            confirmation_action="human_cancel",
        )

    def cancel_by_caller(
        self,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        actor: str,
        now: int,
        origin_namespace: str,
    ) -> None:
        if not origin_namespace:
            raise ValueError("caller cancellation requires an origin namespace")
        self._finish_pending(
            request_id,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            state=RequestState.CANCELLED,
            actor=actor,
            now=now,
            origin_namespace=origin_namespace,
        )

    def expire(
        self,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        actor: str,
        now: int,
    ) -> None:
        self._finish_pending(
            request_id,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            state=RequestState.EXPIRED,
            actor=actor,
            now=now,
            require_expired=True,
        )

    def sweep_expired(
        self,
        *,
        now: int,
        limit: int = 250,
        actor: str = "system:expiry-sweeper",
    ) -> int:
        """Expire at most ``limit`` pending requests in one durable transaction."""

        if (
            not isinstance(now, int)
            or isinstance(now, bool)
            or now < 0
            or not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit <= 0
            or limit > 1_000
            or not actor
            or len(actor.encode("utf-8")) > 512
        ):
            raise ValueError("expiry sweep arguments are invalid")
        with self.database.transaction() as connection:
            expired = self._expire_pending_batch(
                connection,
                now=now,
                limit=limit,
                actor=actor,
            )
            self._fault("expiry_sweep:before_commit")
        return expired

    def claim_execution(
        self,
        request_id: str,
        *,
        worker_id: str,
        now: int,
        lease_seconds: int,
        downstream_idempotency_key: str | None = None,
    ) -> ExecutionLease:
        if not worker_id or lease_seconds <= 0:
            raise ValueError("worker ID and a positive lease are required")
        lease_expires_at = now + lease_seconds
        token = self._token_factory()

        with self.database.transaction() as connection:
            request = self._request_for_update(connection, request_id)
            if request["state"] == RequestState.APPROVED.value:
                attempt_id = str(uuid.uuid4())
                updated = connection.execute(
                    """
                    UPDATE approval_requests
                    SET state = 'executing', execution_started_at = ?,
                        revision = revision + 1
                    WHERE request_id = ? AND state = 'approved'
                    """,
                    (now, request_id),
                ).rowcount
                if updated != 1:
                    raise InvalidTransition("approval was already claimed")
                connection.execute(
                    """
                    INSERT INTO execution_attempts(
                        attempt_id, request_id, version, payload_hash,
                        fencing_token, worker_id, worker_generation, phase,
                        claimed_at, lease_expires_at,
                        downstream_idempotency_key
                    ) VALUES (?, ?, ?, ?, ?, ?, 1, 'preparing', ?, ?, ?)
                    """,
                    (
                        attempt_id,
                        request_id,
                        request["current_version"],
                        request["current_payload_hash"],
                        token,
                        worker_id,
                        now,
                        lease_expires_at,
                        downstream_idempotency_key,
                    ),
                )
                generation = 1
                phase = ExecutionPhase.PREPARING
                action = "execution_claimed"
            elif request["state"] == RequestState.EXECUTING.value:
                attempt = connection.execute(
                    """
                    SELECT * FROM execution_attempts
                    WHERE request_id = ? AND version = ?
                    """,
                    (request_id, request["current_version"]),
                ).fetchone()
                if attempt is None:
                    raise InvalidTransition("executing request has no durable attempt")
                if attempt["phase"] not in {
                    ExecutionPhase.PREPARING.value,
                    ExecutionPhase.REDISPATCH_PREPARING.value,
                }:
                    raise InvalidTransition(
                        "dispatch has started and cannot be reclaimed for blind retry"
                    )
                if attempt["lease_expires_at"] is None or attempt["lease_expires_at"] > now:
                    raise InvalidTransition("the current execution lease is still active")
                generation = int(attempt["worker_generation"]) + 1
                phase = ExecutionPhase(attempt["phase"])
                updated = connection.execute(
                    """
                    UPDATE execution_attempts
                    SET fencing_token = ?, worker_id = ?, worker_generation = ?,
                        claimed_at = ?, lease_expires_at = ?
                    WHERE attempt_id = ? AND fencing_token = ?
                      AND worker_generation = ? AND lease_expires_at <= ?
                      AND phase = ?
                    """,
                    (
                        token,
                        worker_id,
                        generation,
                        now,
                        lease_expires_at,
                        attempt["attempt_id"],
                        attempt["fencing_token"],
                        attempt["worker_generation"],
                        now,
                        attempt["phase"],
                    ),
                ).rowcount
                if updated != 1:
                    raise FenceRejected("the expired lease was reclaimed concurrently")
                attempt_id = attempt["attempt_id"]
                downstream_idempotency_key = attempt["downstream_idempotency_key"]
                action = "execution_reclaimed"
            else:
                raise InvalidTransition(f"request in state {request['state']} cannot execute")

            self._event(
                connection,
                request_id,
                f"gateway:{worker_id}",
                action,
                now,
                request["current_version"],
                request["current_payload_hash"],
                {"worker_generation": generation, "phase": phase.value},
            )
            self._fault("execution_claim:before_commit")

        return ExecutionLease(
            request_id=request_id,
            version=request["current_version"],
            payload_hash=request["current_payload_hash"],
            attempt_id=attempt_id,
            fencing_token=token,
            worker_generation=generation,
            lease_expires_at=lease_expires_at,
            phase=phase,
            downstream_idempotency_key=downstream_idempotency_key,
        )

    def heartbeat(
        self,
        lease: ExecutionLease,
        *,
        now: int,
        lease_seconds: int,
    ) -> ExecutionLease:
        if lease_seconds <= 0:
            raise ValueError("lease duration must be positive")
        new_expiry = now + lease_seconds
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE execution_attempts
                SET lease_expires_at = ?
                WHERE attempt_id = ? AND request_id = ? AND version = ?
                  AND fencing_token = ? AND worker_generation = ?
                  AND phase IN ('preparing', 'redispatch_preparing')
                  AND lease_expires_at > ?
                """,
                (
                    new_expiry,
                    lease.attempt_id,
                    lease.request_id,
                    lease.version,
                    lease.fencing_token,
                    lease.worker_generation,
                    now,
                ),
            ).rowcount
            if updated != 1:
                raise FenceRejected("heartbeat lost its execution fence or lease")
        return ExecutionLease(
            request_id=lease.request_id,
            version=lease.version,
            payload_hash=lease.payload_hash,
            attempt_id=lease.attempt_id,
            fencing_token=lease.fencing_token,
            worker_generation=lease.worker_generation,
            lease_expires_at=new_expiry,
            phase=lease.phase,
            downstream_idempotency_key=lease.downstream_idempotency_key,
        )

    def mark_dispatch_started(self, lease: ExecutionLease, *, now: int) -> None:
        with self.database.transaction() as connection:
            attempt = self._attempt_for_fence(connection, lease, now=now)
            if attempt["phase"] == ExecutionPhase.PREPARING.value:
                next_phase = ExecutionPhase.DISPATCH_STARTED
                update_query = """
                    UPDATE execution_attempts
                    SET phase = ?, dispatch_started_at = ?
                    WHERE attempt_id = ? AND fencing_token = ?
                      AND worker_generation = ? AND phase = ?
                      AND lease_expires_at > ?
                """
            elif attempt["phase"] == ExecutionPhase.REDISPATCH_PREPARING.value:
                next_phase = ExecutionPhase.REDISPATCH_STARTED
                update_query = """
                    UPDATE execution_attempts
                    SET phase = ?, redispatch_started_at = ?
                    WHERE attempt_id = ? AND fencing_token = ?
                      AND worker_generation = ? AND phase = ?
                      AND lease_expires_at > ?
                """
            else:
                raise FenceRejected("attempt is not at a dispatch boundary")

            updated = connection.execute(
                update_query,
                (
                    next_phase.value,
                    now,
                    lease.attempt_id,
                    lease.fencing_token,
                    lease.worker_generation,
                    attempt["phase"],
                    now,
                ),
            ).rowcount
            if updated != 1:
                raise FenceRejected("dispatch boundary lost its fence")
            self._event(
                connection,
                lease.request_id,
                f"gateway:{attempt['worker_id']}",
                next_phase.value,
                now,
                lease.version,
                lease.payload_hash,
                {"worker_generation": lease.worker_generation},
            )
            self._fault("dispatch_started:before_commit")

    def record_pre_dispatch_failure(
        self,
        lease: ExecutionLease,
        *,
        now: int,
        failure_reason: str,
    ) -> None:
        """Terminalize a deterministic failure before any downstream socket write."""

        if (
            not failure_reason
            or len(failure_reason) > 128
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789_.-"
                for character in failure_reason
            )
        ):
            raise ValueError("pre-dispatch failure requires a bounded safe reason code")
        with self.database.transaction() as connection:
            attempt = self._attempt_for_fence(connection, lease, now=now)
            if attempt["phase"] not in {
                ExecutionPhase.PREPARING.value,
                ExecutionPhase.REDISPATCH_PREPARING.value,
            }:
                raise FenceRejected("pre-dispatch failure requires a preparing lease")
            updated_request = connection.execute(
                """
                UPDATE approval_requests
                SET state = 'failed', completed_at = ?, failure_reason = ?,
                    manual_retry_allowed = 1, duplicate_warning_required = 0,
                    revision = revision + 1
                WHERE request_id = ? AND state = 'executing'
                  AND current_version = ? AND current_payload_hash = ?
                """,
                (
                    now,
                    failure_reason,
                    lease.request_id,
                    lease.version,
                    lease.payload_hash,
                ),
            ).rowcount
            if updated_request != 1:
                raise FenceRejected("request is no longer executing the fenced payload")
            updated_attempt = connection.execute(
                """
                UPDATE execution_attempts
                SET phase = 'failed', lease_expires_at = NULL,
                    completed_at = ?, outcome_classification = 'definite_failure',
                    failure_reason = ?
                WHERE attempt_id = ? AND fencing_token = ?
                  AND worker_generation = ? AND phase = ?
                """,
                (
                    now,
                    failure_reason,
                    lease.attempt_id,
                    lease.fencing_token,
                    lease.worker_generation,
                    attempt["phase"],
                ),
            ).rowcount
            if updated_attempt != 1:
                raise FenceRejected("pre-dispatch failure lost its execution fence")
            self._event(
                connection,
                lease.request_id,
                f"gateway:{attempt['worker_id']}",
                "execution_failed_before_dispatch",
                now,
                lease.version,
                lease.payload_hash,
                {"classification": "definite_failure", "reason": failure_reason},
            )
            self._fault("pre_dispatch_failure:before_commit")

    def record_outcome(
        self,
        lease: ExecutionLease,
        *,
        classification: OutcomeClassification,
        now: int,
        safe_outcome: Mapping[str, Any] | None = None,
        failure_reason: str | None = None,
        reconciliation_next_at: int | None = None,
        result_aliases: tuple[ResultAlias, ...] = (),
    ) -> None:
        safe_json = self._safe_outcome_json(safe_outcome)
        public_safe_json = self._safe_outcome_json(
            public_safe_metadata(safe_outcome) if safe_outcome is not None else None
        )
        with self.database.transaction() as connection:
            attempt = self._attempt_for_fence(connection, lease)
            if attempt["phase"] not in {
                ExecutionPhase.DISPATCH_STARTED.value,
                ExecutionPhase.REDISPATCH_STARTED.value,
            }:
                raise FenceRejected("outcome requires a committed dispatch boundary")

            if classification == OutcomeClassification.SUCCEEDED:
                request_state = RequestState.SUCCEEDED
                attempt_phase = ExecutionPhase.SUCCEEDED
                manual_retry = 0
                duplicate_warning = 0
                notify = 0
            elif classification == OutcomeClassification.DEFINITE_FAILURE:
                if not failure_reason:
                    raise ValueError("definite failures require a safe reason code")
                request_state = RequestState.FAILED
                attempt_phase = ExecutionPhase.FAILED
                manual_retry = 1
                duplicate_warning = 0
                notify = 0
            else:
                if reconciliation_next_at is None or reconciliation_next_at < now:
                    raise ValueError("unknown outcomes require a reconciliation time")
                request_state = RequestState.OUTCOME_UNKNOWN
                attempt_phase = ExecutionPhase.OUTCOME_UNKNOWN
                manual_retry = 1
                duplicate_warning = 1
                notify = 1

            connection.execute(
                """
                UPDATE approval_requests
                SET state = ?, completed_at = ?, safe_outcome_json = ?,
                    failure_reason = ?, manual_retry_allowed = ?,
                    duplicate_warning_required = ?, revision = revision + 1
                WHERE request_id = ? AND state = 'executing'
                  AND current_version = ? AND current_payload_hash = ?
                """,
                (
                    request_state.value,
                    now if request_state != RequestState.OUTCOME_UNKNOWN else None,
                    public_safe_json,
                    failure_reason,
                    manual_retry,
                    duplicate_warning,
                    lease.request_id,
                    lease.version,
                    lease.payload_hash,
                ),
            )
            if request_state == RequestState.SUCCEEDED:
                request = self._request_for_update(connection, lease.request_id)
                self._insert_result_aliases(
                    connection,
                    request=request,
                    aliases=result_aliases,
                    created_at=now,
                )
            elif result_aliases:
                raise ValueError("result aliases require a confirmed successful outcome")
            connection.execute(
                """
                UPDATE execution_attempts
                SET phase = ?, lease_expires_at = NULL,
                    reconciliation_next_at = ?,
                    reconciliation_notification_required = ?,
                    completed_at = ?, safe_completion_json = ?,
                    outcome_classification = ?, failure_reason = ?
                WHERE attempt_id = ? AND fencing_token = ?
                  AND worker_generation = ?
                """,
                (
                    attempt_phase.value,
                    reconciliation_next_at,
                    notify,
                    now if request_state != RequestState.OUTCOME_UNKNOWN else None,
                    safe_json,
                    classification.value,
                    failure_reason,
                    lease.attempt_id,
                    lease.fencing_token,
                    lease.worker_generation,
                ),
            )
            self._event(
                connection,
                lease.request_id,
                f"gateway:{attempt['worker_id']}",
                f"execution_{request_state.value}",
                now,
                lease.version,
                lease.payload_hash,
                {"classification": classification.value},
            )
            if request_state == RequestState.OUTCOME_UNKNOWN:
                request = self._request_for_update(connection, lease.request_id)
                self._notification(
                    connection,
                    kind=NotificationKind.OUTCOME_UNKNOWN_ENTERED,
                    request_id=lease.request_id,
                    service=request["downstream_alias"],
                    action=request["tool_name"],
                    now=now,
                    dedupe_key=(
                        f"outcome_unknown_entered:{lease.attempt_id}:{lease.worker_generation}"
                    ),
                )
            self._fault("outcome:before_commit")

    def reconcile(
        self,
        request_id: str,
        *,
        expected_reconciliation_count: int,
        decision: ReconciliationDecision,
        worker_id: str,
        now: int,
        next_check_at: int | None = None,
        exhausted: bool = False,
        lease_seconds: int = 30,
        safe_outcome: Mapping[str, Any] | None = None,
        result_aliases: tuple[ResultAlias, ...] = (),
    ) -> ReconciliationResult:
        safe_json = self._safe_outcome_json(safe_outcome)
        public_safe_json = self._safe_outcome_json(
            public_safe_metadata(safe_outcome) if safe_outcome is not None else None
        )
        with self.database.transaction() as connection:
            request = self._request_for_update(connection, request_id)
            if request["state"] != RequestState.OUTCOME_UNKNOWN.value:
                raise ReconciliationRejected(f"request is not outcome_unknown: {request['state']}")
            attempt = connection.execute(
                """
                SELECT * FROM execution_attempts
                WHERE request_id = ? AND version = ? AND phase = 'outcome_unknown'
                """,
                (request_id, request["current_version"]),
            ).fetchone()
            if attempt is None:
                raise ReconciliationRejected("unknown request has no reconcilable attempt")
            if attempt["reconciliation_attempt_count"] != expected_reconciliation_count:
                raise ReconciliationRejected("stale reconciliation decision")
            if (
                attempt["reconciliation_next_at"] is not None
                and attempt["reconciliation_next_at"] > now
            ):
                raise ReconciliationRejected("reconciliation is not due")

            count = expected_reconciliation_count + 1
            lease: ExecutionLease | None = None
            if decision == ReconciliationDecision.CONFIRMED_EFFECT:
                connection.execute(
                    """
                    UPDATE approval_requests
                    SET state = 'succeeded', completed_at = ?,
                        safe_outcome_json = COALESCE(?, safe_outcome_json),
                        failure_reason = NULL, manual_retry_allowed = 0,
                        duplicate_warning_required = 0, revision = revision + 1
                    WHERE request_id = ? AND state = 'outcome_unknown'
                    """,
                    (now, public_safe_json, request_id),
                )
                connection.execute(
                    """
                    UPDATE execution_attempts
                    SET phase = 'succeeded', reconciliation_attempt_count = ?,
                        reconciliation_next_at = NULL,
                        reconciliation_resolution = 'confirmed_effect',
                        reconciliation_notification_required = 1,
                        completed_at = ?, safe_completion_json = COALESCE(?, safe_completion_json),
                        outcome_classification = 'succeeded'
                    WHERE attempt_id = ?
                    """,
                    (count, now, safe_json, attempt["attempt_id"]),
                )
                self._insert_result_aliases(
                    connection,
                    request=request,
                    aliases=result_aliases,
                    created_at=now,
                )
                action = ReconciliationAction.SUCCEEDED
            elif decision == ReconciliationDecision.CONFIRMED_NO_EFFECT:
                if attempt["downstream_idempotency_key"] and not attempt["redispatch_used"]:
                    if lease_seconds <= 0:
                        raise ValueError("redispatch lease must be positive")
                    token = self._token_factory()
                    generation = int(attempt["worker_generation"]) + 1
                    lease_expiry = now + lease_seconds
                    connection.execute(
                        """
                        UPDATE approval_requests
                        SET state = 'executing', completed_at = NULL,
                            failure_reason = NULL, manual_retry_allowed = 0,
                            duplicate_warning_required = 0, revision = revision + 1
                        WHERE request_id = ? AND state = 'outcome_unknown'
                        """,
                        (request_id,),
                    )
                    updated = connection.execute(
                        """
                        UPDATE execution_attempts
                        SET phase = 'redispatch_preparing', fencing_token = ?,
                            worker_id = ?, worker_generation = ?, claimed_at = ?,
                            lease_expires_at = ?, reconciliation_attempt_count = ?,
                            reconciliation_next_at = NULL,
                            reconciliation_resolution = 'confirmed_no_effect',
                            reconciliation_notification_required = 0,
                            redispatch_used = 1
                        WHERE attempt_id = ? AND phase = 'outcome_unknown'
                          AND redispatch_used = 0
                        """,
                        (
                            token,
                            worker_id,
                            generation,
                            now,
                            lease_expiry,
                            count,
                            attempt["attempt_id"],
                        ),
                    ).rowcount
                    if updated != 1:
                        raise ReconciliationRejected("redispatch was already consumed")
                    lease = ExecutionLease(
                        request_id=request_id,
                        version=request["current_version"],
                        payload_hash=request["current_payload_hash"],
                        attempt_id=attempt["attempt_id"],
                        fencing_token=token,
                        worker_generation=generation,
                        lease_expires_at=lease_expiry,
                        phase=ExecutionPhase.REDISPATCH_PREPARING,
                        downstream_idempotency_key=attempt["downstream_idempotency_key"],
                    )
                    action = ReconciliationAction.REDISPATCH
                else:
                    reason = (
                        "reconciled_no_effect_after_redispatch"
                        if attempt["redispatch_used"]
                        else "reconciled_no_effect"
                    )
                    connection.execute(
                        """
                        UPDATE approval_requests
                        SET state = 'failed', completed_at = ?, failure_reason = ?,
                            manual_retry_allowed = 1,
                            duplicate_warning_required = 0,
                            revision = revision + 1
                        WHERE request_id = ? AND state = 'outcome_unknown'
                        """,
                        (now, reason, request_id),
                    )
                    connection.execute(
                        """
                        UPDATE execution_attempts
                        SET phase = 'failed', reconciliation_attempt_count = ?,
                            reconciliation_next_at = NULL,
                            reconciliation_resolution = 'confirmed_no_effect',
                            reconciliation_notification_required = 1,
                            completed_at = ?, outcome_classification = 'definite_failure',
                            failure_reason = ?
                        WHERE attempt_id = ?
                        """,
                        (count, now, reason, attempt["attempt_id"]),
                    )
                    action = ReconciliationAction.FAILED_NO_EFFECT
            else:
                if result_aliases:
                    raise ValueError("result aliases require a confirmed external effect")
                if exhausted:
                    connection.execute(
                        """
                        UPDATE execution_attempts
                        SET reconciliation_attempt_count = ?,
                            reconciliation_next_at = NULL,
                            reconciliation_resolution = 'exhausted',
                            reconciliation_exhausted_at = ?,
                            reconciliation_notification_required = 1
                        WHERE attempt_id = ?
                        """,
                        (count, now, attempt["attempt_id"]),
                    )
                    action = ReconciliationAction.EXHAUSTED
                else:
                    if next_check_at is None or next_check_at <= now:
                        raise ValueError("inconclusive reconciliation requires a future check")
                    connection.execute(
                        """
                        UPDATE execution_attempts
                        SET reconciliation_attempt_count = ?,
                            reconciliation_next_at = ?,
                            reconciliation_resolution = 'inconclusive',
                            reconciliation_notification_required = 0
                        WHERE attempt_id = ?
                        """,
                        (count, next_check_at, attempt["attempt_id"]),
                    )
                    action = ReconciliationAction.RESCHEDULED

            self._event(
                connection,
                request_id,
                f"gateway:{worker_id}",
                f"reconciliation_{action.value}",
                now,
                request["current_version"],
                request["current_payload_hash"],
                {"decision": decision.value, "attempt": count},
            )
            if decision in {
                ReconciliationDecision.CONFIRMED_EFFECT,
                ReconciliationDecision.CONFIRMED_NO_EFFECT,
            }:
                self._notification(
                    connection,
                    kind=NotificationKind.OUTCOME_UNKNOWN_RESOLVED,
                    request_id=request_id,
                    service=request["downstream_alias"],
                    action=request["tool_name"],
                    now=now,
                    dedupe_key=(f"outcome_unknown_resolved:{attempt['attempt_id']}:{count}"),
                )
            elif action == ReconciliationAction.EXHAUSTED:
                self._notification(
                    connection,
                    kind=NotificationKind.OUTCOME_UNKNOWN_EXHAUSTED,
                    request_id=request_id,
                    service=request["downstream_alias"],
                    action=request["tool_name"],
                    now=now,
                    dedupe_key=f"outcome_unknown_exhausted:{attempt['attempt_id']}",
                )
            self._fault("reconciliation:before_commit")

        return ReconciliationResult(action=action, reconciliation_count=count, lease=lease)

    def recover_startup(self, *, now: int) -> RecoverySummary:
        active: list[str] = []
        reclaimable: list[str] = []
        routed: list[str] = []
        with self.database.transaction() as connection:
            attempts = connection.execute(
                """
                SELECT attempt.*, request.current_version,
                       request.current_payload_hash, request.state,
                       request.downstream_alias, request.tool_name
                FROM execution_attempts AS attempt
                JOIN approval_requests AS request
                  ON request.request_id = attempt.request_id
                WHERE request.state = 'executing'
                  AND attempt.phase IN (
                      'preparing', 'redispatch_preparing',
                      'dispatch_started', 'redispatch_started'
                  )
                ORDER BY attempt.request_id
                """
            ).fetchall()
            for attempt in attempts:
                if attempt["lease_expires_at"] is not None and attempt["lease_expires_at"] > now:
                    active.append(attempt["request_id"])
                    continue
                if attempt["phase"] in {
                    ExecutionPhase.PREPARING.value,
                    ExecutionPhase.REDISPATCH_PREPARING.value,
                }:
                    reclaimable.append(attempt["request_id"])
                    continue

                connection.execute(
                    """
                    UPDATE approval_requests
                    SET state = 'outcome_unknown', completed_at = NULL,
                        manual_retry_allowed = 1,
                        duplicate_warning_required = 1,
                        revision = revision + 1
                    WHERE request_id = ? AND state = 'executing'
                    """,
                    (attempt["request_id"],),
                )
                connection.execute(
                    """
                    UPDATE execution_attempts
                    SET phase = 'outcome_unknown', lease_expires_at = NULL,
                        reconciliation_next_at = ?,
                        reconciliation_resolution = 'startup_abandoned_after_dispatch',
                        reconciliation_notification_required = 1,
                        outcome_classification = 'outcome_unknown'
                    WHERE attempt_id = ? AND phase = ?
                    """,
                    (now, attempt["attempt_id"], attempt["phase"]),
                )
                self._event(
                    connection,
                    attempt["request_id"],
                    "gateway:startup_recovery",
                    "abandoned_dispatch_outcome_unknown",
                    now,
                    attempt["current_version"],
                    attempt["current_payload_hash"],
                )
                self._notification(
                    connection,
                    kind=NotificationKind.OUTCOME_UNKNOWN_ENTERED,
                    request_id=attempt["request_id"],
                    service=attempt["downstream_alias"],
                    action=attempt["tool_name"],
                    now=now,
                    dedupe_key=(
                        f"outcome_unknown_entered:{attempt['attempt_id']}:"
                        f"{attempt['worker_generation']}"
                    ),
                )
                routed.append(attempt["request_id"])
            self._fault("startup_recovery:before_commit")
        return RecoverySummary(
            active=tuple(active),
            reclaimable=tuple(reclaimable),
            routed_to_reconciliation=tuple(routed),
        )

    def add_attachment(
        self,
        request_id: str,
        *,
        version: int,
        payload_hash: str,
        attachment_id: str,
        filename: str,
        mime_type: str,
        size_bytes: int,
        sha256: str,
        storage_path: str,
        created_at: int,
    ) -> None:
        self._validate_hash(sha256)
        with self.database.transaction() as connection:
            request = self._request_for_update(connection, request_id)
            self._require_current(request, version, payload_hash)
            if request["state"] != RequestState.PENDING_APPROVAL.value:
                raise InvalidTransition("attachments can only be staged while pending")
            catalog = connection.execute(
                """
                SELECT adapter, filename, declared_mime, size_bytes, sha256,
                       storage_path, encryption_key_ref, consumed_request_id,
                       purged_at, key_destroyed_at
                FROM staged_objects WHERE attachment_id = ?
                """,
                (attachment_id,),
            ).fetchone()
            if (
                catalog is None
                or catalog["adapter"] != request["downstream_alias"]
                or catalog["filename"] != filename
                or catalog["declared_mime"] != mime_type
                or catalog["size_bytes"] != size_bytes
                or catalog["sha256"] != sha256
                or catalog["storage_path"] != storage_path
                or not isinstance(catalog["encryption_key_ref"], str)
                or not catalog["encryption_key_ref"]
                or catalog["purged_at"] is not None
                or catalog["key_destroyed_at"] is not None
                or catalog["consumed_request_id"] not in {None, request_id}
            ):
                raise InvalidTransition(
                    "a staged attachment is unavailable, changed, or already consumed"
                )
            connection.execute(
                """
                INSERT INTO attachments(
                    attachment_id, request_id, version, payload_hash, filename, mime_type,
                    size_bytes, sha256, storage_path, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attachment_id,
                    request_id,
                    version,
                    payload_hash,
                    filename,
                    mime_type,
                    size_bytes,
                    sha256,
                    storage_path,
                    created_at,
                ),
            )

    def add_result_alias(
        self,
        request_id: str,
        *,
        downstream_alias: str,
        tool_name: str,
        account_namespace: str,
        identifier_kind: str,
        downstream_identifier: str,
        created_at: int,
    ) -> None:
        with self.database.transaction() as connection:
            request = self._request_for_update(connection, request_id)
            if request["state"] != RequestState.SUCCEEDED.value:
                raise InvalidTransition("result aliases require confirmed success")
            if request["downstream_alias"] != downstream_alias or request["tool_name"] != tool_name:
                raise InvalidTransition("result alias scope does not match the request")
            connection.execute(
                """
                INSERT INTO result_aliases(
                    request_id, downstream_alias, tool_name, account_namespace,
                    identifier_kind, downstream_identifier, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    downstream_alias,
                    tool_name,
                    account_namespace,
                    identifier_kind,
                    downstream_identifier,
                    created_at,
                ),
            )

    def _finish_pending(
        self,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        state: RequestState,
        actor: str,
        now: int,
        origin_namespace: str | None = None,
        require_expired: bool = False,
        confirmation: ApprovalConfirmation | None = None,
        confirmation_action: str | None = None,
    ) -> None:
        if state not in {
            RequestState.DENIED,
            RequestState.EXPIRED,
            RequestState.CANCELLED,
        }:
            raise ValueError("pending requests may only be denied, expired, or cancelled")
        with self.database.transaction() as connection:
            request = self._request_for_update(connection, request_id)
            self._require_current(request, expected_version, expected_payload_hash)
            if request["state"] != RequestState.PENDING_APPROVAL.value:
                raise InvalidTransition(
                    f"cannot {state.value} a request in state {request['state']}"
                )
            if origin_namespace is not None and not hmac.compare_digest(
                request["origin_namespace"], origin_namespace
            ):
                raise RequestNotFound(request_id)
            if require_expired and now < request["expires_at"]:
                raise InvalidTransition("request has not reached its expiry")
            if confirmation is not None:
                if confirmation_action is None:
                    raise ValueError("confirmed mutations require an action")
                self._consume_confirmation(
                    connection,
                    confirmation,
                    action=confirmation_action,
                    request_id=request_id,
                    expected_version=expected_version,
                    expected_payload_hash=expected_payload_hash,
                    prospective_payload_hash=None,
                    now=now,
                )
            elif (
                state in {RequestState.DENIED, RequestState.CANCELLED} and origin_namespace is None
            ):
                raise InvalidConfirmation("human deny and cancel require confirmation")
            updated = connection.execute(
                """
                UPDATE approval_requests
                SET state = ?, completed_at = ?, revision = revision + 1
                WHERE request_id = ? AND state = 'pending_approval'
                  AND current_version = ? AND current_payload_hash = ?
                """,
                (
                    state.value,
                    now,
                    request_id,
                    expected_version,
                    expected_payload_hash,
                ),
            ).rowcount
            if updated != 1:
                raise StaleVersion(request_id)
            connection.execute(
                """
                UPDATE approval_challenges SET invalidated_at = ?
                WHERE request_id = ? AND consumed_at IS NULL
                  AND invalidated_at IS NULL
                """,
                (now, request_id),
            )
            connection.execute(
                """
                UPDATE auth_challenges SET invalidated_at = ?
                WHERE request_id = ? AND consumed_at IS NULL
                  AND invalidated_at IS NULL
                """,
                (now, request_id),
            )
            connection.execute(
                """
                UPDATE browser_views SET invalidated_at = ?
                WHERE request_id = ? AND invalidated_at IS NULL
                """,
                (now, request_id),
            )
            self._event(
                connection,
                request_id,
                actor,
                state.value,
                now,
                expected_version,
                expected_payload_hash,
            )
            self._fault(f"{state.value}:before_commit")

    def _attempt_for_fence(
        self,
        connection: Any,
        lease: ExecutionLease,
        *,
        now: int | None = None,
    ) -> Any:
        attempt = connection.execute(
            """
            SELECT * FROM execution_attempts
            WHERE attempt_id = ? AND request_id = ? AND version = ?
            """,
            (lease.attempt_id, lease.request_id, lease.version),
        ).fetchone()
        if attempt is None:
            raise FenceRejected("execution attempt no longer exists")
        if not hmac.compare_digest(attempt["fencing_token"], lease.fencing_token):
            raise FenceRejected("fencing token is stale")
        if attempt["worker_generation"] != lease.worker_generation:
            raise FenceRejected("worker generation is stale")
        if not hmac.compare_digest(attempt["payload_hash"], lease.payload_hash):
            raise FenceRejected("execution payload changed")
        if now is not None and (
            attempt["lease_expires_at"] is None or attempt["lease_expires_at"] <= now
        ):
            raise FenceRejected("execution lease expired")
        return attempt

    @staticmethod
    def _request_for_update(connection: Any, request_id: str) -> Any:
        row = connection.execute(
            "SELECT * FROM approval_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None:
            raise RequestNotFound(request_id)
        return row

    @staticmethod
    def _require_current(
        request: Any,
        expected_version: int,
        expected_payload_hash: str,
    ) -> None:
        if request["current_version"] != expected_version or not hmac.compare_digest(
            request["current_payload_hash"], expected_payload_hash
        ):
            raise StaleVersion(request["request_id"])

    def _notification(
        self,
        connection: Any,
        *,
        kind: NotificationKind,
        request_id: str,
        service: str,
        action: str,
        now: int,
        dedupe_key: str,
    ) -> None:
        if self._notification_user_id is None:
            return
        enqueue_notification(
            connection,
            dedupe_key=dedupe_key,
            user_id=self._notification_user_id,
            message=PushMessage(kind, service=service, action=action),
            request_id=request_id,
            created_at=now,
        )

    @staticmethod
    def _event(
        connection: Any,
        request_id: str,
        actor: str,
        action: str,
        occurred_at: int,
        version: int,
        payload_hash: str,
        safe_details: Mapping[str, Any] | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO request_events(
                request_id, actor, action, occurred_at,
                version, payload_hash, safe_details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                actor,
                action,
                occurred_at,
                version,
                payload_hash,
                ApprovalStateMachine._safe_json(safe_details),
            ),
        )

    @staticmethod
    def _safe_json(value: Mapping[str, Any] | None) -> str | None:
        if value is None:
            return None
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _validate_hash(value: str) -> None:
        if len(value) != 64:
            raise ValueError("hashes must be 64-character SHA-256 hex digests")
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("hashes must be SHA-256 hex digests") from exc

    def _validate_enqueue(self, request: EnqueueRequest) -> None:
        if not all(
            (
                request.request_id,
                request.downstream_alias,
                request.tool_name,
                request.origin_namespace,
                request.encrypted_payload,
                request.pending_result,
                request.payload_fingerprint,
            )
        ):
            raise ValueError("enqueue fields must not be empty")
        if request.policy_mode not in {
            "deny",
            "approval",
            "passthrough",
            "virtualize_local",
        }:
            raise ValueError(f"invalid policy mode: {request.policy_mode}")
        if (
            not isinstance(request.created_at, int)
            or isinstance(request.created_at, bool)
            or request.created_at < 0
            or not isinstance(request.expires_at, int)
            or isinstance(request.expires_at, bool)
            or request.expires_at > 2**63 - 1
            or request.canonical_size is not None
            and (
                not isinstance(request.canonical_size, int)
                or isinstance(request.canonical_size, bool)
                or request.canonical_size < 0
            )
        ):
            raise ValueError("request timestamps and canonical size are invalid")
        if request.expires_at <= request.created_at:
            raise ValueError("request expiry must be after creation")
        self._validate_hash(request.payload_hash)
        self._validate_attachments(request.attachments)

    def _enforce_enqueue_admission(
        self,
        connection: Any,
        *,
        request: EnqueueRequest,
        reviewed_limits: ReviewedToolLimits,
    ) -> None:
        limits = self._admission_limits
        canonical_size = request.canonical_size
        if canonical_size is None:
            if reviewed_limits.payload_bytes is not None:
                raise AdmissionRejected("payload_limit")
            canonical_size = len(request.encrypted_payload)
        payload_limit = limits.maximum_payload_bytes
        if reviewed_limits.payload_bytes is not None:
            payload_limit = min(payload_limit, reviewed_limits.payload_bytes)
        if canonical_size > payload_limit:
            raise AdmissionRejected("payload_limit")

        if reviewed_limits.requests_per_minute is not None:
            recent = connection.execute(
                """
                SELECT COUNT(*) FROM (
                    SELECT 1 FROM approval_requests
                    WHERE downstream_alias = ? AND tool_name = ?
                      AND created_at > ?
                    LIMIT ?
                )
                """,
                (
                    request.downstream_alias,
                    request.tool_name,
                    request.created_at - 60,
                    reviewed_limits.requests_per_minute,
                ),
            ).fetchone()[0]
            if int(recent) >= reviewed_limits.requests_per_minute:
                raise AdmissionRejected("request_rate")

        if self._pending_limit_reached(
            connection,
            scope="global",
            scope_parameters=(),
            now=request.created_at,
            limit=limits.queue_limit,
        ):
            raise AdmissionRejected("queue_capacity")
        if self._pending_limit_reached(
            connection,
            scope="origin",
            scope_parameters=(request.origin_namespace,),
            now=request.created_at,
            limit=limits.origin_pending_limit,
        ):
            raise AdmissionRejected("queue_capacity")
        tool_pending_limit = limits.tool_pending_limit
        if reviewed_limits.pending_requests is not None:
            tool_pending_limit = min(tool_pending_limit, reviewed_limits.pending_requests)
        if self._pending_limit_reached(
            connection,
            scope="tool",
            scope_parameters=(request.downstream_alias, request.tool_name),
            now=request.created_at,
            limit=tool_pending_limit,
        ):
            raise AdmissionRejected("queue_capacity")

        serialized_bytes = self._estimated_enqueue_bytes(request)
        try:
            free_bytes = self._free_space_provider(str(self.database.path.parent))
        except Exception:
            raise AdmissionRejected("storage_headroom") from None
        if (
            not isinstance(free_bytes, int)
            or isinstance(free_bytes, bool)
            or free_bytes < 0
            or free_bytes - serialized_bytes < limits.minimum_free_bytes
        ):
            raise AdmissionRejected("storage_headroom")

    @staticmethod
    def _pending_limit_reached(
        connection: Any,
        *,
        scope: Literal["global", "origin", "tool"],
        scope_parameters: tuple[str, ...],
        now: int,
        limit: int,
    ) -> bool:
        if scope == "global":
            if scope_parameters:
                raise ValueError("global pending scope does not accept parameters")
            query = """
                SELECT COUNT(*) FROM (
                    SELECT 1 FROM approval_requests
                    WHERE state = 'pending_approval' AND expires_at > ?
                    LIMIT ?
                )
            """
        elif scope == "origin":
            if len(scope_parameters) != 1:
                raise ValueError("origin pending scope requires one parameter")
            query = """
                SELECT COUNT(*) FROM (
                    SELECT 1 FROM approval_requests
                    WHERE state = 'pending_approval' AND expires_at > ?
                      AND origin_namespace = ?
                    LIMIT ?
                )
            """
        elif scope == "tool":
            if len(scope_parameters) != 2:
                raise ValueError("tool pending scope requires two parameters")
            query = """
                SELECT COUNT(*) FROM (
                    SELECT 1 FROM approval_requests
                    WHERE state = 'pending_approval' AND expires_at > ?
                      AND downstream_alias = ? AND tool_name = ?
                    LIMIT ?
                )
            """
        else:
            raise ValueError("unknown pending scope")
        count = connection.execute(
            query,
            (now, *scope_parameters, limit),
        ).fetchone()[0]
        return int(count) >= limit

    def _estimated_enqueue_bytes(self, request: EnqueueRequest) -> int:
        metadata = (
            request.request_id,
            request.downstream_alias,
            request.tool_name,
            request.policy_mode,
            request.origin_namespace,
            request.payload_hash,
            request.payload_fingerprint,
            request.policy_version,
            request.adapter_version,
            request.schema_version,
            request.editor_actor,
            request.encryption_key_ref or "",
            request.idempotency_key or "",
            request.retry_of_request_id or "",
        )
        attachment_bytes = sum(
            len(value.encode("utf-8"))
            for attachment in request.attachments
            for value in (
                attachment.attachment_id,
                attachment.filename,
                attachment.mime_type,
                attachment.sha256,
                attachment.storage_path,
            )
        )
        encoded = (
            len(request.encrypted_payload)
            + len(request.pending_result)
            + sum(len(value.encode("utf-8")) for value in metadata)
            + attachment_bytes
        )
        # Reserve for SQLite pages, indexes, the WAL record, and a later checkpoint.
        return self._admission_limits.write_reserve_bytes + (2 * encoded)

    def _expire_pending_batch(
        self,
        connection: Any,
        *,
        now: int,
        limit: int,
        actor: str,
    ) -> int:
        rows = connection.execute(
            """
            SELECT request_id, current_version, current_payload_hash
            FROM approval_requests
            WHERE state = 'pending_approval' AND expires_at <= ?
            ORDER BY expires_at, created_at, request_id
            LIMIT ?
            """,
            (now, limit),
        ).fetchall()
        expired = 0
        for row in rows:
            updated = connection.execute(
                """
                UPDATE approval_requests
                SET state = 'expired', completed_at = ?, revision = revision + 1
                WHERE request_id = ? AND state = 'pending_approval'
                  AND expires_at <= ?
                """,
                (now, row["request_id"], now),
            ).rowcount
            if updated != 1:  # pragma: no cover - BEGIN IMMEDIATE excludes a competing writer
                continue
            connection.execute(
                """
                UPDATE approval_challenges SET invalidated_at = ?
                WHERE request_id = ? AND consumed_at IS NULL
                  AND invalidated_at IS NULL
                """,
                (now, row["request_id"]),
            )
            connection.execute(
                """
                UPDATE auth_challenges SET invalidated_at = ?
                WHERE request_id = ? AND consumed_at IS NULL
                  AND invalidated_at IS NULL
                """,
                (now, row["request_id"]),
            )
            connection.execute(
                """
                UPDATE browser_views SET invalidated_at = ?
                WHERE request_id = ? AND invalidated_at IS NULL
                """,
                (now, row["request_id"]),
            )
            self._event(
                connection,
                row["request_id"],
                actor,
                RequestState.EXPIRED.value,
                now,
                int(row["current_version"]),
                str(row["current_payload_hash"]),
            )
            expired += 1
        return expired

    @staticmethod
    def _validate_attachments(attachments: tuple[AttachmentReference, ...]) -> None:
        attachment_ids: set[str] = set()
        for attachment in attachments:
            if not isinstance(attachment, AttachmentReference):
                raise ValueError("attachments must be immutable attachment references")
            if (
                not attachment.attachment_id
                or attachment.attachment_id in attachment_ids
                or not attachment.filename
                or not attachment.mime_type
                or attachment.size_bytes < 0
                or len(attachment.sha256) != 64
                or not attachment.storage_path
            ):
                raise ValueError("invalid attachment reference")
            attachment_ids.add(attachment.attachment_id)

    @classmethod
    def _require_attachment_catalog(cls, connection: Any, request: EnqueueRequest) -> None:
        cls._require_attachment_catalog_entries(
            connection,
            downstream_alias=request.downstream_alias,
            request_id=request.request_id,
            attachments=request.attachments,
        )

    @staticmethod
    def _require_attachment_catalog_entries(
        connection: Any,
        *,
        downstream_alias: str,
        request_id: str,
        attachments: tuple[AttachmentReference, ...],
    ) -> None:
        for attachment in attachments:
            row = connection.execute(
                """
                SELECT adapter, filename, declared_mime, size_bytes, sha256,
                       storage_path, encryption_key_ref, consumed_request_id,
                       purged_at, key_destroyed_at
                FROM staged_objects WHERE attachment_id = ?
                """,
                (attachment.attachment_id,),
            ).fetchone()
            if (
                row is None
                or row["adapter"] != downstream_alias
                or row["filename"] != attachment.filename
                or row["declared_mime"] != attachment.mime_type
                or row["size_bytes"] != attachment.size_bytes
                or row["sha256"] != attachment.sha256
                or row["storage_path"] != attachment.storage_path
                or not isinstance(row["encryption_key_ref"], str)
                or not row["encryption_key_ref"]
                or row["purged_at"] is not None
                or row["key_destroyed_at"] is not None
                or row["consumed_request_id"] not in {None, request_id}
            ):
                raise InvalidTransition(
                    "a staged attachment is unavailable, changed, or already consumed"
                )

    @staticmethod
    def _insert_attachments(
        connection: Any,
        *,
        request_id: str,
        version: int,
        payload_hash: str,
        attachments: tuple[AttachmentReference, ...],
        created_at: int,
    ) -> None:
        for attachment in attachments:
            connection.execute(
                """
                INSERT INTO attachments(
                    attachment_id, request_id, version, payload_hash,
                    filename, mime_type, size_bytes, sha256, storage_path,
                    created_at, purge_after
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attachment.attachment_id,
                    request_id,
                    version,
                    payload_hash,
                    attachment.filename,
                    attachment.mime_type,
                    attachment.size_bytes,
                    attachment.sha256,
                    attachment.storage_path,
                    created_at,
                    attachment.purge_after,
                ),
            )

    @staticmethod
    def _safe_outcome_json(value: Mapping[str, Any] | None) -> str | None:
        if value is None:
            return None
        allowed = {
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
        }
        if set(value) - allowed:
            raise ValueError("safe outcome metadata contains an unreviewed field")
        for item in value.values():
            if item is not None and not isinstance(item, (str, int, bool)):
                raise ValueError("safe outcome metadata values must be scalar")
            if isinstance(item, str) and len(item) > 512:
                raise ValueError("safe outcome metadata value is too long")
        encoded = json.dumps(dict(value), ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 4096:
            raise ValueError("safe outcome metadata exceeds the storage limit")
        return encoded

    @staticmethod
    def _insert_result_aliases(
        connection: Any,
        *,
        request: Any,
        aliases: tuple[ResultAlias, ...],
        created_at: int,
    ) -> None:
        for alias in aliases:
            if (
                not alias.account_namespace
                or not alias.identifier_kind
                or not alias.downstream_identifier
                or len(alias.downstream_identifier) > 512
            ):
                raise ValueError("invalid safe downstream result alias")
            connection.execute(
                """
                INSERT INTO result_aliases(
                    request_id, downstream_alias, tool_name, account_namespace,
                    identifier_kind, downstream_identifier, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request["request_id"],
                    request["downstream_alias"],
                    request["tool_name"],
                    alias.account_namespace,
                    alias.identifier_kind,
                    alias.downstream_identifier,
                    created_at,
                ),
            )

    def _fault(self, stage: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(stage)


class ReadOnlyMCPClient:
    """Structurally restrict adapter reconciliation to reviewed read tools."""

    def __init__(
        self,
        allowed_tools: set[str] | frozenset[str],
        call_tool: Callable[[str, Mapping[str, Any]], Any | Awaitable[Any]],
    ) -> None:
        self._allowed_tools = frozenset(allowed_tools)
        self._call_tool = call_tool

    async def call_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Any:
        if tool_name not in self._allowed_tools:
            raise ReadOnlyToolViolation(
                f"reconciliation tool is not on the reviewed read-only allowlist: {tool_name}"
            )
        result = self._call_tool(tool_name, arguments)
        if inspect.isawaitable(result):
            return await result
        return result


StateMachine = ApprovalStateMachine


def _filesystem_free_bytes(path: str) -> int:
    return int(shutil.disk_usage(path).free)
