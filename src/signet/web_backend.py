"""Persistent application backend for the private Signet web UI.

This module deliberately contains no downstream client.  It authenticates the
human session, renders authenticated frozen requests, and hands confirmed
mutations to persistence boundaries that own their transaction.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

from signet.adapters.base import ApprovalAdapter, ApprovalSummary
from signet.auth import (
    ActionBinding,
    AuthenticationRateLimited,
    InvalidCredentials,
    InvalidSession,
    PasswordAuthenticator,
    SessionManager,
    SessionPrincipal,
    SQLiteAuthenticationTransactions,
    TotpLoginProof,
    WebAuthnLoginProof,
    canonical_user_id,
)
from signet.canonical import CanonicalizationError, canonical_json
from signet.db import Database
from signet.decision_notes import decision_reason_label, normalize_decision_note, reason_for_action
from signet.execution_scope import ExecutionScopeResolver
from signet.models import (
    ApprovalConfirmation,
    AttachmentReference,
    ConfirmationKind,
    ConfirmationReplay,
    InvalidConfirmation,
    InvalidTransition,
    RequestExpired,
    RequestNotFound,
    StaleVersion,
)
from signet.notifications import (
    NotificationKind,
    PushRepository,
    PushSubscription,
)
from signet.policy import PolicyError
from signet.staging import StagingError, StagingStore
from signet.state_machine import ApprovalStateMachine
from signet.totp import (
    InvalidTotp,
    TotpError,
    TotpVerifier,
    VerifiedTotp,
)
from signet.web import (
    ActionOptions,
    AttachmentDownload,
    AuditEntry,
    DecisionEntry,
    DecisionPage,
    DetailBlock,
    HumanAction,
    LoginOptions,
    PolicyPromotionPreview,
    PushSubscriptionInput,
    QueueItem,
    QueuePage,
    RequestAttachment,
    RequestDetail,
    WebConflict,
    WebForbidden,
    WebRateLimited,
    WebUnauthorized,
)
from signet.webauthn import (
    AssertionInput,
    IssuedWebAuthnChallenge,
    VerifiedWebAuthn,
    WebAuthnAssertionVerifier,
    WebAuthnChallengeIssuer,
    WebAuthnChallengeRateLimited,
    WebAuthnChallengeUnavailable,
    WebAuthnCredentialUnavailable,
    WebAuthnError,
    WebAuthnRepository,
)

type ConfirmationAction = Literal[
    "approve",
    "deny",
    "human_cancel",
    "edit",
    "promote_approval",
    "promote_passthrough",
]
type PolicyPromotion = Literal["promote_approval", "promote_passthrough"]
type ConfirmationKey = tuple[str, int, str, int]
type ConfirmationProof = tuple[str, str]
type ConfirmationMatches = tuple[tuple[ConfirmationProof, ...], int]

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
_PREAUTH_PREFIX = "preauth:"
_SHA256 = frozenset("0123456789abcdef")
_AUDIT_DECISION_ACTIONS = frozenset(
    {
        "approved_via_web",
        "approved_via_mcp",
        "denied",
        "policy_promoted_to_approval",
        "policy_promoted_to_passthrough",
    }
)
_MAX_QUEUE_PAGE_SIZE = 50
_POLICY_PREVIEW_UNAVAILABLE = (
    "Exact frozen policy proposal history is unavailable or failed integrity validation. "
    "Approval is disabled; the frozen request context remains available."
)


class WebPayloadError(RuntimeError):
    """A private payload could not be authenticated or reviewed."""


class PolicyPromotionError(RuntimeError):
    """A policy change failed closed at its durable boundary."""


class PayloadCodec(Protocol):
    """Encryption boundary for exact immutable payload revisions."""

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

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        key_reference: str | None,
        request_id: str,
        version: int,
        payload_hash: str,
    ) -> bytes: ...


@dataclass(frozen=True, slots=True, repr=False)
class ReviewedPayload:
    adapter: ApprovalAdapter
    summary: ApprovalSummary
    arguments: Mapping[str, Any]
    account_ref: str | None
    credential_identity_digest: str | None
    caller_namespace: str
    policy_version: int
    adapter_id: str
    adapter_version: str
    schema_version: str
    staged_file_hashes: tuple[str, ...]
    attachments: tuple[AttachmentReference, ...]

    def __repr__(self) -> str:
        return "ReviewedPayload(payload=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class PreparedEdit:
    encrypted_payload: bytes
    payload_hash: str
    canonical_size: int
    policy_version: str
    adapter_version: str
    schema_version: str
    encryption_key_ref: str

    def __repr__(self) -> str:
        return (
            "PreparedEdit(encrypted_payload=<redacted>, payload_hash=<redacted>, "
            f"canonical_size={self.canonical_size!r}, metadata=<redacted>)"
        )


class PrivatePayloadReviewer(Protocol):
    """Authenticated private read/edit view over frozen request revisions."""

    def review(
        self,
        request_id: str,
        *,
        version: int,
        payload_hash: str,
    ) -> ReviewedPayload: ...

    def review_historical(
        self,
        request_id: str,
        *,
        version: int,
        payload_hash: str,
    ) -> ReviewedPayload: ...

    def prepare_edit(
        self,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        prospective_arguments_json: str,
    ) -> PreparedEdit: ...

    def read_attachment(
        self,
        request_id: str,
        attachment_id: str,
        *,
        version: int,
        payload_hash: str,
    ) -> AttachmentDownload: ...


class EncryptedPayloadReviewer:
    """Decrypt, authenticate, and adapter-validate exact retained revisions."""

    def __init__(
        self,
        state_machine: ApprovalStateMachine,
        codec: PayloadCodec,
        adapters: Mapping[tuple[str, str], ApprovalAdapter],
        execution_scopes: ExecutionScopeResolver,
        *,
        staging: StagingStore | None = None,
        max_payload_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        if max_payload_bytes <= 0 or max_payload_bytes > 64 * 1024 * 1024:
            raise ValueError("private payload size limit is invalid")
        if not adapters or any(
            not alias or not tool or adapter.downstream_alias != alias or adapter.tool_name != tool
            for (alias, tool), adapter in adapters.items()
        ):
            raise ValueError("adapter registry keys must match reviewed adapters")
        if not codec.key_reference:
            raise ValueError("payload codec key reference is required")
        if not callable(getattr(execution_scopes, "resolve", None)):
            raise ValueError("an execution scope resolver is required")
        self._state_machine = state_machine
        self._codec = codec
        self._adapters = dict(adapters)
        self._execution_scopes = execution_scopes
        self._staging = staging
        self.max_payload_bytes = max_payload_bytes

    def review(
        self,
        request_id: str,
        *,
        version: int,
        payload_hash: str,
    ) -> ReviewedPayload:
        return self._review_revision(
            request_id,
            version=version,
            payload_hash=payload_hash,
            require_current=True,
        )

    def review_historical(
        self,
        request_id: str,
        *,
        version: int,
        payload_hash: str,
    ) -> ReviewedPayload:
        return self._review_revision(
            request_id,
            version=version,
            payload_hash=payload_hash,
            require_current=False,
        )

    def _review_revision(
        self,
        request_id: str,
        *,
        version: int,
        payload_hash: str,
        require_current: bool,
    ) -> ReviewedPayload:
        request = self._state_machine.get_request(request_id)
        if require_current and (
            request["current_version"] != version
            or not _same_hash(request["current_payload_hash"], payload_hash)
        ):
            raise WebPayloadError("request revision is no longer current")
        payload = self._state_machine.get_payload_version(request_id, version)
        if not _same_hash(payload["payload_hash"], payload_hash):
            raise WebPayloadError("payload revision does not match the request")
        encrypted = payload["encrypted_payload"]
        canonical_size = payload["canonical_size"]
        if (
            encrypted is None
            or payload["purged_at"] is not None
            or payload["key_destroyed_at"] is not None
            or not isinstance(canonical_size, int)
            or isinstance(canonical_size, bool)
            or canonical_size < 0
            or canonical_size > self.max_payload_bytes
        ):
            raise WebPayloadError("private payload is unavailable")
        key_reference = payload["encryption_key_ref"]
        if key_reference is not None and not isinstance(key_reference, str):
            raise WebPayloadError("private payload metadata is invalid")
        try:
            plaintext = self._codec.decrypt(
                bytes(encrypted),
                key_reference=key_reference,
                request_id=request_id,
                version=version,
                payload_hash=payload_hash,
            )
        except Exception:
            raise WebPayloadError("private payload could not be authenticated") from None
        if (
            not isinstance(plaintext, bytes)
            or len(plaintext) != canonical_size
            or len(plaintext) > self.max_payload_bytes
            or not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), payload_hash)
        ):
            raise WebPayloadError("private payload could not be authenticated")

        envelope = _strict_json_object(plaintext)
        try:
            if canonical_json(envelope) != plaintext:
                raise ValueError
        except (CanonicalizationError, ValueError):
            raise WebPayloadError("private payload is not canonical") from None
        if frozenset(envelope) != _ENVELOPE_FIELDS:
            raise WebPayloadError("private payload has an invalid envelope")

        alias = envelope["alias"]
        tool = envelope["tool"]
        account_ref = envelope["account_ref"]
        adapter_id = envelope["adapter_id"]
        adapter_version = envelope["adapter_version"]
        caller_namespace = envelope["caller_namespace"]
        credential_identity_digest = envelope["credential_identity_digest"]
        policy_version = envelope["policy_version"]
        schema_digest = envelope["schema_digest"]
        arguments = envelope["arguments"]
        staged_hashes = envelope["staged_file_hashes"]
        if (
            not isinstance(alias, str)
            or alias != request["downstream_alias"]
            or not isinstance(tool, str)
            or tool != request["tool_name"]
            or not isinstance(adapter_id, str)
            or not isinstance(adapter_version, str)
            or adapter_version != payload["adapter_version"]
            or not isinstance(policy_version, int)
            or isinstance(policy_version, bool)
            or policy_version < 1
            or str(policy_version) != str(payload["policy_version"])
            or not isinstance(caller_namespace, str)
            or caller_namespace != request["origin_namespace"]
            or not _is_sha256(schema_digest)
            or schema_digest != payload["schema_version"]
            or not isinstance(arguments, dict)
            or not isinstance(staged_hashes, list)
            or any(not _is_sha256(item) for item in staged_hashes)
        ):
            raise WebPayloadError("private payload metadata does not match its revision")
        try:
            adapter = self._adapters[(alias, tool)]
        except KeyError:
            raise WebPayloadError("no reviewed adapter matches the private payload") from None
        if adapter.adapter_id != adapter_id or adapter.adapter_version != adapter_version:
            raise WebPayloadError("reviewed adapter identity does not match the payload")
        gateway_internal = bool(request["gateway_internal"])
        if gateway_internal:
            if account_ref is not None or credential_identity_digest is not None:
                raise WebPayloadError("gateway-internal payload has downstream execution scope")
        elif not isinstance(account_ref, str) or not _is_sha256(credential_identity_digest):
            raise WebPayloadError("private payload execution scope is invalid")
        if require_current and not gateway_internal:
            try:
                current_scope = self._execution_scopes.resolve(alias, tool, adapter)
            except Exception:
                raise WebPayloadError("current execution scope is unavailable") from None
            if (
                current_scope.account_ref != account_ref
                or not hmac.compare_digest(
                    current_scope.credential_identity_digest,
                    cast(str, credential_identity_digest),
                )
                or not hmac.compare_digest(current_scope.schema_digest, cast(str, schema_digest))
            ):
                raise WebPayloadError("current execution scope does not match the payload")
        try:
            canonical_arguments = adapter.canonicalize(cast(dict[str, Any], arguments))
            if canonical_json(canonical_arguments) != canonical_json(arguments):
                raise ValueError
            summary = adapter.summarize_for_web(canonical_arguments)
            frozen_attachments = adapter.freeze_attachments(canonical_arguments)
        except Exception:
            raise WebPayloadError("private payload failed reviewed adapter validation") from None
        try:
            stored_attachments = self._state_machine.get_attachment_references(
                request_id,
                version=version,
                payload_hash=payload_hash,
            )
        except (RequestNotFound, InvalidTransition):
            raise WebPayloadError("private payload attachment snapshot is unavailable") from None
        if tuple(attachment.sha256 for attachment in frozen_attachments) != tuple(
            cast(list[str], staged_hashes)
        ) or _sorted_attachment_identities(frozen_attachments) != _sorted_attachment_identities(
            stored_attachments
        ):
            raise WebPayloadError("private payload attachment snapshot does not match")
        schema_version = payload["schema_version"]
        if not isinstance(schema_version, str) or not schema_version:
            raise WebPayloadError("private payload schema metadata is invalid")
        return ReviewedPayload(
            adapter=adapter,
            summary=summary,
            arguments=canonical_arguments,
            account_ref=cast(str | None, account_ref),
            credential_identity_digest=cast(str | None, credential_identity_digest),
            caller_namespace=caller_namespace,
            policy_version=policy_version,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            schema_version=schema_version,
            staged_file_hashes=tuple(cast(list[str], staged_hashes)),
            attachments=frozen_attachments,
        )

    def prepare_edit(
        self,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        prospective_arguments_json: str,
    ) -> PreparedEdit:
        reviewed = self.review(
            request_id,
            version=expected_version,
            payload_hash=expected_payload_hash,
        )
        prospective = _strict_json_object(prospective_arguments_json)
        try:
            arguments = reviewed.adapter.canonicalize(prospective)
            edited_attachments = reviewed.adapter.freeze_attachments(arguments)
            if tuple(
                _attachment_identity(attachment) for attachment in edited_attachments
            ) != tuple(_attachment_identity(attachment) for attachment in reviewed.attachments):
                raise ValueError("attachment references cannot be changed by an edit")
            envelope = {
                "account_ref": reviewed.account_ref,
                "adapter_id": reviewed.adapter_id,
                "adapter_version": reviewed.adapter_version,
                "alias": reviewed.adapter.downstream_alias,
                "arguments": arguments,
                "caller_namespace": reviewed.caller_namespace,
                "credential_identity_digest": reviewed.credential_identity_digest,
                "policy_version": reviewed.policy_version,
                "schema_digest": reviewed.schema_version,
                "staged_file_hashes": [attachment.sha256 for attachment in edited_attachments],
                "tool": reviewed.adapter.tool_name,
            }
            plaintext = canonical_json(envelope)
        except Exception:
            raise WebPayloadError("edited arguments failed reviewed adapter validation") from None
        if len(plaintext) > self.max_payload_bytes:
            raise WebPayloadError("edited payload exceeds the private payload limit")
        payload_hash = hashlib.sha256(plaintext).hexdigest()
        if hmac.compare_digest(payload_hash, expected_payload_hash):
            raise WebPayloadError("edited arguments do not change the payload")
        try:
            encrypted = self._codec.encrypt(
                plaintext,
                request_id=request_id,
                version=expected_version + 1,
                payload_hash=payload_hash,
            )
        except Exception:
            raise WebPayloadError("edited payload could not be encrypted") from None
        if not isinstance(encrypted, bytes) or not encrypted:
            raise WebPayloadError("edited payload could not be encrypted")
        return PreparedEdit(
            encrypted_payload=encrypted,
            payload_hash=payload_hash,
            canonical_size=len(plaintext),
            policy_version=str(reviewed.policy_version),
            adapter_version=reviewed.adapter_version,
            schema_version=reviewed.schema_version,
            encryption_key_ref=self._codec.key_reference,
        )

    def read_attachment(
        self,
        request_id: str,
        attachment_id: str,
        *,
        version: int,
        payload_hash: str,
    ) -> AttachmentDownload:
        reviewed = self.review(request_id, version=version, payload_hash=payload_hash)
        matching = tuple(
            attachment
            for attachment in reviewed.attachments
            if attachment.attachment_id == attachment_id
        )
        if len(matching) != 1 or self._staging is None:
            raise WebPayloadError("frozen attachment is unavailable for inspection")
        expected = matching[0]
        account = reviewed.account_ref
        if not isinstance(account, str) or not account:
            raise WebPayloadError("frozen attachment scope is unavailable")
        try:
            record, content = self._staging.read_verified(
                attachment_id,
                adapter=reviewed.adapter.downstream_alias,
                account=account,
            )
        except StagingError:
            raise WebPayloadError("frozen attachment is unavailable for inspection") from None
        if (
            record.filename != expected.filename
            or record.declared_mime != expected.mime_type
            or record.size != expected.size_bytes
            or not hmac.compare_digest(record.sha256, expected.sha256)
            or str(record.path) != expected.storage_path
            or len(content) != expected.size_bytes
            or not hmac.compare_digest(hashlib.sha256(content).hexdigest(), expected.sha256)
        ):
            raise WebPayloadError("frozen attachment no longer matches its reviewed metadata")
        return AttachmentDownload(
            content=content,
            size_bytes=expected.size_bytes,
            sha256=expected.sha256,
        )


@dataclass(frozen=True, slots=True, repr=False)
class WebActionDraft:
    challenge_id: str
    action: HumanAction
    binding: ActionBinding
    user_id: str
    session_id: str
    policy_change: bool
    prepared_edit: PreparedEdit | None
    created_at: int
    expires_at: int
    decision_note: str | None = None

    def __repr__(self) -> str:
        return (
            "WebActionDraft(challenge_id=<redacted>, action=<redacted>, "
            "binding=<redacted>, user_id=<redacted>, session_id=<redacted>, "
            f"policy_change={self.policy_change!r}, prepared_edit=<redacted>)"
        )


class ActionDraftRepository(Protocol):
    """Durable immutable drafts spanning passkey options and completion.

    ``save`` must reject a challenge-ID conflict instead of overwriting it.
    ``find`` must remain available after process restart until challenge expiry.
    """

    def save(self, draft: WebActionDraft) -> None: ...

    def find(self, challenge_id: str) -> WebActionDraft | None: ...


class PolicyPromotionBoundary(Protocol):
    """Atomic durable boundary for one human-confirmed policy promotion.

    An implementation must recheck the exact pending request revision, verify
    and consume the unchanged confirmation capability/challenge/credential
    state, apply the reviewed policy change, and append its audit record in one
    transaction.
    """

    def preview(
        self,
        request_id: str,
        action: HumanAction,
        *,
        expected_version: int,
        expected_payload_hash: str,
        now: int,
    ) -> PolicyPromotionPreview: ...

    def binding_action(
        self,
        request_id: str,
        action: HumanAction,
        *,
        expected_version: int,
        expected_payload_hash: str,
        now: int,
    ) -> ConfirmationAction: ...

    def promote(
        self,
        draft: WebActionDraft,
        confirmation: ApprovalConfirmation,
        *,
        actor: str,
        now: int,
    ) -> str: ...

    def promote_totp(
        self,
        action: HumanAction,
        binding: ActionBinding,
        confirmation: ApprovalConfirmation,
        *,
        actor: str,
        now: int,
    ) -> str: ...


class WebBackend:
    """Production orchestration for the normally authenticated private UI."""

    def __init__(
        self,
        database: Database,
        *,
        authorized_user_id: str,
        sessions: SessionManager,
        passwords: PasswordAuthenticator,
        totp: TotpVerifier,
        webauthn_repository: WebAuthnRepository,
        webauthn_issuer: WebAuthnChallengeIssuer,
        webauthn_verifier: WebAuthnAssertionVerifier,
        authentication_transactions: SQLiteAuthenticationTransactions,
        state_machine: ApprovalStateMachine,
        payloads: PrivatePayloadReviewer,
        action_drafts: ActionDraftRepository,
        policy_promotions: PolicyPromotionBoundary,
        pushes: PushRepository,
        max_audit_entries: int = 1_000,
        max_decision_entries: int = 100,
        max_queue_entries: int = _MAX_QUEUE_PAGE_SIZE,
        passkey_login_window_seconds: int = 10 * 60,
        passkey_login_source_limit: int = 20,
        passkey_login_account_limit: int = 10,
        passkey_login_global_limit: int = 200,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if max_audit_entries <= 0 or max_audit_entries > 10_000:
            raise ValueError("audit read limit is invalid")
        try:
            self._authorized_user_id = canonical_user_id(authorized_user_id)
        except (InvalidCredentials, TypeError, ValueError):
            raise ValueError("authorized web user ID is invalid") from None
        if max_decision_entries <= 0 or max_decision_entries > 1_000:
            raise ValueError("decision read limit is invalid")
        if max_queue_entries <= 0 or max_queue_entries > _MAX_QUEUE_PAGE_SIZE:
            raise ValueError("queue read limit is invalid")
        if clock is not None and not callable(clock):
            raise ValueError("web backend clock is invalid")
        if (
            passkey_login_window_seconds < 60
            or passkey_login_window_seconds > 60 * 60
            or passkey_login_source_limit < 1
            or passkey_login_source_limit > 1_000
            or passkey_login_account_limit < 1
            or passkey_login_account_limit > passkey_login_source_limit
            or passkey_login_global_limit < passkey_login_source_limit
            or passkey_login_global_limit > 100_000
        ):
            raise ValueError("passkey login issuance limits are invalid")
        self._database = database
        self._sessions = sessions
        self._passwords = passwords
        self._totp = totp
        self._webauthn_repository = webauthn_repository
        self._webauthn_issuer = webauthn_issuer
        self._webauthn_verifier = webauthn_verifier
        self._authentication_transactions = authentication_transactions
        self._state_machine = state_machine
        self._payloads = payloads
        self._action_drafts = action_drafts
        self._policy_promotions = policy_promotions
        self._pushes = pushes
        self.max_audit_entries = max_audit_entries
        self.max_decision_entries = max_decision_entries
        self.max_queue_entries = max_queue_entries
        self._passkey_login_window_seconds = passkey_login_window_seconds
        self._passkey_login_source_limit = passkey_login_source_limit
        self._passkey_login_account_limit = passkey_login_account_limit
        self._passkey_login_global_limit = passkey_login_global_limit
        self._clock = clock or (lambda: int(time.time()))

    def authenticate(self, token: str | None, *, now: int) -> SessionPrincipal:
        principal = self._sessions.authenticate(token, now=now)
        try:
            self._require_ui_principal(principal)
        except WebUnauthorized:
            raise InvalidSession(
                "authentication has not completed for the authorized user"
            ) from None
        return principal

    def password_totp_login(
        self,
        user_id: str,
        password: str,
        totp_proof: str,
        *,
        source: str,
        previous_token: str | None,
        now: int,
    ) -> str:
        preauth_token: str | None = None
        try:
            password_user = self._passwords.authenticate(
                user_id,
                password,
                source_id=source,
                now=now,
            )
            if not self._is_authorized_user(password_user.user_id):
                raise InvalidCredentials("invalid credentials")
            preauth_token = self._sessions.create_session(
                password_user.user_id,
                auth_method="preauth:password",
                previous_token=previous_token,
                now=now,
            )
            preauth = self._sessions.authenticate(preauth_token, now=now)
            proof = self._totp.verify(
                password_user.user_id,
                totp_proof,
                binding=ActionBinding("login"),
                source_id=source,
                session_id=preauth.session_id,
                http_method="POST",
                now=now,
            )
            return self._authentication_transactions.complete_totp_login(
                password_user,
                cast(TotpLoginProof, proof),
                now=now,
            )
        except AuthenticationRateLimited as exc:
            raise WebRateLimited(str(exc)) from None
        except (InvalidCredentials, InvalidSession, TotpError):
            raise WebUnauthorized("invalid credentials") from None
        finally:
            if preauth_token is not None:
                self._sessions.logout(preauth_token, now=now)

    def begin_passkey_login(
        self,
        user_id: str,
        *,
        source: str,
        http_method: str,
        now: int,
    ) -> LoginOptions:
        if not source or len(source) > 256:
            raise WebUnauthorized("invalid credentials")
        try:
            canonical_user = canonical_user_id(user_id)
            credentials = (
                self._webauthn_repository.credentials_for_user(canonical_user)
                if self._is_authorized_user(canonical_user)
                else ()
            )
        except (InvalidCredentials, TypeError, ValueError, WebAuthnError):
            canonical_user = None
            credentials = ()
        try:
            self._reserve_passkey_login(
                source,
                account=canonical_user,
                now=now,
            )
        except AuthenticationRateLimited as exc:
            raise WebRateLimited(str(exc)) from None
        self._prune_login_ephemera(now=now)
        if canonical_user is None or not credentials:
            raise WebUnauthorized("invalid credentials")
        with self._database.read() as connection:
            active = int(
                connection.execute(
                    """
                    SELECT count(*) FROM auth_challenges
                    WHERE user_id = ? AND action = 'login'
                      AND consumed_at IS NULL AND invalidated_at IS NULL
                      AND expires_at > ?
                    """,
                    (canonical_user, now),
                ).fetchone()[0]
            )
        if active >= self._webauthn_issuer.max_active_per_user:
            raise WebRateLimited("too many active passkey challenges")
        preauth_token: str | None = None
        try:
            preauth_token = self._sessions.create_session(
                canonical_user,
                auth_method="preauth:webauthn",
                now=now,
            )
            preauth = self._sessions.authenticate(preauth_token, now=now)
            issued = self._webauthn_issuer.issue(
                canonical_user,
                ActionBinding("login"),
                session_id=preauth.session_id,
                http_method=http_method,
                now=now,
            )
            return LoginOptions(
                challenge_id=issued.challenge_id,
                public_key=_public_key_options(issued),
            )
        except WebAuthnChallengeRateLimited as exc:
            if preauth_token is not None:
                self._sessions.logout(preauth_token, now=now)
            raise WebRateLimited(str(exc)) from None
        except (InvalidCredentials, InvalidSession, WebAuthnError, ValueError):
            if preauth_token is not None:
                self._sessions.logout(preauth_token, now=now)
            raise WebUnauthorized("invalid credentials") from None

    def _reserve_passkey_login(
        self,
        source: str,
        *,
        account: str | None,
        now: int,
    ) -> None:
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise WebUnauthorized("invalid credentials")
        scopes = [
            ("passkey-login:global", self._passkey_login_global_limit),
            (
                "passkey-login:source:" + hashlib.sha256(source.encode("utf-8")).hexdigest(),
                self._passkey_login_source_limit,
            ),
        ]
        if account is not None:
            scopes.append(
                (
                    "passkey-login:account:" + hashlib.sha256(account.encode("utf-8")).hexdigest(),
                    self._passkey_login_account_limit,
                )
            )
        blocked_until: int | None = None
        with self._database.transaction() as connection:
            connection.execute(
                """
                DELETE FROM auth_attempts WHERE rowid IN (
                    SELECT rowid FROM auth_attempts
                    WHERE (
                        scope_key LIKE 'passkey-login:source:%'
                        OR scope_key LIKE 'passkey-login:account:%'
                    )
                      AND updated_at + ? <= ?
                      AND (locked_until IS NULL OR locked_until <= ?)
                    ORDER BY updated_at LIMIT 500
                )
                """,
                (self._passkey_login_window_seconds, now, now),
            )
            scope_keys = tuple(scope for scope, _limit in scopes)
            rows = {
                str(row["scope_key"]): row
                for row in connection.execute(
                    """
                    SELECT * FROM auth_attempts
                    WHERE scope_key IN (SELECT value FROM json_each(?))
                    """,
                    (json.dumps(scope_keys, separators=(",", ":")),),
                ).fetchall()
            }
            for scope, _limit in scopes:
                row = rows.get(scope)
                if row is not None and row["locked_until"] is not None:
                    locked_until = int(row["locked_until"])
                    if now < locked_until:
                        blocked_until = max(blocked_until or 0, locked_until)
            if blocked_until is None:
                for scope, limit in scopes:
                    row = rows.get(scope)
                    window_start = int(row["updated_at"]) if row is not None else now
                    count = int(row["failures"]) if row is not None else 0
                    if (
                        now < window_start
                        or now >= window_start + self._passkey_login_window_seconds
                    ):
                        window_start = now
                        count = 0
                    new_count = count + 1
                    next_lock = (
                        window_start + self._passkey_login_window_seconds
                        if new_count >= limit
                        else None
                    )
                    connection.execute(
                        """
                        INSERT INTO auth_attempts(
                            scope_key, failures, locked_until, last_attempt_id, updated_at
                        ) VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(scope_key) DO UPDATE SET
                            failures = excluded.failures,
                            locked_until = excluded.locked_until,
                            last_attempt_id = excluded.last_attempt_id,
                            updated_at = excluded.updated_at
                        """,
                        (
                            scope,
                            new_count,
                            next_lock,
                            secrets.token_urlsafe(18),
                            window_start,
                        ),
                    )
        if blocked_until is not None:
            raise AuthenticationRateLimited(max(1, blocked_until - now))

    def _prune_login_ephemera(self, *, now: int) -> None:
        cutoff = max(0, now - 7 * 24 * 60 * 60)
        proof_cutoff = max(0, now - 30 * 24 * 60 * 60)
        with self._database.transaction() as connection:
            connection.execute(
                """
                DELETE FROM auth_login_consumptions WHERE rowid IN (
                    SELECT rowid FROM auth_login_consumptions
                    WHERE consumed_at <= ? ORDER BY consumed_at LIMIT 500
                )
                """,
                (proof_cutoff,),
            )
            connection.execute(
                """
                DELETE FROM auth_proof_consumptions WHERE rowid IN (
                    SELECT rowid FROM auth_proof_consumptions
                    WHERE purpose = 'login' AND consumed_at <= ?
                    ORDER BY consumed_at LIMIT 500
                )
                """,
                (proof_cutoff,),
            )
            connection.execute(
                """
                DELETE FROM auth_challenges WHERE rowid IN (
                    SELECT rowid FROM auth_challenges
                    WHERE action = 'login' AND expires_at <= ?
                    ORDER BY expires_at LIMIT 500
                )
                """,
                (cutoff,),
            )
            connection.execute(
                """
                DELETE FROM web_sessions WHERE rowid IN (
                    SELECT session.rowid FROM web_sessions AS session
                    WHERE (session.revoked_at <= ? OR session.absolute_expires_at <= ?)
                      AND NOT EXISTS (
                          SELECT 1 FROM auth_challenges AS challenge
                          WHERE challenge.session_id = session.session_id
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM auth_login_consumptions AS consumption
                          WHERE consumption.session_id = session.session_id
                      )
                    ORDER BY session.absolute_expires_at LIMIT 500
                )
                """,
                (cutoff, cutoff),
            )
            connection.execute(
                """
                DELETE FROM auth_users WHERE rowid IN (
                    SELECT user.rowid FROM auth_users AS user
                    WHERE NOT EXISTS (
                        SELECT 1 FROM auth_credentials AS credential
                        WHERE credential.user_id = user.user_id
                    )
                      AND NOT EXISTS (
                          SELECT 1 FROM web_sessions AS session
                          WHERE session.user_id = user.user_id
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM auth_challenges AS challenge
                          WHERE challenge.user_id = user.user_id
                      )
                    LIMIT 500
                )
                """
            )

    def complete_passkey_login(
        self,
        challenge_id: str,
        assertion: Mapping[str, Any],
        *,
        source: str,
        http_method: str,
        previous_token: str | None,
        now: int,
    ) -> str:
        if not source or len(source) > 256:
            raise WebUnauthorized("invalid credentials")
        challenge = self._webauthn_repository.find_challenge(challenge_id)
        if (
            challenge is None
            or challenge.binding != ActionBinding("login")
            or not self._is_authorized_user(challenge.user_id)
        ):
            raise WebUnauthorized("invalid credentials")
        try:
            proof = self._webauthn_verifier.verify(
                cast(AssertionInput, assertion),
                challenge_id=challenge_id,
                user_id=challenge.user_id,
                binding=challenge.binding,
                session_id=challenge.session_id,
                http_method=http_method,
                now=now,
            )
            if previous_token is not None:
                self._sessions.logout(previous_token, now=now)
            return self._authentication_transactions.complete_webauthn_login(
                cast(WebAuthnLoginProof, proof),
                now=now,
            )
        except AuthenticationRateLimited as exc:
            self._revoke_preauth_session(
                challenge.session_id,
                user_id=challenge.user_id,
                now=now,
            )
            raise WebRateLimited(str(exc)) from None
        except (InvalidCredentials, InvalidSession, WebAuthnError):
            self._revoke_preauth_session(
                challenge.session_id,
                user_id=challenge.user_id,
                now=now,
            )
            raise WebUnauthorized("invalid credentials") from None

    def logout(self, token: str | None, *, now: int) -> None:
        self._sessions.logout(token, now=now)

    def list_queue(
        self,
        principal: SessionPrincipal,
        *,
        now: int,
        cursor: str | None = None,
    ) -> QueuePage:
        self._require_ui_principal(principal)
        cursor_values = _decode_queue_cursor(cursor) if cursor is not None else None
        with self._database.read() as connection:
            if cursor_values is None:
                rows = connection.execute(
                    """
                    SELECT request_id, downstream_alias, tool_name, state, created_at,
                           expires_at, current_version, current_payload_hash
                    FROM approval_requests
                    WHERE state = 'outcome_unknown'
                       OR (state = 'pending_approval' AND expires_at > ?)
                    ORDER BY CASE state WHEN 'outcome_unknown' THEN 0 ELSE 1 END,
                             created_at, request_id
                    LIMIT ?
                    """,
                    (now, self.max_queue_entries + 1),
                ).fetchall()
            else:
                priority, created_at, after_request_id = cursor_values
                rows = connection.execute(
                    """
                    SELECT request_id, downstream_alias, tool_name, state, created_at,
                           expires_at, current_version, current_payload_hash
                    FROM approval_requests
                    WHERE (state = 'outcome_unknown'
                           OR (state = 'pending_approval' AND expires_at > ?))
                      AND (
                          CASE state WHEN 'outcome_unknown' THEN 0 ELSE 1 END > ?
                          OR (
                              CASE state WHEN 'outcome_unknown' THEN 0 ELSE 1 END = ?
                              AND (
                                  created_at > ?
                                  OR (created_at = ? AND request_id > ?)
                              )
                          )
                      )
                    ORDER BY CASE state WHEN 'outcome_unknown' THEN 0 ELSE 1 END,
                             created_at, request_id
                    LIMIT ?
                    """,
                    (
                        now,
                        priority,
                        priority,
                        created_at,
                        created_at,
                        after_request_id,
                        self.max_queue_entries + 1,
                    ),
                ).fetchall()
        visible = rows[: self.max_queue_entries]
        has_more = len(rows) > self.max_queue_entries
        return QueuePage(
            items=tuple(
                QueueItem(
                    request_id=str(row["request_id"]),
                    downstream_alias=str(row["downstream_alias"]),
                    tool_name=str(row["tool_name"]),
                    state=str(row["state"]),
                    created_at=int(row["created_at"]),
                    expires_at=int(row["expires_at"]),
                    version=int(row["current_version"]),
                    payload_hash_prefix=str(row["current_payload_hash"])[:12],
                )
                for row in visible
            ),
            has_more=has_more,
            next_cursor=(_encode_queue_cursor(visible[-1]) if has_more and visible else None),
        )

    def get_detail(self, principal: SessionPrincipal, request_id: str) -> RequestDetail:
        self._require_ui_principal(principal)
        try:
            request = self._state_machine.get_request(request_id)
            events = self._state_machine.list_events(request_id)
        except RequestNotFound:
            raise WebConflict("request details are unavailable") from None
        return self._get_revision_detail(
            request,
            events=events,
            version=int(request["current_version"]),
            payload_hash=str(request["current_payload_hash"]),
            historical_event=None,
        )

    def get_historical_detail(
        self,
        principal: SessionPrincipal,
        event_id: int,
    ) -> RequestDetail:
        self._require_ui_principal(principal)
        if (
            not isinstance(event_id, int)
            or isinstance(event_id, bool)
            or event_id < 1
            or event_id > (2**63 - 1)
        ):
            raise WebConflict("decision event is invalid")
        with self._database.read() as connection:
            event = connection.execute(
                """
                SELECT event_id, request_id, actor, action, occurred_at,
                       version, payload_hash, safe_details_json
                FROM request_events
                WHERE event_id = ? AND action IN (
                    'approved_via_web', 'approved_via_mcp', 'denied',
                    'policy_promoted_to_approval',
                    'policy_promoted_to_passthrough'
                )
                """,
                (event_id,),
            ).fetchone()
        if event is None or str(event["action"]) not in _AUDIT_DECISION_ACTIONS:
            raise WebConflict("decision event is unavailable")
        request_id = str(event["request_id"])
        version = event["version"]
        payload_hash = event["payload_hash"]
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version < 1
            or not isinstance(payload_hash, str)
            or not _is_sha256(payload_hash)
        ):
            raise WebConflict("decision event binding is invalid")
        try:
            request = self._state_machine.get_request(request_id)
            events = [
                item
                for item in self._state_machine.list_events(request_id)
                if int(item["event_id"]) <= event_id
            ]
        except (RequestNotFound, KeyError, TypeError, ValueError):
            raise WebConflict("decision event context is unavailable") from None
        if not any(int(item["event_id"]) == event_id for item in events):
            raise WebConflict("decision event context is unavailable")
        return self._get_revision_detail(
            request,
            events=events,
            version=version,
            payload_hash=payload_hash,
            historical_event=event,
        )

    def _get_revision_detail(
        self,
        request: Mapping[str, Any],
        *,
        events: Sequence[Mapping[str, Any]],
        version: int,
        payload_hash: str,
        historical_event: Mapping[str, Any] | None,
    ) -> RequestDetail:
        request_id = str(request["request_id"])
        with self._database.read() as connection:
            payload_metadata = connection.execute(
                """
                SELECT canonical_size, policy_version, adapter_version, schema_version,
                       editor_actor, purged_at, purge_reason
                FROM payload_versions
                WHERE request_id = ? AND version = ? AND payload_hash = ?
                """,
                (request_id, version, payload_hash),
            ).fetchone()
            attachment_rows = connection.execute(
                """
                SELECT attachment.attachment_id, attachment.filename,
                       attachment.mime_type, attachment.size_bytes,
                       attachment.sha256, attachment.purged_at,
                       staged.detected_mime, staged.detection_source
                FROM attachments AS attachment
                LEFT JOIN staged_objects AS staged
                  ON staged.attachment_id = attachment.attachment_id
                WHERE attachment.request_id = ? AND attachment.version = ?
                  AND attachment.payload_hash = ?
                ORDER BY attachment.attachment_id
                """,
                (request_id, version, payload_hash),
            ).fetchall()
            confirmation_rows = connection.execute(
                """
                SELECT kind, path, action, consumed_at, version, payload_hash,
                       prospective_payload_hash
                FROM confirmation_consumptions
                WHERE request_id = ? AND action IN (
                    'approve', 'deny', 'human_cancel', 'edit',
                    'promote_approval', 'promote_passthrough'
                )
                """,
                (request_id,),
            ).fetchall()
        provenance = _confirmation_provenance(confirmation_rows)
        rendered_events = tuple(_render_request_event(event, provenance) for event in events)
        if payload_metadata is None:
            return _unavailable_request_detail(
                request,
                version=version,
                payload_hash=payload_hash,
                events=rendered_events,
                payload_metadata=None,
                attachment_rows=(),
                historical_event=historical_event,
            )
        try:
            if historical_event is None:
                reviewed = self._payloads.review(
                    request_id,
                    version=version,
                    payload_hash=payload_hash,
                )
            else:
                reviewed = self._payloads.review_historical(
                    request_id,
                    version=version,
                    payload_hash=payload_hash,
                )
        except (RequestNotFound, WebPayloadError):
            return _unavailable_request_detail(
                request,
                version=version,
                payload_hash=payload_hash,
                events=rendered_events,
                payload_metadata=payload_metadata,
                attachment_rows=attachment_rows,
                historical_event=historical_event,
            )
        arguments_json = json.dumps(
            dict(reviewed.arguments),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        editable = None
        if (
            historical_event is None
            and request["state"] == "pending_approval"
            and not bool(request["gateway_internal"])
        ):
            editable = arguments_json
        account = reviewed.account_ref
        detail_now = self._clock()
        decision_window_expired = (
            historical_event is None
            and request["state"] == "pending_approval"
            and detail_now >= int(request["expires_at"])
        )
        policy_promotion_preview = None
        policy_promotion_preview_unavailable = None
        if bool(request["gateway_internal"]):
            (
                policy_promotion_preview,
                policy_promotion_preview_unavailable,
            ) = self._policy_preview(
                request_id,
                "approve",
                expected_version=version,
                expected_payload_hash=payload_hash,
                now=detail_now,
            )
        return RequestDetail(
            request_id=request_id,
            service=reviewed.summary.service,
            action=reviewed.summary.action,
            title=reviewed.summary.title,
            destination_summary=reviewed.summary.destination_summary,
            state=str(request["state"]),
            created_at=int(request["created_at"]),
            expires_at=int(request["expires_at"]),
            version=version,
            payload_hash=payload_hash,
            detail_blocks=tuple(
                DetailBlock(block.label, block.kind, block.value)
                for block in reviewed.summary.detail_blocks
            ),
            events=rendered_events,
            editable_arguments_json=editable,
            gateway_internal=bool(request["gateway_internal"]),
            warnings=reviewed.summary.warnings,
            reviewed_arguments_json=arguments_json,
            attachments=tuple(
                RequestAttachment(
                    attachment_id=str(row["attachment_id"]),
                    filename=str(row["filename"]),
                    mime_type=str(row["mime_type"]),
                    size_bytes=int(row["size_bytes"]),
                    sha256=str(row["sha256"]),
                    purged=row["purged_at"] is not None,
                    detected_mime=(
                        str(row["detected_mime"]) if row["detected_mime"] is not None else None
                    ),
                    detection_source=(
                        str(row["detection_source"])
                        if row["detection_source"] is not None
                        else None
                    ),
                )
                for row in attachment_rows
            ),
            staged_file_hashes=reviewed.staged_file_hashes,
            downstream_alias=str(request["downstream_alias"]),
            tool_name=str(request["tool_name"]),
            account_context=account,
            policy_promotion_preview=policy_promotion_preview,
            policy_promotion_preview_unavailable=policy_promotion_preview_unavailable,
            decision_window_expired=decision_window_expired,
            policy_mode=str(request["policy_mode"]),
            policy_version=str(reviewed.policy_version),
            adapter_version=reviewed.adapter_version,
            schema_version=reviewed.schema_version,
            origin_namespace=str(request["origin_namespace"]),
            retry_of_request_id=(
                str(request["retry_of_request_id"])
                if request["retry_of_request_id"] is not None
                else None
            ),
            approved_at=_optional_int(request["approved_at"]),
            execution_started_at=_optional_int(request["execution_started_at"]),
            completed_at=_optional_int(request["completed_at"]),
            safe_outcome_json=_stored_json_for_display(request["safe_outcome_json"]),
            failure_reason=(
                str(request["failure_reason"]) if request["failure_reason"] is not None else None
            ),
            manual_retry_allowed=bool(request["manual_retry_allowed"]),
            duplicate_warning_required=bool(request["duplicate_warning_required"]),
            canonical_size=int(payload_metadata["canonical_size"]),
            editor_actor=str(payload_metadata["editor_actor"]),
            historical_event_id=(
                int(historical_event["event_id"]) if historical_event is not None else None
            ),
            historical_event_action=(
                str(historical_event["action"]) if historical_event is not None else None
            ),
            historical_event_actor=(
                str(historical_event["actor"]) if historical_event is not None else None
            ),
            historical_event_occurred_at=(
                int(historical_event["occurred_at"]) if historical_event is not None else None
            ),
        )

    def get_attachment(
        self,
        principal: SessionPrincipal,
        request_id: str,
        attachment_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
    ) -> AttachmentDownload:
        self._require_ui_principal(principal)
        if (
            not isinstance(expected_version, int)
            or isinstance(expected_version, bool)
            or expected_version < 1
            or not _is_sha256(expected_payload_hash)
            or not isinstance(attachment_id, str)
            or not attachment_id.startswith("stg_")
            or not 24 <= len(attachment_id) <= 68
            or not attachment_id.isascii()
            or not attachment_id.removeprefix("stg_").replace("_", "a").isalnum()
        ):
            raise WebConflict("attachment inspection binding is invalid")
        try:
            request = self._state_machine.get_request(request_id)
        except RequestNotFound:
            raise WebConflict("frozen attachment is unavailable for inspection") from None
        if int(request["current_version"]) != expected_version or not hmac.compare_digest(
            str(request["current_payload_hash"]), expected_payload_hash
        ):
            raise WebConflict("attachment inspection binding is stale")
        with self._database.read() as connection:
            row = connection.execute(
                """
                SELECT size_bytes, sha256, storage_path, purged_at, payload_hash
                FROM attachments
                WHERE request_id = ? AND version = ? AND attachment_id = ?
                """,
                (request_id, expected_version, attachment_id),
            ).fetchone()
        if (
            row is None
            or row["storage_path"] is None
            or row["purged_at"] is not None
            or not hmac.compare_digest(str(row["payload_hash"]), expected_payload_hash)
        ):
            raise WebConflict("frozen attachment is unavailable for inspection")
        try:
            download = self._payloads.read_attachment(
                request_id,
                attachment_id,
                version=expected_version,
                payload_hash=expected_payload_hash,
            )
        except (RequestNotFound, WebPayloadError):
            raise WebConflict("frozen attachment is unavailable for inspection") from None
        if (
            download.size_bytes != int(row["size_bytes"])
            or len(download.content) != download.size_bytes
            or not hmac.compare_digest(download.sha256, str(row["sha256"]))
            or not hmac.compare_digest(
                hashlib.sha256(download.content).hexdigest(), download.sha256
            )
        ):
            raise WebConflict("frozen attachment failed integrity verification")
        return download

    def list_audit(self, principal: SessionPrincipal) -> tuple[AuditEntry, ...]:
        self._require_ui_principal(principal)
        with self._database.read() as connection:
            rows = connection.execute(
                """
                SELECT occurred_at, actor, action, request_id, payload_hash
                FROM request_events ORDER BY event_id DESC LIMIT ?
                """,
                (self.max_audit_entries,),
            ).fetchall()
        return tuple(
            AuditEntry(
                occurred_at=int(row["occurred_at"]),
                actor=str(row["actor"]),
                action=str(row["action"]),
                request_id=str(row["request_id"]),
                payload_hash_prefix=str(row["payload_hash"])[:12],
            )
            for row in rows
        )

    def list_decisions(
        self,
        principal: SessionPrincipal,
        *,
        before_event_id: int | None = None,
    ) -> DecisionPage:
        self._require_ui_principal(principal)
        if before_event_id is not None and (
            not isinstance(before_event_id, int)
            or isinstance(before_event_id, bool)
            or before_event_id < 1
            or before_event_id > (2**63 - 1)
        ):
            raise WebConflict("decision history cursor is invalid")
        with self._database.read() as connection:
            rows = connection.execute(
                """
                SELECT event.event_id, event.occurred_at, event.actor, event.action,
                       event.request_id, event.version, event.payload_hash,
                       request.state, request.downstream_alias, request.tool_name
                FROM request_events AS event
                JOIN approval_requests AS request
                  ON request.request_id = event.request_id
                WHERE (
                    event.action IN ('denied', 'approved_via_web', 'approved_via_mcp')
                    OR event.action IN (
                        'policy_promoted_to_approval',
                        'policy_promoted_to_passthrough'
                    )
                )
                  AND (? IS NULL OR event.event_id < ?)
                ORDER BY event.event_id DESC
                LIMIT ?
                """,
                (
                    before_event_id,
                    before_event_id,
                    self.max_decision_entries + 1,
                ),
            ).fetchall()
            visible = rows[: self.max_decision_entries]
            confirmation_rows: tuple[Any, ...] | list[Any] = ()
            if visible:
                request_ids = tuple(sorted({str(row["request_id"]) for row in visible}))
                confirmation_rows = connection.execute(
                    """
                    SELECT kind, path, action, request_id, consumed_at, version,
                           payload_hash, prospective_payload_hash
                    FROM confirmation_consumptions
                    WHERE request_id IN (SELECT value FROM json_each(?))
                      AND action IN (
                          'approve', 'deny',
                          'promote_approval', 'promote_passthrough'
                      )
                    """,
                    (json.dumps(request_ids),),
                ).fetchall()
        visible = rows[: self.max_decision_entries]
        has_more = len(rows) > self.max_decision_entries
        confirmation_rows_by_request: dict[str, list[Any]] = {}
        for confirmation_row in confirmation_rows:
            confirmation_rows_by_request.setdefault(str(confirmation_row["request_id"]), []).append(
                confirmation_row
            )
        provenance_by_request = {
            request_id: _confirmation_provenance(request_rows)
            for request_id, request_rows in confirmation_rows_by_request.items()
        }
        decisions: list[DecisionEntry] = []
        for row in visible:
            action = str(row["action"])
            if action == "policy_promoted_to_approval":
                decision: Literal["approved", "denied", "policy_change"] = "policy_change"
                decision_label = "Policy change approved: approval"
            elif action == "policy_promoted_to_passthrough":
                decision = "policy_change"
                decision_label = "Policy change approved: passthrough"
            elif action in {"approved_via_web", "approved_via_mcp"}:
                decision = "approved"
                decision_label = "Request approved"
            else:
                decision = "denied"
                decision_label = "Request denied"
            confirmation_action = _event_confirmation_action(action)
            provenance = provenance_by_request.get(str(row["request_id"]), {})
            confirmation_matches = (
                provenance.get(
                    (
                        confirmation_action,
                        int(row["version"]),
                        str(row["payload_hash"]),
                        int(row["occurred_at"]),
                    ),
                    ((), 0),
                )
                if confirmation_action is not None
                else ((), 0)
            )
            confirmation_path, confirmation_kind = _decision_provenance(
                confirmation_matches,
                action=action,
            )
            _proofs, confirmation_match_count = confirmation_matches
            decisions.append(
                DecisionEntry(
                    event_id=int(row["event_id"]),
                    occurred_at=int(row["occurred_at"]),
                    actor=str(row["actor"]),
                    decision=decision,
                    decision_label=decision_label,
                    confirmation_path=confirmation_path,
                    confirmation_kind=confirmation_kind,
                    request_id=str(row["request_id"]),
                    current_state=str(row["state"]),
                    downstream_alias=str(row["downstream_alias"]),
                    tool_name=str(row["tool_name"]),
                    version=int(row["version"]),
                    payload_hash_prefix=str(row["payload_hash"])[:12],
                    confirmation_attribution_ambiguous=confirmation_match_count > 1,
                    confirmation_match_count=confirmation_match_count,
                )
            )
        return DecisionPage(
            items=tuple(decisions),
            has_more=has_more,
            next_event_id=(int(visible[-1]["event_id"]) if has_more and visible else None),
        )

    def begin_passkey_action(
        self,
        principal: SessionPrincipal,
        request_id: str,
        action: HumanAction,
        *,
        expected_version: int,
        expected_payload_hash: str,
        prospective_arguments_json: str | None,
        http_method: str,
        now: int,
        decision_note: str | None = None,
    ) -> ActionOptions:
        self._require_ui_principal(principal)
        request = self._require_pending_revision(
            request_id,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            now=now,
        )
        if action != "edit":
            self._require_reviewable_revision(
                request_id,
                expected_version=expected_version,
                expected_payload_hash=expected_payload_hash,
            )
        gateway_internal = bool(request["gateway_internal"])
        if gateway_internal and action in {
            "edit",
            "promote_approval",
            "promote_passthrough",
        }:
            raise WebForbidden("gateway-internal policy proposals cannot be retargeted")
        policy_change = action in {
            "promote_approval",
            "promote_passthrough",
        } or (gateway_internal and action == "approve")
        normalized_note = _decision_note_for_action(
            action,
            decision_note,
            policy_change=policy_change,
        )
        binding_action = (
            self._policy_binding_action(
                request_id,
                action,
                expected_version=expected_version,
                expected_payload_hash=expected_payload_hash,
                now=now,
            )
            if policy_change
            else _confirmation_action(action)
        )
        prepared = self._prepare_action_edit(
            action,
            request_id=request_id,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            prospective_arguments_json=prospective_arguments_json,
        )
        binding = ActionBinding(
            binding_action,
            request_id,
            expected_version,
            expected_payload_hash,
            prepared.payload_hash if prepared is not None else None,
        )
        try:
            issued = self._webauthn_issuer.issue(
                principal.user_id,
                binding,
                session_id=principal.session_id,
                http_method=http_method,
                now=now,
            )
        except WebAuthnChallengeRateLimited as exc:
            raise WebRateLimited(str(exc)) from None
        except (WebAuthnCredentialUnavailable, ValueError) as exc:
            raise WebForbidden("passkey confirmation is unavailable") from exc
        draft = WebActionDraft(
            challenge_id=issued.challenge_id,
            action=action,
            binding=binding,
            user_id=principal.user_id,
            session_id=principal.session_id,
            policy_change=policy_change,
            prepared_edit=prepared,
            created_at=now,
            expires_at=issued.expires_at,
            decision_note=normalized_note,
        )
        try:
            self._action_drafts.save(draft)
        except Exception:
            self._webauthn_repository.invalidate_challenge(
                issued.challenge_id,
                now=now,
            )
            raise WebConflict("passkey action could not be durably staged") from None
        return ActionOptions(
            challenge_id=issued.challenge_id,
            public_key=_public_key_options(issued),
            action=action,
            request_id=request_id,
            version=expected_version,
            payload_hash=expected_payload_hash,
        )

    def complete_passkey_action(
        self,
        principal: SessionPrincipal,
        request_id: str,
        challenge_id: str,
        assertion: Mapping[str, Any],
        *,
        http_method: str,
        now: int,
    ) -> str:
        self._require_ui_principal(principal)
        draft = self._action_drafts.find(challenge_id)
        challenge = self._webauthn_repository.find_challenge(challenge_id)
        if (
            draft is None
            or challenge is None
            or draft.challenge_id != challenge_id
            or draft.binding.request_id != request_id
            or draft.user_id != principal.user_id
            or draft.session_id != principal.session_id
            or draft.binding != challenge.binding
            or challenge.user_id != principal.user_id
            or challenge.session_id != principal.session_id
            or now < draft.created_at
            or now >= draft.expires_at
        ):
            raise WebConflict("passkey action is stale or unavailable")
        self._require_reviewable_revision(
            request_id,
            expected_version=cast(int, draft.binding.version),
            expected_payload_hash=cast(str, draft.binding.payload_hash),
        )
        try:
            proof = self._webauthn_verifier.verify(
                cast(AssertionInput, assertion),
                challenge_id=challenge_id,
                user_id=principal.user_id,
                binding=draft.binding,
                session_id=principal.session_id,
                http_method=http_method,
                now=now,
            )
            confirmation = _webauthn_confirmation(proof)
            if draft.policy_change:
                return self._policy_promotions.promote(
                    draft,
                    confirmation,
                    actor=_actor(principal),
                    now=now,
                )
            return self._apply_request_action(
                draft.action,
                draft.binding,
                confirmation,
                prepared_edit=draft.prepared_edit,
                decision_note=draft.decision_note,
                actor=_actor(principal),
                now=now,
            )
        except WebAuthnChallengeUnavailable as exc:
            raise WebConflict("passkey action is stale or unavailable") from exc
        except WebAuthnError as exc:
            raise WebForbidden("passkey confirmation is invalid") from exc
        except ConfirmationReplay as exc:
            raise WebConflict("confirmation was already used") from exc
        except (InvalidConfirmation, InvalidSession) as exc:
            raise WebForbidden("passkey confirmation is invalid") from exc
        except (RequestNotFound, StaleVersion, InvalidTransition, RequestExpired) as exc:
            raise WebConflict("request changed after review") from exc
        except PolicyPromotionError as exc:
            raise WebConflict("policy change could not be applied safely") from exc

    def complete_totp_action(
        self,
        principal: SessionPrincipal,
        request_id: str,
        action: HumanAction,
        totp_proof: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        prospective_arguments_json: str | None,
        now: int,
        decision_note: str | None = None,
        credential_id: str | None = None,
    ) -> str:
        self._require_ui_principal(principal)
        request = self._require_pending_revision(
            request_id,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            now=now,
        )
        if action != "edit":
            self._require_reviewable_revision(
                request_id,
                expected_version=expected_version,
                expected_payload_hash=expected_payload_hash,
            )
        gateway_internal = bool(request["gateway_internal"])
        if gateway_internal and action in {
            "edit",
            "promote_approval",
            "promote_passthrough",
        }:
            raise WebForbidden("gateway-internal policy proposals cannot be retargeted")
        policy_change = action in {
            "promote_approval",
            "promote_passthrough",
        } or (gateway_internal and action == "approve")
        normalized_note = _decision_note_for_action(
            action,
            decision_note,
            policy_change=policy_change,
        )
        binding_action = (
            self._policy_binding_action(
                request_id,
                action,
                expected_version=expected_version,
                expected_payload_hash=expected_payload_hash,
                now=now,
            )
            if policy_change
            else _confirmation_action(action)
        )
        prepared = self._prepare_action_edit(
            action,
            request_id=request_id,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            prospective_arguments_json=prospective_arguments_json,
        )
        binding = ActionBinding(
            binding_action,
            request_id,
            expected_version,
            expected_payload_hash,
            prepared.payload_hash if prepared is not None else None,
        )
        try:
            proof = self._totp.verify(
                principal.user_id,
                totp_proof,
                binding=binding,
                source_id=f"web-action:{principal.session_id}",
                session_id=principal.session_id,
                http_method="POST",
                now=now,
                credential_id=credential_id,
            )
            confirmation = _totp_confirmation(proof)
            if policy_change:
                return self._policy_promotions.promote_totp(
                    action,
                    binding,
                    confirmation,
                    actor=_actor(principal),
                    now=now,
                )
            return self._apply_request_action(
                action,
                binding,
                confirmation,
                prepared_edit=prepared,
                decision_note=normalized_note,
                actor=_actor(principal),
                now=now,
            )
        except AuthenticationRateLimited as exc:
            raise WebRateLimited(str(exc)) from None
        except (InvalidTotp, TotpError) as exc:
            raise WebForbidden("TOTP confirmation is invalid") from exc
        except ConfirmationReplay as exc:
            raise WebConflict("confirmation was already used") from exc
        except (InvalidConfirmation, InvalidSession) as exc:
            raise WebForbidden("TOTP confirmation is invalid") from exc
        except (RequestNotFound, StaleVersion, InvalidTransition, RequestExpired) as exc:
            raise WebConflict("request changed after review") from exc
        except PolicyPromotionError as exc:
            raise WebConflict("policy change could not be applied safely") from exc

    def subscribe_push(
        self,
        principal: SessionPrincipal,
        subscription: PushSubscriptionInput,
        *,
        now: int,
    ) -> None:
        self._require_ui_principal(principal)
        try:
            categories = frozenset(NotificationKind(value) for value in subscription.categories)
            self._pushes.save(
                PushSubscription(
                    subscription_id=secrets.token_urlsafe(24),
                    user_id=principal.user_id,
                    endpoint=subscription.endpoint,
                    p256dh=subscription.p256dh,
                    auth=subscription.auth,
                    device_label=subscription.device_label,
                    categories=categories,
                    created_at=now,
                )
            )
        except ValueError:
            raise WebForbidden("push subscription is invalid or belongs to another user") from None

    def unsubscribe_push(
        self,
        principal: SessionPrincipal,
        endpoint: str,
        *,
        now: int,
    ) -> None:
        self._require_ui_principal(principal)
        self._pushes.unsubscribe(principal.user_id, endpoint, now=now)

    def _is_authorized_user(self, user_id: str) -> bool:
        try:
            selected = canonical_user_id(user_id)
        except (InvalidCredentials, TypeError, ValueError):
            return False
        return hmac.compare_digest(selected, self._authorized_user_id)

    def _require_ui_principal(self, principal: SessionPrincipal) -> None:
        if (
            not isinstance(principal, SessionPrincipal)
            or _is_preauth_method(principal.auth_method)
            or not self._is_authorized_user(principal.user_id)
        ):
            raise WebUnauthorized("a completed authorized human session is required")

    def _require_pending_revision(
        self,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        now: int,
    ) -> dict[str, Any]:
        if (
            not isinstance(expected_version, int)
            or isinstance(expected_version, bool)
            or expected_version < 1
            or not _is_sha256(expected_payload_hash)
        ):
            raise WebConflict("request changed after review")
        try:
            request = self._state_machine.get_request(request_id)
        except RequestNotFound as exc:
            raise WebConflict("request changed after review") from exc
        if (
            request["state"] != "pending_approval"
            or request["current_version"] != expected_version
            or not _same_hash(request["current_payload_hash"], expected_payload_hash)
            or now >= int(request["expires_at"])
        ):
            raise WebConflict("request changed after review")
        return request

    def _require_reviewable_revision(
        self,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
    ) -> None:
        try:
            self._payloads.review(
                request_id,
                version=expected_version,
                payload_hash=expected_payload_hash,
            )
        except (RequestNotFound, WebPayloadError):
            raise WebConflict("request content is unavailable for review") from None

    def _revoke_preauth_session(
        self,
        session_id: str,
        *,
        user_id: str,
        now: int,
    ) -> None:
        with self._database.transaction() as connection:
            connection.execute(
                """
                UPDATE web_sessions SET revoked_at = max(?, created_at)
                WHERE session_id = ? AND user_id = ? AND revoked_at IS NULL
                  AND (auth_method = 'preauth' OR auth_method LIKE 'preauth:%')
                """,
                (now, session_id, user_id),
            )

    def _prepare_action_edit(
        self,
        action: HumanAction,
        *,
        request_id: str,
        expected_version: int,
        expected_payload_hash: str,
        prospective_arguments_json: str | None,
    ) -> PreparedEdit | None:
        if action == "edit":
            if prospective_arguments_json is None:
                raise WebConflict("edited arguments are required")
            try:
                return self._payloads.prepare_edit(
                    request_id,
                    expected_version=expected_version,
                    expected_payload_hash=expected_payload_hash,
                    prospective_arguments_json=prospective_arguments_json,
                )
            except (RequestNotFound, WebPayloadError):
                raise WebConflict("edited arguments are invalid or stale") from None
        if prospective_arguments_json is not None:
            raise WebConflict("only edits may carry prospective arguments")
        return None

    def _policy_binding_action(
        self,
        request_id: str,
        action: HumanAction,
        *,
        expected_version: int,
        expected_payload_hash: str,
        now: int,
    ) -> ConfirmationAction:
        try:
            return self._policy_promotions.binding_action(
                request_id,
                action,
                expected_version=expected_version,
                expected_payload_hash=expected_payload_hash,
                now=now,
            )
        except PolicyPromotionError as exc:
            raise WebConflict("policy change could not be staged safely") from exc
        except (RequestNotFound, StaleVersion, InvalidTransition, RequestExpired) as exc:
            raise WebConflict("request changed after review") from exc

    def _policy_preview(
        self,
        request_id: str,
        action: HumanAction,
        *,
        expected_version: int,
        expected_payload_hash: str,
        now: int,
    ) -> tuple[PolicyPromotionPreview | None, str | None]:
        try:
            return (
                self._policy_promotions.preview(
                    request_id,
                    action,
                    expected_version=expected_version,
                    expected_payload_hash=expected_payload_hash,
                    now=now,
                ),
                None,
            )
        except (
            PolicyPromotionError,
            RequestNotFound,
            StaleVersion,
            InvalidTransition,
            RequestExpired,
            WebPayloadError,
            PolicyError,
        ):
            return None, _POLICY_PREVIEW_UNAVAILABLE

    def _apply_request_action(
        self,
        action: HumanAction,
        binding: ActionBinding,
        confirmation: ApprovalConfirmation,
        *,
        prepared_edit: PreparedEdit | None,
        decision_note: str | None,
        actor: str,
        now: int,
    ) -> str:
        request_id = cast(str, binding.request_id)
        version = cast(int, binding.version)
        payload_hash = cast(str, binding.payload_hash)
        if action == "approve":
            self._state_machine.approve(
                request_id,
                expected_version=version,
                expected_payload_hash=payload_hash,
                confirmation=confirmation,
                actor=actor,
                now=now,
                decision_note=decision_note,
            )
            return "approved"
        if action == "deny":
            self._state_machine.deny(
                request_id,
                expected_version=version,
                expected_payload_hash=payload_hash,
                confirmation=confirmation,
                actor=actor,
                now=now,
                decision_note=decision_note,
            )
            return "denied"
        if action == "cancel":
            self._state_machine.cancel(
                request_id,
                expected_version=version,
                expected_payload_hash=payload_hash,
                confirmation=confirmation,
                actor=actor,
                now=now,
            )
            return "cancelled"
        if action == "edit" and prepared_edit is not None:
            if not hmac.compare_digest(
                prepared_edit.payload_hash,
                cast(str, binding.prospective_payload_hash),
            ):
                raise InvalidConfirmation("prepared edit does not match its confirmation")
            self._state_machine.edit(
                request_id,
                expected_version=version,
                expected_payload_hash=payload_hash,
                encrypted_payload=prepared_edit.encrypted_payload,
                payload_hash=prepared_edit.payload_hash,
                canonical_size=prepared_edit.canonical_size,
                policy_version=prepared_edit.policy_version,
                adapter_version=prepared_edit.adapter_version,
                schema_version=prepared_edit.schema_version,
                editor_actor=actor,
                confirmation=confirmation,
                now=now,
                encryption_key_ref=prepared_edit.encryption_key_ref,
            )
            return "pending_approval"
        raise InvalidConfirmation("action draft does not match its confirmation")


def _unavailable_request_detail(
    request: Mapping[str, Any],
    *,
    version: int,
    payload_hash: str,
    events: tuple[dict[str, Any], ...],
    payload_metadata: Any | None,
    attachment_rows: tuple[Any, ...] | list[Any],
    historical_event: Mapping[str, Any] | None,
) -> RequestDetail:
    purged = payload_metadata is not None and payload_metadata["purged_at"] is not None
    unavailable_message = (
        "Private reviewed content was purged under the retention policy."
        if purged
        else "Private reviewed content is unavailable and could not be authenticated."
    )

    def metadata_text(name: str) -> str:
        if payload_metadata is None:
            return "unavailable"
        value = payload_metadata[name]
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            return str(value)
        return "unavailable"

    retained_attachments = (
        tuple(
            RequestAttachment(
                attachment_id=str(row["attachment_id"]),
                filename=str(row["filename"]),
                mime_type=str(row["mime_type"]),
                size_bytes=int(row["size_bytes"]),
                sha256=str(row["sha256"]),
                purged=row["purged_at"] is not None,
                detected_mime=(
                    str(row["detected_mime"]) if row["detected_mime"] is not None else None
                ),
                detection_source=(
                    str(row["detection_source"]) if row["detection_source"] is not None else None
                ),
            )
            for row in attachment_rows
        )
        if purged
        else ()
    )
    return RequestDetail(
        request_id=str(request["request_id"]),
        service=str(request["downstream_alias"]),
        action=str(request["tool_name"]),
        title="Reviewed content purged" if purged else "Reviewed content unavailable",
        destination_summary=unavailable_message,
        state=str(request["state"]),
        created_at=int(request["created_at"]),
        expires_at=int(request["expires_at"]),
        version=version,
        payload_hash=payload_hash,
        detail_blocks=(),
        events=events,
        editable_arguments_json=None,
        gateway_internal=bool(request["gateway_internal"]),
        warnings=(unavailable_message,),
        reviewed_arguments_json=None,
        attachments=retained_attachments,
        staged_file_hashes=tuple(attachment.sha256 for attachment in retained_attachments),
        downstream_alias=str(request["downstream_alias"]),
        tool_name=str(request["tool_name"]),
        policy_mode=str(request["policy_mode"]),
        policy_version=metadata_text("policy_version"),
        adapter_version=metadata_text("adapter_version"),
        schema_version=metadata_text("schema_version"),
        origin_namespace=str(request["origin_namespace"]),
        retry_of_request_id=(
            str(request["retry_of_request_id"])
            if request["retry_of_request_id"] is not None
            else None
        ),
        approved_at=_optional_int(request["approved_at"]),
        execution_started_at=_optional_int(request["execution_started_at"]),
        completed_at=_optional_int(request["completed_at"]),
        safe_outcome_json=_stored_json_for_display(request["safe_outcome_json"]),
        failure_reason=(
            str(request["failure_reason"]) if request["failure_reason"] is not None else None
        ),
        manual_retry_allowed=bool(request["manual_retry_allowed"]),
        duplicate_warning_required=bool(request["duplicate_warning_required"]),
        review_available=False,
        content_purged=purged,
        content_purged_at=(
            _optional_int(payload_metadata["purged_at"]) if payload_metadata is not None else None
        ),
        content_purge_reason=(
            str(payload_metadata["purge_reason"])
            if payload_metadata is not None and payload_metadata["purge_reason"] is not None
            else None
        ),
        canonical_size=(
            _optional_int(payload_metadata["canonical_size"])
            if payload_metadata is not None
            else None
        ),
        editor_actor=(
            str(payload_metadata["editor_actor"])
            if payload_metadata is not None and payload_metadata["editor_actor"] is not None
            else None
        ),
        historical_event_id=(
            int(historical_event["event_id"]) if historical_event is not None else None
        ),
        historical_event_action=(
            str(historical_event["action"]) if historical_event is not None else None
        ),
        historical_event_actor=(
            str(historical_event["actor"]) if historical_event is not None else None
        ),
        historical_event_occurred_at=(
            int(historical_event["occurred_at"]) if historical_event is not None else None
        ),
    )


def _render_request_event(
    event: Mapping[str, Any],
    provenance: Mapping[ConfirmationKey, ConfirmationMatches],
) -> dict[str, Any]:
    action = str(event["action"])
    details_json, decision_note = _event_details(event["safe_details_json"], action=action)
    confirmation_action = _event_confirmation_action(action)
    confirmation_matches = (
        provenance.get(
            (
                confirmation_action,
                int(event["version"]),
                str(event["payload_hash"]),
                int(event["occurred_at"]),
            ),
            ((), 0),
        )
        if confirmation_action is not None
        else ((), 0)
    )
    confirmation_proofs, confirmation_match_count = confirmation_matches
    unambiguous = confirmation_match_count == 1
    confirmation_kind = confirmation_proofs[0][0] if unambiguous else None
    confirmation_path = confirmation_proofs[0][1] if unambiguous else None
    if not confirmation_proofs and action in {"approved_via_web", "approved_via_mcp"}:
        candidate = action.removeprefix("approved_via_")
        if candidate in {"web", "mcp"}:
            confirmation_path = candidate
    return {
        "event_id": int(event["event_id"]),
        "occurred_at": int(event["occurred_at"]),
        "actor": str(event["actor"]),
        "action": action,
        "version": int(event["version"]),
        "payload_hash": str(event["payload_hash"]),
        "details_json": details_json,
        "decision_note": decision_note,
        "confirmation_kind": confirmation_kind,
        "confirmation_path": confirmation_path,
        "confirmation_proofs": tuple(
            {"kind": kind, "path": path} for kind, path in confirmation_proofs
        ),
        "confirmation_match_count": confirmation_match_count,
        "confirmation_attribution_ambiguous": confirmation_match_count > 1,
        # Caller-originated cancellation has the same event action as a human cancel,
        # but only the latter has a confirmation consumption to render.
        "decision_confirmation": confirmation_action is not None
        and (action != "cancelled" or bool(confirmation_proofs)),
    }


def _confirmation_provenance(
    rows: tuple[Any, ...] | list[Any],
) -> dict[ConfirmationKey, ConfirmationMatches]:
    grouped: dict[ConfirmationKey, set[ConfirmationProof]] = {}
    match_counts: dict[ConfirmationKey, int] = {}
    for row in rows:
        action = str(row["action"])
        kind = str(row["kind"])
        path = str(row["path"])
        if (
            action
            not in {
                "approve",
                "deny",
                "human_cancel",
                "edit",
                "promote_approval",
                "promote_passthrough",
            }
            or kind not in {"totp", "webauthn"}
            or path
            not in {
                "web",
                "mcp",
            }
        ):
            raise WebConflict("request confirmation provenance is unavailable")
        try:
            version = int(row["version"])
            consumed_at = int(row["consumed_at"])
        except (TypeError, ValueError):
            raise WebConflict("request confirmation provenance is unavailable") from None
        payload_hash = str(row["payload_hash"])
        prospective_payload_hash = row["prospective_payload_hash"]
        if version < 1 or consumed_at < 0 or not _is_sha256(payload_hash):
            raise WebConflict("request confirmation provenance is unavailable")
        if action == "edit":
            if not _is_sha256(prospective_payload_hash):
                raise WebConflict("request confirmation provenance is unavailable")
            version += 1
            payload_hash = str(prospective_payload_hash)
        elif prospective_payload_hash is not None:
            raise WebConflict("request confirmation provenance is unavailable")
        key = (action, version, payload_hash, consumed_at)
        grouped.setdefault(key, set()).add((kind, path))
        match_counts[key] = match_counts.get(key, 0) + 1
    return {key: (tuple(sorted(proofs)), match_counts[key]) for key, proofs in grouped.items()}


def _event_confirmation_action(action: str) -> ConfirmationAction | None:
    actions: dict[str, ConfirmationAction] = {
        "approved_via_web": "approve",
        "approved_via_mcp": "approve",
        "denied": "deny",
        "cancelled": "human_cancel",
        "payload_edited": "edit",
        "policy_promoted_to_approval": "promote_approval",
        "policy_promoted_to_passthrough": "promote_passthrough",
    }
    return actions.get(action)


def _event_decision_action(action: str) -> Literal["approve", "deny"] | None:
    if action in {"approved_via_web", "approved_via_mcp"}:
        return "approve"
    if action == "denied":
        return "deny"
    return None


def _decision_provenance(
    matches: ConfirmationMatches,
    *,
    action: str,
) -> tuple[str | None, str | None]:
    proofs, match_count = matches
    if match_count > 1:
        return None, None
    if match_count == 1 and len(proofs) == 1:
        kind, path = proofs[0]
        return path, kind
    fallback_path: str | None = None
    if action in {"approved_via_web", "approved_via_mcp"}:
        candidate = action.removeprefix("approved_via_")
        if candidate in {"web", "mcp"}:
            fallback_path = candidate
    return fallback_path, None


def _event_details(value: object, *, action: str) -> tuple[str | None, str | None]:
    if value is None:
        return None, None
    if not isinstance(value, str):
        raise WebConflict("request event details are unavailable")
    try:
        details = _strict_json_object(value)
    except WebPayloadError:
        raise WebConflict("request event details are unavailable") from None
    note_present = "decision_note" in details
    note_value = details.pop("decision_note", None)
    decision_note = None
    if note_present:
        try:
            candidate = normalize_decision_note(note_value)
            if candidate is None or candidate != note_value:
                raise ValueError
            decision_action = _event_decision_action(action)
            if candidate == "legacy_unstructured_reason":
                if decision_action is None:
                    raise ValueError
            elif decision_action is None:
                raise ValueError
            else:
                reason_for_action(decision_action, candidate)
            decision_reason_label(candidate)
        except (TypeError, ValueError):
            raise WebConflict("request event decision reason is unavailable") from None
        decision_note = candidate
    details_json = (
        json.dumps(
            details,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        if details
        else None
    )
    return details_json, decision_note


def _stored_json_for_display(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise WebConflict("request outcome details are unavailable")
    try:
        details = _strict_json_object(value)
    except WebPayloadError:
        raise WebConflict("request outcome details are unavailable") from None
    return json.dumps(
        details,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    )


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise WebConflict("request timestamps are unavailable")
    return value


def _encode_queue_cursor(row: Any) -> str:
    priority = 0 if str(row["state"]) == "outcome_unknown" else 1
    raw = json.dumps(
        {
            "priority": priority,
            "created_at": int(row["created_at"]),
            "request_id": str(row["request_id"]),
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_queue_cursor(value: str) -> tuple[int, int, str]:
    if (
        not value
        or len(value) > 512
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in value
        )
    ):
        raise WebConflict("queue page cursor is invalid")
    try:
        padded = value + "=" * (-len(value) % 4)
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
        decoded = _strict_json_object(raw)
    except (binascii.Error, ValueError, WebPayloadError):
        raise WebConflict("queue page cursor is invalid") from None
    if set(decoded) != {"priority", "created_at", "request_id"}:
        raise WebConflict("queue page cursor is invalid")
    priority = decoded["priority"]
    created_at = decoded["created_at"]
    request_id = decoded["request_id"]
    if (
        not isinstance(priority, int)
        or isinstance(priority, bool)
        or priority not in {0, 1}
        or not isinstance(created_at, int)
        or isinstance(created_at, bool)
        or created_at < 0
        or created_at > (2**63) - 1
        or not isinstance(request_id, str)
        or len(request_id) < 5
        or len(request_id) > 132
        or not request_id.startswith("req_")
        or not request_id[4:].isalnum()
        or not request_id.isascii()
    ):
        raise WebConflict("queue page cursor is invalid")
    return priority, created_at, request_id


def _confirmation_action(action: HumanAction) -> ConfirmationAction:
    values: dict[str, ConfirmationAction] = {
        "approve": "approve",
        "deny": "deny",
        "cancel": "human_cancel",
        "edit": "edit",
        "promote_approval": "promote_approval",
        "promote_passthrough": "promote_passthrough",
    }
    try:
        return values[action]
    except KeyError:
        raise WebForbidden("unsupported human action") from None


def _decision_note_for_action(
    action: HumanAction,
    value: str | None,
    *,
    policy_change: bool,
) -> str | None:
    try:
        normalized = normalize_decision_note(value)
    except ValueError:
        raise WebConflict("decision rationale is invalid") from None
    if normalized is not None and (action not in {"approve", "deny"} or policy_change):
        raise WebConflict("decision rationale does not match this action")
    if action in {"approve", "deny"} and not policy_change:
        if normalized is None:
            raise WebConflict("a decision reason is required")
        try:
            return reason_for_action(action, normalized)
        except ValueError:
            raise WebConflict("decision rationale is invalid") from None
    return normalized


def _totp_confirmation(proof: VerifiedTotp) -> ApprovalConfirmation:
    binding = proof.binding
    reservation = proof.attempt_reservation
    return ApprovalConfirmation(
        kind=ConfirmationKind.TOTP,
        use_id=proof.use_id,
        path="web",
        capability=proof.capability,
        user_id=proof.user_id,
        action=binding.action,
        bound_request_id=binding.request_id,
        bound_version=binding.version,
        bound_payload_hash=binding.payload_hash,
        prospective_payload_hash=binding.prospective_payload_hash,
        session_id=proof.session_id,
        http_method=proof.http_method,
        attempt_id=reservation.attempt_id,
        attempt_scope_keys=reservation.scope_keys,
        rate_limit_key=proof.rate_limit_key,
        credential_id=proof.credential_id,
        credential_user_id=proof.user_id,
        verified_at=proof.verified_at,
        expires_at=proof.expires_at,
    )


def _webauthn_confirmation(proof: VerifiedWebAuthn) -> ApprovalConfirmation:
    binding = proof.binding
    return ApprovalConfirmation(
        kind=ConfirmationKind.WEBAUTHN,
        use_id=proof.use_id,
        path="web",
        capability=proof.capability,
        user_id=proof.user_id,
        action=binding.action,
        bound_request_id=binding.request_id,
        bound_version=binding.version,
        bound_payload_hash=binding.payload_hash,
        prospective_payload_hash=binding.prospective_payload_hash,
        session_id=proof.session_id,
        http_method=proof.http_method,
        challenge_id=proof.challenge_id,
        credential_id=proof.credential_id,
        credential_user_id=proof.user_id,
        expected_counter=proof.expected_counter,
        new_counter=proof.new_counter,
        device_type=proof.device_type,
        expected_backup_eligible=proof.expected_backup_eligible,
        new_backup_eligible=proof.new_backup_eligible,
        previous_backed_up=proof.previous_backed_up,
        new_backed_up=proof.new_backed_up,
        verified_at=proof.verified_at,
        expires_at=proof.expires_at,
    )


def _public_key_options(issued: IssuedWebAuthnChallenge) -> dict[str, Any]:
    value = _strict_json_object(issued.options_json)
    return value


def _strict_json_object(value: bytes | str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = child
        return result

    def invalid_constant(_: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        decoded = json.loads(
            value,
            object_pairs_hook=pairs,
            parse_constant=invalid_constant,
        )
    except (json.JSONDecodeError, TypeError, UnicodeError, ValueError):
        raise WebPayloadError("private JSON object is invalid") from None
    if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
        raise WebPayloadError("private JSON object is invalid")
    return cast(dict[str, Any], decoded)


def _same_hash(value: object, expected: str) -> bool:
    return (
        isinstance(value, str)
        and _is_sha256(value)
        and _is_sha256(expected)
        and hmac.compare_digest(value, expected)
    )


def _attachment_identity(
    attachment: AttachmentReference,
) -> tuple[str, str, str, int, str, str]:
    if not isinstance(attachment, AttachmentReference):
        raise WebPayloadError("private payload attachment snapshot is invalid")
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


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _SHA256


def _actor(principal: SessionPrincipal) -> str:
    return f"web:{principal.user_id}"


def _is_preauth_method(auth_method: str) -> bool:
    return auth_method == "preauth" or auth_method.startswith(_PREAUTH_PREFIX)
