"""Persistent application backend for the private Signet web UI.

This module deliberately contains no downstream client.  It authenticates the
human session, renders authenticated frozen requests, and hands confirmed
mutations to persistence boundaries that own their transaction.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Mapping
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
from signet.state_machine import ApprovalStateMachine
from signet.totp import (
    InvalidTotp,
    TotpError,
    TotpVerifier,
    VerifiedTotp,
)
from signet.web import (
    ActionOptions,
    AuditEntry,
    DetailBlock,
    HumanAction,
    LoginOptions,
    PushSubscriptionInput,
    QueueItem,
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

_ENVELOPE_FIELDS = frozenset(
    {
        "adapter_version",
        "alias",
        "arguments",
        "policy_version",
        "staged_file_hashes",
        "tool",
    }
)
_PREAUTH_PREFIX = "preauth:"
_SHA256 = frozenset("0123456789abcdef")


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
    policy_version: int
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

    def prepare_edit(
        self,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        prospective_arguments_json: str,
    ) -> PreparedEdit: ...


class EncryptedPayloadReviewer:
    """Decrypt, authenticate, and adapter-validate exact current revisions."""

    def __init__(
        self,
        state_machine: ApprovalStateMachine,
        codec: PayloadCodec,
        adapters: Mapping[tuple[str, str], ApprovalAdapter],
        *,
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
        self._state_machine = state_machine
        self._codec = codec
        self._adapters = dict(adapters)
        self.max_payload_bytes = max_payload_bytes

    def review(
        self,
        request_id: str,
        *,
        version: int,
        payload_hash: str,
    ) -> ReviewedPayload:
        request = self._state_machine.get_request(request_id)
        if request["current_version"] != version or not _same_hash(
            request["current_payload_hash"], payload_hash
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
        adapter_version = envelope["adapter_version"]
        policy_version = envelope["policy_version"]
        arguments = envelope["arguments"]
        staged_hashes = envelope["staged_file_hashes"]
        if (
            not isinstance(alias, str)
            or alias != request["downstream_alias"]
            or not isinstance(tool, str)
            or tool != request["tool_name"]
            or not isinstance(adapter_version, str)
            or adapter_version != payload["adapter_version"]
            or not isinstance(policy_version, int)
            or isinstance(policy_version, bool)
            or policy_version < 1
            or str(policy_version) != str(payload["policy_version"])
            or not isinstance(arguments, dict)
            or not isinstance(staged_hashes, list)
            or any(not _is_sha256(item) for item in staged_hashes)
        ):
            raise WebPayloadError("private payload metadata does not match its revision")
        try:
            adapter = self._adapters[(alias, tool)]
        except KeyError:
            raise WebPayloadError("no reviewed adapter matches the private payload") from None
        if adapter.adapter_version != adapter_version:
            raise WebPayloadError("reviewed adapter version does not match the payload")
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
            policy_version=policy_version,
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
                "adapter_version": reviewed.adapter_version,
                "alias": reviewed.adapter.downstream_alias,
                "arguments": arguments,
                "policy_version": reviewed.policy_version,
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
    """Atomic durable boundary for one passkey-authorized policy promotion.

    An implementation must recheck the exact pending request revision, verify
    and consume the unchanged confirmation capability/challenge/credential
    state, apply the reviewed policy change, and append its audit record in one
    transaction.  No in-memory implementation is supplied here.
    """

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
        passkey_login_window_seconds: int = 10 * 60,
        passkey_login_source_limit: int = 20,
        passkey_login_account_limit: int = 10,
        passkey_login_global_limit: int = 200,
    ) -> None:
        if max_audit_entries <= 0 or max_audit_entries > 10_000:
            raise ValueError("audit read limit is invalid")
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
        self._passkey_login_window_seconds = passkey_login_window_seconds
        self._passkey_login_source_limit = passkey_login_source_limit
        self._passkey_login_account_limit = passkey_login_account_limit
        self._passkey_login_global_limit = passkey_login_global_limit

    def authenticate(self, token: str | None, *, now: int) -> SessionPrincipal:
        principal = self._sessions.authenticate(token, now=now)
        if _is_preauth_method(principal.auth_method):
            raise InvalidSession("authentication has not completed")
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
            credentials = self._webauthn_repository.credentials_for_user(canonical_user)
        except (TypeError, ValueError, WebAuthnError):
            canonical_user = None
            credentials = ()
        try:
            self._reserve_passkey_login(
                source,
                account=canonical_user if credentials else None,
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
            placeholders = ",".join("?" for _ in scopes)
            rows = {
                str(row["scope_key"]): row
                for row in connection.execute(
                    f"SELECT * FROM auth_attempts WHERE scope_key IN ({placeholders})",
                    tuple(scope for scope, _limit in scopes),
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
        if challenge is None or challenge.binding != ActionBinding("login"):
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
    ) -> tuple[QueueItem, ...]:
        _require_ui_principal(principal)
        with self._database.read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM approval_requests
                WHERE state = 'outcome_unknown'
                   OR (state = 'pending_approval' AND expires_at > ?)
                ORDER BY CASE state WHEN 'outcome_unknown' THEN 0 ELSE 1 END,
                         created_at, request_id
                """,
                (now,),
            ).fetchall()
        items: list[QueueItem] = []
        for row in rows:
            try:
                reviewed = self._payloads.review(
                    str(row["request_id"]),
                    version=int(row["current_version"]),
                    payload_hash=str(row["current_payload_hash"]),
                )
            except (RequestNotFound, WebPayloadError):
                raise WebConflict("a queued request could not be reviewed") from None
            items.append(
                QueueItem(
                    request_id=str(row["request_id"]),
                    service=reviewed.summary.service,
                    action=reviewed.summary.action,
                    destination_summary=reviewed.summary.destination_summary,
                    state=str(row["state"]),
                    created_at=int(row["created_at"]),
                    expires_at=int(row["expires_at"]),
                    version=int(row["current_version"]),
                    payload_hash=str(row["current_payload_hash"]),
                )
            )
        return tuple(items)

    def get_detail(self, principal: SessionPrincipal, request_id: str) -> RequestDetail:
        _require_ui_principal(principal)
        try:
            request = self._state_machine.get_request(request_id)
            reviewed = self._payloads.review(
                request_id,
                version=int(request["current_version"]),
                payload_hash=str(request["current_payload_hash"]),
            )
            events = self._state_machine.list_events(request_id)
        except (RequestNotFound, WebPayloadError):
            raise WebConflict("request details are unavailable") from None
        arguments_json = json.dumps(
            dict(reviewed.arguments),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        editable = None
        if request["state"] == "pending_approval":
            editable = arguments_json
        with self._database.read() as connection:
            attachment_rows = connection.execute(
                """
                SELECT attachment_id, filename, mime_type, size_bytes, sha256, purged_at
                FROM attachments
                WHERE request_id = ? AND version = ?
                ORDER BY attachment_id
                """,
                (request_id, int(request["current_version"])),
            ).fetchall()
        account = getattr(reviewed.adapter, "account", None)
        if not isinstance(account, str) or not account:
            account = None
        return RequestDetail(
            request_id=request_id,
            service=reviewed.summary.service,
            action=reviewed.summary.action,
            title=reviewed.summary.title,
            destination_summary=reviewed.summary.destination_summary,
            state=str(request["state"]),
            created_at=int(request["created_at"]),
            expires_at=int(request["expires_at"]),
            version=int(request["current_version"]),
            payload_hash=str(request["current_payload_hash"]),
            detail_blocks=tuple(
                DetailBlock(block.label, block.kind, block.value)
                for block in reviewed.summary.detail_blocks
            ),
            events=tuple(
                {
                    "occurred_at": int(event["occurred_at"]),
                    "actor": str(event["actor"]),
                    "action": str(event["action"]),
                    "version": int(event["version"]),
                    "payload_hash": str(event["payload_hash"]),
                    "details_json": _event_details_json(event["safe_details_json"]),
                }
                for event in events
            ),
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
                )
                for row in attachment_rows
            ),
            staged_file_hashes=reviewed.staged_file_hashes,
            downstream_alias=str(request["downstream_alias"]),
            tool_name=str(request["tool_name"]),
            account_context=account,
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
        )

    def list_audit(self, principal: SessionPrincipal) -> tuple[AuditEntry, ...]:
        _require_ui_principal(principal)
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
    ) -> ActionOptions:
        _require_ui_principal(principal)
        request = self._require_pending_revision(
            request_id,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            now=now,
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
        _require_ui_principal(principal)
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
    ) -> str:
        _require_ui_principal(principal)
        request = self._require_pending_revision(
            request_id,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            now=now,
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
        _require_ui_principal(principal)
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
        _require_ui_principal(principal)
        self._pushes.unsubscribe(principal.user_id, endpoint, now=now)

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

    def _apply_request_action(
        self,
        action: HumanAction,
        binding: ActionBinding,
        confirmation: ApprovalConfirmation,
        *,
        prepared_edit: PreparedEdit | None,
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


def _event_details_json(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise WebConflict("request event details are unavailable")
    try:
        details = _strict_json_object(value)
    except WebPayloadError:
        raise WebConflict("request event details are unavailable") from None
    return json.dumps(
        details,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    )


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


def _require_ui_principal(principal: SessionPrincipal) -> None:
    if not isinstance(principal, SessionPrincipal) or _is_preauth_method(principal.auth_method):
        raise WebUnauthorized("a completed human session is required")


def _actor(principal: SessionPrincipal) -> str:
    return f"web:{principal.user_id}"


def _is_preauth_method(auth_method: str) -> bool:
    return auth_method == "preauth" or auth_method.startswith(_PREAUTH_PREFIX)
