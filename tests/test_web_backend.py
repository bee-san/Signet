from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from argon2 import PasswordHasher

from signet.adapters.base import (
    ApprovalAdapter,
    ApprovalSummary,
)
from signet.adapters.base import (
    DetailBlock as AdapterDetailBlock,
)
from signet.adapters.fastmail import FastmailAdapter
from signet.auth import (
    WEBAUTHN_PROOF_DOMAIN,
    ActionBinding,
    Argon2PasswordVerifier,
    InvalidSession,
    PasswordAuthenticator,
    PasswordCredential,
    ProofCapability,
    SessionManager,
    SessionPrincipal,
    SQLiteAttemptLimiter,
    SQLiteAuthenticationTransactions,
    SQLitePasswordCredentialRepository,
    SQLiteSessionRepository,
    webauthn_proof_claims,
)
from signet.credential_broker import MemorySecretStore, Secret
from signet.crypto import PayloadCipher
from signet.db import Database
from signet.freezer import RequestFreezer
from signet.models import ApprovalConfirmation, AttachmentReference
from signet.notifications import NotificationKind, SQLitePushRepository
from signet.staging import StagingStore
from signet.state_machine import ApprovalStateMachine
from signet.totp import (
    SQLiteTotpCredentialRepository,
    TotpCredential,
    TotpVerifier,
)
from signet.web import (
    PushSubscriptionInput,
    WebConflict,
    WebForbidden,
    WebRateLimited,
    WebUnauthorized,
)
from signet.web_backend import (
    ActionDraftRepository,
    EncryptedPayloadReviewer,
    PolicyPromotionBoundary,
    PreparedEdit,
    PrivatePayloadReviewer,
    ReviewedPayload,
    WebActionDraft,
    WebBackend,
    WebPayloadError,
)
from signet.webauthn import (
    FakeAssertion,
    FakeWebAuthnProvider,
    SQLiteWebAuthnRepository,
    WebAuthnAssertionVerifier,
    WebAuthnChallengeIssuer,
    WebAuthnCredential,
)
from tests.attachment_fixtures import attachment_cipher

NOW = 1_800_000_000
USER_ID = "autumn"
SECOND_USER_ID = "river"
PASSWORD = "fake-correct-password"
RP_ID = "signet.test"
ORIGIN = f"https://{RP_ID}"
SESSION_KEY = b"web-backend-session-signing-key-0001"
CAPABILITY_KEY = b"web-backend-proof-capability-key-0001"
CAPABILITIES = ProofCapability(CAPABILITY_KEY)
MASTER_SECRET = "fake-web-backend-payload-master-key-0001"
KEY_REFERENCE = "keychain://Signet/fake-web-backend-payload-key"
TOTP_REFERENCE = "keychain://Signet/web-backend-totp"
WEB_CREDENTIAL_ID = base64.urlsafe_b64encode(b"fake-web-backend-credential").rstrip(b"=").decode()
P256DH = base64.urlsafe_b64encode(b"\x04" + b"p" * 64).rstrip(b"=").decode()
PUSH_AUTH = base64.urlsafe_b64encode(b"a" * 16).rstrip(b"=").decode()


class VariableFakeTotpProvider:
    test_only = True

    def verify_step(self, secret: Secret, proof: str, *, now: int) -> int | None:
        del secret, now
        if not proof.startswith("fake:"):
            return None
        try:
            step = int(proof.removeprefix("fake:"))
        except ValueError:
            return None
        return step if step >= 0 else None


class ReviewOnlyAdapter:
    adapter_id = "fake.review-only"
    adapter_version = "7"
    downstream_alias = "fake-service"
    tool_name = "create_item"
    communication_send = False
    supports_idempotency = False
    reconciliation_tools: frozenset[str] = frozenset()
    input_schema: Mapping[str, Any] = {"type": "object"}

    def __init__(self) -> None:
        self.downstream_calls: list[str] = []

    def canonicalize(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if set(arguments) != {"recipient", "body"}:
            raise ValueError("fake arguments are invalid")
        recipient = arguments["recipient"]
        body = arguments["body"]
        if not isinstance(recipient, str) or not isinstance(body, str):
            raise ValueError("fake arguments are invalid")
        return {"body": body, "recipient": recipient}

    def freeze_attachments(self, arguments: Mapping[str, Any]) -> tuple[AttachmentReference, ...]:
        self.canonicalize(arguments)
        return ()

    def summarize_for_web(self, arguments: Mapping[str, Any]) -> ApprovalSummary:
        canonical = self.canonicalize(arguments)
        return ApprovalSummary(
            service="Fake service",
            action="Create item",
            title="Review private item",
            destination_summary=cast(str, canonical["recipient"]),
            detail_blocks=(AdapterDetailBlock("Body", "plain_text", canonical["body"]),),
        )

    def __getattr__(self, name: str) -> Any:
        if name in {
            "prepare_for_execution",
            "execute",
            "classify_outcome",
            "reconcile",
            "safe_result_metadata",
        }:
            self.downstream_calls.append(name)
            raise AssertionError("the web backend crossed a downstream boundary")
        raise AttributeError(name)


@dataclass
class ReviewerSpy:
    delegate: PrivatePayloadReviewer
    review_calls: list[tuple[str, int, str]] = field(default_factory=list)

    def review(
        self,
        request_id: str,
        *,
        version: int,
        payload_hash: str,
    ) -> ReviewedPayload:
        self.review_calls.append((request_id, version, payload_hash))
        return self.delegate.review(request_id, version=version, payload_hash=payload_hash)

    def prepare_edit(
        self,
        request_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        prospective_arguments_json: str,
    ) -> PreparedEdit:
        return self.delegate.prepare_edit(
            request_id,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            prospective_arguments_json=prospective_arguments_json,
        )


@dataclass
class DraftBacking:
    records: dict[str, WebActionDraft] = field(default_factory=dict)


class DurableFakeDraftRepository:
    def __init__(self, backing: DraftBacking) -> None:
        self.backing = backing

    def save(self, draft: WebActionDraft) -> None:
        if draft.challenge_id in self.backing.records:
            raise ValueError("draft already exists")
        self.backing.records[draft.challenge_id] = draft

    def find(self, challenge_id: str) -> WebActionDraft | None:
        return self.backing.records.get(challenge_id)


@dataclass
class FakePolicyPromotionBoundary:
    calls: list[tuple[WebActionDraft, ApprovalConfirmation, str, int]] = field(default_factory=list)
    totp_calls: list[tuple[str, ActionBinding, ApprovalConfirmation, str, int]] = field(
        default_factory=list
    )

    def binding_action(
        self,
        request_id: str,
        action: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        now: int,
    ) -> str:
        del request_id, expected_version, expected_payload_hash, now
        return action if action.startswith("promote_") else "promote_approval"

    def promote(
        self,
        draft: WebActionDraft,
        confirmation: ApprovalConfirmation,
        *,
        actor: str,
        now: int,
    ) -> str:
        self.calls.append((draft, confirmation, actor, now))
        return "policy_updated"

    def promote_totp(
        self,
        action: str,
        binding: ActionBinding,
        confirmation: ApprovalConfirmation,
        *,
        actor: str,
        now: int,
    ) -> str:
        self.totp_calls.append((action, binding, confirmation, actor, now))
        return "policy_updated"


@dataclass
class BackendBundle:
    database: Database
    backend: WebBackend
    sessions: SessionManager
    state_machine: ApprovalStateMachine
    webauthn: SQLiteWebAuthnRepository
    adapter: ReviewOnlyAdapter
    cipher: PayloadCipher
    drafts: DraftBacking
    promotions: FakePolicyPromotionBoundary

    def session(
        self,
        *,
        user_id: str = USER_ID,
        auth_method: str = "webauthn",
        now: int = NOW - 20,
    ) -> tuple[str, SessionPrincipal]:
        token = self.sessions.create_session(user_id, auth_method=auth_method, now=now)
        return token, self.backend.authenticate(token, now=now + 1)

    def enqueue(
        self,
        *,
        recipient: str = "private@example.test",
        body: str = "private body that must remain encrypted",
        gateway_internal: bool = False,
    ) -> str:
        freezer = RequestFreezer(
            self.cipher,
            pending_ttl_seconds=900,
            clock=lambda: datetime.fromtimestamp(NOW, tz=UTC),
        )
        frozen = freezer.freeze(
            cast(ApprovalAdapter, self.adapter),
            {"recipient": recipient, "body": body},
            origin_namespace="profile:web-test",
            policy_version=3,
            schema_version="schema-1",
            editor_actor="caller:web-test",
            gateway_internal=gateway_internal,
        )
        self.state_machine.enqueue(frozen.enqueue_request)
        return frozen.enqueue_request.request_id

    def assertion(self, challenge_id: str, *, signature_valid: bool = True) -> FakeAssertion:
        challenge = self.webauthn.find_challenge(challenge_id)
        credential = self.webauthn.find_credential(WEB_CREDENTIAL_ID)
        assert challenge is not None and credential is not None
        return FakeAssertion(
            credential_id=WEB_CREDENTIAL_ID,
            user_handle=b"fake-web-backend-user-handle",
            challenge=challenge.challenge,
            origin=ORIGIN,
            rp_id=RP_ID,
            new_sign_count=credential.sign_count + 1,
            signature_valid=signature_valid,
        )


def password_verifier() -> Argon2PasswordVerifier:
    return Argon2PasswordVerifier(
        PasswordHasher(
            time_cost=1,
            memory_cost=8_192,
            parallelism=1,
            hash_len=16,
            salt_len=16,
        )
    )


def assemble(
    database: Database,
    *,
    drafts: DraftBacking | None = None,
    promotions: FakePolicyPromotionBoundary | None = None,
    adapter: ReviewOnlyAdapter | None = None,
    cipher: PayloadCipher | None = None,
) -> BackendBundle:
    database.initialize()
    selected_drafts = drafts or DraftBacking()
    selected_promotions = promotions or FakePolicyPromotionBoundary()
    selected_adapter = adapter or ReviewOnlyAdapter()
    selected_cipher = cipher or PayloadCipher(Secret(MASTER_SECRET), KEY_REFERENCE)
    sessions = SessionManager(
        SQLiteSessionRepository(database),
        signing_key=SESSION_KEY,
        idle_timeout=300,
        absolute_timeout=1_200,
    )
    verifier = password_verifier()
    limiter = SQLiteAttemptLimiter(database, lock_schedule=((20, 60),))
    passwords = PasswordAuthenticator(
        SQLitePasswordCredentialRepository(database),
        limiter,
        capabilities=CAPABILITIES,
        verifier=verifier,
    )
    totp = TotpVerifier(
        SQLiteTotpCredentialRepository(database),
        MemorySecretStore({("Signet", "web-backend-totp"): "fake-totp-secret"}),
        limiter,
        capabilities=CAPABILITIES,
        provider=VariableFakeTotpProvider(),
        allow_test_provider=True,
    )
    webauthn = SQLiteWebAuthnRepository(database)
    issuer = WebAuthnChallengeIssuer(webauthn, rp_id=RP_ID)
    assertion_verifier = WebAuthnAssertionVerifier(
        webauthn,
        rp_id=RP_ID,
        origin=ORIGIN,
        capabilities=CAPABILITIES,
        provider=FakeWebAuthnProvider(),
        allow_test_provider=True,
    )
    transactions = SQLiteAuthenticationTransactions(
        database,
        signing_key=SESSION_KEY,
        capabilities=CAPABILITIES,
        idle_timeout=300,
        absolute_timeout=1_200,
    )
    state_machine = ApprovalStateMachine(database, capabilities=CAPABILITIES)
    payloads = EncryptedPayloadReviewer(
        state_machine,
        selected_cipher,
        {
            (selected_adapter.downstream_alias, selected_adapter.tool_name): cast(
                ApprovalAdapter, selected_adapter
            )
        },
    )
    backend = WebBackend(
        database,
        sessions=sessions,
        passwords=passwords,
        totp=totp,
        webauthn_repository=webauthn,
        webauthn_issuer=issuer,
        webauthn_verifier=assertion_verifier,
        authentication_transactions=transactions,
        state_machine=state_machine,
        payloads=payloads,
        action_drafts=cast(ActionDraftRepository, DurableFakeDraftRepository(selected_drafts)),
        policy_promotions=cast(PolicyPromotionBoundary, selected_promotions),
        pushes=SQLitePushRepository(database),
    )
    return BackendBundle(
        database,
        backend,
        sessions,
        state_machine,
        webauthn,
        selected_adapter,
        selected_cipher,
        selected_drafts,
        selected_promotions,
    )


@pytest.fixture
def bundle(tmp_path: Path) -> BackendBundle:
    database = Database(tmp_path / "web-backend.sqlite3")
    database.initialize()
    verifier = password_verifier()
    SQLitePasswordCredentialRepository(database).replace_password(
        PasswordCredential(
            "password-main",
            USER_ID,
            verifier._hasher.hash(PASSWORD),
        ),
        now=NOW - 200,
    )
    SQLiteTotpCredentialRepository(database).replace_totp(
        TotpCredential("totp-main", USER_ID, TOTP_REFERENCE),
        now=NOW - 190,
    )
    SQLiteWebAuthnRepository(database).add_credential(
        WebAuthnCredential(
            WEB_CREDENTIAL_ID,
            USER_ID,
            b"fake-web-backend-user-handle",
            b"fake-web-backend-public-key",
            4,
            "single_device",
            False,
        ),
        now=NOW - 180,
    )
    return assemble(database)


def test_password_totp_login_rotates_old_and_intermediate_sessions(
    bundle: BackendBundle,
) -> None:
    old_token, _ = bundle.session(now=NOW - 10)
    token = bundle.backend.password_totp_login(
        USER_ID,
        PASSWORD,
        "fake:100",
        source="fake-login-source",
        previous_token=old_token,
        now=NOW,
    )
    principal = bundle.backend.authenticate(token, now=NOW + 1)
    assert principal.user_id == USER_ID
    assert principal.auth_method == "password+totp"
    with pytest.raises(InvalidSession):
        bundle.sessions.authenticate(old_token, now=NOW + 1)
    with bundle.database.read() as connection:
        active = connection.execute(
            "SELECT auth_method FROM web_sessions WHERE revoked_at IS NULL"
        ).fetchall()
    assert [row["auth_method"] for row in active] == ["password+totp"]


def test_passkey_login_options_are_exact_and_completion_rotates_previous_session(
    bundle: BackendBundle,
) -> None:
    previous, _ = bundle.session(now=NOW - 10)
    options = bundle.backend.begin_passkey_login(
        USER_ID,
        source="fake-login-source",
        http_method="POST",
        now=NOW,
    )
    assert set(options.model_dump()) == {"challenge_id", "public_key"}
    assert set(options.public_key) == {
        "rpId",
        "challenge",
        "timeout",
        "allowCredentials",
        "userVerification",
    }
    assert options.public_key["allowCredentials"] == [
        {"id": WEB_CREDENTIAL_ID, "type": "public-key"}
    ]
    token = bundle.backend.complete_passkey_login(
        options.challenge_id,
        cast(Mapping[str, Any], bundle.assertion(options.challenge_id)),
        source="fake-login-source",
        http_method="POST",
        previous_token=previous,
        now=NOW + 1,
    )
    assert bundle.backend.authenticate(token, now=NOW + 2).auth_method == "webauthn"
    with pytest.raises(InvalidSession):
        bundle.sessions.authenticate(previous, now=NOW + 2)


@pytest.mark.parametrize("auth_method", ["preauth", "preauth:webauthn"])
def test_preauth_sessions_are_never_ui_authority(
    bundle: BackendBundle,
    auth_method: str,
) -> None:
    token = bundle.sessions.create_session(
        USER_ID,
        auth_method=auth_method,
        now=NOW,
    )
    preauth = bundle.sessions.authenticate(token, now=NOW + 1)
    with pytest.raises(InvalidSession):
        bundle.backend.authenticate(token, now=NOW + 1)
    with pytest.raises(WebUnauthorized):
        bundle.backend.list_queue(preauth, now=NOW + 1)


def test_failed_passkey_login_revokes_its_durable_preauth_session(
    bundle: BackendBundle,
) -> None:
    options = bundle.backend.begin_passkey_login(
        USER_ID,
        source="fake-login-source",
        http_method="POST",
        now=NOW,
    )
    challenge = bundle.webauthn.find_challenge(options.challenge_id)
    assert challenge is not None
    with pytest.raises(WebUnauthorized):
        bundle.backend.complete_passkey_login(
            options.challenge_id,
            cast(
                Mapping[str, Any],
                bundle.assertion(options.challenge_id, signature_valid=False),
            ),
            source="fake-login-source",
            http_method="POST",
            previous_token=None,
            now=NOW + 1,
        )
    with bundle.database.read() as connection:
        row = connection.execute(
            "SELECT revoked_at FROM web_sessions WHERE session_id = ?",
            (challenge.session_id,),
        ).fetchone()
    assert row is not None and row["revoked_at"] == NOW + 1


def test_unknown_passkey_accounts_create_no_users_sessions_or_challenges(
    bundle: BackendBundle,
) -> None:
    with bundle.database.read() as connection:
        before = tuple(
            int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in ("auth_users", "web_sessions", "auth_challenges")
        )

    outcomes: list[type[Exception]] = []
    for index in range(25):
        try:
            bundle.backend.begin_passkey_login(
                f"unknown-{index}",
                source="one-untrusted-source",
                http_method="POST",
                now=NOW + index,
            )
        except (WebUnauthorized, WebRateLimited) as exc:
            outcomes.append(type(exc))

    assert outcomes[:20] == [WebUnauthorized] * 20
    assert outcomes[20:] == [WebRateLimited] * 5
    with bundle.database.read() as connection:
        after = tuple(
            int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in ("auth_users", "web_sessions", "auth_challenges")
        )
        limiter_rows = int(
            connection.execute(
                """
                SELECT count(*) FROM auth_attempts
                WHERE scope_key LIKE 'passkey-login:%'
                """
            ).fetchone()[0]
        )
    assert after == before
    assert limiter_rows == 2


def test_passkey_limiter_prunes_expired_untrusted_source_scopes(
    bundle: BackendBundle,
) -> None:
    window_seconds = 10 * 60
    for window in range(8):
        for source_index in range(200):
            with pytest.raises(WebUnauthorized):
                bundle.backend.begin_passkey_login(
                    f"unknown-{window}-{source_index}",
                    source=f"untrusted-{window}-{source_index}",
                    http_method="POST",
                    now=NOW + window * window_seconds,
                )

    with bundle.database.read() as connection:
        limiter_rows = int(
            connection.execute(
                """
                SELECT count(*) FROM auth_attempts
                WHERE scope_key LIKE 'passkey-login:%'
                """
            ).fetchone()[0]
        )
    assert limiter_rows <= 201


def test_passkey_challenge_cap_is_checked_before_creating_an_extra_session(
    bundle: BackendBundle,
) -> None:
    for offset in range(5):
        bundle.backend.begin_passkey_login(
            USER_ID,
            source="known-account-source",
            http_method="POST",
            now=NOW + offset,
        )

    with pytest.raises(WebRateLimited, match="active passkey"):
        bundle.backend.begin_passkey_login(
            USER_ID,
            source="known-account-source",
            http_method="POST",
            now=NOW + 5,
        )

    with bundle.database.read() as connection:
        challenges = int(
            connection.execute(
                """
                SELECT count(*) FROM auth_challenges
                WHERE user_id = ? AND action = 'login'
                """,
                (USER_ID,),
            ).fetchone()[0]
        )
        sessions = int(
            connection.execute(
                """
                SELECT count(*) FROM web_sessions
                WHERE user_id = ? AND auth_method = 'preauth:webauthn'
                """,
                (USER_ID,),
            ).fetchone()[0]
        )
    assert (challenges, sessions) == (5, 5)


def test_queue_detail_and_audit_only_expose_authenticated_private_review(
    bundle: BackendBundle,
) -> None:
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    with pytest.raises(InvalidSession):
        bundle.backend.authenticate("not-a-session", now=NOW)

    queue = bundle.backend.list_queue(principal, now=NOW)
    assert [(item.request_id, item.downstream_alias, item.tool_name) for item in queue.items] == [
        (request_id, "fake-service", "create_item")
    ]
    assert queue.has_more is False and queue.next_cursor is None
    detail = bundle.backend.get_detail(principal, request_id)
    assert detail.detail_blocks[0].value == "private body that must remain encrypted"
    assert json.loads(cast(str, detail.editable_arguments_json)) == {
        "body": "private body that must remain encrypted",
        "recipient": "private@example.test",
    }
    audit = bundle.backend.list_audit(principal)
    assert audit[0].request_id == request_id
    assert audit[0].payload_hash_prefix == detail.payload_hash[:12]
    assert bundle.adapter.downstream_calls == []
    with bundle.database.read() as connection:
        encrypted = bytes(
            connection.execute(
                "SELECT encrypted_payload FROM payload_versions WHERE request_id = ?",
                (request_id,),
            ).fetchone()[0]
        )
    assert b"private body" not in encrypted


def test_unresolved_unknowns_are_pinned_ahead_of_pending_requests(
    bundle: BackendBundle,
) -> None:
    pending_id = bundle.enqueue(recipient="pending@example.test")
    unknown_id = bundle.enqueue(recipient="unknown@example.test")
    with bundle.database.transaction() as connection:
        connection.execute(
            "UPDATE approval_requests SET state = 'outcome_unknown' WHERE request_id = ?",
            (unknown_id,),
        )
    _, principal = bundle.session()

    queue = bundle.backend.list_queue(principal, now=NOW)

    assert [(item.request_id, item.state) for item in queue.items] == [
        (unknown_id, "outcome_unknown"),
        (pending_id, "pending_approval"),
    ]


def test_queue_is_hard_capped_keyset_paginated_and_never_reviews_payloads(
    bundle: BackendBundle,
) -> None:
    request_ids = {bundle.enqueue(recipient=f"private-{index}@example.test") for index in range(55)}
    unknown_id = max(request_ids)
    with bundle.database.transaction() as connection:
        connection.execute(
            "UPDATE approval_requests SET state = 'outcome_unknown' WHERE request_id = ?",
            (unknown_id,),
        )
    original = cast(PrivatePayloadReviewer, cast(Any, bundle.backend)._payloads)
    reviewer = ReviewerSpy(original)
    cast(Any, bundle.backend)._payloads = reviewer
    _, principal = bundle.session()

    first = bundle.backend.list_queue(principal, now=NOW)
    second = bundle.backend.list_queue(principal, now=NOW, cursor=first.next_cursor)

    assert len(first.items) == 50
    assert first.items[0].request_id == unknown_id
    assert first.has_more is True and first.next_cursor is not None
    assert len(second.items) == 5
    assert second.has_more is False and second.next_cursor is None
    assert {item.request_id for item in first.items + second.items} == request_ids
    assert reviewer.review_calls == []

    bundle.backend.get_detail(principal, first.items[0].request_id)
    assert reviewer.review_calls == [
        (
            first.items[0].request_id,
            first.items[0].version,
            bundle.state_machine.get_request(first.items[0].request_id)["current_payload_hash"],
        )
    ]


def test_queue_cursor_rejects_sqlite_integer_overflow(bundle: BackendBundle) -> None:
    _, principal = bundle.session()
    encoded = base64.urlsafe_b64encode(
        json.dumps(
            {
                "priority": 0,
                "created_at": 2**63,
                "request_id": "req_overflow",
            },
            separators=(",", ":"),
        ).encode()
    ).decode().rstrip("=")

    with pytest.raises(WebConflict, match="cursor is invalid"):
        bundle.backend.list_queue(principal, now=NOW, cursor=encoded)


def test_wrong_payload_key_returns_non_actionable_metadata_without_private_data(
    bundle: BackendBundle,
) -> None:
    request_id = bundle.enqueue(body="never disclose this payload")
    _, principal = bundle.session()
    wrong_cipher = PayloadCipher(
        Secret("different-fake-web-backend-master-key-02"),
        KEY_REFERENCE,
    )
    wrong = assemble(
        Database(bundle.database.path),
        drafts=bundle.drafts,
        promotions=bundle.promotions,
        adapter=bundle.adapter,
        cipher=wrong_cipher,
    )
    detail = wrong.backend.get_detail(principal, request_id)
    assert detail.review_available is False
    assert detail.content_purged is False
    assert detail.editable_arguments_json is None
    assert detail.detail_blocks == ()
    assert "never disclose" not in detail.destination_summary
    assert "never disclose" not in str(detail)
    assert bundle.adapter.downstream_calls == []

    row = bundle.state_machine.get_request(request_id)
    with pytest.raises(WebConflict, match="unavailable for review"):
        wrong.backend.complete_totp_action(
            principal,
            request_id,
            "approve",
            "fake:404",
            expected_version=1,
            expected_payload_hash=str(row["current_payload_hash"]),
            prospective_arguments_json=None,
            now=NOW + 1,
        )
    assert bundle.state_machine.get_request(request_id)["state"] == "pending_approval"

    assert (
        bundle.backend.complete_totp_action(
            principal,
            request_id,
            "approve",
            "fake:404",
            expected_version=1,
            expected_payload_hash=str(row["current_payload_hash"]),
            prospective_arguments_json=None,
            now=NOW + 2,
        )
        == "approved"
    )


def test_decision_history_is_metadata_only_until_exact_request_expansion(
    bundle: BackendBundle,
) -> None:
    approved_id = bundle.enqueue(body="approved private body")
    denied_id = bundle.enqueue(body="denied private body")
    _, principal = bundle.session()
    approved_hash = str(bundle.state_machine.get_request(approved_id)["current_payload_hash"])
    denied_hash = str(bundle.state_machine.get_request(denied_id)["current_payload_hash"])

    assert (
        bundle.backend.complete_totp_action(
            principal,
            approved_id,
            "approve",
            "fake:501",
            expected_version=1,
            expected_payload_hash=approved_hash,
            prospective_arguments_json=None,
            now=NOW + 1,
            decision_note="Release scope reviewed <script>alert(1)</script>",
        )
        == "approved"
    )
    assert (
        bundle.backend.complete_totp_action(
            principal,
            denied_id,
            "deny",
            "fake:502",
            expected_version=1,
            expected_payload_hash=denied_hash,
            prospective_arguments_json=None,
            now=NOW + 2,
            decision_note="Recipient does not match the requested change.",
        )
        == "denied"
    )
    original = cast(PrivatePayloadReviewer, cast(Any, bundle.backend)._payloads)
    reviewer = ReviewerSpy(original)
    cast(Any, bundle.backend)._payloads = reviewer

    page = bundle.backend.list_decisions(principal)
    decisions = page.items

    assert [(entry.request_id, entry.decision) for entry in decisions] == [
        (denied_id, "denied"),
        (approved_id, "approved"),
    ]
    assert decisions[1].confirmation_path == "web"
    assert decisions[1].confirmation_kind == "totp"
    assert decisions[0].confirmation_path == "web"
    assert decisions[0].confirmation_kind == "totp"
    assert page.has_more is False and page.next_event_id is None
    assert reviewer.review_calls == []
    approved = bundle.backend.get_detail(principal, approved_id)
    denied = bundle.backend.get_detail(principal, denied_id)
    approved_event = next(
        event for event in approved.events if event["action"] == "approved_via_web"
    )
    denied_event = next(event for event in denied.events if event["action"] == "denied")
    assert approved_event["decision_note"] == "Release scope reviewed <script>alert(1)</script>"
    assert denied_event["decision_note"] == "Recipient does not match the requested change."
    assert (approved_event["confirmation_kind"], approved_event["confirmation_path"]) == (
        "totp",
        "web",
    )
    assert (denied_event["confirmation_kind"], denied_event["confirmation_path"]) == (
        "totp",
        "web",
    )
    assert approved_event["details_json"] is None
    assert denied_event["details_json"] is None
    assert len(reviewer.review_calls) == 2
    assert bundle.adapter.downstream_calls == []


def test_decision_history_is_bounded_and_keyset_paginated(
    bundle: BackendBundle,
) -> None:
    cast(Any, bundle.backend).max_decision_entries = 2
    request_ids = [bundle.enqueue(body=f"decision-{index}") for index in range(5)]
    _, principal = bundle.session()
    for index, request_id in enumerate(request_ids):
        payload_hash = str(bundle.state_machine.get_request(request_id)["current_payload_hash"])
        assert (
            bundle.backend.complete_totp_action(
                principal,
                request_id,
                "deny",
                f"fake:{610 + index}",
                expected_version=1,
                expected_payload_hash=payload_hash,
                prospective_arguments_json=None,
                now=NOW + index + 1,
            )
            == "denied"
        )
    original = cast(PrivatePayloadReviewer, cast(Any, bundle.backend)._payloads)
    reviewer = ReviewerSpy(original)
    cast(Any, bundle.backend)._payloads = reviewer

    first = bundle.backend.list_decisions(principal)
    second = bundle.backend.list_decisions(principal, before_event_id=first.next_event_id)
    third = bundle.backend.list_decisions(principal, before_event_id=second.next_event_id)

    assert [entry.request_id for entry in first.items] == list(reversed(request_ids[-2:]))
    assert [entry.request_id for entry in second.items] == list(reversed(request_ids[1:3]))
    assert [entry.request_id for entry in third.items] == [request_ids[0]]
    assert first.has_more is True and first.next_event_id is not None
    assert second.has_more is True and second.next_event_id is not None
    assert third.has_more is False and third.next_event_id is None
    assert reviewer.review_calls == []

    for invalid in (0, 2**63, True):
        with pytest.raises(WebConflict, match="cursor is invalid"):
            bundle.backend.list_decisions(principal, before_event_id=cast(Any, invalid))


def test_passkey_decision_provenance_is_safe_and_visible(
    bundle: BackendBundle,
) -> None:
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    payload_hash = str(bundle.state_machine.get_request(request_id)["current_payload_hash"])
    options = bundle.backend.begin_passkey_action(
        principal,
        request_id,
        "deny",
        expected_version=1,
        expected_payload_hash=payload_hash,
        prospective_arguments_json=None,
        http_method="POST",
        now=NOW + 1,
    )
    assert (
        bundle.backend.complete_passkey_action(
            principal,
            request_id,
            options.challenge_id,
            cast(Mapping[str, Any], bundle.assertion(options.challenge_id)),
            http_method="POST",
            now=NOW + 2,
        )
        == "denied"
    )

    decision = bundle.backend.list_decisions(principal).items[0]
    detail = bundle.backend.get_detail(principal, request_id)
    event = next(value for value in detail.events if value["action"] == "denied")

    assert (decision.confirmation_kind, decision.confirmation_path) == ("webauthn", "web")
    assert (event["confirmation_kind"], event["confirmation_path"]) == (
        "webauthn",
        "web",
    )
    assert "credential" not in str(decision).lower()


@pytest.mark.parametrize("invalid_note", ["x" * 1_001, "unsafe\x00control"])
def test_invalid_decision_note_fails_before_proof_consumption(
    bundle: BackendBundle,
    invalid_note: str,
) -> None:
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    payload_hash = str(bundle.state_machine.get_request(request_id)["current_payload_hash"])

    with pytest.raises(WebConflict, match="rationale is invalid"):
        bundle.backend.complete_totp_action(
            principal,
            request_id,
            "deny",
            "fake:503",
            expected_version=1,
            expected_payload_hash=payload_hash,
            prospective_arguments_json=None,
            now=NOW + 1,
            decision_note=invalid_note,
        )

    assert (
        bundle.backend.complete_totp_action(
            principal,
            request_id,
            "deny",
            "fake:503",
            expected_version=1,
            expected_payload_hash=payload_hash,
            prospective_arguments_json=None,
            now=NOW + 2,
            decision_note=None,
        )
        == "denied"
    )


def test_terminal_purged_request_retains_decision_metadata_and_timeline(
    bundle: BackendBundle,
) -> None:
    request_id = bundle.enqueue(body="purge this private body")
    _, principal = bundle.session()
    payload_hash = str(bundle.state_machine.get_request(request_id)["current_payload_hash"])
    bundle.backend.complete_totp_action(
        principal,
        request_id,
        "deny",
        "fake:504",
        expected_version=1,
        expected_payload_hash=payload_hash,
        prospective_arguments_json=None,
        now=NOW + 1,
        decision_note="Request is outside the approved scope.",
    )
    with bundle.database.transaction() as connection:
        connection.execute(
            """
            UPDATE payload_versions
            SET encrypted_payload = NULL, purged_at = ?, purge_reason = ?
            WHERE request_id = ? AND version = 1
            """,
            (NOW + 2, "retention_denied", request_id),
        )

    detail = bundle.backend.get_detail(principal, request_id)

    assert detail.state == "denied"
    assert detail.review_available is False
    assert detail.content_purged is True
    assert detail.content_purged_at == NOW + 2
    assert detail.content_purge_reason == "retention_denied"
    assert detail.reviewed_arguments_json is None
    assert detail.editable_arguments_json is None
    assert detail.detail_blocks == ()
    assert "purge this private body" not in str(detail)
    decision = next(event for event in detail.events if event["action"] == "denied")
    assert decision["decision_note"] == "Request is outside the approved scope."
    assert bundle.backend.list_decisions(principal).items[0].request_id == request_id
    assert bundle.adapter.downstream_calls == []


def test_attachment_edit_and_review_are_bound_to_exact_catalog_snapshot(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "attachment-edit.sqlite3")
    database.initialize()
    source_root = tmp_path / "sources"
    source_root.mkdir()
    source = source_root / "review.txt"
    source.write_bytes(b"same bytes under two opaque identifiers")
    staging = StagingStore(
        tmp_path / "staging",
        database=database,
        cipher=attachment_cipher(),
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    adapter = FastmailAdapter(staging_store=staging, account="primary")
    original = adapter.stage_attachment(
        source,
        filename="review.txt",
        mime_type="text/plain",
    )
    replacement = adapter.stage_attachment(
        source,
        filename="review.txt",
        mime_type="text/plain",
    )
    assert original["sha256"] == replacement["sha256"]
    arguments = {
        "from": "sender@example.test",
        "to": ["recipient@example.test"],
        "cc": [],
        "bcc": [],
        "subject": "Review",
        "body": "original body",
        "attachments": [original],
    }
    payload_cipher = PayloadCipher(Secret(MASTER_SECRET), KEY_REFERENCE)
    freezer = RequestFreezer(
        payload_cipher,
        clock=lambda: datetime.fromtimestamp(NOW, tz=UTC),
    )
    frozen = freezer.freeze(
        adapter,
        arguments,
        origin_namespace="profile:web-attachment-test",
        policy_version=3,
        schema_version="schema-1",
        editor_actor="caller:web-attachment-test",
        attachments=adapter.freeze_attachments(arguments),
    )
    machine = ApprovalStateMachine(database)
    machine.enqueue(frozen.enqueue_request)
    request_id = frozen.enqueue_request.request_id
    payload_hash = frozen.enqueue_request.payload_hash
    reviewer = EncryptedPayloadReviewer(
        machine,
        payload_cipher,
        {(adapter.downstream_alias, adapter.tool_name): adapter},
    )

    retargeted = {**arguments, "body": "edited body", "attachments": [replacement]}
    with pytest.raises(WebPayloadError, match="adapter validation"):
        reviewer.prepare_edit(
            request_id,
            expected_version=1,
            expected_payload_hash=payload_hash,
            prospective_arguments_json=json.dumps(retargeted),
        )

    unchanged = {**arguments, "body": "edited body"}
    prepared = reviewer.prepare_edit(
        request_id,
        expected_version=1,
        expected_payload_hash=payload_hash,
        prospective_arguments_json=json.dumps(unchanged),
    )
    plaintext = payload_cipher.decrypt(
        prepared.encrypted_payload,
        key_reference=prepared.encryption_key_ref,
        request_id=request_id,
        version=2,
        payload_hash=prepared.payload_hash,
    )
    edited_envelope = json.loads(plaintext)
    assert edited_envelope["arguments"]["attachments"] == [original]
    assert edited_envelope["staged_file_hashes"] == [original["sha256"]]

    with database.transaction() as connection:
        connection.execute("DELETE FROM attachments WHERE request_id = ?", (request_id,))
    with pytest.raises(WebPayloadError, match="does not match"):
        reviewer.review(request_id, version=1, payload_hash=payload_hash)


@pytest.mark.parametrize(
    ("action", "expected_state"),
    [
        ("approve", "approved"),
        ("deny", "denied"),
        ("cancel", "cancelled"),
        ("edit", "pending_approval"),
    ],
)
def test_totp_request_actions_are_exact_and_make_no_downstream_call(
    bundle: BackendBundle,
    action: str,
    expected_state: str,
) -> None:
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    result = bundle.backend.complete_totp_action(
        principal,
        request_id,
        cast(Any, action),
        f"fake:{200 + len(action)}",
        expected_version=1,
        expected_payload_hash=bundle.state_machine.get_request(request_id)["current_payload_hash"],
        prospective_arguments_json=(
            '{"recipient":"edited@example.test","body":"edited private body"}'
            if action == "edit"
            else None
        ),
        now=NOW + 1,
    )
    assert result == expected_state
    row = bundle.state_machine.get_request(request_id)
    assert row["state"] == expected_state
    if action == "edit":
        assert row["current_version"] == 2
        detail = bundle.backend.get_detail(principal, request_id)
        assert detail.destination_summary == "edited@example.test"
        assert detail.detail_blocks[0].value == "edited private body"
    assert bundle.adapter.downstream_calls == []


@pytest.mark.parametrize(
    ("action", "expected_result"),
    [
        ("approve", "approved"),
        ("deny", "denied"),
        ("cancel", "cancelled"),
        ("edit", "pending_approval"),
        ("promote_approval", "policy_updated"),
        ("promote_passthrough", "policy_updated"),
    ],
)
def test_passkey_actions_use_durable_drafts_and_exact_options(
    bundle: BackendBundle,
    action: str,
    expected_result: str,
) -> None:
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    row = bundle.state_machine.get_request(request_id)
    options = bundle.backend.begin_passkey_action(
        principal,
        request_id,
        cast(Any, action),
        expected_version=1,
        expected_payload_hash=row["current_payload_hash"],
        prospective_arguments_json=(
            '{"recipient":"edited@example.test","body":"passkey edit"}'
            if action == "edit"
            else None
        ),
        http_method="POST",
        now=NOW + 1,
    )
    assert set(options.model_dump()) == {
        "challenge_id",
        "public_key",
        "action",
        "request_id",
        "version",
        "payload_hash",
    }
    assert options.action == action
    assert options.request_id == request_id
    assert options.challenge_id in bundle.drafts.records
    result = bundle.backend.complete_passkey_action(
        principal,
        request_id,
        options.challenge_id,
        cast(Mapping[str, Any], bundle.assertion(options.challenge_id)),
        http_method="POST",
        now=NOW + 2,
    )
    assert result == expected_result
    if action.startswith("promote_"):
        draft, confirmation, actor, called_at = bundle.promotions.calls[-1]
        assert draft.action == action
        assert confirmation.challenge_id == options.challenge_id
        assert actor == f"web:{USER_ID}" and called_at == NOW + 2
        binding = draft.binding
        assert CAPABILITIES.verify(
            confirmation.capability,
            domain=WEBAUTHN_PROOF_DOMAIN,
            claims=webauthn_proof_claims(
                credential_id=cast(str, confirmation.credential_id),
                credential_user_id=cast(str, confirmation.credential_user_id),
                user_id=cast(str, confirmation.user_id),
                challenge_id=cast(str, confirmation.challenge_id),
                use_id=confirmation.use_id,
                binding=binding,
                path=confirmation.path,
                session_id=cast(str, confirmation.session_id),
                http_method=cast(str, confirmation.http_method),
                expected_counter=cast(int, confirmation.expected_counter),
                new_counter=cast(int, confirmation.new_counter),
                device_type=cast(str, confirmation.device_type),
                expected_backup_eligible=cast(bool, confirmation.expected_backup_eligible),
                new_backup_eligible=cast(bool, confirmation.new_backup_eligible),
                previous_backed_up=cast(bool, confirmation.previous_backed_up),
                new_backed_up=cast(bool, confirmation.new_backed_up),
            ),
        )
    else:
        assert bundle.state_machine.get_request(request_id)["state"] == expected_result
    assert bundle.adapter.downstream_calls == []


def test_gateway_internal_approval_uses_policy_boundary_and_cannot_be_retargeted(
    bundle: BackendBundle,
) -> None:
    request_id = bundle.enqueue(gateway_internal=True)
    _, principal = bundle.session()
    row = bundle.state_machine.get_request(request_id)

    for action in ("edit", "promote_approval", "promote_passthrough"):
        with pytest.raises(WebForbidden):
            bundle.backend.begin_passkey_action(
                principal,
                request_id,
                cast(Any, action),
                expected_version=1,
                expected_payload_hash=row["current_payload_hash"],
                prospective_arguments_json=("{}" if action == "edit" else None),
                http_method="POST",
                now=NOW + 1,
            )

    options = bundle.backend.begin_passkey_action(
        principal,
        request_id,
        "approve",
        expected_version=1,
        expected_payload_hash=row["current_payload_hash"],
        prospective_arguments_json=None,
        http_method="POST",
        now=NOW + 2,
    )
    assert (
        bundle.backend.complete_passkey_action(
            principal,
            request_id,
            options.challenge_id,
            cast(Mapping[str, Any], bundle.assertion(options.challenge_id)),
            http_method="POST",
            now=NOW + 3,
        )
        == "policy_updated"
    )
    assert bundle.promotions.calls[-1][0].policy_change is True
    assert bundle.state_machine.get_request(request_id)["state"] == "pending_approval"


def test_passkey_completion_rejects_a_different_route_request_id(
    bundle: BackendBundle,
) -> None:
    request_id = bundle.enqueue()
    other_id = bundle.enqueue(recipient="other@example.test")
    _, principal = bundle.session()
    row = bundle.state_machine.get_request(request_id)
    options = bundle.backend.begin_passkey_action(
        principal,
        request_id,
        "approve",
        expected_version=1,
        expected_payload_hash=row["current_payload_hash"],
        prospective_arguments_json=None,
        http_method="POST",
        now=NOW + 1,
    )

    with pytest.raises(WebConflict):
        bundle.backend.complete_passkey_action(
            principal,
            other_id,
            options.challenge_id,
            cast(Mapping[str, Any], bundle.assertion(options.challenge_id)),
            http_method="POST",
            now=NOW + 2,
        )

    assert bundle.state_machine.get_request(request_id)["state"] == "pending_approval"
    assert bundle.state_machine.get_request(other_id)["state"] == "pending_approval"


def test_totp_gateway_internal_approval_uses_atomic_policy_boundary(
    bundle: BackendBundle,
) -> None:
    request_id = bundle.enqueue(gateway_internal=True)
    _, principal = bundle.session()
    row = bundle.state_machine.get_request(request_id)

    result = bundle.backend.complete_totp_action(
        principal,
        request_id,
        "approve",
        "fake:777",
        expected_version=1,
        expected_payload_hash=row["current_payload_hash"],
        prospective_arguments_json=None,
        now=NOW + 1,
    )

    assert result == "policy_updated"
    assert bundle.state_machine.get_request(request_id)["state"] == "pending_approval"
    assert bundle.promotions.totp_calls[-1][0] == "approve"
    assert bundle.promotions.totp_calls[-1][1].action == "promote_approval"


def test_stale_and_tampered_passkey_proofs_do_not_mutate_request(
    bundle: BackendBundle,
) -> None:
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    payload_hash = bundle.state_machine.get_request(request_id)["current_payload_hash"]
    options = bundle.backend.begin_passkey_action(
        principal,
        request_id,
        "approve",
        expected_version=1,
        expected_payload_hash=payload_hash,
        prospective_arguments_json=None,
        http_method="POST",
        now=NOW + 1,
    )
    with pytest.raises(WebForbidden):
        bundle.backend.complete_passkey_action(
            principal,
            request_id,
            options.challenge_id,
            cast(
                Mapping[str, Any],
                bundle.assertion(options.challenge_id, signature_valid=False),
            ),
            http_method="POST",
            now=NOW + 2,
        )
    assert bundle.state_machine.get_request(request_id)["state"] == "pending_approval"

    bundle.backend.complete_totp_action(
        principal,
        request_id,
        "deny",
        "fake:900",
        expected_version=1,
        expected_payload_hash=payload_hash,
        prospective_arguments_json=None,
        now=NOW + 3,
    )
    with pytest.raises(WebConflict):
        bundle.backend.complete_passkey_action(
            principal,
            request_id,
            options.challenge_id,
            cast(Mapping[str, Any], bundle.assertion(options.challenge_id)),
            http_method="POST",
            now=NOW + 4,
        )
    assert bundle.state_machine.get_request(request_id)["state"] == "denied"


def test_tampered_durable_edit_draft_cannot_retarget_verified_capability(
    bundle: BackendBundle,
) -> None:
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    payload_hash = bundle.state_machine.get_request(request_id)["current_payload_hash"]
    options = bundle.backend.begin_passkey_action(
        principal,
        request_id,
        "edit",
        expected_version=1,
        expected_payload_hash=payload_hash,
        prospective_arguments_json=('{"recipient":"edited@example.test","body":"intended edit"}'),
        http_method="POST",
        now=NOW + 1,
    )
    draft = bundle.drafts.records[options.challenge_id]
    assert draft.prepared_edit is not None
    bundle.drafts.records[options.challenge_id] = replace(
        draft,
        prepared_edit=replace(draft.prepared_edit, payload_hash="f" * 64),
    )
    with pytest.raises(WebForbidden):
        bundle.backend.complete_passkey_action(
            principal,
            request_id,
            options.challenge_id,
            cast(Mapping[str, Any], bundle.assertion(options.challenge_id)),
            http_method="POST",
            now=NOW + 2,
        )
    assert bundle.state_machine.get_request(request_id)["current_version"] == 1
    with bundle.database.read() as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM auth_proof_consumptions WHERE purpose = 'mutation'"
            ).fetchone()
            is None
        )


def test_passkey_edit_completes_after_backend_restart_through_injected_draft_store(
    bundle: BackendBundle,
) -> None:
    request_id = bundle.enqueue()
    token, principal = bundle.session()
    payload_hash = bundle.state_machine.get_request(request_id)["current_payload_hash"]
    options = bundle.backend.begin_passkey_action(
        principal,
        request_id,
        "edit",
        expected_version=1,
        expected_payload_hash=payload_hash,
        prospective_arguments_json=('{"recipient":"restart@example.test","body":"durable draft"}'),
        http_method="POST",
        now=NOW + 1,
    )
    assertion = bundle.assertion(options.challenge_id)

    restarted = assemble(
        Database(bundle.database.path),
        drafts=bundle.drafts,
        promotions=bundle.promotions,
        adapter=bundle.adapter,
    )
    restarted_principal = restarted.backend.authenticate(token, now=NOW + 2)
    assert (
        restarted.backend.complete_passkey_action(
            restarted_principal,
            request_id,
            options.challenge_id,
            cast(Mapping[str, Any], assertion),
            http_method="POST",
            now=NOW + 3,
        )
        == "pending_approval"
    )
    detail = restarted.backend.get_detail(restarted_principal, request_id)
    assert detail.destination_summary == "restart@example.test"
    assert detail.detail_blocks[0].value == "durable draft"


def test_push_subscription_ownership_survives_restart(bundle: BackendBundle) -> None:
    _, owner = bundle.session()
    endpoint = "https://push.example.test/device"
    subscription = PushSubscriptionInput(
        endpoint=endpoint,
        p256dh=P256DH,
        auth=PUSH_AUTH,
        device_label="Fake phone",
        categories=("new_pending",),
    )
    bundle.backend.subscribe_push(owner, subscription, now=NOW)
    repository = SQLitePushRepository(Database(bundle.database.path))
    assert len(repository.active_for(USER_ID, NotificationKind.NEW_PENDING)) == 1

    _, other = bundle.session(user_id=SECOND_USER_ID)
    with pytest.raises(WebForbidden):
        bundle.backend.subscribe_push(other, subscription, now=NOW + 1)
    bundle.backend.unsubscribe_push(other, endpoint, now=NOW + 2)
    assert len(repository.active_for(USER_ID, NotificationKind.NEW_PENDING)) == 1
    bundle.backend.unsubscribe_push(owner, endpoint, now=NOW + 3)
    assert repository.active_for(USER_ID, NotificationKind.NEW_PENDING) == ()


def test_policy_promotion_accepts_web_totp_with_distinct_binding(
    bundle: BackendBundle,
) -> None:
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    row = bundle.state_machine.get_request(request_id)
    assert (
        bundle.backend.complete_totp_action(
            principal,
            request_id,
            "promote_approval",
            "fake:999",
            expected_version=1,
            expected_payload_hash=row["current_payload_hash"],
            prospective_arguments_json=None,
            now=NOW + 1,
        )
        == "policy_updated"
    )
    assert bundle.promotions.totp_calls[-1][1].action == "promote_approval"
