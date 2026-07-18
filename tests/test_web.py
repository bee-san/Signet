from __future__ import annotations

import asyncio
import base64
import re
import struct
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from signet.auth import InvalidSession, SessionPrincipal
from signet.browser_auth import BootstrapService, BrowserAuthController
from signet.db import Database
from signet.web import (
    ActionOptions,
    AttachmentDownload,
    AuditEntry,
    CsrfManager,
    DecisionEntry,
    DecisionPage,
    DetailBlock,
    LoginOptions,
    PolicyPromotionPreview,
    PushSubscriptionInput,
    QueueItem,
    QueuePage,
    RequestAttachment,
    RequestDetail,
    WebConflict,
    WebSettings,
    create_agent_health_app,
    create_web_app,
)
from signet.webauthn import SQLiteWebAuthnRepository
from signet.webauthn_registration import PasskeyRegistrationService, RegistrationResult

NOW = 1_800_000_000
ORIGIN = "https://signet.test"
HASH = "a" * 64
ROOT = Path(__file__).resolve().parents[1]


@dataclass
class FakeBackend:
    actions: list[tuple[str, str, str]] = field(default_factory=list)
    totp_credential_ids: list[str | None] = field(default_factory=list)
    push_endpoints: list[str] = field(default_factory=list)
    conflict: bool = False
    detail_state: str = "pending_approval"
    review_available: bool = True
    queue_has_more: bool = False
    queue_cursors: list[str | None] = field(default_factory=list)
    decision_before_event_ids: list[int | None] = field(default_factory=list)
    decision_has_more: bool = False
    decision_notes: list[str | None] = field(default_factory=list)
    staged_decision_note: str | None = None
    event_decision_note: str | None = None
    attachment_detection_source: str | None = "content_signature_v1"
    gateway_internal: bool = False
    gateway_proposed_mode: str = "passthrough"
    gateway_active_policy_version: int = 3
    gateway_can_approve: bool | None = None
    gateway_stale: bool = False
    gateway_preview_unavailable: bool = False
    decision_window_expired: bool = False
    attachment_calls: list[tuple[str, str, int, str]] = field(default_factory=list)

    def authenticate(self, token: str | None, *, now: int) -> SessionPrincipal:
        assert now == NOW
        if token != "session-good":
            raise InvalidSession("invalid")
        return SessionPrincipal("autumn", "session-id", "passkey", NOW - 10, NOW + 1000)

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
        assert (user_id, password, totp_proof) == ("autumn", "fake-password", "fake:totp")
        assert source and now == NOW
        del previous_token
        return "session-good"

    def begin_passkey_login(
        self,
        user_id: str,
        *,
        source: str,
        http_method: str,
        now: int,
    ) -> LoginOptions:
        assert user_id == "autumn" and source and http_method == "POST" and now == NOW
        return LoginOptions(
            challenge_id="challenge-login",
            public_key={"challenge": "ZmFrZQ", "allowCredentials": []},
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
        assert challenge_id == "challenge-login" and assertion == {"fake": True}
        assert source and http_method == "POST" and now == NOW
        del previous_token
        return "session-good"

    def logout(self, token: str | None, *, now: int) -> None:
        assert token == "session-good" and now == NOW

    def list_queue(
        self,
        principal: SessionPrincipal,
        *,
        now: int,
        cursor: str | None = None,
    ) -> QueuePage:
        assert principal.user_id == "autumn" and now == NOW
        self.queue_cursors.append(cursor)
        return QueuePage(
            (
                QueueItem(
                    request_id="req_test",
                    downstream_alias="fastmail",
                    tool_name="send_email",
                    state="pending_approval",
                    created_at=NOW - 60,
                    expires_at=NOW + 600,
                    version=1,
                    payload_hash_prefix=HASH[:12],
                ),
            ),
            self.queue_has_more,
            "next-page" if self.queue_has_more else None,
        )

    def get_detail(self, principal: SessionPrincipal, request_id: str) -> RequestDetail:
        assert principal.user_id == "autumn" and request_id == "req_test"
        hostile = '</pre><script src="https://evil.test/a.js"></script><form action="//evil.test">'
        return RequestDetail(
            request_id="req_test",
            service="Fastmail",
            action="send_email",
            title=(
                "Viewing on Tuesday <script>alert(1)</script>"
                if self.review_available
                else "Reviewed content unavailable"
            ),
            destination_summary=(
                "person@example.test"
                if self.review_available
                else "Private reviewed content could not be authenticated."
            ),
            state=self.detail_state,
            created_at=NOW - 60,
            expires_at=NOW + 600,
            version=1,
            payload_hash=HASH,
            detail_blocks=(
                (
                    DetailBlock("Message", "plain_text", hostile),
                    DetailBlock(
                        "Recipients",
                        "json",
                        {
                            "to": ["person@example.test"],
                            "cc": ["copy@example.test"],
                            "bcc": ["blind@example.test"],
                        },
                    ),
                    DetailBlock("Reason", "plain_text", "Requested for the Tuesday release"),
                )
                if self.review_available
                else ()
            ),
            events=(
                {
                    "occurred_at": NOW,
                    "action": "queued",
                    "actor": "caller:test",
                    "version": 1,
                    "payload_hash": HASH,
                    "details_json": '{\n  "classification": "reviewed"\n}',
                    "decision_note": self.event_decision_note,
                },
            ),
            editable_arguments_json=(
                '{"body":"exact"}'
                if self.review_available and self.detail_state == "pending_approval"
                else None
            ),
            warnings=("Recipient list changed during drafting.",),
            reviewed_arguments_json=(
                (
                    '{\n  "bcc": ["blind@example.test"],\n  "body": "exact",\n'
                    '  "reason": "Requested for the Tuesday release"\n}'
                )
                if self.review_available
                else None
            ),
            attachments=(
                (
                    RequestAttachment(
                        "stg_" + "x" * 20,
                        "agenda<script>.pdf",
                        "application/pdf",
                        1234,
                        "b" * 64,
                        False,
                        "application/pdf",
                        self.attachment_detection_source,
                    ),
                )
                if self.review_available
                else ()
            ),
            staged_file_hashes=(("b" * 64,) if self.review_available else ()),
            downstream_alias="fastmail",
            tool_name="send_email",
            account_context="primary-account",
            policy_promotion_preview=(
                PolicyPromotionPreview(
                    target_alias="fastmail",
                    target_tool="search_email",
                    current_mode="deny",
                    proposed_mode=self.gateway_proposed_mode,
                    reviewed_read_only=self.gateway_proposed_mode == "passthrough",
                    communication_send=False,
                    reviewed_classification=(
                        None if self.gateway_proposed_mode == "passthrough" else "destructive"
                    ),
                    current_policy_version=3,
                    proposed_policy_version=4,
                    active_policy_version=self.gateway_active_policy_version,
                    can_approve=(
                        self.detail_state == "pending_approval"
                        if self.gateway_can_approve is None
                        else self.gateway_can_approve
                    ),
                    stale=self.gateway_stale,
                )
                if self.gateway_internal and not self.gateway_preview_unavailable
                else None
            ),
            policy_promotion_preview_unavailable=(
                "Exact frozen policy proposal history is unavailable or failed integrity "
                "validation. Approval is disabled; the frozen request context remains available."
                if self.gateway_internal and self.gateway_preview_unavailable
                else None
            ),
            decision_window_expired=self.decision_window_expired,
            policy_mode="approval",
            policy_version="3",
            adapter_version="7",
            schema_version="schema-reviewed-1",
            origin_namespace="profile:web-test",
            review_available=self.review_available,
            gateway_internal=self.gateway_internal,
        )

    def get_historical_detail(
        self,
        principal: SessionPrincipal,
        event_id: int,
    ) -> RequestDetail:
        if event_id not in {101, 102}:
            raise WebConflict("decision event is unavailable")
        detail = self.get_detail(principal, "req_test")
        request_id = "req_approved" if event_id == 102 else "req_test"
        payload_hash = "b" * 64 if event_id == 102 else HASH
        action = "approved_via_web" if event_id == 102 else "denied"
        event = {
            "event_id": event_id,
            "occurred_at": NOW + (1 if event_id == 102 else 0),
            "action": action,
            "actor": "web:autumn",
            "version": 1,
            "payload_hash": payload_hash,
            "details_json": '{\n  "decision_note": "exact_request_approved"\n}',
            "decision_note": ("exact_request_approved" if event_id == 102 else "wrong_destination"),
            "confirmation_kind": "webauthn" if event_id == 102 else "totp",
            "confirmation_path": "web",
            "confirmation_proofs": (),
            "confirmation_match_count": 1,
            "confirmation_attribution_ambiguous": False,
            "decision_confirmation": True,
        }
        return replace(
            detail,
            request_id=request_id,
            version=1,
            payload_hash=payload_hash,
            events=(event,),
            editable_arguments_json=None,
            policy_promotion_preview=None,
            policy_promotion_preview_unavailable=None,
            decision_window_expired=False,
            historical_event_id=event_id,
            historical_event_action=action,
            historical_event_actor="web:autumn",
            historical_event_occurred_at=NOW + (1 if event_id == 102 else 0),
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
        assert principal.user_id == "autumn"
        self.attachment_calls.append(
            (request_id, attachment_id, expected_version, expected_payload_hash)
        )
        if (
            request_id != "req_test"
            or attachment_id != "stg_" + "x" * 20
            or expected_version != 1
            or expected_payload_hash != HASH
        ):
            raise WebConflict("attachment inspection binding is stale")
        content = b'<svg onload="alert(1)">hostile attachment</svg>'
        return AttachmentDownload(content, len(content), "c" * 64)

    def list_audit(self, principal: SessionPrincipal) -> tuple[AuditEntry, ...]:
        assert principal.user_id == "autumn"
        return (AuditEntry(NOW, "caller:test", "queued", "req_test", HASH[:12]),)

    def list_decisions(
        self,
        principal: SessionPrincipal,
        *,
        before_event_id: int | None = None,
    ) -> DecisionPage:
        assert principal.user_id == "autumn"
        self.decision_before_event_ids.append(before_event_id)
        return DecisionPage(
            items=(
                DecisionEntry(
                    102,
                    NOW + 1,
                    "web:autumn",
                    "approved",
                    "Request approved",
                    "web",
                    "webauthn",
                    "req_approved",
                    "succeeded",
                    "fastmail",
                    "send_email",
                    1,
                    "b" * 12,
                ),
                DecisionEntry(
                    101,
                    NOW,
                    "web:autumn",
                    "denied",
                    "Request denied",
                    "web",
                    "totp",
                    "req_test",
                    "denied",
                    "fastmail",
                    "send_email",
                    1,
                    HASH[:12],
                ),
            ),
            has_more=self.decision_has_more,
            next_event_id=41 if self.decision_has_more else None,
        )

    def begin_passkey_action(
        self,
        principal: SessionPrincipal,
        request_id: str,
        action: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        prospective_arguments_json: str | None,
        http_method: str,
        now: int,
        decision_note: str | None = None,
    ) -> ActionOptions:
        assert principal.user_id == "autumn"
        assert (request_id, expected_version, expected_payload_hash) == ("req_test", 1, HASH)
        assert prospective_arguments_json is None and http_method == "POST" and now == NOW
        self.staged_decision_note = decision_note
        return ActionOptions(
            challenge_id="challenge-action",
            public_key={"challenge": "ZmFrZQ", "allowCredentials": []},
            action=action,  # type: ignore[arg-type]
            request_id=request_id,
            version=1,
            payload_hash=HASH,
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
        assert principal.user_id == "autumn"
        assert request_id == "req_test"
        assert challenge_id == "challenge-action" and assertion == {"fake": True}
        assert http_method == "POST" and now == NOW
        self.actions.append(("passkey", "req_test", "approve"))
        self.decision_notes.append(self.staged_decision_note)
        return "approved"

    def complete_totp_action(
        self,
        principal: SessionPrincipal,
        request_id: str,
        action: str,
        totp_proof: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        prospective_arguments_json: str | None,
        now: int,
        decision_note: str | None = None,
        credential_id: str | None = None,
    ) -> str:
        assert principal.user_id == "autumn" and now == NOW
        if self.conflict:
            raise WebConflict("request changed after review")
        assert expected_version == 1 and expected_payload_hash == HASH
        assert prospective_arguments_json is None
        self.actions.append((action, request_id, totp_proof))
        self.totp_credential_ids.append(credential_id)
        self.decision_notes.append(decision_note)
        return {"approve": "approved", "deny": "denied"}.get(action, action)

    def subscribe_push(
        self,
        principal: SessionPrincipal,
        subscription: PushSubscriptionInput,
        *,
        now: int,
    ) -> None:
        assert principal.user_id == "autumn" and now == NOW
        self.push_endpoints.append(subscription.endpoint)

    def unsubscribe_push(
        self,
        principal: SessionPrincipal,
        endpoint: str,
        *,
        now: int,
    ) -> None:
        assert principal.user_id == "autumn" and now == NOW
        self.push_endpoints.remove(endpoint)


class BlockingBackend(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.queue_started = threading.Event()
        self.queue_release = threading.Event()
        self.password_started = threading.Event()
        self.password_release = threading.Event()

    def list_queue(
        self,
        principal: SessionPrincipal,
        *,
        now: int,
        cursor: str | None = None,
    ) -> QueuePage:
        self.queue_started.set()
        if not self.queue_release.wait(timeout=5):
            raise AssertionError("blocking queue test was not released")
        return super().list_queue(principal, now=now, cursor=cursor)

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
        self.password_started.set()
        if not self.password_release.wait(timeout=5):
            raise AssertionError("blocking password test was not released")
        return super().password_totp_login(
            user_id,
            password,
            totp_proof,
            source=source,
            previous_token=previous_token,
            now=now,
        )


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def csrf() -> CsrfManager:
    return CsrfManager(b"c" * 32)


@pytest.fixture
def client(backend: FakeBackend, csrf: CsrfManager) -> TestClient:
    app = create_web_app(
        backend,
        settings=WebSettings(
            public_origin=ORIGIN,
            allowed_hosts=("signet.test",),
            vapid_public_key="fake-public-key",
        ),
        csrf=csrf,
        clock=lambda: NOW,
    )
    return TestClient(app, base_url=ORIGIN)


def authenticate(client: TestClient) -> None:
    client.cookies.set("__Host-signet_session", "session-good")


def test_agent_listener_has_only_privacy_safe_health() -> None:
    with TestClient(create_agent_health_app()) as client:
        assert client.get("/").status_code == 404
        assert client.get("/login").status_code == 404
        health = client.get("/healthz")
    assert health.json() == {"status": "ok", "service": "signet"}
    assert "request" not in health.text and "target" not in health.text


def test_web_health_probe_fails_closed_without_leaking_details(backend: FakeBackend) -> None:
    app = _blocking_app(backend)

    def failed_probe() -> bool:
        raise RuntimeError("private worker detail")

    app.state.signet_health_probe = failed_probe
    with TestClient(app, base_url=ORIGIN) as client:
        response = client.get("/healthz")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "service": "signet-web"}
    assert "private worker detail" not in response.text


def _blocking_app(backend: FakeBackend) -> Any:
    return create_web_app(
        backend,
        settings=WebSettings(
            public_origin=ORIGIN,
            allowed_hosts=("signet.test",),
            vapid_public_key="fake-public-key",
        ),
        csrf=CsrfManager(b"c" * 32),
        clock=lambda: NOW,
    )


@pytest.mark.asyncio
async def test_blocking_queue_storage_does_not_stall_event_loop_health() -> None:
    backend = BlockingBackend()
    transport = ASGITransport(app=_blocking_app(backend))
    safety_release = threading.Timer(3, backend.queue_release.set)
    safety_release.start()
    try:
        async with AsyncClient(transport=transport, base_url=ORIGIN) as client:
            client.cookies.set("__Host-signet_session", "session-good")
            queue_task = asyncio.create_task(client.get("/"))
            assert await asyncio.to_thread(backend.queue_started.wait, 1)
            assert not backend.queue_release.is_set()
            health = await asyncio.wait_for(client.get("/healthz"), timeout=1)
            backend.queue_release.set()
            queue_response = await queue_task
    finally:
        backend.queue_release.set()
        safety_release.cancel()

    assert health.status_code == 200
    assert queue_response.status_code == 200


@pytest.mark.asyncio
async def test_blocking_password_verification_does_not_stall_event_loop_health() -> None:
    backend = BlockingBackend()
    transport = ASGITransport(app=_blocking_app(backend))
    safety_release = threading.Timer(3, backend.password_release.set)
    safety_release.start()
    try:
        async with AsyncClient(transport=transport, base_url=ORIGIN) as client:
            login = await client.get("/login")
            csrf_token = client.cookies.get("__Host-signet_login_csrf")
            assert login.status_code == 200 and csrf_token
            login_task = asyncio.create_task(
                client.post(
                    "/login/password",
                    data={
                        "user_id": "autumn",
                        "password": "fake-password",
                        "totp_proof": "fake:totp",
                        "csrf_token": csrf_token,
                    },
                    headers={"Origin": ORIGIN},
                )
            )
            assert await asyncio.to_thread(backend.password_started.wait, 1)
            assert not backend.password_release.is_set()
            health = await asyncio.wait_for(client.get("/healthz"), timeout=1)
            backend.password_release.set()
            login_response = await login_task
    finally:
        backend.password_release.set()
        safety_release.cancel()

    assert health.status_code == 200
    assert login_response.status_code == 303


def test_oversized_passkey_login_is_rejected_before_backend(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    page = client.get("/login")
    token = client.cookies.get("__Host-signet_login_csrf")
    assert page.status_code == 200 and token

    response = client.post(
        "/login/passkey/options",
        content=b"{" + b'"padding":"' + b"x" * 9000 + b'"}',
        headers={
            "Content-Type": "application/json",
            "Origin": ORIGIN,
            "X-CSRF-Token": token,
        },
    )

    assert response.status_code == 413
    assert response.headers["cache-control"] == "no-store"
    assert backend.actions == []


def test_queue_and_detail_require_session_and_ignore_mcp_bearer(client: TestClient) -> None:
    assert client.get("/").status_code == 401
    for path in (
        "/requests/req_test",
        "/requests/req_test/review",
        "/audit/events/101",
        "/audit/events/101/review",
    ):
        response = client.get(
            path,
            headers={"Authorization": "Bearer valid-agent-token"},
        )
        assert response.status_code == 401
        assert "person@example.test" not in response.text
        assert "Viewing on Tuesday" not in response.text


def test_authenticated_queue_has_security_headers_and_no_sensitive_title(
    client: TestClient,
) -> None:
    authenticate(client)
    response = client.get("/")
    assert response.status_code == 200
    assert '<details class="request-expander">' in response.text
    collapsed_summary = response.text.split("<summary>", 1)[1].split("</summary>", 1)[0]
    assert "person@example.test" not in collapsed_summary
    assert "Viewing on Tuesday" not in collapsed_summary
    assert "blind@example.test" not in collapsed_summary
    assert "person@example.test" not in response.text
    assert "Viewing on Tuesday" not in response.text
    assert "blind@example.test" not in response.text
    assert 'data-review-url="/requests/req_test/review"' in response.text
    assert "fastmail" in response.text
    assert "send_email" in response.text
    assert "req_test" in response.text
    assert HASH[:12] in response.text
    assert "no-store" in response.headers["cache-control"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "form-action 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "same-origin"
    assert "<title>Signet</title>" in response.text


def test_queue_pagination_uses_opaque_cursor_without_loading_private_context(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    backend.queue_has_more = True
    authenticate(client)

    first = client.get("/")
    second = client.get("/?after=opaque-page-token")

    assert first.status_code == 200
    assert 'href="/?after=next-page"' in first.text
    assert "person@example.test" not in first.text
    assert second.status_code == 200
    assert backend.queue_cursors == [None, "opaque-page-token"]


def test_expanded_review_fragment_contains_complete_bound_context(client: TestClient) -> None:
    authenticate(client)
    response = client.get("/requests/req_test/review")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert "Viewing on Tuesday" in response.text
    assert "person@example.test" in response.text
    assert "blind@example.test" in response.text
    assert "Requested for the Tuesday release" in response.text
    assert "Frozen execution arguments" in response.text
    assert "schema-reviewed-1" in response.text
    assert "profile:web-test" in response.text
    assert "agenda&lt;script&gt;.pdf" in response.text
    assert "b" * 64 in response.text
    assert f'name="expected_payload_hash" value="{HASH}"' in response.text
    assert 'name="expected_version" value="1"' in response.text
    assert 'data-decision-note name="decision_note"' not in response.text
    assert 'name="decision_note"' not in response.text
    assert "data-decision-form" in response.text
    assert "data-approval-reason" in response.text
    assert "data-denial-reason" in response.text
    approval_select = re.search(
        r'<select id="approval-reason-([a-f0-9]+)" name="approval_reason" '
        r'form="totp-action-\1" data-approval-reason>',
        response.text,
    )
    denial_select = re.search(
        r'<select id="denial-reason-([a-f0-9]+)" name="denial_reason" '
        r'form="totp-action-\1" data-denial-reason>',
        response.text,
    )
    assert approval_select is not None and denial_select is not None
    assert "Approval reason" in response.text and "Denial reason" in response.text
    assert "Exact content, destination, and scope reviewed and approved" in response.text
    assert "No downstream execution" in response.text
    assert '<time datetime="2027-01-15T07:59:00Z">2027-01-15 07:59:00 UTC</time>' in response.text
    assert '<time datetime="2027-01-15T08:10:00Z">2027-01-15 08:10:00 UTC</time>' in response.text
    assert '<script src="https://evil.test' not in response.text
    assert "&lt;script" in response.text


def test_review_fragment_renders_all_distinct_confirmation_proofs(
    client: TestClient,
    backend: FakeBackend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_get_detail = backend.get_detail

    def get_detail(principal: SessionPrincipal, request_id: str) -> RequestDetail:
        detail = original_get_detail(principal, request_id)
        event = {
            "occurred_at": NOW,
            "action": "policy_promoted_to_approval",
            "actor": "web:autumn",
            "version": 1,
            "payload_hash": HASH,
            "details_json": None,
            "decision_note": None,
            "confirmation_kind": None,
            "confirmation_path": None,
            "confirmation_proofs": (
                {"kind": "totp", "path": "web"},
                {"kind": "webauthn", "path": "web"},
            ),
            "confirmation_match_count": 2,
            "confirmation_attribution_ambiguous": True,
            "decision_confirmation": True,
        }
        return replace(detail, events=(event,))

    monkeypatch.setattr(backend, "get_detail", get_detail)
    authenticate(client)

    response = client.get("/requests/req_test/review")

    assert response.status_code == 200
    normalized = " ".join(response.text.split())
    assert (
        "2 same-second matching proofs (per-event attribution unavailable): "
        "TOTP via web; Passkey via web"
    ) in normalized
    assert "method unavailable" not in normalized


def test_legacy_attachment_filename_guess_is_never_labeled_as_byte_detection(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    backend.attachment_detection_source = "legacy_filename_unverified"
    authenticate(client)

    response = client.get("/requests/req_test/review")

    assert response.status_code == 200
    assert "Legacy filename guess (unverified: application/pdf)" in response.text
    assert "Bounded byte signature" not in response.text


def test_attachment_inspection_is_authenticated_exact_and_forced_binary(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    attachment_id = "stg_" + "x" * 20
    path = f"/requests/req_test/attachments/{attachment_id}?version=1&payload_hash={HASH}"

    unauthenticated = client.get(path)
    assert unauthenticated.status_code == 401
    assert backend.attachment_calls == []

    authenticate(client)
    response = client.get(path)

    assert response.status_code == 200
    assert response.content == b'<svg onload="alert(1)">hostile attachment</svg>'
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"] == (
        'attachment; filename="signet-attachment.bin"'
    )
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-signet-content-sha256"] == "c" * 64
    assert "agenda" not in response.headers["content-disposition"]
    assert backend.attachment_calls == [("req_test", attachment_id, 1, HASH)]

    stale = client.get(path.replace(f"payload_hash={HASH}", f"payload_hash={'d' * 64}"))
    assert stale.status_code == 409
    assert b"hostile attachment" not in stale.content


def test_audit_decisions_are_private_when_collapsed_and_terminal_review_expands(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    authenticate(client)
    audit = client.get("/audit")

    assert audit.status_code == 200
    assert "Recent request decisions and policy changes" in audit.text
    assert 'class="request-expander decision-approved"' in audit.text
    assert 'class="request-expander decision-denied"' in audit.text
    assert 'data-review-url="/audit/events/102/review"' in audit.text
    assert 'data-review-url="/audit/events/101/review"' in audit.text
    assert 'href="/audit/events/102">dedicated audit event view</a>' in audit.text
    assert 'href="/audit/events/101">dedicated audit event view</a>' in audit.text
    assert 'href="/requests/req_approved">request view</a>' not in audit.text
    assert 'href="/requests/req_test">request view</a>' not in audit.text
    assert "Request approved" in audit.text
    assert "Request denied" in audit.text
    assert "person@example.test" not in audit.text
    assert "Requested for the Tuesday release" not in audit.text
    assert "Append-only events" in audit.text
    assert "Passkey" in audit.text
    assert "TOTP" in audit.text
    assert "via web" in audit.text
    assert '<time datetime="2027-01-15T08:00:00Z">2027-01-15 08:00:00 UTC</time>' in audit.text

    backend.detail_state = "pending_approval"
    expanded = client.get("/audit/events/101/review")
    assert expanded.status_code == 200
    assert "person@example.test" in expanded.text
    assert "Requested for the Tuesday release" in expanded.text
    assert "Selected audit event" in expanded.text
    assert "Payload hash at event" in expanded.text
    assert 'data-historical-event-id="101"' in expanded.text
    assert "Current request state: pending approval" in " ".join(expanded.text.split())
    assert "wrong_destination" in expanded.text
    assert "Unavailable in read-only history" in expanded.text
    assert "Open current request view" in expanded.text
    assert "data-csrf" not in expanded.text
    assert "<form" not in expanded.text
    assert 'class="totp-action"' not in expanded.text
    assert "data-passkey-action" not in expanded.text
    assert "Download frozen bytes" not in expanded.text
    assert "Edit frozen arguments" not in expanded.text
    assert ">Policy<" not in expanded.text
    assert "No downstream execution" in expanded.text

    full_page = client.get("/audit/events/101")
    assert full_page.status_code == 200
    assert "Exact audit event" in full_page.text
    assert "person@example.test" in full_page.text
    assert "Requested for the Tuesday release" in full_page.text
    assert 'data-historical-event-id="101"' in full_page.text
    assert "Payload hash at event" in full_page.text
    assert "wrong_destination" in full_page.text
    assert "Open current request view" in full_page.text
    assert "data-csrf" not in full_page.text
    assert full_page.text.count("<form") == 1
    assert 'form action="/logout"' in full_page.text
    assert "/requests/req_test/actions" not in full_page.text
    assert "data-passkey-action" not in full_page.text
    assert "Download frozen bytes" not in full_page.text
    assert full_page.headers["cache-control"] == "no-store, max-age=0"


def test_repeated_request_decisions_have_unique_event_anchors(
    client: TestClient,
    backend: FakeBackend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_list_decisions = backend.list_decisions

    def list_decisions(
        principal: SessionPrincipal,
        *,
        before_event_id: int | None = None,
    ) -> DecisionPage:
        page = original_list_decisions(principal, before_event_id=before_event_id)
        first = replace(
            page.items[0],
            confirmation_kind=None,
            confirmation_path=None,
            confirmation_attribution_ambiguous=True,
            confirmation_match_count=2,
        )
        repeated = replace(page.items[1], request_id=page.items[0].request_id)
        return replace(page, items=(first, repeated))

    monkeypatch.setattr(backend, "list_decisions", list_decisions)
    authenticate(client)

    audit = client.get("/audit")

    assert audit.status_code == 200
    ids = re.findall(r'id="(decision-event-[0-9]+)"', audit.text)
    assert ids == ["decision-event-102", "decision-event-101"]
    assert len(ids) == len(set(ids))
    assert audit.text.count('data-decision-request-id="req_approved"') == 2
    assert 'id="decision-req_approved"' not in audit.text
    assert 'data-review-url="/audit/events/102/review"' in audit.text
    assert 'data-review-url="/audit/events/101/review"' in audit.text
    assert "2 same-second matching proofs; expand for proof details" in " ".join(audit.text.split())

    first_fragment = client.get("/audit/events/102/review")
    second_fragment = client.get("/audit/events/101/review")
    assert first_fragment.status_code == second_fragment.status_code == 200
    assert 'id="context-audit-event-102"' in first_fragment.text
    assert 'id="context-audit-event-101"' in second_fragment.text
    first_ids = set(re.findall(r'\bid="([^"]+)"', first_fragment.text))
    second_ids = set(re.findall(r'\bid="([^"]+)"', second_fragment.text))
    assert first_ids.isdisjoint(second_ids)
    assert "<form" not in first_fragment.text + second_fragment.text


def test_decision_history_cursor_is_session_bound_and_tamper_resistant(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    backend.decision_has_more = True
    authenticate(client)

    first = client.get("/audit")
    match = re.search(r'href="/audit\?before=([A-Za-z0-9.]+)"', first.text)
    assert first.status_code == 200 and match is not None
    cursor = match.group(1)

    second = client.get(f"/audit?before={cursor}")
    replacement = "0" if cursor[-1] != "0" else "1"
    tampered = client.get(f"/audit?before={cursor[:-1]}{replacement}")

    assert second.status_code == 200
    assert backend.decision_before_event_ids == [None, 41]
    assert tampered.status_code == 409
    assert backend.decision_before_event_ids == [None, 41]


def test_mobile_styles_preserve_audit_navigation(client: TestClient) -> None:
    authenticate(client)
    page = client.get("/")
    stylesheet = (ROOT / "src" / "signet" / "static" / "app.css").read_text()

    assert 'class="primary-audit-link" href="/audit"' in page.text
    assert "nav .primary-audit-link" in stylesheet
    assert "nav a { display: none; }" not in stylesheet


def test_keyboard_focus_outline_meets_non_text_contrast() -> None:
    stylesheet = (ROOT / "src" / "signet" / "static" / "app.css").read_text()
    match = re.search(
        r"\.table-scroll:focus-visible \{ outline: 3px solid (#[0-9a-f]{6});",
        stylesheet,
    )
    assert match is not None

    def luminance(color: str) -> float:
        channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [
            channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
            for channel in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    def contrast(first: str, second: str) -> float:
        lighter, darker = sorted((luminance(first), luminance(second)), reverse=True)
        return (lighter + 0.05) / (darker + 0.05)

    focus = match.group(1)
    assert contrast(focus, "#ffffff") >= 3
    assert contrast(focus, "#f7f8f5") >= 3


def test_no_javascript_hides_inert_controls_and_keeps_login_fallback(
    client: TestClient,
) -> None:
    page = client.get("/login")
    stylesheet = (ROOT / "src" / "signet" / "static" / "app.css").read_text()

    assert page.status_code == 200
    assert "data-passkey-login" in page.text
    assert 'action="/login/password" method="post"' in page.text
    assert ".no-js [data-passkey-login]" in stylesheet
    assert ".no-js [data-passkey-action]" in stylesheet
    assert ".no-js [data-enable-push]" in stylesheet


def test_unavailable_review_fragment_is_metadata_only_and_has_no_actions(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    backend.review_available = False
    authenticate(client)

    response = client.get("/requests/req_test/review")

    assert response.status_code == 200
    assert "Reviewed content unavailable" in response.text
    assert "authenticated exact-revision review" in response.text
    assert "Frozen execution arguments" not in response.text
    assert "agenda&lt;script&gt;.pdf" not in response.text
    assert 'class="totp-action"' not in response.text
    assert "data-passkey-action" not in response.text
    assert "Always allow" not in response.text


def test_host_origin_preflight_and_csrf_fail_before_mutation(
    client: TestClient,
    backend: FakeBackend,
    csrf: CsrfManager,
) -> None:
    authenticate(client)
    assert client.get("/", headers={"Host": "evil.test"}).status_code == 400
    assert client.options("/requests/req_test/actions/totp").status_code == 403
    form = {
        "action": "approve",
        "expected_version": "1",
        "expected_payload_hash": HASH,
        "totp_proof": "fake:proof",
        "csrf_token": csrf.session_token("session-id", "request:req_test"),
    }
    assert client.post("/requests/req_test/actions/totp", data=form).status_code == 403
    assert (
        client.post(
            "/requests/req_test/actions/totp",
            data={**form, "csrf_token": "wrong"},
            headers={"Origin": ORIGIN},
        ).status_code
        == 403
    )
    assert backend.actions == []


def test_valid_totp_action_and_stale_conflict_are_explicit(
    client: TestClient,
    backend: FakeBackend,
    csrf: CsrfManager,
) -> None:
    authenticate(client)
    form = {
        "action": "approve",
        "expected_version": "1",
        "expected_payload_hash": HASH,
        "totp_proof": "fake:proof",
        "totp_credential_id": "totp-travel",
        "decision_note": "exact_request_approved",
        "csrf_token": csrf.session_token("session-id", "request:req_test"),
    }
    response = client.post(
        "/requests/req_test/actions/totp",
        data=form,
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/audit#decision-req_test"
    assert backend.actions == [("approve", "req_test", "fake:proof")]
    assert backend.totp_credential_ids == ["totp-travel"]
    assert backend.decision_notes == ["exact_request_approved"]

    backend.conflict = True
    response = client.post(
        "/requests/req_test/actions/totp",
        data=form,
        headers={"Origin": ORIGIN, "Accept": "application/json"},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "stale_request"


@pytest.mark.parametrize(
    ("action", "field", "reason"),
    (
        ("approve", "approval_reason", "expected_and_authorized"),
        ("deny", "denial_reason", "wrong_destination"),
    ),
)
def test_javascript_free_totp_decisions_submit_action_specific_reasons(
    client: TestClient,
    backend: FakeBackend,
    csrf: CsrfManager,
    action: str,
    field: str,
    reason: str,
) -> None:
    authenticate(client)
    response = client.post(
        "/requests/req_test/actions/totp",
        data={
            "action": action,
            "expected_version": "1",
            "expected_payload_hash": HASH,
            "totp_proof": "fake:proof",
            field: reason,
            "csrf_token": csrf.session_token("session-id", "request:req_test"),
        },
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert backend.decision_notes == [reason]


@pytest.mark.parametrize(
    ("proposed_mode", "expected_consequence", "expected_read_only"),
    (
        ("passthrough", "Future calls will bypass approval.", "Yes"),
        ("approval", "Future calls will still require separate approval.", "No"),
    ),
)
def test_javascript_free_gateway_policy_approval_has_full_exact_preview(
    client: TestClient,
    backend: FakeBackend,
    csrf: CsrfManager,
    proposed_mode: str,
    expected_consequence: str,
    expected_read_only: str,
) -> None:
    backend.gateway_internal = True
    backend.gateway_proposed_mode = proposed_mode
    authenticate(client)
    review = client.get("/requests/req_test/review")
    assert review.status_code == 200
    assert 'data-gateway-internal="true"' in review.text
    assert "data-approval-reason" not in review.text
    assert "data-denial-reason" in review.text
    assert "Edit frozen arguments" not in review.text
    assert "data-edit-json" not in review.text
    assert "data-policy-preview" in review.text
    assert "Exact policy change on approval" in review.text
    assert "fastmail.search_email" in review.text
    assert "Target mode at review" in review.text and "deny" in review.text
    assert "Proposed new mode" in review.text and proposed_mode in review.text
    assert "Reviewed read-only" in review.text and expected_read_only in review.text
    assert "Communication classification" in review.text
    assert "Not a communication send" in review.text
    assert "Reviewed classification" in review.text
    assert "Policy version at review" in review.text and ">3<" in review.text
    assert "Expected next version at review" in review.text and ">4<" in review.text
    assert "Active policy version" in review.text
    assert expected_consequence in review.text
    assert "Approve policy change" in review.text

    token = csrf.session_token("session-id", "request:req_test")
    approved = client.post(
        "/requests/req_test/actions/totp",
        data={
            "action": "approve",
            "expected_version": "1",
            "expected_payload_hash": HASH,
            "totp_proof": "fake:proof",
            "csrf_token": token,
        },
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert approved.status_code == 303
    assert backend.decision_notes == [None]

    reasoned_approval = client.post(
        "/requests/req_test/actions/totp",
        data={
            "action": "approve",
            "approval_reason": "exact_request_approved",
            "expected_version": "1",
            "expected_payload_hash": HASH,
            "totp_proof": "fake:proof",
            "csrf_token": token,
        },
        headers={"Origin": ORIGIN},
    )
    assert reasoned_approval.status_code == 422

    missing_denial = client.post(
        "/requests/req_test/actions/totp",
        data={
            "action": "deny",
            "expected_version": "1",
            "expected_payload_hash": HASH,
            "totp_proof": "fake:proof",
            "csrf_token": token,
        },
        headers={"Origin": ORIGIN},
    )
    assert missing_denial.status_code == 422


def test_stale_gateway_preview_keeps_full_context_and_deny_cancel_controls(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    backend.gateway_internal = True
    backend.gateway_active_policy_version = 4
    backend.gateway_can_approve = False
    backend.gateway_stale = True
    authenticate(client)

    review = client.get("/requests/req_test/review")

    assert review.status_code == 200
    assert "Frozen policy proposal at review" in review.text
    assert "Requested for the Tuesday release" in review.text
    assert "Frozen execution arguments" in review.text
    assert "reviewed against policy v3, but active policy is v4" in review.text
    assert 'name="action" value="approve"' not in review.text
    assert 'data-passkey-action="approve"' not in review.text
    assert 'name="action" value="deny"' in review.text
    assert 'name="action" value="cancel"' in review.text
    assert "Edit frozen arguments" not in review.text


def test_expired_unswept_gateway_preview_has_context_without_resolution_controls(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    backend.gateway_internal = True
    backend.gateway_active_policy_version = 4
    backend.gateway_can_approve = False
    backend.gateway_stale = True
    backend.decision_window_expired = True
    authenticate(client)

    review = client.get("/requests/req_test/review")

    assert review.status_code == 200
    assert "Frozen policy proposal at review" in review.text
    assert "Requested for the Tuesday release" in review.text
    assert "This proposal has expired" in review.text
    assert "cannot be approved, denied, or cancelled" in review.text
    assert "Deny or cancel it" not in review.text
    assert "action-band" not in review.text
    assert 'name="action" value="approve"' not in review.text
    assert 'name="action" value="deny"' not in review.text
    assert 'name="action" value="cancel"' not in review.text


def test_expired_unswept_ordinary_request_hides_all_mutations(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    backend.decision_window_expired = True
    authenticate(client)

    review = client.get("/requests/req_test/review")

    assert review.status_code == 200
    assert "Decision window expired" in review.text
    assert "can no longer be approved, denied, edited, or cancelled" in review.text
    assert "Requested for the Tuesday release" in review.text
    assert "action-band" not in review.text
    assert "edit-band" not in review.text


def test_terminal_gateway_denial_retains_frozen_policy_reasoning(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    backend.gateway_internal = True
    backend.detail_state = "denied"
    backend.gateway_can_approve = False
    authenticate(client)

    review = client.get("/requests/req_test/review")

    assert review.status_code == 200
    assert "Frozen policy proposal at review" in review.text
    assert "Requested for the Tuesday release" in review.text
    assert "Target mode at review" in review.text
    assert "Expected next version at review" in review.text
    assert "This historical view does not change policy" in review.text
    assert 'name="action" value="approve"' not in review.text
    assert 'name="action" value="deny"' not in review.text


def test_unavailable_gateway_history_preserves_base_context_and_disables_only_approval(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    backend.gateway_internal = True
    backend.gateway_preview_unavailable = True
    authenticate(client)

    review = client.get("/requests/req_test/review")

    assert review.status_code == 200
    assert "Policy proposal history unavailable" in review.text
    assert "failed integrity validation" in review.text
    assert "frozen request context remains available" in review.text
    assert "Requested for the Tuesday release" in review.text
    assert "Frozen execution arguments" in review.text
    assert 'name="action" value="approve"' not in review.text
    assert 'name="action" value="deny"' in review.text
    assert 'name="action" value="cancel"' in review.text


def test_passkey_gateway_policy_approval_stages_and_completes_without_reason(
    client: TestClient,
    backend: FakeBackend,
    csrf: CsrfManager,
) -> None:
    backend.gateway_internal = True
    authenticate(client)
    token = csrf.session_token("session-id", "request:req_test")
    options = client.post(
        "/requests/req_test/actions/passkey/options",
        json={
            "action": "approve",
            "expected_version": 1,
            "expected_payload_hash": HASH,
            "decision_note": None,
        },
        headers={"Origin": ORIGIN, "X-CSRF-Token": token},
    )
    assert options.status_code == 200
    assert backend.staged_decision_note is None

    complete = client.post(
        "/requests/req_test/actions/passkey/complete",
        json={"challenge_id": "challenge-action", "assertion": {"fake": True}},
        headers={"Origin": ORIGIN, "X-CSRF-Token": token},
    )
    assert complete.status_code == 200
    assert backend.decision_notes == [None]

    reasoned = client.post(
        "/requests/req_test/actions/passkey/options",
        json={
            "action": "approve",
            "expected_version": 1,
            "expected_payload_hash": HASH,
            "decision_note": "exact_request_approved",
        },
        headers={"Origin": ORIGIN, "X-CSRF-Token": token},
    )
    assert reasoned.status_code == 422


@pytest.mark.parametrize(
    ("action", "field", "reason"),
    (
        ("approve", "approval_reason", "wrong_destination"),
        ("deny", "denial_reason", "exact_request_approved"),
    ),
)
def test_javascript_free_totp_decisions_reject_cross_action_reasons(
    client: TestClient,
    backend: FakeBackend,
    csrf: CsrfManager,
    action: str,
    field: str,
    reason: str,
) -> None:
    authenticate(client)
    response = client.post(
        "/requests/req_test/actions/totp",
        data={
            "action": action,
            "expected_version": "1",
            "expected_payload_hash": HASH,
            "totp_proof": "fake:proof",
            field: reason,
            "csrf_token": csrf.session_token("session-id", "request:req_test"),
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 422
    assert backend.actions == []


@pytest.mark.parametrize("decision_note", ["not_a_reason", "unsafe\x00control"])
def test_invalid_decision_rationale_is_rejected_before_mutation(
    client: TestClient,
    backend: FakeBackend,
    csrf: CsrfManager,
    decision_note: str,
) -> None:
    authenticate(client)
    response = client.post(
        "/requests/req_test/actions/totp",
        data={
            "action": "deny",
            "expected_version": "1",
            "expected_payload_hash": HASH,
            "totp_proof": "fake:proof",
            "decision_note": decision_note,
            "csrf_token": csrf.session_token("session-id", "request:req_test"),
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 422
    assert backend.actions == []


def test_decision_reason_is_rendered_as_a_fixed_label(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    backend.detail_state = "denied"
    backend.event_decision_note = "wrong_destination"
    authenticate(client)

    response = client.get("/requests/req_test/review")

    assert response.status_code == 200
    assert "Decision reason" in response.text
    assert "Recipient or destination is incorrect" in response.text
    assert "Reason code:" in response.text
    assert "wrong_destination" in response.text


def test_passkey_action_is_session_method_and_csrf_bound(
    client: TestClient,
    backend: FakeBackend,
    csrf: CsrfManager,
) -> None:
    authenticate(client)
    token = csrf.session_token("session-id", "request:req_test")
    options = client.post(
        "/requests/req_test/actions/passkey/options",
        json={
            "action": "approve",
            "expected_version": 1,
            "expected_payload_hash": HASH,
            "decision_note": "exact_request_approved",
        },
        headers={"Origin": ORIGIN, "X-CSRF-Token": token},
    )
    assert options.status_code == 200
    assert options.json()["challenge_id"] == "challenge-action"
    complete = client.post(
        "/requests/req_test/actions/passkey/complete",
        json={"challenge_id": "challenge-action", "assertion": {"fake": True}},
        headers={"Origin": ORIGIN, "X-CSRF-Token": token},
    )
    assert complete.json() == {
        "status": "approved",
        "request_id": "req_test",
        "redirect_url": "/audit#decision-req_test",
    }
    assert backend.actions == [("passkey", "req_test", "approve")]
    assert backend.decision_notes == ["exact_request_approved"]


def test_login_csrf_session_cookie_and_fixation_input(client: TestClient) -> None:
    page = client.get("/login")
    token = client.cookies.get("__Host-signet_login_csrf")
    assert page.status_code == 200 and token
    assert "Secure" in page.headers["set-cookie"]
    assert "HttpOnly" in page.headers["set-cookie"]
    client.cookies.set("__Host-signet_session", "attacker-fixed")
    response = client.post(
        "/login/password",
        data={
            "user_id": "autumn",
            "password": "fake-password",
            "totp_proof": "fake:totp",
            "csrf_token": token,
        },
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "session-good" in response.headers["set-cookie"]
    assert "SameSite=strict" in response.headers["set-cookie"]


def test_insecure_cookies_are_available_only_on_named_loopback_http(
    backend: FakeBackend,
    csrf: CsrfManager,
) -> None:
    origin = "http://127.0.0.1:8790"
    app = create_web_app(
        backend,
        settings=WebSettings(
            public_origin=origin,
            allowed_hosts=("127.0.0.1", "localhost"),
            session_cookie="signet_demo_session",
            login_csrf_cookie="signet_demo_login_csrf",
            secure_cookies=False,
            fake_only_ui=True,
        ),
        csrf=csrf,
        clock=lambda: NOW,
    )
    with TestClient(app, base_url=origin) as loopback:
        page = loopback.get("/login")
        token = loopback.cookies.get("signet_demo_login_csrf")
        assert page.status_code == 200 and token
        assert "Secure" not in page.headers["set-cookie"]

        wrong_origin = loopback.post(
            "/login/password",
            data={
                "user_id": "autumn",
                "password": "fake-password",
                "totp_proof": "fake:totp",
                "csrf_token": token,
            },
            headers={"Origin": "http://evil.test"},
        )
        assert wrong_origin.status_code == 403

        response = loopback.post(
            "/login/password",
            data={
                "user_id": "autumn",
                "password": "fake-password",
                "totp_proof": "fake:totp",
                "csrf_token": token,
            },
            headers={"Origin": origin},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "signet_demo_session=session-good" in response.headers["set-cookie"]
        assert "Secure" not in response.headers["set-cookie"]
        assert loopback.get("/").status_code == 200
        assert loopback.get("/", headers={"Host": "evil.test"}).status_code == 400


@pytest.mark.parametrize(
    "kwargs",
    (
        {
            "public_origin": "http://example.test",
            "allowed_hosts": ("example.test",),
            "session_cookie": "demo_session",
            "login_csrf_cookie": "demo_login",
            "secure_cookies": False,
        },
        {
            "public_origin": "http://127.0.0.1:8790",
            "allowed_hosts": ("127.0.0.1",),
            "secure_cookies": False,
        },
        {
            "public_origin": "https://signet.test",
            "allowed_hosts": ("signet.test",),
            "session_cookie": "not-host-prefixed",
        },
        {
            "public_origin": "https://signet.test",
            "allowed_hosts": ("other.test",),
        },
        {
            "public_origin": "https://signet.test",
            "allowed_hosts": ("signet.test", "*"),
        },
        {
            "public_origin": "https://signet.test",
            "allowed_hosts": ("signet.test",),
            "session_cookie": "__Host-bad;cookie",
        },
        {
            "public_origin": "https://signet.test",
            "allowed_hosts": ("signet.test",),
            "session_cookie": "__Host-same",
            "login_csrf_cookie": "__Host-same",
        },
        {
            "public_origin": "https://signet.test",
            "allowed_hosts": ("signet.test",),
            "fake_only_ui": True,
        },
        {
            "public_origin": "https://signet.test",
            "allowed_hosts": ("signet.test", "SIGNET.TEST"),
        },
    ),
)
def test_web_settings_reject_unsafe_origin_host_and_cookie_combinations(
    kwargs: dict[str, Any],
) -> None:
    with pytest.raises(ValueError):
        WebSettings(**kwargs)


def test_hostile_detail_is_opaque_text_without_remote_fetch_surface(client: TestClient) -> None:
    authenticate(client)
    response = client.get("/requests/req_test")
    assert response.status_code == 200
    assert '<script src="https://evil.test' not in response.text
    assert '<form action="//evil.test"' not in response.text
    assert "&lt;script" in response.text
    assert "https://evil.test" in response.text
    assert "<title>Signet</title>" in response.text


def test_push_subscription_is_session_and_csrf_scoped(
    client: TestClient,
    backend: FakeBackend,
    csrf: CsrfManager,
) -> None:
    authenticate(client)
    token = csrf.session_token("session-id", "push")
    payload = {
        "endpoint": "https://push.example.test/device",
        "p256dh": "fake-p256dh",
        "auth": "fake-auth",
        "device_label": "Test phone",
        "categories": [],
    }
    assert (
        client.post(
            "/push/subscriptions",
            json=payload,
            headers={"Origin": ORIGIN, "X-CSRF-Token": token},
        ).status_code
        == 204
    )
    assert backend.push_endpoints == [payload["endpoint"]]


def test_pwa_assets_install_without_offline_approval(client: TestClient) -> None:
    manifest = client.get("/manifest.webmanifest")
    assert manifest.status_code == 200
    assert manifest.json()["name"] == "Signet"
    assert manifest.json()["display"] == "standalone"
    assert manifest.json()["icons"][0]["sizes"] == "1254x1254"
    worker = client.get("/service-worker.js")
    assert "backgroundsync" not in worker.text.lower()
    assert "caches." not in worker.text
    assert 'addEventListener("fetch"' not in worker.text
    assert "event.data" not in worker.text
    assert 'body: "Approval queue updated"' in worker.text
    assert 'data: { url: "/" }' in worker.text
    assert worker.headers["service-worker-allowed"] == "/"

    icon = ROOT / "src/signet/static/icons/signet-1254.png"
    with icon.open("rb") as handle:
        header = handle.read(24)
    assert header[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", header[16:24]) == (1254, 1254)


def test_csrf_repr_redacts_key() -> None:
    manager = CsrfManager(b"highly-sensitive-csrf-key-value" * 2)
    assert "highly-sensitive" not in repr(manager)
    token = manager.session_token("session", "action")
    assert manager.verify_session("session", "action", token)
    assert not manager.verify_session("session", "other", token)
    assert re.fullmatch(r"c1\.[a-f0-9]{64}", token)


class _SetupRegistrationProvider:
    test_only = True

    def verify(
        self,
        credential: Mapping[str, Any],
        *,
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
    ) -> RegistrationResult:
        assert credential["challenge"] == expected_challenge.hex()
        assert expected_rp_id == "signet.test"
        assert expected_origin == ORIGIN
        return RegistrationResult(
            credential_id=base64.urlsafe_b64encode(b"setup-passkey").rstrip(b"=").decode(),
            public_key=b"public-key",
            sign_count=0,
            device_type="multi_device",
            backed_up=True,
            transports=("internal",),
            discoverable=True,
        )


def test_initial_owner_setup_is_browser_only_resumable_and_one_time(
    tmp_path: Path,
    backend: FakeBackend,
    csrf: CsrfManager,
) -> None:
    database = Database(tmp_path / "setup-web.db")
    database.initialize()
    bootstrap = BootstrapService(database, owner_user_id="user:owner")
    registrations = PasskeyRegistrationService(
        database,
        provider=_SetupRegistrationProvider(),
        rp_id="signet.test",
        origin=ORIGIN,
        allow_test_provider=True,
    )
    unused = cast(Any, object())
    webauthn_repository = SQLiteWebAuthnRepository(database)
    browser_auth = BrowserAuthController(
        bootstrap=bootstrap,
        registrations=registrations,
        manager=unused,
        totp_verifier=unused,
        webauthn_issuer=unused,
        webauthn_verifier=unused,
        webauthn_repository=webauthn_repository,
    )
    app = create_web_app(
        backend,
        settings=WebSettings(public_origin=ORIGIN, allowed_hosts=("signet.test",)),
        csrf=csrf,
        browser_auth=browser_auth,
        clock=lambda: NOW,
    )

    with TestClient(app, base_url=ORIGIN) as setup_client:
        login = setup_client.get("/login", follow_redirects=False)
        assert login.status_code == 303
        assert login.headers["location"] == "/setup"

        page = setup_client.get("/setup")
        token = setup_client.cookies.get("__Host-signet_login_csrf")
        assert page.status_code == 200 and token
        assert "Set up Signet" in page.text
        assert "Create your password" in page.text
        assert "Add an authenticator" in page.text

        wrong_origin = setup_client.post(
            "/setup/password",
            data={
                "password": "correct horse battery staple",
                "password_confirmation": "correct horse battery staple",
                "csrf_token": token,
            },
            headers={"Origin": "https://attacker.test"},
        )
        assert wrong_origin.status_code == 403

        password = setup_client.post(
            "/setup/password",
            data={
                "password": "correct horse battery staple",
                "password_confirmation": "correct horse battery staple",
                "csrf_token": token,
            },
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
        assert password.status_code == 303

        too_early = setup_client.post(
            "/setup/complete",
            data={"csrf_token": token},
            headers={"Origin": ORIGIN},
        )
        assert too_early.status_code == 400

        options = setup_client.post(
            "/setup/passkeys/options",
            json={"label": "Mac passkey"},
            headers={"Origin": ORIGIN, "X-CSRF-Token": token},
        )
        assert options.status_code == 200
        body = options.json()
        assert body["publicKey"]["rp"]["id"] == "signet.test"
        encoded_challenge = str(body["publicKey"]["challenge"])
        challenge = base64.urlsafe_b64decode(
            encoded_challenge + "=" * (-len(encoded_challenge) % 4)
        )

        completed = setup_client.post(
            "/setup/passkeys/complete",
            json={
                "challenge_id": body["challenge_id"],
                "credential": {"id": "test", "challenge": challenge.hex()},
            },
            headers={"Origin": ORIGIN, "X-CSRF-Token": token},
        )
        assert completed.status_code == 200

        finished = setup_client.post(
            "/setup/complete",
            data={"csrf_token": token},
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
        assert finished.status_code == 303
        assert finished.headers["location"] == "/login?setup=complete"

        login_after_setup = setup_client.get("/login")
        replay_token = setup_client.cookies.get("__Host-signet_login_csrf")
        assert login_after_setup.status_code == 200 and replay_token
        replay = setup_client.post(
            "/setup/complete",
            data={"csrf_token": replay_token},
            headers={"Origin": ORIGIN},
        )
        assert replay.status_code == 409
        assert "correct horse" not in replay.text
