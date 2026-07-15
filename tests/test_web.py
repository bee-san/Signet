from __future__ import annotations

import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from signet.auth import InvalidSession, SessionPrincipal
from signet.web import (
    ActionOptions,
    AuditEntry,
    CsrfManager,
    DecisionEntry,
    DetailBlock,
    LoginOptions,
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

NOW = 1_800_000_000
ORIGIN = "https://signet.test"
HASH = "a" * 64
ROOT = Path(__file__).resolve().parents[1]


@dataclass
class FakeBackend:
    actions: list[tuple[str, str, str]] = field(default_factory=list)
    push_endpoints: list[str] = field(default_factory=list)
    conflict: bool = False
    detail_state: str = "pending_approval"
    review_available: bool = True
    queue_has_more: bool = False
    queue_cursors: list[str | None] = field(default_factory=list)
    decision_notes: list[str | None] = field(default_factory=list)
    staged_decision_note: str | None = None
    event_decision_note: str | None = None

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
                        "stg_test",
                        "agenda<script>.pdf",
                        "application/pdf",
                        1234,
                        "b" * 64,
                        False,
                    ),
                )
                if self.review_available
                else ()
            ),
            staged_file_hashes=(("b" * 64,) if self.review_available else ()),
            downstream_alias="fastmail",
            tool_name="send_email",
            account_context="primary-account",
            policy_mode="approval",
            policy_version="3",
            adapter_version="7",
            schema_version="schema-reviewed-1",
            origin_namespace="profile:web-test",
            review_available=self.review_available,
        )

    def list_audit(self, principal: SessionPrincipal) -> tuple[AuditEntry, ...]:
        assert principal.user_id == "autumn"
        return (AuditEntry(NOW, "caller:test", "queued", "req_test", HASH[:12]),)

    def list_decisions(self, principal: SessionPrincipal) -> tuple[DecisionEntry, ...]:
        assert principal.user_id == "autumn"
        return (
            DecisionEntry(
                NOW + 1,
                "web:autumn",
                "approved",
                "web",
                "req_approved",
                "succeeded",
                "fastmail",
                "send_email",
                1,
                "b" * 12,
            ),
            DecisionEntry(
                NOW,
                "web:autumn",
                "denied",
                None,
                "req_test",
                "denied",
                "fastmail",
                "send_email",
                1,
                HASH[:12],
            ),
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
    ) -> str:
        assert principal.user_id == "autumn" and now == NOW
        if self.conflict:
            raise WebConflict("request changed after review")
        assert expected_version == 1 and expected_payload_hash == HASH
        assert prospective_arguments_json is None
        self.actions.append((action, request_id, totp_proof))
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
    for path in ("/requests/req_test", "/requests/req_test/review"):
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
    assert 'name="decision_note"' in response.text
    assert 'maxlength="1000"' in response.text
    assert "No downstream execution" in response.text
    assert '<script src="https://evil.test' not in response.text
    assert "&lt;script" in response.text


def test_audit_decisions_are_private_when_collapsed_and_terminal_review_expands(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    authenticate(client)
    audit = client.get("/audit")

    assert audit.status_code == 200
    assert "Recent approvals and denials" in audit.text
    assert 'class="request-expander decision-approved"' in audit.text
    assert 'class="request-expander decision-denied"' in audit.text
    assert 'data-review-url="/requests/req_approved/review"' in audit.text
    assert 'data-review-url="/requests/req_test/review"' in audit.text
    assert "person@example.test" not in audit.text
    assert "Requested for the Tuesday release" not in audit.text
    assert "Append-only events" in audit.text

    backend.detail_state = "denied"
    expanded = client.get("/requests/req_test/review")
    assert expanded.status_code == 200
    assert "person@example.test" in expanded.text
    assert "Requested for the Tuesday release" in expanded.text
    assert 'class="totp-action"' not in expanded.text
    assert "data-passkey-action" not in expanded.text
    assert "Nothing was executed downstream" in expanded.text


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
        "decision_note": "Destination and scope reviewed.",
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
    assert backend.decision_notes == ["Destination and scope reviewed."]

    backend.conflict = True
    response = client.post(
        "/requests/req_test/actions/totp",
        data=form,
        headers={"Origin": ORIGIN, "Accept": "application/json"},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "stale_request"


@pytest.mark.parametrize("decision_note", ["x" * 1_001, "unsafe\x00control"])
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


def test_decision_note_is_escaped_in_expanded_event_timeline(
    client: TestClient,
    backend: FakeBackend,
) -> None:
    backend.detail_state = "denied"
    backend.event_decision_note = '<script src="https://evil.test/note.js"></script>'
    authenticate(client)

    response = client.get("/requests/req_test/review")

    assert response.status_code == 200
    assert "Decision note" in response.text
    assert '<script src="https://evil.test/note.js">' not in response.text
    assert "&lt;script src=&#34;https://evil.test/note.js&#34;&gt;" in response.text


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
            "decision_note": "Passkey decision rationale.",
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
    assert backend.decision_notes == ["Passkey decision rationale."]


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
        WebSettings(**kwargs)  # type: ignore[arg-type]


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
