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
    DetailBlock,
    LoginOptions,
    PushSubscriptionInput,
    QueueItem,
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
    ) -> tuple[QueueItem, ...]:
        assert principal.user_id == "autumn" and now == NOW
        return (
            QueueItem(
                "req_test",
                "Fastmail",
                "send_email",
                "masked@example.test",
                "pending_approval",
                NOW - 60,
                NOW + 600,
                1,
                HASH,
            ),
        )

    def get_detail(self, principal: SessionPrincipal, request_id: str) -> RequestDetail:
        assert principal.user_id == "autumn" and request_id == "req_test"
        hostile = '</pre><script src="https://evil.test/a.js"></script><form action="//evil.test">'
        return RequestDetail(
            request_id="req_test",
            service="Fastmail",
            action="send_email",
            title="Viewing on Tuesday <script>alert(1)</script>",
            destination_summary="person@example.test",
            state="pending_approval",
            created_at=NOW - 60,
            expires_at=NOW + 600,
            version=1,
            payload_hash=HASH,
            detail_blocks=(
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
            ),
            events=(
                {
                    "occurred_at": NOW,
                    "action": "queued",
                    "actor": "caller:test",
                    "version": 1,
                    "payload_hash": HASH,
                    "details_json": '{\n  "classification": "reviewed"\n}',
                },
            ),
            editable_arguments_json='{"body":"exact"}',
            warnings=("Recipient list changed during drafting.",),
            reviewed_arguments_json=(
                '{\n  "bcc": ["blind@example.test"],\n  "body": "exact",\n'
                '  "reason": "Requested for the Tuesday release"\n}'
            ),
            attachments=(
                RequestAttachment(
                    "stg_test",
                    "agenda<script>.pdf",
                    "application/pdf",
                    1234,
                    "b" * 64,
                    False,
                ),
            ),
            staged_file_hashes=("b" * 64,),
            downstream_alias="fastmail",
            tool_name="send_email",
            account_context="primary-account",
            policy_mode="approval",
            policy_version="3",
            adapter_version="7",
            schema_version="schema-reviewed-1",
            origin_namespace="profile:web-test",
        )

    def list_audit(self, principal: SessionPrincipal) -> tuple[AuditEntry, ...]:
        assert principal.user_id == "autumn"
        return (AuditEntry(NOW, "caller:test", "queued", "req_test", HASH[:12]),)

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
    ) -> ActionOptions:
        assert principal.user_id == "autumn"
        assert (request_id, expected_version, expected_payload_hash) == ("req_test", 1, HASH)
        assert prospective_arguments_json is None and http_method == "POST" and now == NOW
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
    ) -> str:
        assert principal.user_id == "autumn" and now == NOW
        if self.conflict:
            raise WebConflict("request changed after review")
        assert expected_version == 1 and expected_payload_hash == HASH
        assert prospective_arguments_json is None
        self.actions.append((action, request_id, totp_proof))
        return action

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
    assert "no-store" in response.headers["cache-control"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "form-action 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "<title>Signet</title>" in response.text


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
    assert '<script src="https://evil.test' not in response.text
    assert "&lt;script" in response.text


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
    assert client.post(
        "/requests/req_test/actions/totp",
        data={**form, "csrf_token": "wrong"},
        headers={"Origin": ORIGIN},
    ).status_code == 403
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
        "csrf_token": csrf.session_token("session-id", "request:req_test"),
    }
    response = client.post(
        "/requests/req_test/actions/totp",
        data=form,
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert backend.actions == [("approve", "req_test", "fake:proof")]

    backend.conflict = True
    response = client.post(
        "/requests/req_test/actions/totp",
        data=form,
        headers={"Origin": ORIGIN, "Accept": "application/json"},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "stale_request"


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
    assert complete.json() == {"status": "approved", "request_id": "req_test"}
    assert backend.actions == [("passkey", "req_test", "approve")]


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


def test_hostile_detail_is_opaque_text_without_remote_fetch_surface(client: TestClient) -> None:
    authenticate(client)
    response = client.get("/requests/req_test")
    assert response.status_code == 200
    assert '<script src="https://evil.test' not in response.text
    assert "<form action=\"//evil.test\"" not in response.text
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
    assert client.post(
        "/push/subscriptions",
        json=payload,
        headers={"Origin": ORIGIN, "X-CSRF-Token": token},
    ).status_code == 204
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
