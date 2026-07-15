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
    AttachmentDownload,
    AuditEntry,
    CsrfManager,
    DecisionEntry,
    DecisionPage,
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
    decision_before_event_ids: list[int | None] = field(default_factory=list)
    decision_has_more: bool = False
    decision_notes: list[str | None] = field(default_factory=list)
    staged_decision_note: str | None = None
    event_decision_note: str | None = None
    attachment_detection_source: str | None = "content_signature_v1"
    gateway_internal: bool = False
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
            policy_mode="approval",
            policy_version="3",
            adapter_version="7",
            schema_version="schema-reviewed-1",
            origin_namespace="profile:web-test",
            review_available=self.review_available,
            gateway_internal=self.gateway_internal,
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
                    NOW + 1,
                    "web:autumn",
                    "approved",
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
                    NOW,
                    "web:autumn",
                    "denied",
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
    assert "Recent approvals and denials" in audit.text
    assert 'class="request-expander decision-approved"' in audit.text
    assert 'class="request-expander decision-denied"' in audit.text
    assert 'data-review-url="/requests/req_approved/review"' in audit.text
    assert 'data-review-url="/requests/req_test/review"' in audit.text
    assert "person@example.test" not in audit.text
    assert "Requested for the Tuesday release" not in audit.text
    assert "Append-only events" in audit.text
    assert "Passkey" in audit.text
    assert "TOTP" in audit.text
    assert "via web" in audit.text
    assert '<time datetime="2027-01-15T08:00:00Z">2027-01-15 08:00:00 UTC</time>' in audit.text

    backend.detail_state = "denied"
    expanded = client.get("/requests/req_test/review")
    assert expanded.status_code == 200
    assert "person@example.test" in expanded.text
    assert "Requested for the Tuesday release" in expanded.text
    assert 'class="totp-action"' not in expanded.text
    assert "data-passkey-action" not in expanded.text
    assert "Nothing was executed downstream" in expanded.text


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


def test_javascript_free_gateway_policy_approval_has_no_ordinary_reason(
    client: TestClient,
    backend: FakeBackend,
    csrf: CsrfManager,
) -> None:
    backend.gateway_internal = True
    authenticate(client)
    review = client.get("/requests/req_test/review")
    assert review.status_code == 200
    assert 'data-gateway-internal="true"' in review.text
    assert "data-approval-reason" not in review.text
    assert "data-denial-reason" in review.text

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
