from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from signet.auth import SessionPrincipal
from signet.effects import (
    EffectEvidence,
    EffectProfile,
    EvidenceSource,
    MutationEffect,
    RecommendedMode,
    TriState,
    recommend_policy,
)
from signet.web import (
    CsrfManager,
    EffectReviewResult,
    EffectReviewView,
    IntegrationConnectorSummary,
    IntegrationPasskeyOptions,
    IntegrationPluginSummary,
    IntegrationsPage,
    IntegrationToolDetail,
    IntegrationToolSummary,
    WebConflict,
    WebSettings,
    create_web_app,
)
from tests.test_web import FakeBackend

NOW = 1_800_000_000
ORIGIN = "https://signet.test"
OPAQUE_ID = "integration_tool_A1"
SNAPSHOT_DIGEST = "f" * 64
SCHEMA_DIGEST = "d" * 64
EVIDENCE_DIGEST = "e" * 64
ROOT = Path(__file__).resolve().parents[1]


def reviewed_profile() -> EffectProfile:
    return EffectProfile(
        mutation=MutationEffect.ADDITIVE,
        external_communication=TriState.TRUE,
        code_execution=TriState.FALSE,
        privilege_change=TriState.FALSE,
        open_world=TriState.FALSE,
        idempotent=TriState.FALSE,
    )


def integration_page() -> IntegrationsPage:
    tool = IntegrationToolSummary(
        opaque_id=OPAQUE_ID,
        tool_name="send_message",
        display_label="Send a message",
        schema_digest=SCHEMA_DIGEST,
        present=True,
        review_state="unreviewed",
    )
    connector = IntegrationConnectorSummary(
        alias="telegram-primary",
        connector_id="telegram",
        display_name="Telegram <connector>",
        config_digest="c" * 64,
        enabled=True,
        discovery_status="succeeded",
        discovery_source="fixture",
        discovered_at=NOW - 60,
        server_identity_digest="b" * 64,
        tools=(tool,),
    )
    plugin = IntegrationPluginSummary(
        plugin_id="signet.telegram",
        plugin_version="1.0.0",
        manifest_sha256="a" * 64,
        display_name="Telegram <script>alert(1)</script>",
        enabled=True,
        connectors=(connector,),
    )
    return IntegrationsPage((plugin,))


def integration_detail() -> IntegrationToolDetail:
    hostile = '</pre><script src="https://evil.test/integration.js"></script>'
    canonical_tool = json.dumps(
        {
            "name": "send_message",
            "description": hostile,
            "annotations": {"readOnlyHint": False, "openWorldHint": True},
            "inputSchema": {"type": "object", "additionalProperties": False},
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    annotation = EffectEvidence(
        source=EvidenceSource.MCP_ANNOTATIONS,
        proposed_profile=EffectProfile(
            mutation=MutationEffect.UNKNOWN,
            open_world=TriState.TRUE,
            idempotent=TriState.FALSE,
        ),
        signals=("annotation:openWorldHint=true", hostile),
    )
    heuristic = EffectEvidence(
        source=EvidenceSource.NAME_SCHEMA_HEURISTIC,
        proposed_profile=EffectProfile(
            mutation=MutationEffect.ADDITIVE,
            external_communication=TriState.TRUE,
        ),
        signals=("name:send", "name:message"),
    )
    plugin = EffectEvidence(
        source=EvidenceSource.PLUGIN_PROPOSAL,
        proposed_profile=reviewed_profile(),
        signals=("plugin_action:telegram.send",),
        action_id="telegram.send",
    )
    review = EffectReviewView(
        review_id=7,
        profile=reviewed_profile(),
        recommended_mode=RecommendedMode.APPROVAL,
        actor="web:autumn",
        auth_kind="totp",
        reviewed_at=NOW - 10,
        current=True,
    )
    return IntegrationToolDetail(
        opaque_id=OPAQUE_ID,
        plugin_id="signet.telegram",
        plugin_version="1.0.0",
        plugin_display_name="Telegram staged plugin",
        manifest_sha256="a" * 64,
        connector_id="telegram",
        connector_alias="telegram-primary",
        connector_display_name="Telegram primary",
        connector_config_digest="c" * 64,
        discovery_status="succeeded",
        discovery_source="fixture",
        discovered_at=NOW - 60,
        server_identity_digest="b" * 64,
        tool_name="send_message",
        display_label="Send a message",
        action_id="telegram.send",
        schema_digest=SCHEMA_DIGEST,
        target_snapshot_digest=SNAPSHOT_DIGEST,
        evidence_bundle_digest=EVIDENCE_DIGEST,
        canonical_tool_json=canonical_tool,
        sensitive_json_paths=("/text", "/recipient"),
        safe_result_fields=("/message_id",),
        evidence=(annotation, heuristic, plugin),
        disagreements=("mutation", "open_world"),
        reviews=(review,),
    )


@dataclass
class FakeIntegrationBackend:
    conflict: bool = False
    totp_calls: list[tuple[str, EffectProfile, str, str]] = field(default_factory=list)
    totp_credential_ids: list[str | None] = field(default_factory=list)
    option_calls: list[tuple[str, EffectProfile, str, str]] = field(default_factory=list)
    complete_calls: list[tuple[str, str, dict[str, Any], str, str]] = field(default_factory=list)

    def list_integrations(
        self,
        principal: SessionPrincipal,
        *,
        now: int,
    ) -> IntegrationsPage:
        assert principal.user_id == "autumn" and now == NOW
        return integration_page()

    def get_integration_tool(
        self,
        principal: SessionPrincipal,
        opaque_id: str,
        *,
        now: int,
    ) -> IntegrationToolDetail:
        assert principal.user_id == "autumn" and now == NOW and opaque_id == OPAQUE_ID
        return integration_detail()

    def complete_totp_effect_review(
        self,
        principal: SessionPrincipal,
        opaque_id: str,
        profile: EffectProfile,
        totp_proof: str,
        *,
        expected_snapshot_digest: str,
        now: int,
        credential_id: str | None = None,
    ) -> EffectReviewResult:
        assert principal.user_id == "autumn" and now == NOW
        if self.conflict:
            raise WebConflict("effect review target changed after review")
        self.totp_calls.append((opaque_id, profile, totp_proof, expected_snapshot_digest))
        self.totp_credential_ids.append(credential_id)
        return EffectReviewResult(opaque_id, 8, recommend_policy(profile))

    def begin_passkey_effect_review(
        self,
        principal: SessionPrincipal,
        opaque_id: str,
        profile: EffectProfile,
        *,
        expected_snapshot_digest: str,
        http_method: str,
        now: int,
    ) -> IntegrationPasskeyOptions:
        assert principal.user_id == "autumn" and now == NOW
        self.option_calls.append((opaque_id, profile, expected_snapshot_digest, http_method))
        return IntegrationPasskeyOptions(
            challenge_id="integration-challenge-1",
            public_key={"challenge": "ZmFrZQ", "allowCredentials": []},
            opaque_id=opaque_id,
            target_snapshot_digest=expected_snapshot_digest,
            recommended_mode=recommend_policy(profile),
        )

    def complete_passkey_effect_review(
        self,
        principal: SessionPrincipal,
        opaque_id: str,
        challenge_id: str,
        assertion: dict[str, Any],
        *,
        expected_snapshot_digest: str,
        http_method: str,
        now: int,
    ) -> EffectReviewResult:
        assert principal.user_id == "autumn" and now == NOW
        self.complete_calls.append(
            (
                opaque_id,
                challenge_id,
                assertion,
                expected_snapshot_digest,
                http_method,
            )
        )
        return EffectReviewResult(opaque_id, 9, RecommendedMode.APPROVAL)


@dataclass
class IntegrationWebFixture:
    client: TestClient
    csrf: CsrfManager
    integrations: FakeIntegrationBackend

    def authenticate(self) -> None:
        self.client.cookies.set("__Host-signet_session", "session-good")

    @property
    def review_csrf(self) -> str:
        purpose = f"effect-review:{OPAQUE_ID}:{SNAPSHOT_DIGEST}"
        return self.csrf.session_token("session-id", purpose)


@pytest.fixture
def web() -> IntegrationWebFixture:
    backend = FakeBackend()
    integrations = FakeIntegrationBackend()
    csrf = CsrfManager(b"i" * 32)
    app = create_web_app(
        backend,
        settings=WebSettings(public_origin=ORIGIN, allowed_hosts=("signet.test",)),
        csrf=csrf,
        integrations=integrations,
        clock=lambda: NOW,
    )
    return IntegrationWebFixture(TestClient(app, base_url=ORIGIN), csrf, integrations)


def effect_form(**changes: str) -> dict[str, str]:
    form = {
        "opaque_id": OPAQUE_ID,
        "expected_snapshot_digest": SNAPSHOT_DIGEST,
        "mutation": "additive",
        "external_communication": "true",
        "code_execution": "false",
        "privilege_change": "false",
        "open_world": "false",
        "idempotent": "false",
        "totp_proof": "fake:fresh-review",
    }
    form.update(changes)
    return form


def passkey_options_body() -> dict[str, Any]:
    return {
        "opaque_id": OPAQUE_ID,
        "expected_snapshot_digest": SNAPSHOT_DIGEST,
        "profile": {
            "mutation": "additive",
            "external_communication": "true",
            "code_execution": "false",
            "privilege_change": "false",
            "open_world": "false",
            "idempotent": "false",
        },
    }


def test_integrations_are_absent_without_explicit_backend() -> None:
    csrf = CsrfManager(b"n" * 32)
    app = create_web_app(
        FakeBackend(),
        settings=WebSettings(public_origin=ORIGIN, allowed_hosts=("signet.test",)),
        csrf=csrf,
        clock=lambda: NOW,
    )
    with TestClient(app, base_url=ORIGIN) as client:
        client.cookies.set("__Host-signet_session", "session-good")
        assert client.get("/integrations").status_code == 404
        assert 'href="/integrations"' not in client.get("/").text


def test_workspace_is_authenticated_bounded_and_schema_lazy(web: IntegrationWebFixture) -> None:
    unauthenticated = web.client.get(
        "/integrations",
        headers={"Authorization": "Bearer agent-authority-is-irrelevant"},
    )
    assert unauthenticated.status_code == 401

    web.authenticate()
    response = web.client.get("/integrations")

    assert response.status_code == 200
    assert 'class="primary-integrations-link" href="/integrations"' in response.text
    assert "Live dispatch is disabled" in response.text
    assert "Telegram &lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "telegram-primary" in response.text
    assert "send_message" in response.text
    assert SCHEMA_DIGEST in response.text
    assert f'href="/integrations/tools/{OPAQUE_ID}"' in response.text
    assert "evil.test/integration.js" not in response.text
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert "connect-src 'self'" in response.headers["content-security-policy"]


def test_exact_tool_page_escapes_json_and_separates_all_evidence(
    web: IntegrationWebFixture,
) -> None:
    web.authenticate()
    response = web.client.get(f"/integrations/tools/{OPAQUE_ID}")

    assert response.status_code == 200
    assert "Exact discovered MCP tool definition" in response.text
    assert "MCP annotations — untrusted server hints" in response.text
    assert "Name and schema classifier signals" in response.text
    assert "Plugin proposal — untrusted mapping evidence" in response.text
    assert "Evidence disagreements" in response.text
    assert "mutation" in response.text and "open world" in response.text
    assert "Sensitive JSON paths" in response.text and "/recipient" in response.text
    assert "Safe result fields" in response.text and "/message_id" in response.text
    assert "approval recommendation" in response.text
    assert "TOTP via the authenticated web app" in response.text
    assert '<script src="https://evil.test' not in response.text
    assert "&lt;/pre&gt;&lt;script" in response.text
    for axis in (
        "mutation",
        "external_communication",
        "code_execution",
        "privilege_change",
        "open_world",
        "idempotent",
    ):
        assert f'name="{axis}"' in response.text
    assert 'action="/integrations/effect-reviews/totp" method="post"' in response.text
    assert "data-effect-review-passkey" in response.text
    assert "incomplete or unknown profiles are denied" in response.text


def test_totp_review_requires_origin_exact_csrf_and_current_snapshot(
    web: IntegrationWebFixture,
) -> None:
    web.authenticate()
    form = {
        **effect_form(),
        "csrf_token": web.review_csrf,
        "totp_credential_id": "totp-travel",
    }

    assert web.client.post("/integrations/effect-reviews/totp", data=form).status_code == 403
    assert (
        web.client.post(
            "/integrations/effect-reviews/totp",
            data={**form, "csrf_token": "wrong"},
            headers={"Origin": ORIGIN},
        ).status_code
        == 403
    )
    assert web.integrations.totp_calls == []

    response = web.client.post(
        "/integrations/effect-reviews/totp",
        data=form,
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == (
        f"/integrations/tools/{OPAQUE_ID}#effect-review-current"
    )
    assert web.integrations.totp_calls == [
        (OPAQUE_ID, reviewed_profile(), "fake:fresh-review", SNAPSHOT_DIGEST)
    ]
    assert web.integrations.totp_credential_ids == ["totp-travel"]

    calls = list(web.integrations.totp_calls)
    wrong_binding = web.client.post(
        "/integrations/effect-reviews/totp",
        data={**form, "expected_snapshot_digest": "0" * 64},
        headers={"Origin": ORIGIN},
    )
    assert wrong_binding.status_code == 403
    assert web.integrations.totp_calls == calls

    web.integrations.conflict = True
    stale = web.client.post(
        "/integrations/effect-reviews/totp",
        data=form,
        headers={"Origin": ORIGIN, "Accept": "application/json"},
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "stale_request"
    assert web.integrations.totp_calls == calls


def test_passkey_review_is_exact_strict_and_body_limited(web: IntegrationWebFixture) -> None:
    web.authenticate()
    headers = {"Origin": ORIGIN, "X-CSRF-Token": web.review_csrf}

    invalid = passkey_options_body()
    invalid["profile"] = {**invalid["profile"], "extra": "forbidden"}
    rejected = web.client.post(
        "/integrations/effect-reviews/passkey/options",
        json=invalid,
        headers=headers,
    )
    assert rejected.status_code == 422
    assert web.integrations.option_calls == []

    options = web.client.post(
        "/integrations/effect-reviews/passkey/options",
        json=passkey_options_body(),
        headers=headers,
    )
    assert options.status_code == 200
    assert options.json()["challenge_id"] == "integration-challenge-1"
    assert options.json()["target_snapshot_digest"] == SNAPSHOT_DIGEST
    assert options.json()["recommended_mode"] == "approval"
    assert web.integrations.option_calls == [
        (OPAQUE_ID, reviewed_profile(), SNAPSHOT_DIGEST, "POST")
    ]

    completed = web.client.post(
        "/integrations/effect-reviews/passkey/complete",
        json={
            "opaque_id": OPAQUE_ID,
            "expected_snapshot_digest": SNAPSHOT_DIGEST,
            "challenge_id": "integration-challenge-1",
            "assertion": {"fake": True},
        },
        headers=headers,
    )
    assert completed.status_code == 200
    assert completed.json() == {
        "status": "reviewed",
        "review_id": 9,
        "recommended_mode": "approval",
        "redirect_url": f"/integrations/tools/{OPAQUE_ID}#effect-review-current",
    }
    assert web.integrations.complete_calls == [
        (
            OPAQUE_ID,
            "integration-challenge-1",
            {"fake": True},
            SNAPSHOT_DIGEST,
            "POST",
        )
    ]

    oversized = web.client.post(
        "/integrations/effect-reviews/passkey/options",
        content=b"{" + b'"padding":"' + b"x" * 33_000 + b'"}',
        headers={**headers, "Content-Type": "application/json"},
    )
    assert oversized.status_code == 413
    assert len(web.integrations.option_calls) == 1


def test_no_javascript_keeps_totp_review_and_hides_only_passkey(
    web: IntegrationWebFixture,
) -> None:
    web.authenticate()
    page = web.client.get(f"/integrations/tools/{OPAQUE_ID}")
    stylesheet = (ROOT / "src" / "signet" / "static" / "app.css").read_text()

    assert page.status_code == 200
    assert 'action="/integrations/effect-reviews/totp" method="post"' in page.text
    assert "data-effect-review-passkey" in page.text
    assert ".no-js [data-effect-review-passkey]" in stylesheet
