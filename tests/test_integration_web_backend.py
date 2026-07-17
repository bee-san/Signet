from __future__ import annotations

import asyncio
import base64
import copy
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import pytest

from signet.auth import (
    ProofCapability,
    SessionManager,
    SessionPrincipal,
    SQLiteAttemptLimiter,
    SQLiteSessionRepository,
)
from signet.canonical import canonical_json
from signet.connector_discovery import ConnectorDiscoveryService
from signet.credential_broker import MemorySecretStore
from signet.db import Database
from signet.effects import (
    EffectEvidence,
    EffectProfile,
    MutationEffect,
    RecommendedMode,
    TriState,
    annotation_evidence,
    heuristic_evidence,
    plugin_evidence,
)
from signet.integration_store import SQLiteIntegrationStore
from signet.integration_web_backend import SQLiteIntegrationWebBackend
from signet.plugin_manifest import (
    load_reference_discovery_fixture,
    load_reference_plugin,
    parse_plugin_manifest,
)
from signet.totp import (
    FakeTotpProvider,
    SQLiteTotpCredentialRepository,
    TotpCredential,
    TotpVerifier,
)
from signet.web import WebConflict, WebUnauthorized
from signet.webauthn import (
    FakeAssertion,
    FakeWebAuthnProvider,
    SQLiteWebAuthnRepository,
    WebAuthnAssertionVerifier,
    WebAuthnChallengeIssuer,
    WebAuthnCredential,
)

NOW = 2_200_000_000
USER_ID = "autumn"
RP_ID = "signet.test"
ORIGIN = f"https://{RP_ID}"
SESSION_KEY = b"integration-review-session-signing-key-0001"
CAPABILITIES = ProofCapability(b"integration-review-proof-capability-key-0001")
TOTP_PROOF = "fake:integration-review"
TOTP_REFERENCE = "keychain://Signet/integration-review-totp"
WEB_CREDENTIAL_ID = base64.urlsafe_b64encode(b"integration-review-passkey").rstrip(b"=").decode()


def read_profile() -> EffectProfile:
    return EffectProfile(
        mutation=MutationEffect.NONE,
        external_communication=TriState.FALSE,
        code_execution=TriState.FALSE,
        privilege_change=TriState.FALSE,
        open_world=TriState.FALSE,
        idempotent=TriState.TRUE,
    )


@dataclass(frozen=True)
class BackendBundle:
    database: Database
    store: SQLiteIntegrationStore
    sessions: SessionManager
    backend: SQLiteIntegrationWebBackend
    webauthn: SQLiteWebAuthnRepository
    token: str
    principal: SessionPrincipal

    def tool(self, name: str, *, now: int = NOW + 2) -> tuple[str, str]:
        page = self.backend.list_integrations(self.principal, now=now)
        summary = next(
            tool
            for plugin in page.plugins
            for connector in plugin.connectors
            for tool in connector.tools
            if tool.tool_name == name
        )
        detail = self.backend.get_integration_tool(self.principal, summary.opaque_id, now=now)
        return summary.opaque_id, detail.target_snapshot_digest

    def assertion(self, challenge_id: str) -> FakeAssertion:
        challenge = self.webauthn.find_challenge(challenge_id)
        credential = self.webauthn.find_credential(WEB_CREDENTIAL_ID)
        assert challenge is not None and credential is not None
        return FakeAssertion(
            credential_id=WEB_CREDENTIAL_ID,
            user_handle=b"integration-review-user-handle",
            challenge=challenge.challenge,
            origin=ORIGIN,
            rp_id=RP_ID,
            new_sign_count=credential.sign_count + 1,
        )


def assemble_backend(
    database: Database,
    *,
    fault_injector: Callable[[str], None] | None = None,
) -> tuple[
    SQLiteIntegrationStore,
    SessionManager,
    SQLiteIntegrationWebBackend,
    SQLiteWebAuthnRepository,
]:
    store = SQLiteIntegrationStore(database)
    sessions = SessionManager(
        SQLiteSessionRepository(database),
        signing_key=SESSION_KEY,
        idle_timeout=300,
        absolute_timeout=1_200,
    )
    limiter = SQLiteAttemptLimiter(database, lock_schedule=((20, 60),))
    totp = TotpVerifier(
        SQLiteTotpCredentialRepository(database),
        MemorySecretStore({("Signet", "integration-review-totp"): "fake-secret"}),
        limiter,
        capabilities=CAPABILITIES,
        provider=FakeTotpProvider(TOTP_PROOF, step=777),
        allow_test_provider=True,
    )
    webauthn = SQLiteWebAuthnRepository(database)
    backend = SQLiteIntegrationWebBackend(
        database,
        authorized_user_id=USER_ID,
        sessions=sessions,
        store=store,
        totp=totp,
        capabilities=CAPABILITIES,
        webauthn_repository=webauthn,
        webauthn_issuer=WebAuthnChallengeIssuer(webauthn, rp_id=RP_ID),
        webauthn_verifier=WebAuthnAssertionVerifier(
            webauthn,
            rp_id=RP_ID,
            origin=ORIGIN,
            capabilities=CAPABILITIES,
            provider=FakeWebAuthnProvider(),
            allow_test_provider=True,
        ),
        opaque_id_key=b"integration-review-opaque-id-key-0001",
        clock=lambda: NOW,
        fault_injector=fault_injector,
    )
    return store, sessions, backend, webauthn


@pytest.fixture
def bundle(tmp_path: Path) -> BackendBundle:
    database = Database(tmp_path / "integration-web.sqlite3")
    database.initialize()
    store, sessions, backend, webauthn = assemble_backend(database)
    store.install_plugin(load_reference_plugin("fastmail"), installed_at=NOW - 20)
    store.configure_connector(
        plugin_id="signet.fastmail",
        connector_id="fastmail",
        alias="mail",
        config={"transport": "streamable_http", "url": "https://mcp.test/fastmail"},
        configured_at=NOW - 19,
    )
    asyncio.run(
        ConnectorDiscoveryService.staged(store).discover_fixture(
            "mail",
            load_reference_discovery_fixture("fastmail"),
            discovered_at=NOW - 18,
        )
    )
    SQLiteTotpCredentialRepository(database).replace_totp(
        TotpCredential("totp-main", USER_ID, TOTP_REFERENCE),
        now=NOW - 17,
    )
    webauthn.add_credential(
        WebAuthnCredential(
            WEB_CREDENTIAL_ID,
            USER_ID,
            b"integration-review-user-handle",
            b"integration-review-public-key",
            4,
            "single_device",
            False,
        ),
        now=NOW - 16,
    )
    token = sessions.create_session(USER_ID, auth_method="webauthn", now=NOW)
    principal = sessions.authenticate(token, now=NOW + 1)
    return BackendBundle(database, store, sessions, backend, webauthn, token, principal)


def test_authenticated_workspace_shows_exact_unreviewed_tools_as_denied(
    bundle: BackendBundle,
) -> None:
    page = bundle.backend.list_integrations(bundle.principal, now=NOW + 2)

    assert len(page.plugins) == 1
    plugin = page.plugins[0]
    assert (plugin.plugin_id, plugin.enabled) == ("signet.fastmail", True)
    assert len(plugin.connectors) == 1
    connector = plugin.connectors[0]
    assert connector.alias == "mail"
    assert connector.discovery_source == "fixture"
    assert len(connector.tools) == 5
    assert {tool.review_state for tool in connector.tools} == {"unreviewed — denied"}
    assert {tool.recommended_mode for tool in connector.tools} == {None}

    read = next(tool for tool in connector.tools if tool.tool_name == "read_email")
    detail = bundle.backend.get_integration_tool(bundle.principal, read.opaque_id, now=NOW + 2)
    assert detail.tool_name == "read_email"
    assert detail.action_id == "fastmail.read_email"
    assert detail.reviewable
    assert detail.reviews == ()
    assert detail.unavailable_reason is None
    assert {item.source.value for item in detail.evidence} == {
        "mcp_annotations",
        "name_schema_heuristic",
        "plugin_proposal",
    }
    assert bundle.store.current_valid_review("mail", "read_email") is None

    preauth = replace(bundle.principal, auth_method="preauth")
    with pytest.raises(WebUnauthorized, match="completed authorized human session"):
        bundle.backend.list_integrations(preauth, now=NOW + 2)
    with pytest.raises(WebUnauthorized, match="completed authorized human session"):
        bundle.backend.get_integration_tool(preauth, read.opaque_id, now=NOW + 2)


def test_plugin_upgrade_keeps_stale_connector_generation_visible_and_unreviewable(
    bundle: BackendBundle,
) -> None:
    opaque_id, _snapshot = bundle.tool("read_email")
    manifest = load_reference_plugin("fastmail").manifest.model_dump(
        mode="json",
        exclude_none=True,
    )
    manifest["plugin_version"] = "2.0.0"
    upgraded = parse_plugin_manifest(canonical_json(manifest))
    bundle.store.install_plugin(upgraded, installed_at=NOW + 3)

    page = bundle.backend.list_integrations(bundle.principal, now=NOW + 4)
    assert [(item.plugin_version, item.enabled) for item in page.plugins] == [
        ("1.0.0", False),
        ("2.0.0", True),
    ]
    assert page.plugins[0].connectors[0].alias == "mail"
    assert not page.plugins[0].connectors[0].enabled
    assert page.plugins[1].connectors == ()

    detail = bundle.backend.get_integration_tool(bundle.principal, opaque_id, now=NOW + 4)
    assert not detail.reviewable
    assert detail.unavailable_reason is not None
    assert "disabled" in detail.unavailable_reason


def test_totp_review_appends_once_and_rejects_replay(bundle: BackendBundle) -> None:
    opaque_id, snapshot = bundle.tool("read_email")

    result = bundle.backend.complete_totp_effect_review(
        bundle.principal,
        opaque_id,
        read_profile(),
        TOTP_PROOF,
        expected_snapshot_digest=snapshot,
        now=NOW + 3,
    )

    assert result.recommended_mode is RecommendedMode.PASSTHROUGH
    review = bundle.store.current_valid_review("mail", "read_email")
    assert review is not None
    assert review.review_id == result.review_id
    assert (review.actor, review.auth_kind) == (f"web:{USER_ID}", "totp")
    assert (
        bundle.backend.get_integration_tool(bundle.principal, opaque_id, now=NOW + 4)
        .reviews[0]
        .current
    )

    with pytest.raises(WebConflict, match="already used"):
        bundle.backend.complete_totp_effect_review(
            bundle.principal,
            opaque_id,
            read_profile(),
            TOTP_PROOF,
            expected_snapshot_digest=snapshot,
            now=NOW + 5,
        )
    assert len(bundle.store.list_effect_reviews("mail", "read_email")) == 1
    with bundle.database.read() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM auth_proof_consumptions WHERE kind = 'totp'"
            ).fetchone()[0]
            == 1
        )


@pytest.mark.parametrize("drift", ["schema", "evidence"])
def test_stale_schema_or_evidence_snapshot_is_rejected_before_totp(
    bundle: BackendBundle,
    drift: str,
) -> None:
    opaque_id, snapshot = bundle.tool("read_email")
    before = bundle.backend.get_integration_tool(bundle.principal, opaque_id, now=NOW + 2)
    fixture = load_reference_discovery_fixture("fastmail")
    tools = cast(list[dict[str, Any]], fixture["tools"])

    if drift == "schema":
        changed = copy.deepcopy(fixture)
        changed_tools = cast(list[dict[str, Any]], changed["tools"])
        read = next(item for item in changed_tools if item["name"] == "read_email")
        read["description"] = "Changed exact fake read-email definition."
        asyncio.run(
            ConnectorDiscoveryService.staged(bundle.store).discover_fixture(
                "mail",
                changed,
                discovered_at=NOW + 3,
            )
        )
    else:
        discovery = bundle.store.discovery_detail("mail")
        assert discovery is not None and discovery.initialize_result is not None
        connector = bundle.store.active_connector("mail")
        mappings = {
            mapping.tool_name: mapping for mapping in bundle.store.mappings_for_connector(connector)
        }
        evidence: dict[str, tuple[EffectEvidence, ...]] = {}
        for tool in tools:
            name = cast(str, tool["name"])
            mapping = mappings[name]
            packet = (
                annotation_evidence(tool),
                heuristic_evidence(tool),
                plugin_evidence(mapping.action_id, mapping.proposed_effect),
            )
            if name == "read_email":
                packet = (
                    packet[0],
                    replace(packet[1], signals=(*packet[1].signals, "classifier:v2")),
                    packet[2],
                )
            evidence[name] = packet
        bundle.store.record_discovery(
            alias="mail",
            source="fixture",
            initialize_result=discovery.initialize_result,
            tools=tools,
            evidence=evidence,
            discovered_at=NOW + 3,
        )

    after = bundle.backend.get_integration_tool(bundle.principal, opaque_id, now=NOW + 4)
    if drift == "schema":
        assert after.schema_digest != before.schema_digest
    else:
        assert after.schema_digest == before.schema_digest
        assert after.server_identity_digest == before.server_identity_digest
        assert after.evidence_bundle_digest != before.evidence_bundle_digest
    assert after.target_snapshot_digest != snapshot

    with pytest.raises(WebConflict, match="changed after review"):
        bundle.backend.complete_totp_effect_review(
            bundle.principal,
            opaque_id,
            read_profile(),
            TOTP_PROOF,
            expected_snapshot_digest=snapshot,
            now=NOW + 5,
        )
    assert bundle.store.list_effect_reviews("mail", "read_email") == ()
    with bundle.database.read() as connection:
        assert connection.execute("SELECT count(*) FROM auth_proof_consumptions").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM auth_attempts").fetchone()[0] == 0


def test_passkey_draft_survives_backend_restart_and_replay_is_rejected(
    bundle: BackendBundle,
) -> None:
    opaque_id, snapshot = bundle.tool("read_email")
    options = bundle.backend.begin_passkey_effect_review(
        bundle.principal,
        opaque_id,
        read_profile(),
        expected_snapshot_digest=snapshot,
        http_method="POST",
        now=NOW + 3,
    )
    assertion = bundle.assertion(options.challenge_id)

    restarted_database = Database(bundle.database.path)
    restarted_database.initialize()
    store, sessions, backend, _webauthn = assemble_backend(restarted_database)
    principal = sessions.authenticate(bundle.token, now=NOW + 4)
    result = backend.complete_passkey_effect_review(
        principal,
        opaque_id,
        options.challenge_id,
        cast(Mapping[str, Any], assertion),
        expected_snapshot_digest=snapshot,
        http_method="POST",
        now=NOW + 5,
    )

    assert result.recommended_mode is RecommendedMode.PASSTHROUGH
    review = store.current_valid_review("mail", "read_email")
    assert review is not None
    assert (review.review_id, review.auth_kind) == (result.review_id, "webauthn")
    with pytest.raises(WebConflict, match="stale or unavailable"):
        backend.complete_passkey_effect_review(
            principal,
            opaque_id,
            options.challenge_id,
            cast(Mapping[str, Any], assertion),
            expected_snapshot_digest=snapshot,
            http_method="POST",
            now=NOW + 6,
        )
    assert len(store.list_effect_reviews("mail", "read_email")) == 1


class InjectedFault(RuntimeError):
    pass


def test_totp_fault_rolls_back_review_proof_and_credential_then_allows_retry(
    bundle: BackendBundle,
) -> None:
    def inject(stage: str) -> None:
        assert stage == "totp:before_commit"
        raise InjectedFault("stop before commit")

    _store, sessions, faulty, _webauthn = assemble_backend(
        bundle.database,
        fault_injector=inject,
    )
    principal = sessions.authenticate(bundle.token, now=NOW + 2)
    opaque_id, snapshot = bundle.tool("read_email")
    with bundle.database.read() as connection:
        before = connection.execute(
            "SELECT last_used_at FROM auth_credentials WHERE credential_id = 'totp-main'"
        ).fetchone()[0]

    with pytest.raises(InjectedFault, match="stop before commit"):
        faulty.complete_totp_effect_review(
            principal,
            opaque_id,
            read_profile(),
            TOTP_PROOF,
            expected_snapshot_digest=snapshot,
            now=NOW + 3,
        )

    assert bundle.store.list_effect_reviews("mail", "read_email") == ()
    with bundle.database.read() as connection:
        assert connection.execute("SELECT count(*) FROM auth_proof_consumptions").fetchone()[0] == 0
        assert (
            connection.execute(
                "SELECT last_used_at FROM auth_credentials WHERE credential_id = 'totp-main'"
            ).fetchone()[0]
            == before
        )

    healthy_store, healthy_sessions, healthy, _repository = assemble_backend(bundle.database)
    healthy_principal = healthy_sessions.authenticate(bundle.token, now=NOW + 4)
    result = healthy.complete_totp_effect_review(
        healthy_principal,
        opaque_id,
        read_profile(),
        TOTP_PROOF,
        expected_snapshot_digest=snapshot,
        now=NOW + 5,
    )
    assert healthy_store.current_valid_review("mail", "read_email") is not None
    assert result.recommended_mode is RecommendedMode.PASSTHROUGH


def test_passkey_fault_rolls_back_review_proof_challenge_draft_and_credential(
    bundle: BackendBundle,
) -> None:
    def inject(stage: str) -> None:
        assert stage == "passkey:before_commit"
        raise InjectedFault("stop before commit")

    _store, sessions, faulty, webauthn = assemble_backend(
        bundle.database,
        fault_injector=inject,
    )
    principal = sessions.authenticate(bundle.token, now=NOW + 2)
    opaque_id, snapshot = bundle.tool("read_email")
    options = faulty.begin_passkey_effect_review(
        principal,
        opaque_id,
        read_profile(),
        expected_snapshot_digest=snapshot,
        http_method="POST",
        now=NOW + 3,
    )
    assertion = bundle.assertion(options.challenge_id)
    credential_before = webauthn.find_credential(WEB_CREDENTIAL_ID)
    assert credential_before is not None

    with pytest.raises(InjectedFault, match="stop before commit"):
        faulty.complete_passkey_effect_review(
            principal,
            opaque_id,
            options.challenge_id,
            cast(Mapping[str, Any], assertion),
            expected_snapshot_digest=snapshot,
            http_method="POST",
            now=NOW + 4,
        )

    challenge = webauthn.find_challenge(options.challenge_id)
    credential_after = webauthn.find_credential(WEB_CREDENTIAL_ID)
    assert challenge is not None and challenge.consumed_at is None
    assert credential_after is not None
    assert credential_after.sign_count == credential_before.sign_count
    assert bundle.store.list_effect_reviews("mail", "read_email") == ()
    with bundle.database.read() as connection:
        assert connection.execute("SELECT count(*) FROM auth_proof_consumptions").fetchone()[0] == 0
        assert (
            connection.execute(
                "SELECT count(*) FROM connector_effect_review_drafts WHERE challenge_id = ?",
                (options.challenge_id,),
            ).fetchone()[0]
            == 1
        )

    healthy_store, healthy_sessions, healthy, _repository = assemble_backend(bundle.database)
    healthy_principal = healthy_sessions.authenticate(bundle.token, now=NOW + 5)
    result = healthy.complete_passkey_effect_review(
        healthy_principal,
        opaque_id,
        options.challenge_id,
        cast(Mapping[str, Any], assertion),
        expected_snapshot_digest=snapshot,
        http_method="POST",
        now=NOW + 6,
    )
    assert healthy_store.current_valid_review("mail", "read_email") is not None
    assert result.recommended_mode is RecommendedMode.PASSTHROUGH
