from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal

import pytest

import signet.integration_store as integration_store
from signet.canonical import canonical_json
from signet.connector_config import parse_connector_config
from signet.db import Database, IntegrityError
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
from signet.integration_store import (
    EffectReviewRecord,
    IntegrationStoreError,
    SQLiteIntegrationStore,
)
from signet.plugin_manifest import (
    ValidatedPluginManifest,
    load_reference_plugin,
    parse_plugin_manifest,
)

NOW = 2_000_000_000


@pytest.fixture
def store(tmp_path: Path) -> SQLiteIntegrationStore:
    database = Database(tmp_path / "approval.sqlite3")
    database.initialize()
    return SQLiteIntegrationStore(database)


def install_fastmail(store: SQLiteIntegrationStore) -> ValidatedPluginManifest:
    plugin = load_reference_plugin("fastmail")
    store.install_plugin(plugin, installed_at=NOW)
    return plugin


def configure_fastmail(store: SQLiteIntegrationStore) -> None:
    store.configure_connector(
        plugin_id="signet.fastmail",
        connector_id="fastmail",
        alias="mail",
        config={"transport": "streamable_http", "url": "https://mcp.test/fastmail"},
        credential_ref="keychain://signet/fastmail/test",
        credential_identity_digest="a" * 64,
        configured_at=NOW + 1,
    )


def raw_tool(*, description: str = "Read fake email", read_only: bool = True) -> dict[str, Any]:
    return {
        "name": "read_email",
        "description": description,
        "inputSchema": {
            "type": "object",
            "required": ["message_id"],
            "properties": {"message_id": {"type": "string"}},
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    }


def initialize_result(*, version: str = "1.0") -> dict[str, Any]:
    return {
        "protocolVersion": "2025-11-25",
        "capabilities": {"tools": {"listChanged": True}},
        "serverInfo": {"name": "fake-fastmail", "version": version},
    }


def tool_evidence(
    store: SQLiteIntegrationStore,
    tool: dict[str, Any],
) -> tuple[EffectEvidence, ...]:
    connector = store.active_connector("mail")
    mapping = next(
        item for item in store.mappings_for_connector(connector) if item.tool_name == tool["name"]
    )
    return (
        annotation_evidence(tool),
        heuristic_evidence(tool),
        plugin_evidence(mapping.action_id, mapping.proposed_effect),
    )


def reviewed_read_profile() -> EffectProfile:
    return EffectProfile(
        mutation=MutationEffect.NONE,
        external_communication=TriState.FALSE,
        code_execution=TriState.FALSE,
        privilege_change=TriState.FALSE,
        open_world=TriState.FALSE,
        idempotent=TriState.TRUE,
    )


def discover_read(
    store: SQLiteIntegrationStore,
    *,
    at: int,
    tool: dict[str, Any] | None = None,
    server_version: str = "1.0",
) -> None:
    selected = tool or raw_tool()
    store.record_discovery(
        alias="mail",
        source="live",
        initialize_result=initialize_result(version=server_version),
        tools=[selected],
        evidence={"read_email": tool_evidence(store, selected)},
        discovered_at=at,
    )


def review_read(store: SQLiteIntegrationStore, *, at: int = NOW + 3) -> None:
    digest = store.current_evidence_bundle_digest("mail", "read_email")
    review = append_unverified_review_for_test(
        store,
        alias="mail",
        tool_name="read_email",
        profile=reviewed_read_profile(),
        expected_evidence_bundle_digest=digest,
        actor="owner",
        auth_kind="totp",
        auth_use_id=f"totp-{at}",
        reviewed_at=at,
    )
    assert review.recommended_mode is RecommendedMode.PASSTHROUGH


def append_unverified_review_for_test(
    store: SQLiteIntegrationStore,
    *,
    alias: str,
    tool_name: str,
    profile: EffectProfile,
    expected_evidence_bundle_digest: str,
    actor: str,
    auth_kind: Literal["totp", "webauthn"],
    auth_use_id: str,
    reviewed_at: int,
) -> EffectReviewRecord:
    """Exercise immutable store history without exposing a production auth bypass."""

    with store.database.transaction() as connection:
        target = store.current_review_target_in_transaction(
            connection,
            alias=alias,
            tool_name=tool_name,
        )
        if target is None:
            raise IntegrationStoreError("effect review target is stale or unavailable")
        if target.evidence_bundle_digest != expected_evidence_bundle_digest:
            raise IntegrationStoreError("effect evidence changed after review")
        try:
            review_id = store._append_effect_review_in_transaction(
                connection,
                target=target,
                profile=profile,
                actor=actor,
                auth_kind=auth_kind,
                auth_use_id=auth_use_id,
                reviewed_at=reviewed_at,
            )
        except IntegrityError as exc:
            raise IntegrationStoreError("effect review proof was already used") from exc
    review = store.review_by_id(review_id)
    assert review is not None
    return review


def test_install_configure_and_bounded_read_models_exclude_configuration_secrets(
    store: SQLiteIntegrationStore,
) -> None:
    plugin = install_fastmail(store)
    configure_fastmail(store)

    assert store.list_plugins()[0].plugin.manifest_sha256 == plugin.sha256
    detail = store.get_plugin("signet.fastmail")
    assert detail is not None
    assert detail.manifest["plugin_manifest_version"] == 1
    assert len(detail.mappings) == 5

    connector = store.list_connectors()[0]
    assert connector.is_active
    assert connector.credential_ref is None
    assert connector.credential_identity_digest is None
    assert "signet/fastmail/test" not in repr(connector)
    assert store.active_connector("mail").credential_ref == "keychain://signet/fastmail/test"

    with pytest.raises(ValueError, match="limit"):
        store.list_plugins(limit=0)
    with pytest.raises(ValueError, match="limit"):
        store.list_connectors(limit=1001)


def test_discovery_transaction_rejects_stale_expected_connector_generation(
    store: SQLiteIntegrationStore,
) -> None:
    install_fastmail(store)
    configure_fastmail(store)
    expected_config_digest = store.active_connector("mail").config_digest
    store.configure_connector(
        plugin_id="signet.fastmail",
        connector_id="fastmail",
        alias="mail",
        config={"transport": "streamable_http", "url": "https://replacement.test/mcp"},
        configured_at=NOW + 2,
    )
    selected = raw_tool()

    with pytest.raises(IntegrationStoreError, match="connector changed during discovery"):
        store.record_discovery(
            alias="mail",
            source="live",
            initialize_result=initialize_result(),
            tools=[selected],
            evidence={"read_email": tool_evidence(store, selected)},
            discovered_at=NOW + 3,
            expected_config_digest=expected_config_digest,
        )

    assert store.current_tools("mail") == ()
    with store.database.read() as connection:
        run_count = connection.execute("SELECT count(*) FROM connector_discovery_runs").fetchone()[
            0
        ]
    assert run_count == 0


def test_durable_workspace_bounds_reject_new_identities_without_hiding_state(
    store: SQLiteIntegrationStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(integration_store, "MAX_ACTIVE_PLUGIN_IDS", 1)
    install_fastmail(store)
    with pytest.raises(IntegrationStoreError, match="plugin identifier limit"):
        store.install_plugin(load_reference_plugin("telegram"), installed_at=NOW + 1)
    assert [item.plugin.plugin_id for item in store.list_plugins()] == ["signet.fastmail"]

    monkeypatch.setattr(integration_store, "MAX_CONNECTOR_ALIASES", 1)
    configure_fastmail(store)
    with pytest.raises(IntegrationStoreError, match="connector alias limit"):
        store.configure_connector(
            plugin_id="signet.fastmail",
            connector_id="fastmail",
            alias="mail-two",
            config={"transport": "streamable_http", "url": "https://two.test/mcp"},
            configured_at=NOW + 2,
        )
    assert [item.alias for item in store.list_connectors()] == ["mail"]


def test_retained_tool_name_churn_is_bounded_before_discovery_is_recorded(
    store: SQLiteIntegrationStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_fastmail(store)
    configure_fastmail(store)
    monkeypatch.setattr(integration_store, "MAX_RETAINED_TOOL_NAMES_PER_ALIAS", 1)
    discover_read(store, at=NOW + 2)
    unexpected = {
        "name": "unexpected_tool",
        "inputSchema": {"type": "object", "additionalProperties": False},
    }
    with pytest.raises(IntegrationStoreError, match="retained tool-name limit"):
        store.record_discovery(
            alias="mail",
            source="live",
            initialize_result=initialize_result(),
            tools=[unexpected],
            evidence={"unexpected_tool": (annotation_evidence(unexpected),)},
            discovered_at=NOW + 3,
        )
    assert [item.tool_name for item in store.current_tools("mail")] == ["read_email"]
    with store.database.read() as connection:
        count = connection.execute("SELECT count(*) FROM connector_discovery_runs").fetchone()[0]
    assert count == 1


def test_connector_can_persist_the_exact_validated_configuration_digest(
    store: SQLiteIntegrationStore,
) -> None:
    install_fastmail(store)
    validated = parse_connector_config(
        canonical_json(
            {
                "connector_config_version": 1,
                "transport": "streamable_http",
                "credential_ref": "keychain://signet/fastmail-test",
                "credential_identity_digest": "a" * 64,
                "url": "https://mcp.test/fastmail",
            }
        )
    )

    configured = store.configure_connector(
        plugin_id="signet.fastmail",
        connector_id="fastmail",
        alias="mail",
        config={
            "connector_config_version": 1,
            "transport": "streamable_http",
            "url": "https://mcp.test/fastmail",
            "timeout_seconds": 30.0,
            "output_limit_bytes": 1_048_576,
        },
        credential_ref=validated.config.credential_ref,
        credential_identity_digest=validated.config.credential_identity_digest,
        canonical_config_bytes=validated.canonical_bytes,
        canonical_config_sha256=validated.sha256,
        configured_at=NOW + 1,
    )

    assert configured.config_digest == validated.sha256
    assert store.connector_configuration("mail") == validated.config.model_dump(
        mode="json", exclude_none=True
    )

    tampered_detached = validated.config.model_dump(mode="json", exclude_none=True)
    tampered_detached.pop("credential_ref")
    tampered_detached.pop("credential_identity_digest")
    tampered_detached["url"] = "https://replacement.test/mcp"
    with pytest.raises(IntegrationStoreError, match="detached fields"):
        store.configure_connector(
            plugin_id="signet.fastmail",
            connector_id="fastmail",
            alias="mail-tampered",
            config=tampered_detached,
            credential_ref=validated.config.credential_ref,
            credential_identity_digest=validated.config.credential_identity_digest,
            canonical_config_bytes=validated.canonical_bytes,
            canonical_config_sha256=validated.sha256,
            configured_at=NOW + 2,
        )


@pytest.mark.parametrize(
    "config",
    [
        {"password": "operator-secret"},
        {"url": "https://operator:secret@mcp.test/"},
        {"label": "Bearer abcdefghijklmnop"},
        {"label": "sk-abcdefghijklmnopqrstuvwxyz"},
    ],
)
def test_connector_configuration_rejects_embedded_credentials(
    store: SQLiteIntegrationStore,
    config: dict[str, str],
) -> None:
    install_fastmail(store)
    with pytest.raises(IntegrationStoreError, match="credential"):
        store.configure_connector(
            plugin_id="signet.fastmail",
            connector_id="fastmail",
            alias="mail",
            config=config,
            configured_at=NOW + 1,
        )


def test_discovery_review_and_read_details_are_bound_to_exact_current_material(
    store: SQLiteIntegrationStore,
) -> None:
    install_fastmail(store)
    configure_fastmail(store)
    discover_read(store, at=NOW + 2)

    assert store.current_valid_review("mail", "read_email") is None
    review_read(store)
    valid = store.current_valid_review("mail", "read_email")
    assert valid is not None
    assert valid.action_id == "fastmail.read_email"

    discovery = store.discovery_detail("mail")
    assert discovery is not None
    assert discovery.initialize_result == initialize_result()
    assert discovery.tools == (raw_tool(),)
    tool = store.tool_detail("mail", "read_email")
    assert tool is not None
    assert tool.current.present
    assert tool.definition == raw_tool()
    assert {item["source"] for item in tool.evidence} == {
        "mcp_annotations",
        "name_schema_heuristic",
        "plugin_proposal",
    }
    assert tool.valid_review == valid

    # An identical complete rediscovery retains an exact schema/server review.
    discover_read(store, at=NOW + 4)
    assert store.current_valid_review("mail", "read_email") is not None

    changed = raw_tool(description="Changed description")
    discover_read(store, at=NOW + 5, tool=changed)
    assert store.current_valid_review("mail", "read_email") is None


def test_classifier_evidence_drift_invalidates_an_otherwise_identical_review(
    store: SQLiteIntegrationStore,
) -> None:
    install_fastmail(store)
    configure_fastmail(store)
    tool = raw_tool()
    discover_read(store, at=NOW + 2, tool=tool)
    review_read(store)
    evidence = list(tool_evidence(store, tool))
    evidence[1] = replace(evidence[1], signals=(*evidence[1].signals, "classifier:v2"))

    store.record_discovery(
        alias="mail",
        source="live",
        initialize_result=initialize_result(),
        tools=[tool],
        evidence={"read_email": tuple(evidence)},
        discovered_at=NOW + 4,
    )

    assert store.current_valid_review("mail", "read_email") is None


def test_server_config_plugin_and_removal_drift_all_invalidate_reviews(
    store: SQLiteIntegrationStore,
) -> None:
    plugin = install_fastmail(store)
    configure_fastmail(store)
    discover_read(store, at=NOW + 2)
    review_read(store)

    discover_read(store, at=NOW + 4, server_version="2.0")
    assert store.current_valid_review("mail", "read_email") is None
    review_read(store, at=NOW + 5)

    store.configure_connector(
        plugin_id="signet.fastmail",
        connector_id="fastmail",
        alias="mail",
        config={"transport": "streamable_http", "url": "https://replacement.test/mcp"},
        configured_at=NOW + 6,
    )
    assert store.current_valid_review("mail", "read_email") is None
    with pytest.raises(IntegrationStoreError, match="stale"):
        append_unverified_review_for_test(
            store,
            alias="mail",
            tool_name="read_email",
            profile=reviewed_read_profile(),
            expected_evidence_bundle_digest="b" * 64,
            actor="owner",
            auth_kind="webauthn",
            auth_use_id="passkey-stale",
            reviewed_at=NOW + 7,
        )

    # Restore the original connector generation and prove removal fails closed.
    configure_fastmail(store)
    discover_read(store, at=NOW + 8)
    review_read(store, at=NOW + 9)
    store.record_discovery(
        alias="mail",
        source="live",
        initialize_result=initialize_result(),
        tools=[],
        evidence={},
        discovered_at=NOW + 10,
    )
    assert store.current_valid_review("mail", "read_email") is None
    removed = store.tool_detail("mail", "read_email")
    assert removed is not None
    assert not removed.current.present
    assert removed.definition == raw_tool()

    upgraded_data = copy.deepcopy(plugin.manifest.model_dump(mode="json", exclude_none=True))
    upgraded_data["plugin_version"] = "1.0.1"
    upgraded = parse_plugin_manifest(canonical_json(upgraded_data))
    store.install_plugin(upgraded, installed_at=NOW + 11)
    connectors = store.list_connectors()
    assert len(connectors) == 1
    assert not connectors[0].plugin_current
    assert not connectors[0].is_active
    with pytest.raises(IntegrationStoreError, match="active"):
        store.active_connector("mail")


def test_history_and_reviews_are_append_only_and_auth_proofs_are_single_use(
    store: SQLiteIntegrationStore,
) -> None:
    install_fastmail(store)
    configure_fastmail(store)
    discover_read(store, at=NOW + 2)
    review_read(store)

    with pytest.raises(IntegrationStoreError, match="already used"):
        append_unverified_review_for_test(
            store,
            alias="mail",
            tool_name="read_email",
            profile=reviewed_read_profile(),
            expected_evidence_bundle_digest=store.current_evidence_bundle_digest(
                "mail", "read_email"
            ),
            actor="owner",
            auth_kind="totp",
            auth_use_id=f"totp-{NOW + 3}",
            reviewed_at=NOW + 4,
        )

    with pytest.raises(IntegrityError, match="append-only"), store.database.transaction() as conn:
        conn.execute("UPDATE connector_effect_reviews SET actor = 'attacker'")
    with pytest.raises(IntegrityError, match="retained"), store.database.transaction() as conn:
        conn.execute("DELETE FROM connector_discovered_tools")
