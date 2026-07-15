from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from signet.access_requests import FrozenAccessRequestFactory
from signet.adapters.base import ApprovalAdapter
from signet.adapters.tool_access import ToolAccessAdapter
from signet.auth import ActionBinding
from signet.db import Database, IntegrityError
from signet.freezer import RequestFreezer
from signet.gateway_tools import AccessRequestDraft
from signet.mcp_mirror import SchemaMirror
from signet.policy import (
    PolicyEngine,
    PolicyMode,
    PolicySnapshot,
    dump_policy,
    load_policy,
    parse_policy,
    policy_config_hash,
    policy_document,
)
from signet.policy_persistence import (
    PolicyDivergenceError,
    SQLiteActionDraftRepository,
    SQLitePolicyPromotionBoundary,
)
from signet.totp import SQLiteTotpCredentialRepository, TotpCredential
from signet.web import WebConflict
from signet.web_backend import (
    EncryptedPayloadReviewer,
    PolicyPromotionBoundary,
    WebActionDraft,
)
from signet.webauthn import SQLiteWebAuthnRepository, WebAuthnCredential
from tests.test_web_backend import (
    NOW,
    TOTP_REFERENCE,
    USER_ID,
    WEB_CREDENTIAL_ID,
    BackendBundle,
    assemble,
)


class InjectedPolicyCrash(RuntimeError):
    pass


@dataclass
class InstalledBoundary:
    boundary: SQLitePolicyPromotionBoundary
    engine: PolicyEngine
    mirror: SchemaMirror
    applied: list[int]
    notified: list[frozenset[str]]


def _snapshot(
    *,
    mode: str = "deny",
    reviewed_read_only: bool = True,
) -> PolicySnapshot:
    return parse_policy(
        {
            "version": 1,
            "default_mode": "deny",
            "mode_contracts": {
                "passthrough": {
                    "exposure": "reviewed_tools_only",
                    "downstream_calls": "immediate",
                    "result_contract": "downstream_verbatim",
                },
                "virtualize_local": {
                    "exposure": "reviewed_tools_only",
                    "downstream_calls": 0,
                    "standalone_approval": False,
                    "result_contract": "captured_downstream_output_schema",
                    "storage": "local_only",
                    "scope_fields": ["adapter", "account", "caller_namespace"],
                    "staging": {
                        "root": "var/staging",
                        "path_rule": "descendants_only",
                        "reject_absolute_paths": True,
                        "reject_parent_traversal": True,
                        "reject_symlinks": True,
                        "reject_hardlinks": True,
                    },
                },
                "approval": {
                    "exposure": "reviewed_tools_only",
                    "downstream_calls_before_approval": 0,
                    "result_contract": "gateway_pending_result",
                },
                "deny": {
                    "exposure": "explicit_reviewed_only",
                    "downstream_calls": 0,
                    "result_contract": "call_tool_error",
                },
            },
            "downstreams": {
                "fake-service": {
                    "transport": "http",
                    "url": "https://provider.example.test/mcp",
                    "credential_ref": "keychain://Signet/fake-provider",
                    "schema_review": {
                        "source": "reviewed_fixture",
                        "fixture_status": "approved",
                        "fail_closed_on_digest_change": True,
                    },
                    "account_ref": "fake-account",
                    "tools": {
                        "create_item": {
                            "mode": mode,
                            "adapter": "fake.review-only",
                            "reviewed_read_only": reviewed_read_only,
                            "schema_digest": "a" * 64,
                            "limits": {
                                "payload_bytes": 4096,
                                "pending_requests": 10,
                                "requests_per_minute": 20,
                            },
                        }
                    },
                }
            },
            "policy_changes": {
                "approval_channel": "web_only",
                "require_fresh_human_confirmation": True,
                "passthrough_requires_reviewed_read_only": True,
                "communication_sends_may_be_passthrough": False,
            },
        }
    )


def _write_policy(path: Path, snapshot: PolicySnapshot | None = None) -> PolicySnapshot:
    selected = snapshot or _snapshot()
    path.write_bytes(dump_policy(selected))
    return selected


def _assemble_enrolled(database: Database) -> BackendBundle:
    database.initialize()
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


def _reviewer(bundle: BackendBundle) -> EncryptedPayloadReviewer:
    access = ToolAccessAdapter()
    return EncryptedPayloadReviewer(
        bundle.state_machine,
        bundle.cipher,
        {
            (bundle.adapter.downstream_alias, bundle.adapter.tool_name): cast(
                ApprovalAdapter, bundle.adapter
            ),
            (access.downstream_alias, access.tool_name): cast(ApprovalAdapter, access),
        },
    )


def _install(
    bundle: BackendBundle,
    policy_path: Path,
    *,
    fault: Any = None,
) -> InstalledBoundary:
    engine = PolicyEngine(load_policy(policy_path))
    mirror = SchemaMirror(engine.snapshot)
    applied: list[int] = []
    notified: list[frozenset[str]] = []

    def apply(snapshot: PolicySnapshot) -> None:
        mirror.apply_policy(snapshot)
        applied.append(snapshot.version)

    boundary = SQLitePolicyPromotionBoundary(
        bundle.database,
        bundle.state_machine,
        _reviewer(bundle),
        engine,
        policy_path,
        apply_policy=apply,
        notify_list_changed=notified.append,
        fault_injector=fault,
        clock=lambda: NOW,
    )
    bundle.backend._payloads = _reviewer(bundle)
    bundle.backend._policy_promotions = cast(PolicyPromotionBoundary, boundary)
    bundle.backend._action_drafts = SQLiteActionDraftRepository(bundle.database)
    return InstalledBoundary(boundary, engine, mirror, applied, notified)


@pytest.fixture
def durable_bundle(tmp_path: Path) -> tuple[BackendBundle, Path, InstalledBoundary]:
    database = Database(tmp_path / "policy.sqlite3")
    bundle = _assemble_enrolled(database)
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path)
    installed = _install(bundle, policy_path)
    installed.applied.clear()
    return bundle, policy_path, installed


def test_sqlite_action_draft_is_immutable_and_survives_restart(
    durable_bundle: tuple[BackendBundle, Path, InstalledBoundary],
) -> None:
    bundle, _, _ = durable_bundle
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    row = bundle.state_machine.get_request(request_id)
    options = bundle.backend.begin_passkey_action(
        principal,
        request_id,
        "edit",
        expected_version=1,
        expected_payload_hash=str(row["current_payload_hash"]),
        prospective_arguments_json=(
            '{"recipient":"restart@example.test","body":"durable edit"}'
        ),
        http_method="POST",
        now=NOW + 1,
    )

    restarted = SQLiteActionDraftRepository(Database(bundle.database.path))
    draft = restarted.find(options.challenge_id)
    assert isinstance(draft, WebActionDraft)
    assert draft.action == "edit"
    assert draft.prepared_edit is not None
    assert draft.prepared_edit.payload_hash == draft.binding.prospective_payload_hash
    with pytest.raises(ValueError, match="conflicts"):
        restarted.save(draft)
    with (
        bundle.database.transaction() as connection,
        pytest.raises(IntegrityError, match="immutable"),
    ):
        connection.execute(
            "UPDATE web_action_drafts SET action = 'deny' WHERE challenge_id = ?",
            (options.challenge_id,),
        )


def test_failed_draft_save_invalidates_the_issued_challenge(
    durable_bundle: tuple[BackendBundle, Path, InstalledBoundary],
) -> None:
    bundle, _, _ = durable_bundle

    class FailingDrafts:
        def save(self, draft: WebActionDraft) -> None:
            del draft
            raise OSError("injected draft storage failure")

        def find(self, challenge_id: str) -> WebActionDraft | None:
            del challenge_id
            return None

    bundle.backend._action_drafts = cast(Any, FailingDrafts())
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    row = bundle.state_machine.get_request(request_id)
    with pytest.raises(WebConflict, match="durably staged"):
        bundle.backend.begin_passkey_action(
            principal,
            request_id,
            "approve",
            expected_version=1,
            expected_payload_hash=str(row["current_payload_hash"]),
            prospective_arguments_json=None,
            http_method="POST",
            now=NOW + 1,
        )
    with bundle.database.read() as connection:
        challenge = connection.execute(
            "SELECT invalidated_at FROM auth_challenges ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
    assert challenge is not None and challenge["invalidated_at"] == NOW + 1


def test_policy_migration_installs_restart_safe_tables_and_guards(tmp_path: Path) -> None:
    database = Database(tmp_path / "policy.sqlite3")
    database.initialize()
    restarted = Database(database.path)
    with restarted.read() as connection:
        tables = {
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            ).fetchall()
        }
        triggers = {
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'trigger'"
            ).fetchall()
        }
    assert {
        "web_action_drafts",
        "durable_policy_snapshots",
        "durable_policy_file_state",
    } <= tables
    assert {
        "web_action_drafts_no_update",
        "durable_policy_snapshots_no_update",
    } <= triggers


def test_web_totp_promotion_is_atomic_distinct_audited_and_single_use(
    durable_bundle: tuple[BackendBundle, Path, InstalledBoundary],
) -> None:
    bundle, policy_path, installed = durable_bundle
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    payload_hash = str(bundle.state_machine.get_request(request_id)["current_payload_hash"])

    assert bundle.backend.complete_totp_action(
        principal,
        request_id,
        "promote_approval",
        "fake:410",
        expected_version=1,
        expected_payload_hash=payload_hash,
        prospective_arguments_json=None,
        now=NOW + 1,
    ) == "policy_updated"

    applied = load_policy(policy_path)
    assert applied.version == 2
    assert applied.resolve("fake-service", "create_item") is PolicyMode.APPROVAL
    assert installed.engine.snapshot == applied
    assert installed.mirror.policy == applied
    assert installed.applied == [2]
    assert installed.notified == [frozenset({"fake-service"})]
    assert bundle.state_machine.get_request(request_id)["state"] == "pending_approval"
    assert bundle.adapter.downstream_calls == []
    with bundle.database.read() as connection:
        version = connection.execute(
            "SELECT * FROM policy_versions WHERE policy_version_id = 2"
        ).fetchone()
        state = connection.execute("SELECT * FROM durable_policy_file_state").fetchone()
        consumption_count = int(
            connection.execute(
                "SELECT count(*) FROM auth_proof_consumptions WHERE purpose = 'mutation'"
            ).fetchone()[0]
        )
    assert version["actor"] == "web:autumn"
    assert json.loads(str(version["mode_diffs_json"])) == {
        "alias": "fake-service",
        "new_mode": "approval",
        "old_mode": "deny",
        "request_id": request_id,
        "tool": "create_item",
    }
    assert state["sync_state"] == "synced"
    assert state["publication_pending"] == 0
    assert consumption_count == 1

    with pytest.raises(WebConflict, match="already used"):
        bundle.backend.complete_totp_action(
            principal,
            request_id,
            "promote_passthrough",
            "fake:410",
            expected_version=1,
            expected_payload_hash=payload_hash,
            prospective_arguments_json=None,
            now=NOW + 2,
        )
    assert load_policy(policy_path).version == 2
    assert not installed.boundary.pending_path.exists()


def test_passkey_promotion_binds_exact_mode_and_consumes_durable_draft(
    durable_bundle: tuple[BackendBundle, Path, InstalledBoundary],
) -> None:
    bundle, policy_path, _ = durable_bundle
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    payload_hash = str(bundle.state_machine.get_request(request_id)["current_payload_hash"])
    options = bundle.backend.begin_passkey_action(
        principal,
        request_id,
        "promote_passthrough",
        expected_version=1,
        expected_payload_hash=payload_hash,
        prospective_arguments_json=None,
        http_method="POST",
        now=NOW + 1,
    )
    challenge = bundle.webauthn.find_challenge(options.challenge_id)
    assert challenge is not None
    assert challenge.binding.action == "promote_passthrough"
    assert SQLiteActionDraftRepository(bundle.database).find(options.challenge_id) is not None

    assert bundle.backend.complete_passkey_action(
        principal,
        request_id,
        options.challenge_id,
        cast(dict[str, Any], bundle.assertion(options.challenge_id)),
        http_method="POST",
        now=NOW + 2,
    ) == "policy_updated"
    assert load_policy(policy_path).resolve(
        "fake-service", "create_item"
    ) is PolicyMode.PASSTHROUGH
    consumed = bundle.webauthn.find_challenge(options.challenge_id)
    assert consumed is not None and consumed.consumed_at == NOW + 2
    assert bundle.adapter.downstream_calls == []


def test_stale_policy_passkey_cannot_apply_after_request_terminalizes(
    durable_bundle: tuple[BackendBundle, Path, InstalledBoundary],
) -> None:
    bundle, policy_path, _ = durable_bundle
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    payload_hash = str(bundle.state_machine.get_request(request_id)["current_payload_hash"])
    options = bundle.backend.begin_passkey_action(
        principal,
        request_id,
        "promote_passthrough",
        expected_version=1,
        expected_payload_hash=payload_hash,
        prospective_arguments_json=None,
        http_method="POST",
        now=NOW + 1,
    )
    assertion = bundle.assertion(options.challenge_id)
    bundle.backend.complete_totp_action(
        principal,
        request_id,
        "deny",
        "fake:455",
        expected_version=1,
        expected_payload_hash=payload_hash,
        prospective_arguments_json=None,
        now=NOW + 2,
    )
    with pytest.raises(WebConflict, match="stale"):
        bundle.backend.complete_passkey_action(
            principal,
            request_id,
            options.challenge_id,
            cast(dict[str, Any], assertion),
            http_method="POST",
            now=NOW + 3,
        )
    assert load_policy(policy_path).version == 1
    assert bundle.adapter.downstream_calls == []


def test_mcp_totp_context_cannot_create_a_policy_confirmation(
    durable_bundle: tuple[BackendBundle, Path, InstalledBoundary],
) -> None:
    bundle, _, _ = durable_bundle
    request_id = bundle.enqueue()
    payload_hash = str(bundle.state_machine.get_request(request_id)["current_payload_hash"])
    with pytest.raises(ValueError, match="context is invalid"):
        bundle.backend._totp.verify(
            USER_ID,
            "fake:456",
            binding=ActionBinding(
                "promote_passthrough",
                request_id,
                1,
                payload_hash,
            ),
            source_id="profile:mcp-test",
            session_id=None,
            http_method="MCP",
            now=NOW + 1,
        )
    with bundle.database.read() as connection:
        assert connection.execute(
            "SELECT 1 FROM auth_proof_consumptions"
        ).fetchone() is None


@pytest.mark.parametrize(
    ("reviewed_read_only", "expected_mode", "expected_binding"),
    [
        (True, PolicyMode.PASSTHROUGH, "promote_passthrough"),
        (False, PolicyMode.APPROVAL, "promote_approval"),
    ],
)
def test_gateway_access_request_chooses_guarded_mode_and_never_dispatches(
    tmp_path: Path,
    reviewed_read_only: bool,
    expected_mode: PolicyMode,
    expected_binding: str,
) -> None:
    bundle = _assemble_enrolled(Database(tmp_path / "gateway-policy.sqlite3"))
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, _snapshot(reviewed_read_only=reviewed_read_only))
    _install(bundle, policy_path)
    factory = FrozenAccessRequestFactory(
        RequestFreezer(
            bundle.cipher,
            pending_ttl_seconds=900,
            clock=lambda: datetime.fromtimestamp(NOW, tz=UTC),
        ),
        policy_version=lambda: 1,
    )
    request = factory.freeze(
        AccessRequestDraft(
            origin_namespace="profile:agent",
            alias="fake-service",
            tool="create_item",
            reason="Need this reviewed capability for a bounded workflow.",
            actor="mcp:profile:agent",
            created_at=NOW,
        )
    )
    bundle.state_machine.enqueue(request)
    request_id = request.request_id
    _, principal = bundle.session()
    payload_hash = str(bundle.state_machine.get_request(request_id)["current_payload_hash"])
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
    challenge = bundle.webauthn.find_challenge(options.challenge_id)
    assert challenge is not None and challenge.binding.action == expected_binding

    assert bundle.backend.complete_passkey_action(
        principal,
        request_id,
        options.challenge_id,
        cast(dict[str, Any], bundle.assertion(options.challenge_id)),
        http_method="POST",
        now=NOW + 2,
    ) == "policy_updated"
    result = bundle.state_machine.get_request(request_id)
    assert result["state"] == "succeeded"
    assert json.loads(str(result["safe_outcome_json"])) == {"status": "policy_updated"}
    assert load_policy(policy_path).resolve("fake-service", "create_item") is expected_mode
    with bundle.database.read() as connection:
        assert connection.execute(
            "SELECT 1 FROM execution_attempts WHERE request_id = ?", (request_id,)
        ).fetchone() is None
    assert bundle.adapter.downstream_calls == []


@pytest.mark.parametrize(
    "stage",
    [
        "policy:pending_fsynced",
        "policy:before_db_commit",
        "policy:db_committed",
        "policy:before_rename",
        "policy:renamed",
        "policy:before_sync_mark",
        "policy:synced",
        "policy:published_callbacks",
    ],
)
def test_every_policy_crash_step_is_rollback_safe_or_restart_recoverable(
    tmp_path: Path,
    stage: str,
) -> None:
    bundle = _assemble_enrolled(Database(tmp_path / "crash.sqlite3"))
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path)
    selected_stage: list[str | None] = [stage]

    def fault(current: str) -> None:
        if current == selected_stage[0]:
            raise InjectedPolicyCrash(current)

    installed = _install(bundle, policy_path, fault=fault)
    installed.applied.clear()
    request_id = bundle.enqueue()
    token, principal = bundle.session()
    payload_hash = str(bundle.state_machine.get_request(request_id)["current_payload_hash"])
    with pytest.raises(InjectedPolicyCrash, match=stage):
        bundle.backend.complete_totp_action(
            principal,
            request_id,
            "promote_approval",
            "fake:520",
            expected_version=1,
            expected_payload_hash=payload_hash,
            prospective_arguments_json=None,
            now=NOW + 1,
        )

    committed = stage not in {"policy:pending_fsynced", "policy:before_db_commit"}
    with bundle.database.read() as connection:
        state = connection.execute("SELECT * FROM durable_policy_file_state").fetchone()
        versions = int(connection.execute("SELECT count(*) FROM policy_versions").fetchone()[0])
        consumptions = int(
            connection.execute("SELECT count(*) FROM auth_proof_consumptions").fetchone()[0]
        )
    if not committed:
        assert versions == 1
        assert consumptions == 0
        assert state["sync_state"] == "synced"
        assert not installed.boundary.pending_path.exists()
        selected_stage[0] = None
        assert bundle.backend.complete_totp_action(
            principal,
            request_id,
            "promote_approval",
            "fake:520",
            expected_version=1,
            expected_payload_hash=payload_hash,
            prospective_arguments_json=None,
            now=NOW + 2,
        ) == "policy_updated"
        return

    assert versions == 2
    assert consumptions == 1
    assert not installed.boundary.ready
    restarted_bundle = assemble(Database(bundle.database.path), adapter=bundle.adapter)
    restarted_bundle.backend.authenticate(token, now=NOW + 2)
    recovered = _install(restarted_bundle, policy_path)
    assert recovered.boundary.ready
    assert recovered.engine.snapshot.version == 2
    assert load_policy(policy_path).version == 2
    assert recovered.notified == [frozenset({"fake-service"})]
    with bundle.database.read() as connection:
        recovered_state = connection.execute(
            "SELECT * FROM durable_policy_file_state"
        ).fetchone()
    assert recovered_state["sync_state"] == "synced"
    assert recovered_state["publication_pending"] == 0
    assert not recovered.boundary.pending_path.exists()
    assert bundle.adapter.downstream_calls == []


def test_concurrent_policy_confirmations_have_one_stale_loser(
    durable_bundle: tuple[BackendBundle, Path, InstalledBoundary],
) -> None:
    bundle, policy_path, _ = durable_bundle
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    payload_hash = str(bundle.state_machine.get_request(request_id)["current_payload_hash"])

    def promote(step: int) -> str:
        try:
            return bundle.backend.complete_totp_action(
                principal,
                request_id,
                "promote_approval",
                f"fake:{step}",
                expected_version=1,
                expected_payload_hash=payload_hash,
                prospective_arguments_json=None,
                now=NOW + 1,
            )
        except WebConflict:
            return "stale"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(promote, (601, 602)))
    assert sorted(results) == ["policy_updated", "stale"]
    assert load_policy(policy_path).version == 2
    with bundle.database.read() as connection:
        assert int(connection.execute("SELECT count(*) FROM policy_versions").fetchone()[0]) == 2
        assert int(
            connection.execute("SELECT count(*) FROM auth_proof_consumptions").fetchone()[0]
        ) == 1
    assert bundle.adapter.downstream_calls == []


def test_startup_refuses_policy_file_or_ledger_divergence(tmp_path: Path) -> None:
    bundle = assemble(Database(tmp_path / "divergence.sqlite3"))
    policy_path = tmp_path / "policy.yaml"
    initial = _write_policy(policy_path)
    _install(bundle, policy_path)
    policy_path.write_bytes(dump_policy(initial) + b"# unreviewed external edit\n")

    with pytest.raises(PolicyDivergenceError, match="differs"):
        SQLitePolicyPromotionBoundary(
            bundle.database,
            bundle.state_machine,
            _reviewer(bundle),
            PolicyEngine(initial),
            policy_path,
            clock=lambda: NOW + 1,
        )

    policy_path.write_bytes(dump_policy(initial))
    with bundle.database.transaction() as connection:
        connection.execute(
            "UPDATE durable_policy_file_state SET file_sha256 = ? WHERE singleton = 1",
            ("f" * 64,),
        )
    with pytest.raises(PolicyDivergenceError, match="hashes disagree"):
        SQLitePolicyPromotionBoundary(
            bundle.database,
            bundle.state_machine,
            _reviewer(bundle),
            PolicyEngine(initial),
            policy_path,
            clock=lambda: NOW + 2,
        )


def test_writeback_preserves_every_strict_security_field(
    durable_bundle: tuple[BackendBundle, Path, InstalledBoundary],
) -> None:
    bundle, policy_path, _ = durable_bundle
    before = policy_document(load_policy(policy_path))
    request_id = bundle.enqueue()
    _, principal = bundle.session()
    payload_hash = str(bundle.state_machine.get_request(request_id)["current_payload_hash"])
    bundle.backend.complete_totp_action(
        principal,
        request_id,
        "promote_passthrough",
        "fake:730",
        expected_version=1,
        expected_payload_hash=payload_hash,
        prospective_arguments_json=None,
        now=NOW + 1,
    )
    after_snapshot = load_policy(policy_path)
    after = policy_document(after_snapshot)
    assert after_snapshot.version == 2
    assert after["mode_contracts"] == before["mode_contracts"]
    assert after["policy_changes"] == before["policy_changes"]
    assert after["downstreams"]["fake-service"]["schema_review"] == before[
        "downstreams"
    ]["fake-service"]["schema_review"]
    after_tool = after["downstreams"]["fake-service"]["tools"]["create_item"]
    before_tool = before["downstreams"]["fake-service"]["tools"]["create_item"]
    assert {key: value for key, value in after_tool.items() if key != "mode"} == {
        key: value for key, value in before_tool.items() if key != "mode"
    }
    assert policy_config_hash(after_snapshot) != policy_config_hash(_snapshot())
