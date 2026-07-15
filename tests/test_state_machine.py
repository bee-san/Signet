from __future__ import annotations

import asyncio
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest

from signet.auth import (
    TOTP_PROOF_DOMAIN,
    WEBAUTHN_PROOF_DOMAIN,
    ActionBinding,
    ProofCapability,
    source_rate_limit_key,
    totp_proof_claims,
    totp_rate_limit_key,
    webauthn_proof_claims,
)
from signet.db import Database, IntegrityError
from signet.models import (
    ApprovalConfirmation,
    ConfirmationKind,
    ConfirmationReplay,
    EnqueueRequest,
    FenceRejected,
    IdempotencyConflict,
    InvalidConfirmation,
    InvalidTransition,
    OutcomeClassification,
    ReadOnlyToolViolation,
    ReconciliationAction,
    ReconciliationDecision,
    ReconciliationRejected,
    RequestNotFound,
    ResultAlias,
    StaleVersion,
)
from signet.state_machine import ApprovalStateMachine, ReadOnlyMCPClient
from tests.attachment_fixtures import register_catalog_attachment

NOW = 1_800_000_000
HUMAN_USER = "owner"
WEB_SESSION_ID = "web-session-for-tests-0000000001"
TEST_CAPABILITIES = ProofCapability(b"test-only-proof-capability-key-0001")
TOTP_CREDENTIAL_ID = "totp-owner-tests"
TOTP_ATTEMPT_ID = "state-test-attempt-opaque"
TOTP_SOURCE_KEY = source_rate_limit_key("state-machine-tests")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def database(tmp_path: Path) -> Database:
    value = Database(tmp_path / "approvals.sqlite3")
    value.initialize()
    return value


@pytest.fixture
def machine(database: Database) -> ApprovalStateMachine:
    return ApprovalStateMachine(database, capabilities=TEST_CAPABILITIES)


def request(
    request_id: str,
    *,
    namespace: str = "profile:one",
    payload: str = "body-one",
    invocation_key: str | None = None,
    gateway_internal: bool = False,
) -> EnqueueRequest:
    payload_hash = digest(payload)
    return EnqueueRequest(
        request_id=request_id,
        downstream_alias="gateway" if gateway_internal else "fastmail",
        tool_name="request_tool_access" if gateway_internal else "send_email",
        policy_mode="approval",
        origin_namespace=namespace,
        encrypted_payload=("encrypted:" + payload).encode(),
        payload_hash=payload_hash,
        payload_fingerprint=digest("fingerprint:" + payload),
        pending_result=json.dumps(
            {"status": "pending_approval", "request_id": request_id},
            separators=(",", ":"),
        ).encode(),
        created_at=NOW,
        expires_at=NOW + 600,
        policy_version="policy-1",
        adapter_version="adapter-1",
        schema_version="schema-1",
        editor_actor=f"caller:{namespace}",
        canonical_size=len(payload),
        idempotency_key=invocation_key,
        gateway_internal=gateway_internal,
    )


def approve(
    machine: ApprovalStateMachine,
    request_id: str,
    *,
    payload: str = "body-one",
    use_id: str | None = None,
    path: str = "web",
) -> None:
    confirmation = totp_confirmation(
        machine,
        request_id,
        action="approve",
        version=1,
        payload_hash=digest(payload),
        use_id=use_id or f"totp:{request_id}",
        path=path,
    )
    machine.approve(
        request_id,
        expected_version=1,
        expected_payload_hash=digest(payload),
        confirmation=confirmation,
        actor=f"human:{path}",
        now=NOW + 1,
    )


def ensure_web_session(machine: ApprovalStateMachine, *, now: int = NOW) -> None:
    with machine.database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO auth_users(user_id, created_at) VALUES (?, ?)
            ON CONFLICT(user_id) DO NOTHING
            """,
            (HUMAN_USER, now),
        )
        connection.execute(
            """
            INSERT INTO web_sessions(
                session_id, user_id, auth_method, auth_generation,
                created_at, last_seen_at, absolute_expires_at
            ) VALUES (?, ?, 'test-auth', 0, ?, ?, ?)
            ON CONFLICT(session_id) DO NOTHING
            """,
            (WEB_SESSION_ID, HUMAN_USER, now, now, now + 10_000),
        )


def totp_confirmation(
    machine: ApprovalStateMachine,
    request_id: str,
    *,
    action: str,
    version: int,
    payload_hash: str,
    use_id: str,
    path: str = "web",
    prospective_payload_hash: str | None = None,
) -> ApprovalConfirmation:
    if path == "web":
        ensure_web_session(machine)
    with machine.database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO auth_credentials(
                credential_id, user_id, kind, secret_reference, enrolled_at
            ) VALUES (?, ?, 'totp', 'keychain://Signet/state-test', ?)
            ON CONFLICT(credential_id) DO NOTHING
            """,
            (TOTP_CREDENTIAL_ID, HUMAN_USER, NOW),
        )
    rate_key = totp_rate_limit_key(HUMAN_USER)
    binding = ActionBinding(
        action,
        request_id,
        version,
        payload_hash,
        prospective_payload_hash,
    )
    http_method = "POST" if path == "web" else "MCP"
    session_id = WEB_SESSION_ID if path == "web" else None
    capability = TEST_CAPABILITIES.seal(
        TOTP_PROOF_DOMAIN,
        totp_proof_claims(
            credential_id=TOTP_CREDENTIAL_ID,
            credential_user_id=HUMAN_USER,
            user_id=HUMAN_USER,
            use_id=use_id,
            binding=binding,
            path=path,
            session_id=session_id,
            http_method=http_method,
            rate_limit_key=rate_key,
            attempt_id=TOTP_ATTEMPT_ID,
            attempt_scope_keys=(rate_key, TOTP_SOURCE_KEY),
        ),
    )
    return ApprovalConfirmation(
        kind=ConfirmationKind.TOTP,
        use_id=use_id,
        path=path,  # type: ignore[arg-type]
        capability=capability,
        user_id=HUMAN_USER,
        action=action,
        bound_request_id=request_id,
        bound_version=version,
        bound_payload_hash=payload_hash,
        prospective_payload_hash=prospective_payload_hash,
        session_id=session_id,
        http_method=http_method,
        attempt_id=TOTP_ATTEMPT_ID,
        attempt_scope_keys=(rate_key, TOTP_SOURCE_KEY),
        rate_limit_key=rate_key,
        credential_id=TOTP_CREDENTIAL_ID,
        credential_user_id=HUMAN_USER,
    )


def signed_webauthn_confirmation(
    confirmation: ApprovalConfirmation,
) -> ApprovalConfirmation:
    assert confirmation.kind is ConfirmationKind.WEBAUTHN
    assert confirmation.user_id is not None
    assert confirmation.action is not None
    assert confirmation.credential_id is not None
    assert confirmation.credential_user_id is not None
    assert confirmation.challenge_id is not None
    assert confirmation.session_id is not None
    assert confirmation.http_method is not None
    assert confirmation.expected_counter is not None
    assert confirmation.new_counter is not None
    assert confirmation.device_type is not None
    assert confirmation.expected_backup_eligible is not None
    assert confirmation.new_backup_eligible is not None
    assert confirmation.previous_backed_up is not None
    assert confirmation.new_backed_up is not None
    binding = ActionBinding(
        confirmation.action,
        confirmation.bound_request_id,
        confirmation.bound_version,
        confirmation.bound_payload_hash,
        confirmation.prospective_payload_hash,
    )
    capability = TEST_CAPABILITIES.seal(
        WEBAUTHN_PROOF_DOMAIN,
        webauthn_proof_claims(
            credential_id=confirmation.credential_id,
            credential_user_id=confirmation.credential_user_id,
            user_id=confirmation.user_id,
            challenge_id=confirmation.challenge_id,
            use_id=confirmation.use_id,
            binding=binding,
            path=confirmation.path,
            session_id=confirmation.session_id,
            http_method=confirmation.http_method,
            expected_counter=confirmation.expected_counter,
            new_counter=confirmation.new_counter,
            device_type=confirmation.device_type,
            expected_backup_eligible=confirmation.expected_backup_eligible,
            new_backup_eligible=confirmation.new_backup_eligible,
            previous_backed_up=confirmation.previous_backed_up,
            new_backed_up=confirmation.new_backed_up,
        ),
    )
    return replace(confirmation, capability=capability)


def make_unknown(
    machine: ApprovalStateMachine,
    request_id: str,
    *,
    downstream_key: str | None,
) -> None:
    machine.enqueue(request(request_id))
    approve(machine, request_id)
    lease = machine.claim_execution(
        request_id,
        worker_id="worker-one",
        now=NOW + 2,
        lease_seconds=20,
        downstream_idempotency_key=downstream_key,
    )
    machine.mark_dispatch_started(lease, now=NOW + 3)
    machine.record_outcome(
        lease,
        classification=OutcomeClassification.UNKNOWN,
        now=NOW + 4,
        reconciliation_next_at=NOW + 5,
    )


def test_pending_ack_is_returned_only_after_full_durable_commit(database: Database) -> None:
    def fail(stage: str) -> None:
        if stage == "enqueue:before_commit":
            raise RuntimeError("power loss")

    crashing = ApprovalStateMachine(database, fault_injector=fail)
    with pytest.raises(RuntimeError, match="power loss"):
        crashing.enqueue(request("crash-before-ack", invocation_key="call-1"))
    with pytest.raises(RequestNotFound):
        crashing.get_request("crash-before-ack")
    with database.read() as connection:
        assert connection.execute("SELECT count(*) FROM idempotency_records").fetchone()[0] == 0
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2

    result = ApprovalStateMachine(database).enqueue(request("committed", invocation_key="call-1"))
    assert result.created
    assert ApprovalStateMachine(database).get_request("committed")["state"] == "pending_approval"


def test_attachment_references_commit_atomically_with_pending_ack(database: Database) -> None:
    attachment_id = "stg_" + "f" * 20
    attachment = register_catalog_attachment(
        database,
        attachment_id=attachment_id,
        storage_path=f"/private/staging/{attachment_id}",
    )
    candidate = replace(
        request("with-attachment", invocation_key="attachment-call"),
        attachments=(
            attachment,
        ),
    )
    ApprovalStateMachine(database).enqueue(candidate)
    with database.read() as connection:
        row = connection.execute(
            "SELECT request_id, version, sha256 FROM attachments WHERE attachment_id = ?",
            (attachment_id,),
        ).fetchone()
    assert tuple(row) == ("with-attachment", 1, "b" * 64)


def test_body_edit_preserves_attachment_snapshot_and_explicit_empty_removes_it(
    machine: ApprovalStateMachine,
    database: Database,
) -> None:
    attachment_id = "stg_" + "e" * 20
    attachment = register_catalog_attachment(
        database,
        attachment_id=attachment_id,
        storage_path=f"/private/staging/{attachment_id}",
    )
    candidate = replace(
        request("edit-attachment"),
        attachments=(
            attachment,
        ),
    )
    machine.enqueue(candidate)
    second_hash = digest("body-two")
    machine.edit(
        "edit-attachment",
        expected_version=1,
        expected_payload_hash=digest("body-one"),
        encrypted_payload=b"encrypted:body-two",
        payload_hash=second_hash,
        canonical_size=8,
        policy_version="policy-1",
        adapter_version="adapter-1",
        schema_version="schema-1",
        editor_actor="human:web",
        confirmation=totp_confirmation(
            machine,
            "edit-attachment",
            action="edit",
            version=1,
            payload_hash=digest("body-one"),
            prospective_payload_hash=second_hash,
            use_id="edit-attachment-v1",
        ),
        now=NOW + 1,
    )
    with database.read() as connection:
        versions = connection.execute(
            """
            SELECT version, payload_hash
            FROM attachments WHERE attachment_id = ? ORDER BY version
            """,
            (attachment_id,),
        ).fetchall()
    assert [tuple(row) for row in versions] == [
        (1, digest("body-one")),
        (2, second_hash),
    ]

    machine.edit(
        "edit-attachment",
        expected_version=2,
        expected_payload_hash=second_hash,
        encrypted_payload=b"encrypted:body-three",
        payload_hash=digest("body-three"),
        canonical_size=10,
        policy_version="policy-1",
        adapter_version="adapter-1",
        schema_version="schema-1",
        editor_actor="human:web",
        confirmation=totp_confirmation(
            machine,
            "edit-attachment",
            action="edit",
            version=2,
            payload_hash=second_hash,
            prospective_payload_hash=digest("body-three"),
            use_id="edit-attachment-v2",
        ),
        now=NOW + 2,
        attachments=(),
    )
    with database.read() as connection:
        current_count = connection.execute(
            "SELECT count(*) FROM attachments WHERE request_id = ? AND version = 3",
            ("edit-attachment",),
        ).fetchone()[0]
    assert current_count == 0


def test_hash_bindings_are_database_constraints(database: Database) -> None:
    ApprovalStateMachine(database).enqueue(request("hash-bound"))
    with pytest.raises(IntegrityError), database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO request_events(
                request_id, actor, action, occurred_at, version, payload_hash
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("hash-bound", "gateway:test", "invalid", NOW, 1, "f" * 64),
        )


def test_safe_outcome_metadata_rejects_sensitive_or_nested_fields(
    machine: ApprovalStateMachine,
) -> None:
    machine.enqueue(request("safe-metadata"))
    approve(machine, "safe-metadata")
    lease = machine.claim_execution(
        "safe-metadata", worker_id="worker", now=NOW + 2, lease_seconds=30
    )
    machine.mark_dispatch_started(lease, now=NOW + 3)
    for unsafe in (
        {"body": "private"},
        {"recipient": "person@example.test"},
        {"provider_id": {"nested": "not-safe"}},
    ):
        with pytest.raises(ValueError, match="safe outcome"):
            machine.record_outcome(
                lease,
                classification=OutcomeClassification.SUCCEEDED,
                now=NOW + 4,
                safe_outcome=unsafe,
            )
    assert machine.get_request("safe-metadata")["state"] == "executing"


def test_happy_path_records_real_alias_and_events_without_payload(
    machine: ApprovalStateMachine,
) -> None:
    marker = "private-message-body"
    machine.enqueue(request("happy", payload=marker))
    approve(machine, "happy", payload=marker)
    lease = machine.claim_execution("happy", worker_id="worker", now=NOW + 2, lease_seconds=30)
    assert machine.get_request("happy")["state"] == "executing"
    machine.mark_dispatch_started(lease, now=NOW + 3)
    machine.record_outcome(
        lease,
        classification=OutcomeClassification.SUCCEEDED,
        now=NOW + 4,
        safe_outcome={"provider_id": "safe-id"},
        result_aliases=(ResultAlias("primary", "message_id", "safe-id"),),
    )

    assert machine.get_request("happy")["state"] == "succeeded"
    serialized_events = json.dumps(machine.list_events("happy"))
    assert marker not in serialized_events
    assert "caller:profile:one" in serialized_events
    assert digest(marker) in serialized_events


@pytest.mark.parametrize("terminal", ["deny", "cancel", "expire"])
def test_denied_expired_and_cancelled_requests_never_execute(
    machine: ApprovalStateMachine,
    terminal: str,
) -> None:
    request_id = f"terminal-{terminal}"
    machine.enqueue(request(request_id))
    kwargs = {
        "expected_version": 1,
        "expected_payload_hash": digest("body-one"),
        "actor": "human:web",
        "now": NOW + (601 if terminal == "expire" else 1),
    }
    if terminal in {"deny", "cancel"}:
        kwargs["confirmation"] = totp_confirmation(
            machine,
            request_id,
            action="deny" if terminal == "deny" else "human_cancel",
            version=1,
            payload_hash=digest("body-one"),
            use_id=f"terminal-proof:{terminal}",
        )
    getattr(machine, terminal)(request_id, **kwargs)
    with pytest.raises(InvalidTransition):
        machine.claim_execution(request_id, worker_id="worker", now=NOW + 700, lease_seconds=30)
    assert (
        machine.get_request(request_id)["state"]
        == {
            "deny": "denied",
            "cancel": "cancelled",
            "expire": "expired",
        }[terminal]
    )


@pytest.mark.parametrize(
    "paths",
    [("web", "web"), ("mcp", "mcp"), ("web", "mcp")],
)
def test_double_approval_has_one_cas_winner(
    database: Database,
    paths: tuple[str, str],
) -> None:
    ApprovalStateMachine(database).enqueue(request("double"))
    barrier = Barrier(2)

    def contender(index: int) -> str:
        contender_machine = ApprovalStateMachine(database, capabilities=TEST_CAPABILITIES)
        barrier.wait()
        try:
            approve(
                contender_machine,
                "double",
                use_id=f"valid-code-{index}",
                path=paths[index],
            )
            return "won"
        except InvalidTransition:
            return "lost"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(contender, range(2)))
    assert sorted(results) == ["lost", "won"]
    with database.read() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM confirmation_consumptions WHERE request_id = 'double'"
            ).fetchone()[0]
            == 1
        )


def test_totp_consumption_is_atomic_and_replay_fails_across_paths(
    machine: ApprovalStateMachine,
) -> None:
    machine.enqueue(request("first"))
    machine.enqueue(request("second"))
    approve(machine, "first", use_id="totp:user:window", path="web")
    with pytest.raises(ConfirmationReplay):
        approve(machine, "second", use_id="totp:user:window", path="mcp")
    assert machine.get_request("second")["state"] == "pending_approval"


def test_confirmation_action_method_and_prospective_hash_are_exact(
    machine: ApprovalStateMachine,
) -> None:
    machine.enqueue(request("exact-binding"))
    payload_hash = digest("body-one")
    deny_proof = totp_confirmation(
        machine,
        "exact-binding",
        action="deny",
        version=1,
        payload_hash=payload_hash,
        use_id="exact-binding-proof",
    )
    with pytest.raises(InvalidConfirmation, match="action binding"):
        machine.approve(
            "exact-binding",
            expected_version=1,
            expected_payload_hash=payload_hash,
            confirmation=deny_proof,
            actor="human:web",
            now=NOW + 1,
        )
    with pytest.raises(InvalidConfirmation, match="capability"):
        machine.approve(
            "exact-binding",
            expected_version=1,
            expected_payload_hash=payload_hash,
            confirmation=replace(
                deny_proof,
                action="approve",
                http_method="GET",
            ),
            actor="human:web",
            now=NOW + 1,
        )
    assert machine.get_request("exact-binding")["state"] == "pending_approval"

    edited_hash = digest("edited-body")
    wrong_hash = digest("different-edit")
    wrong_edit = totp_confirmation(
        machine,
        "exact-binding",
        action="edit",
        version=1,
        payload_hash=payload_hash,
        prospective_payload_hash=wrong_hash,
        use_id="exact-edit-proof",
    )
    with pytest.raises(InvalidConfirmation, match="action binding"):
        machine.edit(
            "exact-binding",
            expected_version=1,
            expected_payload_hash=payload_hash,
            encrypted_payload=b"encrypted:edited-body",
            payload_hash=edited_hash,
            canonical_size=11,
            policy_version="policy-1",
            adapter_version="adapter-1",
            schema_version="schema-1",
            editor_actor="human:web",
            confirmation=wrong_edit,
            now=NOW + 2,
        )
    assert machine.get_request("exact-binding")["current_version"] == 1


def test_state_machine_without_capability_verifier_fails_closed(database: Database) -> None:
    unsigned_consumer = ApprovalStateMachine(database)
    unsigned_consumer.enqueue(request("missing-capability-verifier"))
    proof = totp_confirmation(
        unsigned_consumer,
        "missing-capability-verifier",
        action="approve",
        version=1,
        payload_hash=digest("body-one"),
        use_id="missing-capability-verifier-proof",
    )

    with pytest.raises(InvalidConfirmation, match="unavailable"):
        unsigned_consumer.approve(
            "missing-capability-verifier",
            expected_version=1,
            expected_payload_hash=digest("body-one"),
            confirmation=proof,
            actor="human:web",
            now=NOW + 1,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"capability": "pc1.forged"},
        {"use_id": "tampered-use-id"},
        {"user_id": "other-user"},
        {"action": "deny"},
        {"bound_request_id": "other-request"},
        {"bound_version": 2},
        {"bound_payload_hash": "b" * 64},
        {"prospective_payload_hash": "b" * 64},
        {"path": "mcp"},
        {"session_id": "other-session-identifier-00000000001"},
        {"http_method": "GET"},
        {"attempt_id": "different-attempt-opaque"},
        {"attempt_scope_keys": (TOTP_SOURCE_KEY, totp_rate_limit_key(HUMAN_USER))},
        {"rate_limit_key": totp_rate_limit_key("other-user")},
        {"credential_id": "other-totp-credential"},
        {"credential_user_id": "other-user"},
    ],
)
def test_tampered_totp_confirmation_claims_fail_before_mutation(
    machine: ApprovalStateMachine,
    database: Database,
    changes: dict[str, object],
) -> None:
    machine.enqueue(request("tampered-capability"))
    proof = totp_confirmation(
        machine,
        "tampered-capability",
        action="approve",
        version=1,
        payload_hash=digest("body-one"),
        use_id="tampered-capability-proof",
    )

    with pytest.raises(InvalidConfirmation):
        machine.approve(
            "tampered-capability",
            expected_version=1,
            expected_payload_hash=digest("body-one"),
            confirmation=replace(proof, **changes),  # type: ignore[arg-type]
            actor="human:web",
            now=NOW + 1,
        )
    assert machine.get_request("tampered-capability")["state"] == "pending_approval"
    with database.read() as connection:
        assert connection.execute(
            "SELECT count(*) FROM auth_proof_consumptions"
        ).fetchone()[0] == 0
        assert connection.execute(
            """
            SELECT last_used_at FROM auth_credentials
            WHERE credential_id = ?
            """,
            (TOTP_CREDENTIAL_ID,),
        ).fetchone()[0] is None


def test_webauthn_challenge_cannot_cross_sessions_and_cas_rolls_back(
    machine: ApprovalStateMachine,
    database: Database,
) -> None:
    machine.enqueue(request("cross-session"))
    payload_hash = digest("body-one")
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO auth_credentials(
                credential_id, user_id, kind, public_material, enrolled_at,
                sign_count, backup_eligible, backup_state
            ) VALUES ('cross-session-credential', 'owner', 'webauthn', X'01', ?, 3, 0, 0)
            """,
            (NOW,),
        )
    ensure_web_session(machine)
    other_session = "other-web-session-for-tests-00000001"
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO web_sessions(
                session_id, user_id, auth_method, auth_generation,
                created_at, last_seen_at, absolute_expires_at
            ) VALUES (?, 'owner', 'test-auth', 0, ?, ?, ?)
            """,
            (other_session, NOW, NOW, NOW + 10_000),
        )
    machine.create_challenge(
        "cross-session-challenge-opaque",
        "cross-session",
        kind=ConfirmationKind.WEBAUTHN,
        user_id=HUMAN_USER,
        action="approve",
        challenge=b"s" * 32,
        session_id=WEB_SESSION_ID,
        http_method="POST",
        offered_credential_ids=("cross-session-credential",),
        expected_version=1,
        expected_payload_hash=payload_hash,
        created_at=NOW,
        expires_at=NOW + 100,
    )

    with pytest.raises(InvalidConfirmation, match="misbound"):
        machine.approve(
            "cross-session",
            expected_version=1,
            expected_payload_hash=payload_hash,
            confirmation=signed_webauthn_confirmation(ApprovalConfirmation(
                kind=ConfirmationKind.WEBAUTHN,
                use_id="cross-session-assertion-proof",
                path="web",
                capability="",
                user_id=HUMAN_USER,
                action="approve",
                bound_request_id="cross-session",
                bound_version=1,
                bound_payload_hash=payload_hash,
                session_id=other_session,
                http_method="POST",
                challenge_id="cross-session-challenge-opaque",
                credential_id="cross-session-credential",
                credential_user_id=HUMAN_USER,
                expected_counter=3,
                new_counter=4,
                device_type="single_device",
                expected_backup_eligible=False,
                new_backup_eligible=False,
                previous_backed_up=False,
                new_backed_up=False,
            )),
            actor="human:web",
            now=NOW + 1,
        )

    with database.read() as connection:
        assert connection.execute(
            """
            SELECT sign_count FROM auth_credentials
            WHERE credential_id = 'cross-session-credential'
            """
        ).fetchone()[0] == 3
        assert connection.execute(
            """
            SELECT consumed_at FROM auth_challenges
            WHERE challenge_id = 'cross-session-challenge-opaque'
            """
        ).fetchone()[0] is None
    assert machine.get_request("cross-session")["state"] == "pending_approval"


@pytest.mark.parametrize(
    ("terminal", "action", "fault_stage", "expected_state"),
    [
        ("deny", "deny", "denied:before_commit", "denied"),
        ("cancel", "human_cancel", "cancelled:before_commit", "cancelled"),
    ],
)
def test_confirmed_terminal_fault_rolls_back_proof_and_transition(
    database: Database,
    terminal: str,
    action: str,
    fault_stage: str,
    expected_state: str,
) -> None:
    request_id = f"rollback-{terminal}"
    machine = ApprovalStateMachine(database, capabilities=TEST_CAPABILITIES)
    machine.enqueue(request(request_id))
    proof = totp_confirmation(
        machine,
        request_id,
        action=action,
        version=1,
        payload_hash=digest("body-one"),
        use_id=f"rollback-proof-{terminal}",
    )

    def fail(stage: str) -> None:
        if stage == fault_stage:
            raise RuntimeError("injected terminal failure")

    crashing = ApprovalStateMachine(
        database,
        fault_injector=fail,
        capabilities=TEST_CAPABILITIES,
    )
    with pytest.raises(RuntimeError, match="injected terminal failure"):
        getattr(crashing, terminal)(
            request_id,
            expected_version=1,
            expected_payload_hash=digest("body-one"),
            confirmation=proof,
            actor="human:web",
            now=NOW + 1,
        )
    assert machine.get_request(request_id)["state"] == "pending_approval"
    with database.read() as connection:
        assert connection.execute(
            "SELECT count(*) FROM confirmation_consumptions WHERE use_id = ?",
            (proof.use_id,),
        ).fetchone()[0] == 0

    getattr(machine, terminal)(
        request_id,
        expected_version=1,
        expected_payload_hash=digest("body-one"),
        confirmation=proof,
        actor="human:web",
        now=NOW + 2,
    )
    assert machine.get_request(request_id)["state"] == expected_state


def test_edit_fault_rolls_back_proof_and_new_revision(database: Database) -> None:
    machine = ApprovalStateMachine(database, capabilities=TEST_CAPABILITIES)
    machine.enqueue(request("rollback-edit"))
    old_hash = digest("body-one")
    new_hash = digest("edited-body")
    proof = totp_confirmation(
        machine,
        "rollback-edit",
        action="edit",
        version=1,
        payload_hash=old_hash,
        prospective_payload_hash=new_hash,
        use_id="rollback-edit-proof",
    )

    def fail(stage: str) -> None:
        if stage == "edit:before_commit":
            raise RuntimeError("injected edit failure")

    arguments = {
        "expected_version": 1,
        "expected_payload_hash": old_hash,
        "encrypted_payload": b"encrypted:edited-body",
        "payload_hash": new_hash,
        "canonical_size": 11,
        "policy_version": "policy-1",
        "adapter_version": "adapter-1",
        "schema_version": "schema-1",
        "editor_actor": "human:web",
        "confirmation": proof,
    }
    with pytest.raises(RuntimeError, match="injected edit failure"):
        ApprovalStateMachine(
            database,
            fault_injector=fail,
            capabilities=TEST_CAPABILITIES,
        ).edit(
            "rollback-edit",
            now=NOW + 1,
            **arguments,  # type: ignore[arg-type]
        )
    assert machine.get_request("rollback-edit")["current_version"] == 1
    with database.read() as connection:
        assert connection.execute(
            "SELECT count(*) FROM confirmation_consumptions WHERE use_id = ?",
            (proof.use_id,),
        ).fetchone()[0] == 0

    assert machine.edit(
        "rollback-edit",
        now=NOW + 2,
        **arguments,  # type: ignore[arg-type]
    ) == 2


def test_caller_cancel_is_code_free_but_exactly_namespace_scoped(
    machine: ApprovalStateMachine,
) -> None:
    machine.enqueue(request("caller-cancel", namespace="profile:owner"))
    with pytest.raises(RequestNotFound):
        machine.cancel_by_caller(
            "caller-cancel",
            expected_version=1,
            expected_payload_hash=digest("body-one"),
            actor="caller:profile:other",
            origin_namespace="profile:other",
            now=NOW + 1,
        )
    assert machine.get_request("caller-cancel")["state"] == "pending_approval"

    machine.cancel_by_caller(
        "caller-cancel",
        expected_version=1,
        expected_payload_hash=digest("body-one"),
        actor="caller:profile:owner",
        origin_namespace="profile:owner",
        now=NOW + 2,
    )
    assert machine.get_request("caller-cancel")["state"] == "cancelled"


def test_webauthn_credential_state_and_approval_commit_atomically(
    machine: ApprovalStateMachine,
    database: Database,
) -> None:
    machine.enqueue(request("webauthn-approval"))
    payload_hash = digest("body-one")
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO auth_credentials(
                credential_id, user_id, kind, public_material, enrolled_at,
                sign_count, backup_eligible, backup_state
            ) VALUES ('credential-one', 'owner', 'webauthn', X'01', ?, 7, 1, 0)
            """,
            (NOW,),
        )
    ensure_web_session(machine)
    machine.create_challenge(
        "challenge-one-opaque",
        "webauthn-approval",
        kind=ConfirmationKind.WEBAUTHN,
        user_id=HUMAN_USER,
        action="approve",
        challenge=b"w" * 32,
        session_id=WEB_SESSION_ID,
        http_method="POST",
        offered_credential_ids=("credential-one",),
        expected_version=1,
        expected_payload_hash=payload_hash,
        created_at=NOW,
        expires_at=NOW + 100,
    )

    machine.approve(
        "webauthn-approval",
        expected_version=1,
        expected_payload_hash=payload_hash,
        confirmation=signed_webauthn_confirmation(ApprovalConfirmation(
            kind=ConfirmationKind.WEBAUTHN,
            use_id="assertion-one",
            path="web",
            capability="",
            user_id=HUMAN_USER,
            action="approve",
            bound_request_id="webauthn-approval",
            bound_version=1,
            bound_payload_hash=payload_hash,
            session_id=WEB_SESSION_ID,
            http_method="POST",
            challenge_id="challenge-one-opaque",
            credential_id="credential-one",
            credential_user_id="owner",
            expected_counter=7,
            new_counter=8,
            device_type="multi_device",
            expected_backup_eligible=True,
            new_backup_eligible=True,
            previous_backed_up=False,
            new_backed_up=True,
        )),
        actor="human:web",
        now=NOW + 1,
    )

    with database.read() as connection:
        credential = connection.execute(
            """
            SELECT sign_count, backup_eligible, backup_state, last_used_at
            FROM auth_credentials WHERE credential_id = 'credential-one'
            """
        ).fetchone()
    assert tuple(credential) == (8, 1, 1, NOW + 1)
    assert machine.get_request("webauthn-approval")["state"] == "approved"


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"expected_counter": 6}, "stale or unavailable"),
        ({"new_counter": 7}, "counter transition"),
        ({"new_backup_eligible": True}, "backup state transition"),
        ({"new_backed_up": True}, "backup state transition"),
    ],
)
def test_invalid_webauthn_state_rolls_back_challenge_and_approval(
    machine: ApprovalStateMachine,
    database: Database,
    override: dict[str, object],
    message: str,
) -> None:
    machine.enqueue(request("bad-webauthn"))
    payload_hash = digest("body-one")
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO auth_credentials(
                credential_id, user_id, kind, public_material, enrolled_at,
                sign_count, backup_eligible, backup_state
            ) VALUES ('credential-bad', 'owner', 'webauthn', X'01', ?, 7, 0, 0)
            """,
            (NOW,),
        )
    ensure_web_session(machine)
    machine.create_challenge(
        "challenge-bad-opaque",
        "bad-webauthn",
        kind=ConfirmationKind.WEBAUTHN,
        user_id=HUMAN_USER,
        action="approve",
        challenge=b"b" * 32,
        session_id=WEB_SESSION_ID,
        http_method="POST",
        offered_credential_ids=("credential-bad",),
        expected_version=1,
        expected_payload_hash=payload_hash,
        created_at=NOW,
        expires_at=NOW + 100,
    )
    values: dict[str, object] = {
        "kind": ConfirmationKind.WEBAUTHN,
        "use_id": "assertion-bad",
        "path": "web",
        "capability": "",
        "user_id": HUMAN_USER,
        "action": "approve",
        "bound_request_id": "bad-webauthn",
        "bound_version": 1,
        "bound_payload_hash": payload_hash,
        "session_id": WEB_SESSION_ID,
        "http_method": "POST",
        "challenge_id": "challenge-bad-opaque",
        "credential_id": "credential-bad",
        "credential_user_id": "owner",
        "expected_counter": 7,
        "new_counter": 8,
        "device_type": "single_device",
        "expected_backup_eligible": False,
        "new_backup_eligible": False,
        "previous_backed_up": False,
        "new_backed_up": False,
    }
    values.update(override)
    with pytest.raises(InvalidConfirmation, match=message):
        machine.approve(
            "bad-webauthn",
            expected_version=1,
            expected_payload_hash=payload_hash,
            confirmation=signed_webauthn_confirmation(
                ApprovalConfirmation(**values)  # type: ignore[arg-type]
            ),
            actor="human:web",
            now=NOW + 1,
        )

    with database.read() as connection:
        challenge = connection.execute(
            "SELECT consumed_at FROM auth_challenges "
            "WHERE challenge_id = 'challenge-bad-opaque'"
        ).fetchone()
        credential = connection.execute(
            """
            SELECT sign_count, backup_state FROM auth_credentials
            WHERE credential_id = 'credential-bad'
            """
        ).fetchone()
    assert challenge[0] is None
    assert tuple(credential) == (7, 0)
    assert machine.get_request("bad-webauthn")["state"] == "pending_approval"


def test_edit_is_immutable_and_invalidates_challenge_totp_binding_and_view(
    machine: ApprovalStateMachine,
    database: Database,
) -> None:
    machine.enqueue(request("edit"))
    old_hash = digest("body-one")
    ensure_web_session(machine)
    machine.create_challenge(
        "old-challenge-opaque",
        "edit",
        kind=ConfirmationKind.WEBAUTHN,
        user_id=HUMAN_USER,
        action="approve",
        challenge=b"o" * 32,
        session_id=WEB_SESSION_ID,
        http_method="POST",
        offered_credential_ids=("old-credential",),
        expected_version=1,
        expected_payload_hash=old_hash,
        created_at=NOW + 1,
        expires_at=NOW + 100,
    )
    machine.create_browser_view(
        "old-view",
        "edit",
        expected_version=1,
        expected_payload_hash=old_hash,
        created_at=NOW + 1,
    )
    new_hash = digest("edited-body")
    assert (
        machine.edit(
            "edit",
            expected_version=1,
            expected_payload_hash=old_hash,
            encrypted_payload=b"encrypted:edited-body",
            payload_hash=new_hash,
            canonical_size=11,
            policy_version="policy-1",
            adapter_version="adapter-1",
            schema_version="schema-1",
            editor_actor="human:web",
            confirmation=totp_confirmation(
                machine,
                "edit",
                action="edit",
                version=1,
                payload_hash=old_hash,
                prospective_payload_hash=new_hash,
                use_id="edit-proof",
            ),
            now=NOW + 2,
        )
        == 2
    )
    assert not machine.browser_view_is_current("old-view")
    with pytest.raises(StaleVersion):
        machine.approve(
            "edit",
            expected_version=1,
            expected_payload_hash=old_hash,
            confirmation=ApprovalConfirmation(
                ConfirmationKind.TOTP,
                "old-totp-binding",
                "mcp",
                "",
            ),
            actor="human:mcp",
            now=NOW + 3,
        )
    with (
        pytest.raises(IntegrityError, match="immutable"),
        database.transaction() as connection,
    ):
        connection.execute(
            """
            UPDATE payload_versions SET payload_hash = ?
            WHERE request_id = 'edit' AND version = 1
            """,
            ("f" * 64,),
        )
    assert machine.get_payload_version("edit", 1)["payload_hash"] == old_hash


def test_concurrent_idempotency_and_restart_replay(database: Database) -> None:
    barrier = Barrier(2)

    def enqueue_contender(index: int) -> tuple[bool, str, bytes]:
        candidate = request(f"idem-{index}", invocation_key="same-call")
        barrier.wait()
        result = ApprovalStateMachine(database).enqueue(candidate)
        return result.created, result.request_id, result.pending_result

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(enqueue_contender, range(2)))
    assert sum(created for created, _, _ in results) == 1
    assert len({request_id for _, request_id, _ in results}) == 1
    assert len({pending for _, _, pending in results}) == 1

    winner = results[0][1]
    replay = ApprovalStateMachine(database).enqueue(
        request("restart-new-id", invocation_key="same-call")
    )
    assert not replay.created
    assert replay.request_id == winner

    with pytest.raises(IdempotencyConflict):
        ApprovalStateMachine(database).enqueue(
            request("different", payload="different-body", invocation_key="same-call")
        )


def test_idempotency_survives_terminal_states_and_is_caller_scoped(
    machine: ApprovalStateMachine,
) -> None:
    original = machine.enqueue(request("denied-original", invocation_key="call"))
    machine.deny(
        "denied-original",
        expected_version=1,
        expected_payload_hash=digest("body-one"),
        confirmation=totp_confirmation(
            machine,
            "denied-original",
            action="deny",
            version=1,
            payload_hash=digest("body-one"),
            use_id="deny-original-proof",
        ),
        actor="human:web",
        now=NOW + 1,
    )
    replay = machine.enqueue(request("denied-retry", invocation_key="call"))
    assert replay == type(replay)(original.request_id, original.pending_result, False)

    other = machine.enqueue(
        request("other-profile", namespace="profile:two", invocation_key="call")
    )
    assert other.created and other.request_id == "other-profile"
    assert machine.enqueue(request("equal-a")).request_id == "equal-a"
    assert machine.enqueue(request("equal-b")).request_id == "equal-b"


def test_fencing_recovery_and_crash_boundaries(database: Database) -> None:
    machine = ApprovalStateMachine(database, capabilities=TEST_CAPABILITIES)
    machine.enqueue(request("fenced"))
    approve(machine, "fenced")

    def fail_claim(stage: str) -> None:
        if stage == "execution_claim:before_commit":
            raise RuntimeError("crash before intent commit")

    with pytest.raises(RuntimeError):
        ApprovalStateMachine(database, fault_injector=fail_claim).claim_execution(
            "fenced", worker_id="dead", now=NOW + 2, lease_seconds=5
        )
    assert machine.get_request("fenced")["state"] == "approved"

    first = machine.claim_execution("fenced", worker_id="first", now=NOW + 3, lease_seconds=5)
    assert machine.recover_startup(now=NOW + 4).active == ("fenced",)
    assert machine.recover_startup(now=NOW + 8).reclaimable == ("fenced",)
    with pytest.raises(FenceRejected):
        machine.heartbeat(first, now=NOW + 8, lease_seconds=5)

    second = machine.claim_execution("fenced", worker_id="second", now=NOW + 8, lease_seconds=5)
    with pytest.raises(FenceRejected):
        machine.mark_dispatch_started(first, now=NOW + 9)

    def fail_dispatch(stage: str) -> None:
        if stage == "dispatch_started:before_commit":
            raise RuntimeError("crash before dispatch intent commit")

    with pytest.raises(RuntimeError):
        ApprovalStateMachine(database, fault_injector=fail_dispatch).mark_dispatch_started(
            second, now=NOW + 9
        )
    assert machine.recover_startup(now=NOW + 13).reclaimable == ("fenced",)

    third = machine.claim_execution("fenced", worker_id="third", now=NOW + 13, lease_seconds=5)
    machine.mark_dispatch_started(third, now=NOW + 14)
    assert machine.recover_startup(now=NOW + 15).active == ("fenced",)

    def fail_result(stage: str) -> None:
        if stage == "outcome:before_commit":
            raise RuntimeError("crash after possible socket write")

    with pytest.raises(RuntimeError, match="possible socket write"):
        ApprovalStateMachine(database, fault_injector=fail_result).record_outcome(
            third,
            classification=OutcomeClassification.SUCCEEDED,
            now=NOW + 16,
        )
    assert machine.get_request("fenced")["state"] == "executing"
    recovery = machine.recover_startup(now=NOW + 18)
    assert recovery.routed_to_reconciliation == ("fenced",)
    assert machine.get_request("fenced")["state"] == "outcome_unknown"
    with pytest.raises(FenceRejected):
        machine.record_outcome(third, classification=OutcomeClassification.SUCCEEDED, now=NOW + 19)


def test_reconciliation_decisions_are_bounded_and_never_blindly_retry(
    machine: ApprovalStateMachine,
    database: Database,
) -> None:
    make_unknown(machine, "effect", downstream_key=None)
    effect = machine.reconcile(
        "effect",
        expected_reconciliation_count=0,
        decision=ReconciliationDecision.CONFIRMED_EFFECT,
        worker_id="reconciler",
        now=NOW + 5,
        safe_outcome={"provider_id": "confirmed"},
    )
    assert effect.action is ReconciliationAction.SUCCEEDED
    assert machine.get_request("effect")["state"] == "succeeded"

    make_unknown(machine, "no-key", downstream_key=None)
    no_key = machine.reconcile(
        "no-key",
        expected_reconciliation_count=0,
        decision=ReconciliationDecision.CONFIRMED_NO_EFFECT,
        worker_id="reconciler",
        now=NOW + 5,
    )
    no_key_request = machine.get_request("no-key")
    assert no_key.action is ReconciliationAction.FAILED_NO_EFFECT
    assert no_key_request["failure_reason"] == "reconciled_no_effect"
    assert no_key_request["manual_retry_allowed"] == 1
    assert no_key_request["duplicate_warning_required"] == 0

    make_unknown(machine, "keyed", downstream_key="stable-provider-key")
    keyed = machine.reconcile(
        "keyed",
        expected_reconciliation_count=0,
        decision=ReconciliationDecision.CONFIRMED_NO_EFFECT,
        worker_id="redispatcher",
        now=NOW + 5,
        lease_seconds=10,
    )
    assert keyed.action is ReconciliationAction.REDISPATCH
    assert keyed.lease is not None
    assert keyed.lease.downstream_idempotency_key == "stable-provider-key"
    with pytest.raises(ReconciliationRejected):
        machine.reconcile(
            "keyed",
            expected_reconciliation_count=0,
            decision=ReconciliationDecision.CONFIRMED_NO_EFFECT,
            worker_id="racer",
            now=NOW + 5,
        )
    machine.mark_dispatch_started(keyed.lease, now=NOW + 6)
    machine.record_outcome(
        keyed.lease,
        classification=OutcomeClassification.UNKNOWN,
        now=NOW + 7,
        reconciliation_next_at=NOW + 8,
    )
    second_no_effect = machine.reconcile(
        "keyed",
        expected_reconciliation_count=1,
        decision=ReconciliationDecision.CONFIRMED_NO_EFFECT,
        worker_id="reconciler",
        now=NOW + 8,
    )
    assert second_no_effect.action is ReconciliationAction.FAILED_NO_EFFECT
    with database.read() as connection:
        attempt = connection.execute(
            "SELECT * FROM execution_attempts WHERE request_id = 'keyed'"
        ).fetchone()
    assert attempt["redispatch_used"] == 1
    assert attempt["failure_reason"] == "reconciled_no_effect_after_redispatch"


def test_reconciliation_exhaustion_sets_notification(
    machine: ApprovalStateMachine,
    database: Database,
) -> None:
    make_unknown(machine, "exhaust", downstream_key=None)
    scheduled = machine.reconcile(
        "exhaust",
        expected_reconciliation_count=0,
        decision=ReconciliationDecision.INCONCLUSIVE,
        worker_id="reconciler",
        now=NOW + 5,
        next_check_at=NOW + 10,
    )
    assert scheduled.action is ReconciliationAction.RESCHEDULED
    exhausted = machine.reconcile(
        "exhaust",
        expected_reconciliation_count=1,
        decision=ReconciliationDecision.INCONCLUSIVE,
        worker_id="reconciler",
        now=NOW + 10,
        exhausted=True,
    )
    assert exhausted.action is ReconciliationAction.EXHAUSTED
    assert machine.get_request("exhaust")["state"] == "outcome_unknown"
    with database.read() as connection:
        attempt = connection.execute(
            "SELECT * FROM execution_attempts WHERE request_id = 'exhaust'"
        ).fetchone()
    assert attempt["reconciliation_notification_required"] == 1
    assert attempt["reconciliation_exhausted_at"] == NOW + 10


def test_reconciliation_client_rejects_non_allowlisted_tool_before_call() -> None:
    downstream_calls: list[str] = []

    async def downstream(tool: str, arguments: object) -> dict[str, bool]:
        downstream_calls.append(tool)
        return {"ok": True}

    client = ReadOnlyMCPClient({"search_sent"}, downstream)
    assert asyncio.run(client.call_tool("search_sent", {"id": "safe"})) == {"ok": True}
    with pytest.raises(ReadOnlyToolViolation):
        asyncio.run(client.call_tool("send_email", {"body": "must-not-send"}))
    assert downstream_calls == ["search_sent"]


def test_gateway_internal_approval_is_web_only(machine: ApprovalStateMachine) -> None:
    machine.enqueue(request("policy-change", gateway_internal=True))
    with pytest.raises(InvalidTransition):
        machine.claim_execution("policy-change", worker_id="worker", now=NOW + 1, lease_seconds=10)
    with pytest.raises(InvalidConfirmation, match="web-approval-only"):
        approve(machine, "policy-change", path="mcp")
