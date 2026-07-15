from __future__ import annotations

import asyncio
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest

from signet.db import Database, IntegrityError
from signet.models import (
    ApprovalConfirmation,
    AttachmentReference,
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

NOW = 1_800_000_000


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def database(tmp_path: Path) -> Database:
    value = Database(tmp_path / "approvals.sqlite3")
    value.initialize()
    return value


@pytest.fixture
def machine(database: Database) -> ApprovalStateMachine:
    return ApprovalStateMachine(database)


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
    machine.approve(
        request_id,
        expected_version=1,
        expected_payload_hash=digest(payload),
        confirmation=ApprovalConfirmation(
            kind=ConfirmationKind.TOTP,
            use_id=use_id or f"totp:{request_id}",
            path=path,  # type: ignore[arg-type]
        ),
        actor=f"human:{path}",
        now=NOW + 1,
    )


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
    candidate = replace(
        request("with-attachment", invocation_key="attachment-call"),
        attachments=(
            AttachmentReference(
                attachment_id="stg_fixture",
                filename="fixture.txt",
                mime_type="text/plain",
                size_bytes=7,
                sha256="b" * 64,
                storage_path="/private/staging/stg_fixture",
            ),
        ),
    )
    ApprovalStateMachine(database).enqueue(candidate)
    with database.read() as connection:
        row = connection.execute(
            "SELECT request_id, version, sha256 FROM attachments WHERE attachment_id = ?",
            ("stg_fixture",),
        ).fetchone()
    assert tuple(row) == ("with-attachment", 1, "b" * 64)


def test_body_edit_preserves_attachment_snapshot_and_explicit_empty_removes_it(
    machine: ApprovalStateMachine,
    database: Database,
) -> None:
    candidate = replace(
        request("edit-attachment"),
        attachments=(
            AttachmentReference(
                "stg_edit",
                "fixture.txt",
                "text/plain",
                7,
                "b" * 64,
                "/private/staging/stg_edit",
            ),
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
        now=NOW + 1,
    )
    with database.read() as connection:
        versions = connection.execute(
            """
            SELECT version, payload_hash
            FROM attachments WHERE attachment_id = ? ORDER BY version
            """,
            ("stg_edit",),
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
        contender_machine = ApprovalStateMachine(database)
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
    machine.create_challenge(
        "challenge-one",
        "webauthn-approval",
        kind=ConfirmationKind.WEBAUTHN,
        expected_version=1,
        expected_payload_hash=payload_hash,
        created_at=NOW,
        expires_at=NOW + 100,
    )

    machine.approve(
        "webauthn-approval",
        expected_version=1,
        expected_payload_hash=payload_hash,
        confirmation=ApprovalConfirmation(
            kind=ConfirmationKind.WEBAUTHN,
            use_id="assertion-one",
            path="web",
            challenge_id="challenge-one",
            credential_id="credential-one",
            credential_user_id="owner",
            expected_counter=7,
            new_counter=8,
            expected_backup_eligible=True,
            new_backup_eligible=True,
            previous_backed_up=False,
            new_backed_up=True,
        ),
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
    machine.create_challenge(
        "challenge-bad",
        "bad-webauthn",
        kind=ConfirmationKind.WEBAUTHN,
        expected_version=1,
        expected_payload_hash=payload_hash,
        created_at=NOW,
        expires_at=NOW + 100,
    )
    values: dict[str, object] = {
        "kind": ConfirmationKind.WEBAUTHN,
        "use_id": "assertion-bad",
        "path": "web",
        "challenge_id": "challenge-bad",
        "credential_id": "credential-bad",
        "credential_user_id": "owner",
        "expected_counter": 7,
        "new_counter": 8,
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
            confirmation=ApprovalConfirmation(**values),  # type: ignore[arg-type]
            actor="human:web",
            now=NOW + 1,
        )

    with database.read() as connection:
        challenge = connection.execute(
            "SELECT consumed_at FROM approval_challenges WHERE challenge_id = 'challenge-bad'"
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
    machine.create_challenge(
        "old-challenge",
        "edit",
        kind=ConfirmationKind.WEBAUTHN,
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
            confirmation=ApprovalConfirmation(ConfirmationKind.TOTP, "old-totp-binding", "mcp"),
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
    machine = ApprovalStateMachine(database)
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
