from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from signet.adapters.base import (
    AdapterRequest,
    ExecutionAttempt,
    MCPClient,
    Outcome,
    ReadOnlyMCPClient,
    Reconciliation,
    conservative_outcome,
)
from signet.canonical import payload_fingerprint
from signet.db import Database
from signet.delivery import DeliveryDispatcher, FrozenRequestLoader, PayloadDecryptor
from signet.models import EnqueueRequest
from signet.reconcile import ReconciliationCoordinator
from signet.state_machine import ApprovalStateMachine

NOW = 1_910_000_000


class FakeDecryptor(PayloadDecryptor):
    def __init__(self) -> None:
        self.failing_request_ids: set[str] = set()

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        key_reference: str | None,
        request_id: str,
        version: int,
        payload_hash: str,
    ) -> bytes:
        del key_reference, version, payload_hash
        if request_id in self.failing_request_ids:
            raise ValueError("explicit fake corrupt payload")
        return ciphertext.removeprefix(b"sealed:")


class FakeProvider(MCPClient):
    def __init__(self, send_outcomes: list[object]) -> None:
        self.send_outcomes = send_outcomes
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.calls.append((tool_name, dict(arguments)))
        if tool_name == "lookup":
            return {"found": True}
        if tool_name != "send":
            raise AssertionError(f"unexpected fake provider call: {tool_name}")
        value = self.send_outcomes.pop(0)
        if isinstance(value, Exception):
            raise value
        assert isinstance(value, Mapping)
        return value


class FakeAdapter:
    adapter_id = "fake.send"
    adapter_version = "1"
    downstream_alias = "fake"
    tool_name = "send"
    communication_send = True
    reconciliation_tools = frozenset({"lookup"})
    input_schema: Mapping[str, Any] = {"type": "object"}

    def __init__(
        self,
        decisions: list[Reconciliation],
        *,
        supports_idempotency: bool,
        lookup_tool: str = "lookup",
    ) -> None:
        self.decisions = decisions
        self.supports_idempotency = supports_idempotency
        self.lookup_tool = lookup_tool
        self.idempotency_keys: list[str | None] = []

    def validate(self, arguments: Mapping[str, Any]) -> None:
        if not isinstance(arguments.get("value"), str):
            raise ValueError("invalid fake arguments")

    def canonicalize(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self.validate(arguments)
        return dict(arguments)

    def summarize_for_web(self, arguments: Mapping[str, Any]) -> Any:
        raise NotImplementedError

    def redact_for_audit(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        return {"value": "<redacted>"}

    def prepare_for_execution(self, request: AdapterRequest) -> dict[str, Any]:
        self.idempotency_keys.append(request.idempotency_key)
        return {**dict(request.arguments), "idempotency_key": request.idempotency_key}

    async def execute(
        self,
        downstream: MCPClient,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        return dict(await downstream.call_tool(self.tool_name, payload))

    def classify_outcome(self, result_or_error: object) -> Outcome:
        return conservative_outcome(result_or_error)

    async def reconcile(
        self,
        downstream: ReadOnlyMCPClient,
        request: AdapterRequest,
        attempt: ExecutionAttempt,
    ) -> Reconciliation:
        del request, attempt
        await downstream.call_tool(self.lookup_tool, {"safe": True})
        return self.decisions.pop(0)

    def safe_result_metadata(self, downstream_result: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "message_id": downstream_result.get("id"),
            "provider_status": downstream_result.get("status"),
        }


@pytest.fixture
def machine(tmp_path: Path) -> ApprovalStateMachine:
    database = Database(tmp_path / "reconcile.sqlite3")
    database.initialize()
    return ApprovalStateMachine(database, notification_user_id="human:test")


def notification_kinds(machine: ApprovalStateMachine, request_id: str) -> list[str]:
    with machine.database.read() as connection:
        rows = connection.execute(
            """
            SELECT kind FROM notification_outbox
            WHERE request_id = ? ORDER BY created_at, kind
            """,
            (request_id,),
        ).fetchall()
    return [str(row["kind"]) for row in rows]


def enqueue_approved(machine: ApprovalStateMachine, request_id: str) -> None:
    frozen, payload_hash = payload_fingerprint(
        alias="fake",
        tool="send",
        arguments={"value": "private"},
        policy_version=1,
        adapter_version="1",
    )
    machine.enqueue(
        EnqueueRequest(
            request_id=request_id,
            downstream_alias="fake",
            tool_name="send",
            policy_mode="approval",
            origin_namespace="profile:test",
            encrypted_payload=b"sealed:" + frozen,
            payload_hash=payload_hash,
            payload_fingerprint=payload_hash,
            pending_result=b'{"status":"pending_approval"}',
            created_at=NOW,
            expires_at=NOW + 600,
            policy_version="1",
            adapter_version="1",
            schema_version="1",
            editor_actor="caller:test",
            canonical_size=len(frozen),
            encryption_key_ref="keychain://Signet/fake-payload",
        )
    )
    with machine.database.transaction() as connection:
        connection.execute(
            """
            UPDATE approval_requests SET state = 'approved', approved_at = ?
            WHERE request_id = ? AND current_version = ? AND current_payload_hash = ?
            """,
            (NOW + 1, request_id, 1, payload_hash),
        )


def services(
    machine: ApprovalStateMachine,
    adapter: FakeAdapter,
    provider: FakeProvider,
    *,
    schedule: tuple[int, ...] = (1, 2),
    reviewed_tools: Mapping[tuple[str, str], frozenset[str]] | None = None,
    decryptor: FakeDecryptor | None = None,
) -> tuple[DeliveryDispatcher, ReconciliationCoordinator]:
    loader = FrozenRequestLoader(
        machine,
        decryptor or FakeDecryptor(),
        {("fake", "send"): adapter},
        {"fake": "primary"},
    )
    dispatcher = DeliveryDispatcher(
        machine,
        loader,
        {"fake": provider},
        initial_reconciliation_delay=schedule[0],
    )
    coordinator = ReconciliationCoordinator(
        machine,
        loader,
        dispatcher,
        {"fake": provider},
        schedule=schedule,
        reviewed_tools=(
            {("fake", "send"): frozenset({"lookup"})}
            if reviewed_tools is None
            else reviewed_tools
        ),
    )
    return dispatcher, coordinator


@pytest.mark.asyncio
async def test_confirmed_effect_uses_read_only_lookup_and_records_safe_alias(
    machine: ApprovalStateMachine,
) -> None:
    enqueue_approved(machine, "effect")
    adapter = FakeAdapter(
        [Reconciliation.CONFIRMED_EFFECT],
        supports_idempotency=False,
    )
    provider = FakeProvider([{"status": "ambiguous", "id": "real-message"}])
    dispatcher, coordinator = services(machine, adapter, provider)
    await dispatcher.dispatch("effect", worker_id="sender", now=NOW + 2)

    run = await coordinator.reconcile_once("effect", worker_id="reader", now=NOW + 3)

    assert run.result.action.value == "succeeded"
    assert run.redispatch is None
    assert [call[0] for call in provider.calls] == ["send", "lookup"]
    request = machine.get_request("effect")
    assert request["state"] == "succeeded"
    assert request["safe_outcome_json"] is not None
    assert notification_kinds(machine, "effect") == [
        "new_pending",
        "outcome_unknown_entered",
        "outcome_unknown_resolved",
    ]
    with machine.database.read() as connection:
        alias = connection.execute(
            "SELECT identifier_kind, downstream_identifier FROM result_aliases"
        ).fetchone()
    assert tuple(alias) == ("message_id", "real-message")


@pytest.mark.asyncio
async def test_confirmed_no_effect_without_key_is_terminal_and_never_redispatches(
    machine: ApprovalStateMachine,
) -> None:
    enqueue_approved(machine, "no-key")
    adapter = FakeAdapter(
        [Reconciliation.CONFIRMED_NO_EFFECT],
        supports_idempotency=False,
    )
    provider = FakeProvider([TimeoutError("ambiguous")])
    dispatcher, coordinator = services(machine, adapter, provider)
    await dispatcher.dispatch("no-key", worker_id="sender", now=NOW + 2)

    run = await coordinator.reconcile_once("no-key", worker_id="reader", now=NOW + 3)

    assert run.result.action.value == "failed_no_effect"
    assert run.redispatch is None
    assert [call[0] for call in provider.calls] == ["send", "lookup"]
    assert machine.get_request("no-key")["failure_reason"] == "reconciled_no_effect"
    assert notification_kinds(machine, "no-key") == [
        "new_pending",
        "outcome_unknown_entered",
        "outcome_unknown_resolved",
    ]


@pytest.mark.asyncio
async def test_confirmed_no_effect_allows_exactly_one_same_key_redispatch(
    machine: ApprovalStateMachine,
) -> None:
    enqueue_approved(machine, "keyed")
    adapter = FakeAdapter(
        [Reconciliation.CONFIRMED_NO_EFFECT, Reconciliation.CONFIRMED_NO_EFFECT],
        supports_idempotency=True,
    )
    provider = FakeProvider([TimeoutError("first"), TimeoutError("second")])
    dispatcher, coordinator = services(machine, adapter, provider)
    await dispatcher.dispatch("keyed", worker_id="sender", now=NOW + 2)

    first = await coordinator.reconcile_once("keyed", worker_id="reader", now=NOW + 3)
    assert first.result.action.value == "redispatch"
    assert first.redispatch is not None
    assert first.redispatch.outcome.value == "outcome_unknown"
    assert adapter.idempotency_keys[0] == adapter.idempotency_keys[1]
    assert adapter.idempotency_keys[0] is not None

    second = await coordinator.reconcile_once("keyed", worker_id="reader", now=NOW + 4)
    assert second.result.action.value == "failed_no_effect"
    assert second.redispatch is None
    assert [call[0] for call in provider.calls] == ["send", "lookup", "send", "lookup"]
    assert machine.get_request("keyed")["failure_reason"] == (
        "reconciled_no_effect_after_redispatch"
    )


@pytest.mark.asyncio
async def test_inconclusive_schedule_exhausts_and_blocks_unreviewed_mutation(
    machine: ApprovalStateMachine,
) -> None:
    enqueue_approved(machine, "exhaust")
    adapter = FakeAdapter(
        [Reconciliation.CONFIRMED_EFFECT],
        supports_idempotency=False,
        lookup_tool="send_mutation",
    )
    provider = FakeProvider([TimeoutError("ambiguous")])
    dispatcher, coordinator = services(machine, adapter, provider)
    await dispatcher.dispatch("exhaust", worker_id="sender", now=NOW + 2)

    first = await coordinator.reconcile_once("exhaust", worker_id="reader", now=NOW + 3)
    assert first.decision.value == "inconclusive"
    assert first.result.action.value == "rescheduled"
    assert coordinator.due_request_ids(now=NOW + 4) == ()

    second = await coordinator.reconcile_once("exhaust", worker_id="reader", now=NOW + 5)
    assert second.result.action.value == "exhausted"
    assert [call[0] for call in provider.calls] == ["send"]
    assert coordinator.due_request_ids(now=NOW + 100) == ()
    with machine.database.read() as connection:
        attempt = connection.execute(
            """
            SELECT reconciliation_attempt_count, reconciliation_exhausted_at,
                   reconciliation_notification_required
            FROM execution_attempts
            """
        ).fetchone()
    assert tuple(attempt) == (2, NOW + 5, 1)
    assert notification_kinds(machine, "exhaust") == [
        "new_pending",
        "outcome_unknown_entered",
        "outcome_unknown_exhausted",
    ]


@pytest.mark.asyncio
async def test_missing_policy_review_blocks_declared_reconciliation_tool(
    machine: ApprovalStateMachine,
) -> None:
    enqueue_approved(machine, "unreviewed")
    adapter = FakeAdapter(
        [Reconciliation.CONFIRMED_EFFECT],
        supports_idempotency=False,
    )
    provider = FakeProvider([TimeoutError("ambiguous")])
    dispatcher, coordinator = services(
        machine,
        adapter,
        provider,
        reviewed_tools={},
    )
    await dispatcher.dispatch("unreviewed", worker_id="sender", now=NOW + 2)

    result = await coordinator.reconcile_once(
        "unreviewed", worker_id="reader", now=NOW + 3
    )

    assert result.decision.value == "inconclusive"
    assert result.result.action.value == "rescheduled"
    assert [call[0] for call in provider.calls] == ["send"]


@pytest.mark.asyncio
async def test_due_query_and_runner_are_batch_bounded(machine: ApprovalStateMachine) -> None:
    adapter = FakeAdapter(
        [Reconciliation.INCONCLUSIVE, Reconciliation.INCONCLUSIVE],
        supports_idempotency=False,
    )
    provider = FakeProvider([TimeoutError("one"), TimeoutError("two")])
    dispatcher, coordinator = services(machine, adapter, provider)
    for request_id in ("one", "two"):
        enqueue_approved(machine, request_id)
        await dispatcher.dispatch(request_id, worker_id="sender", now=NOW + 2)

    assert len(coordinator.due_request_ids(now=NOW + 3, limit=1)) == 1
    runs = await coordinator.run_due(worker_id="reader", now=NOW + 3, limit=1)
    assert len(runs) == 1
    with pytest.raises(ValueError, match="batch"):
        coordinator.due_request_ids(now=NOW + 3, limit=101)


@pytest.mark.asyncio
async def test_corrupt_due_payload_is_bounded_and_does_not_block_later_rows(
    machine: ApprovalStateMachine,
) -> None:
    adapter = FakeAdapter(
        [Reconciliation.CONFIRMED_EFFECT],
        supports_idempotency=False,
    )
    provider = FakeProvider([TimeoutError("bad"), TimeoutError("good")])
    decryptor = FakeDecryptor()
    dispatcher, coordinator = services(
        machine,
        adapter,
        provider,
        decryptor=decryptor,
    )
    for request_id in ("bad", "good"):
        enqueue_approved(machine, request_id)
        await dispatcher.dispatch(request_id, worker_id="sender", now=NOW + 2)
    decryptor.failing_request_ids.add("bad")

    runs = await coordinator.run_due(worker_id="reader", now=NOW + 3)

    assert [(run.request_id, run.result.action.value) for run in runs] == [
        ("bad", "rescheduled"),
        ("good", "succeeded"),
    ]
    assert machine.get_request("bad")["state"] == "outcome_unknown"
    assert machine.get_request("good")["state"] == "succeeded"
    assert coordinator.due_request_ids(now=NOW + 3) == ()
