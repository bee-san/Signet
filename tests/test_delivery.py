from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from signet.adapters.base import (
    AdapterRequest,
    DispatchError,
    ExecutionAttempt,
    MCPClient,
    Outcome,
    ReadOnlyMCPClient,
    Reconciliation,
    conservative_outcome,
)
from signet.canonical import payload_fingerprint
from signet.db import Database
from signet.delivery import (
    DeliveryDispatcher,
    DeliveryPreparationError,
    FrozenRequestLoader,
    PayloadDecryptor,
)
from signet.models import EnqueueRequest, InvalidTransition
from signet.state_machine import ApprovalStateMachine

NOW = 1_900_000_000


class FakeDecryptor(PayloadDecryptor):
    def __init__(self, *, corrupt: bool = False) -> None:
        self.corrupt = corrupt
        self.calls: list[tuple[str, int, str, str | None]] = []

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        key_reference: str | None,
        request_id: str,
        version: int,
        payload_hash: str,
    ) -> bytes:
        self.calls.append((request_id, version, payload_hash, key_reference))
        assert ciphertext.startswith(b"sealed:")
        value = ciphertext.removeprefix(b"sealed:")
        if self.corrupt and value:
            return bytes([value[0] ^ 1]) + value[1:]
        return value


class FakeClient(MCPClient):
    def __init__(self, machine: ApprovalStateMachine, outcomes: list[object]) -> None:
        self.machine = machine
        self.outcomes = outcomes
        self.calls: list[tuple[str, dict[str, Any], str]] = []

    async def call_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        with self.machine.database.read() as connection:
            phase = connection.execute(
                "SELECT phase FROM execution_attempts ORDER BY claimed_at DESC LIMIT 1"
            ).fetchone()[0]
        self.calls.append((tool_name, dict(arguments), phase))
        value = self.outcomes.pop(0)
        if isinstance(value, Exception):
            raise value
        assert isinstance(value, Mapping)
        return value


class BlockingClient(MCPClient):
    def __init__(self, machine: ApprovalStateMachine) -> None:
        self.machine = machine
        self.started = asyncio.Event()
        self.calls = 0

    async def call_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del tool_name, arguments
        with self.machine.database.read() as connection:
            assert (
                connection.execute("SELECT phase FROM execution_attempts").fetchone()[0]
                == "dispatch_started"
            )
        self.calls += 1
        self.started.set()
        await asyncio.Future()
        raise AssertionError("unreachable")


class CrashingClient(MCPClient):
    def __init__(self, machine: ApprovalStateMachine) -> None:
        self.machine = machine
        self.calls = 0

    async def call_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del tool_name, arguments
        with self.machine.database.read() as connection:
            assert (
                connection.execute("SELECT phase FROM execution_attempts").fetchone()[0]
                == "dispatch_started"
            )
        self.calls += 1
        raise SystemExit("simulated hard worker exit")


class FakeAdapter:
    adapter_id = "fake.send"
    adapter_version = "1"
    downstream_alias = "fake"
    tool_name = "send"
    communication_send = True
    reconciliation_tools = frozenset({"lookup"})
    input_schema: Mapping[str, Any] = {"type": "object"}

    def __init__(self, *, supports_idempotency: bool = False, fail_prepare: bool = False) -> None:
        self.supports_idempotency = supports_idempotency
        self.fail_prepare = fail_prepare
        self.prepared: list[AdapterRequest] = []

    def validate(self, arguments: Mapping[str, Any]) -> None:
        if not isinstance(arguments.get("value"), str):
            raise ValueError("invalid fake payload")

    def canonicalize(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self.validate(arguments)
        return dict(arguments)

    def summarize_for_web(self, arguments: Mapping[str, Any]) -> Any:
        raise NotImplementedError

    def redact_for_audit(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        return {"value": "<redacted>"}

    def prepare_for_execution(self, request: AdapterRequest) -> dict[str, Any]:
        self.prepared.append(request)
        if self.fail_prepare:
            raise ValueError("fake preparation failure")
        return {
            **dict(request.arguments),
            "idempotency_key": request.idempotency_key,
        }

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
        del downstream, request, attempt
        return Reconciliation.INCONCLUSIVE

    def safe_result_metadata(self, downstream_result: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "message_id": downstream_result.get("id"),
            "provider_status": downstream_result.get("status"),
            "unreviewed_secret": downstream_result.get("secret"),
        }


@pytest.fixture
def machine(tmp_path: Path) -> ApprovalStateMachine:
    database = Database(tmp_path / "delivery.sqlite3")
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


def enqueue_approved(
    machine: ApprovalStateMachine,
    request_id: str,
    *,
    arguments: Mapping[str, Any] | None = None,
) -> bytes:
    frozen, payload_hash = payload_fingerprint(
        alias="fake",
        tool="send",
        arguments=arguments or {"value": "private"},
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
    return frozen


def dispatcher(
    machine: ApprovalStateMachine,
    adapter: FakeAdapter,
    client: MCPClient,
    *,
    decryptor: FakeDecryptor | None = None,
    reconciliation_delay: int = 10,
) -> DeliveryDispatcher:
    loader = FrozenRequestLoader(
        machine,
        decryptor or FakeDecryptor(),
        {("fake", "send"): adapter},
        {"fake": "primary"},
    )
    return DeliveryDispatcher(
        machine,
        loader,
        {"fake": client},
        initial_reconciliation_delay=reconciliation_delay,
    )


@pytest.mark.asyncio
async def test_success_commits_boundary_before_one_call_and_stores_only_safe_aliases(
    machine: ApprovalStateMachine,
) -> None:
    enqueue_approved(machine, "success")
    adapter = FakeAdapter(supports_idempotency=True)
    client = FakeClient(
        machine,
        [{"status": "sent", "id": "real-message", "secret": "never-store"}],
    )

    result = await dispatcher(machine, adapter, client).dispatch(
        "success", worker_id="worker", now=NOW + 2
    )

    assert result.outcome.value == "succeeded"
    assert len(client.calls) == 1
    assert client.calls[0][2] == "dispatch_started"
    assert client.calls[0][1]["idempotency_key"].startswith("sgd_")
    assert result.safe_metadata == {
        "message_id": "sgref_54f5be45b98a2fff53aa64e9a9dced0a",
        "provider_status": "sent",
    }
    request = machine.get_request("success")
    assert request["state"] == "succeeded"
    assert "never-store" not in request["safe_outcome_json"]
    with machine.database.read() as connection:
        aliases = connection.execute(
            "SELECT account_namespace, identifier_kind, downstream_identifier FROM result_aliases"
        ).fetchall()
    assert [tuple(row) for row in aliases] == [("primary", "message_id", "real-message")]
    assert "real-message" not in request["safe_outcome_json"]


@pytest.mark.asyncio
async def test_provider_identifier_cannot_echo_private_content_to_status_metadata(
    machine: ApprovalStateMachine,
) -> None:
    enqueue_approved(machine, "covert-id")
    adapter = FakeAdapter(supports_idempotency=True)
    echoed = "cHJpdmF0ZSByZXF1ZXN0IGNvbnRlbnQ="
    client = FakeClient(machine, [{"status": "sent", "id": echoed}])

    result = await dispatcher(machine, adapter, client).dispatch(
        "covert-id", worker_id="worker", now=NOW + 2
    )

    assert result.safe_metadata["message_id"].startswith("sgref_")
    assert echoed not in json.dumps(dict(result.safe_metadata))
    assert echoed not in machine.get_request("covert-id")["safe_outcome_json"]
    with machine.database.read() as connection:
        internal = connection.execute(
            "SELECT downstream_identifier FROM result_aliases WHERE request_id = 'covert-id'"
        ).fetchone()
    assert internal is not None and internal[0] == echoed


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["decrypt", "prepare"])
async def test_pre_dispatch_failure_is_terminal_and_makes_no_network_call(
    machine: ApprovalStateMachine,
    failure: str,
) -> None:
    enqueue_approved(machine, f"pre-{failure}")
    adapter = FakeAdapter(fail_prepare=failure == "prepare")
    client = FakeClient(machine, [{"status": "sent"}])
    selected = dispatcher(
        machine,
        adapter,
        client,
        decryptor=FakeDecryptor(corrupt=failure == "decrypt"),
    )

    with pytest.raises(DeliveryPreparationError, match="before network"):
        await selected.dispatch(f"pre-{failure}", worker_id="worker", now=NOW + 2)

    assert client.calls == []
    assert machine.get_request(f"pre-{failure}")["state"] == "failed"
    with machine.database.read() as connection:
        attempt = connection.execute(
            "SELECT phase, failure_reason FROM execution_attempts"
        ).fetchone()
    assert tuple(attempt) == ("failed", "delivery_preparation_failed")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected_state"),
    [
        (DispatchError("rejected", dispatch_may_have_occurred=False), "failed"),
        (TimeoutError("ambiguous"), "outcome_unknown"),
    ],
)
async def test_post_boundary_errors_are_classified_without_retry(
    machine: ApprovalStateMachine,
    error: Exception,
    expected_state: str,
) -> None:
    enqueue_approved(machine, f"error-{expected_state}")
    adapter = FakeAdapter()
    client = FakeClient(machine, [error])

    result = await dispatcher(machine, adapter, client).dispatch(
        f"error-{expected_state}", worker_id="worker", now=NOW + 2
    )

    assert len(client.calls) == 1
    assert machine.get_request(f"error-{expected_state}")["state"] == expected_state
    assert result.outcome.value == (
        "definite_failure" if expected_state == "failed" else "outcome_unknown"
    )
    expected_notifications = ["new_pending"]
    if expected_state == "outcome_unknown":
        expected_notifications.append("outcome_unknown_entered")
    assert notification_kinds(machine, f"error-{expected_state}") == expected_notifications


@pytest.mark.asyncio
async def test_cancellation_after_boundary_records_unknown_and_propagates(
    machine: ApprovalStateMachine,
) -> None:
    enqueue_approved(machine, "cancelled")
    adapter = FakeAdapter()
    client = BlockingClient(machine)
    selected = dispatcher(machine, adapter, client)
    task = asyncio.create_task(
        selected.dispatch("cancelled", worker_id="worker", now=NOW + 2)
    )
    await client.started.wait()

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert client.calls == 1
    request = machine.get_request("cancelled")
    assert request["state"] == "outcome_unknown"
    assert request["failure_reason"] == "dispatch_cancelled"
    assert notification_kinds(machine, "cancelled") == [
        "new_pending",
        "outcome_unknown_entered",
    ]


@pytest.mark.asyncio
async def test_hard_exit_after_boundary_is_reconciled_without_another_send(
    machine: ApprovalStateMachine,
) -> None:
    enqueue_approved(machine, "hard-exit")
    adapter = FakeAdapter()
    client = CrashingClient(machine)
    selected = dispatcher(machine, adapter, client)

    with pytest.raises(SystemExit, match="hard worker exit"):
        await selected.dispatch(
            "hard-exit",
            worker_id="worker",
            now=NOW + 2,
            lease_seconds=1,
        )

    assert client.calls == 1
    assert machine.get_request("hard-exit")["state"] == "executing"
    recovered = machine.recover_startup(now=NOW + 4)
    assert recovered.routed_to_reconciliation == ("hard-exit",)
    assert client.calls == 1
    assert machine.get_request("hard-exit")["state"] == "outcome_unknown"
    assert notification_kinds(machine, "hard-exit") == [
        "new_pending",
        "outcome_unknown_entered",
    ]


@pytest.mark.asyncio
async def test_second_initial_dispatch_loses_before_network(
    machine: ApprovalStateMachine,
) -> None:
    enqueue_approved(machine, "double")
    adapter = FakeAdapter()
    client = BlockingClient(machine)
    selected = dispatcher(machine, adapter, client)
    first = asyncio.create_task(selected.dispatch("double", worker_id="one", now=NOW + 2))
    await client.started.wait()

    with pytest.raises(InvalidTransition):
        await selected.dispatch("double", worker_id="two", now=NOW + 2)
    assert client.calls == 1
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
