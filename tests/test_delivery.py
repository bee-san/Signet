from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from collections.abc import Mapping
from dataclasses import replace
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
from signet.canonical import canonical_json, payload_fingerprint
from signet.db import Database
from signet.delivery import (
    DeliveryDispatcher,
    DeliveryPreparationError,
    FrozenRequestLoader,
    PayloadDecryptor,
)
from signet.execution_scope import (
    ExecutionScope,
    ExecutionScopeError,
    StaticExecutionScopeResolver,
)
from signet.models import AttachmentReference, EnqueueRequest, InvalidTransition
from signet.state_machine import ApprovalStateMachine
from tests.attachment_fixtures import register_catalog_attachment

NOW = 1_900_000_000
ACCOUNT_REF = "primary"
CREDENTIAL_DIGEST = "c" * 64
SCHEMA_DIGEST = "d" * 64


class MutableScopeResolver:
    def __init__(self) -> None:
        self.calls = 0
        self.scope = ExecutionScope(
            account_ref=ACCOUNT_REF,
            credential_identity_digest=CREDENTIAL_DIGEST,
            schema_digest=SCHEMA_DIGEST,
        )

    def resolve(
        self,
        downstream_alias: str,
        tool_name: str,
        adapter: Any,
        downstream_client: object | None = None,
    ) -> ExecutionScope:
        del downstream_alias, tool_name, adapter, downstream_client
        self.calls += 1
        return self.scope


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
    def __init__(
        self,
        machine: ApprovalStateMachine,
        outcomes: list[object],
        *,
        credential_identity_digest: str = CREDENTIAL_DIGEST,
    ) -> None:
        self.machine = machine
        self.outcomes = outcomes
        self.credential_ref = "keychain://Signet/fake-provider"
        self.credential_identity_digest = credential_identity_digest
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
        self.credential_identity_digest = CREDENTIAL_DIGEST
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
        self.credential_identity_digest = CREDENTIAL_DIGEST
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

    def __init__(
        self,
        *,
        supports_idempotency: bool = False,
        fail_prepare: bool = False,
        attachments: tuple[AttachmentReference, ...] = (),
        account: str = ACCOUNT_REF,
        adapter_id: str = "fake.send",
    ) -> None:
        self.adapter_id = adapter_id
        self.supports_idempotency = supports_idempotency
        self.account = account
        self.fail_prepare = fail_prepare
        self.attachments = attachments
        self.prepared: list[AdapterRequest] = []

    def validate(self, arguments: Mapping[str, Any]) -> None:
        if not isinstance(arguments.get("value"), str):
            raise ValueError("invalid fake payload")

    def canonicalize(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self.validate(arguments)
        return dict(arguments)

    def freeze_attachments(self, arguments: Mapping[str, Any]) -> tuple[AttachmentReference, ...]:
        self.validate(arguments)
        return self.attachments

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
    attachments: tuple[AttachmentReference, ...] = (),
    legacy_envelope: bool = False,
) -> bytes:
    selected_arguments = arguments or {"value": "private"}
    if legacy_envelope:
        frozen = canonical_json(
            {
                "adapter_version": "1",
                "alias": "fake",
                "arguments": dict(selected_arguments),
                "policy_version": 1,
                "staged_file_hashes": [attachment.sha256 for attachment in attachments],
                "tool": "send",
            }
        )
        payload_hash = hashlib.sha256(frozen).hexdigest()
    else:
        frozen, payload_hash = payload_fingerprint(
            alias="fake",
            tool="send",
            account_ref=ACCOUNT_REF,
            credential_identity_digest=CREDENTIAL_DIGEST,
            schema_digest=SCHEMA_DIGEST,
            caller_namespace="profile:test",
            arguments=selected_arguments,
            staged_file_hashes=tuple(attachment.sha256 for attachment in attachments),
            policy_version=1,
            adapter_id="fake.send",
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
            schema_version=SCHEMA_DIGEST,
            editor_actor="caller:test",
            canonical_size=len(frozen),
            encryption_key_ref="keychain://Signet/fake-payload",
            attachments=attachments,
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


@pytest.mark.asyncio
async def test_missing_catalog_attachment_snapshot_fails_before_network(
    machine: ApprovalStateMachine,
) -> None:
    attachment_id = "stg_" + "a" * 20
    attachment = register_catalog_attachment(
        machine.database,
        attachment_id=attachment_id,
        storage_path=f"/private/staging/{attachment_id}",
        adapter="fake",
    )
    enqueue_approved(
        machine,
        "attachment-tamper",
        arguments={"value": "private", "staged_id": attachment_id},
        attachments=(attachment,),
    )
    with machine.database.transaction() as connection:
        connection.execute(
            "DELETE FROM attachments WHERE request_id = ?",
            ("attachment-tamper",),
        )
    adapter = FakeAdapter(attachments=(attachment,))
    client = FakeClient(machine, [{"status": "sent"}])

    with pytest.raises(DeliveryPreparationError, match="before network"):
        await dispatcher(machine, adapter, client).dispatch(
            "attachment-tamper", worker_id="worker", now=NOW + 2
        )

    assert client.calls == []
    assert machine.get_request("attachment-tamper")["state"] == "failed"


def dispatcher(
    machine: ApprovalStateMachine,
    adapter: FakeAdapter,
    client: MCPClient,
    *,
    decryptor: FakeDecryptor | None = None,
    reconciliation_delay: int = 10,
    scope: ExecutionScope | None = None,
) -> DeliveryDispatcher:
    loader = FrozenRequestLoader(
        machine,
        decryptor or FakeDecryptor(),
        {("fake", "send"): adapter},
        StaticExecutionScopeResolver(
            {
                ("fake", "send"): scope
                or ExecutionScope(
                    account_ref=ACCOUNT_REF,
                    credential_identity_digest=CREDENTIAL_DIGEST,
                    schema_digest=SCHEMA_DIGEST,
                )
            },
            {"fake": client},
        ),
    )
    return DeliveryDispatcher(
        machine,
        loader,
        {"fake": client},
        initial_reconciliation_delay=reconciliation_delay,
    )


def test_static_scope_resolver_validates_configured_client_without_explicit_selection(
    machine: ApprovalStateMachine,
) -> None:
    adapter = FakeAdapter()
    rotated_client = FakeClient(
        machine,
        [],
        credential_identity_digest="e" * 64,
    )
    resolver = StaticExecutionScopeResolver(
        {
            ("fake", "send"): ExecutionScope(
                account_ref=ACCOUNT_REF,
                credential_identity_digest=CREDENTIAL_DIGEST,
                schema_digest=SCHEMA_DIGEST,
            )
        },
        {"fake": rotated_client},
    )

    with pytest.raises(ExecutionScopeError, match="identity"):
        resolver.resolve("fake", "send", adapter)


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", ["account", "credential", "schema"])
async def test_restart_scope_drift_fails_before_network(
    machine: ApprovalStateMachine,
    drift: str,
) -> None:
    enqueue_approved(machine, f"restart-{drift}")
    restarted_database = Database(machine.database.path)
    restarted_database.initialize()
    restarted_machine = ApprovalStateMachine(
        restarted_database,
        notification_user_id="human:test",
    )
    scope = ExecutionScope(
        account_ref=ACCOUNT_REF,
        credential_identity_digest=CREDENTIAL_DIGEST,
        schema_digest=SCHEMA_DIGEST,
    )
    adapter = FakeAdapter(account="secondary" if drift == "account" else ACCOUNT_REF)
    if drift == "account":
        scope = replace(scope, account_ref="secondary")
    elif drift == "credential":
        scope = replace(scope, credential_identity_digest="e" * 64)
    else:
        scope = replace(scope, schema_digest="f" * 64)
    client = FakeClient(restarted_machine, [{"status": "sent"}])

    with pytest.raises(DeliveryPreparationError, match="before network"):
        await dispatcher(restarted_machine, adapter, client, scope=scope).dispatch(
            f"restart-{drift}",
            worker_id="restarted-worker",
            now=NOW + 2,
        )

    assert client.calls == []
    assert restarted_machine.get_request(f"restart-{drift}")["state"] == "failed"


@pytest.mark.asyncio
async def test_legacy_envelope_without_execution_scope_fails_closed(
    machine: ApprovalStateMachine,
) -> None:
    enqueue_approved(machine, "legacy-scope", legacy_envelope=True)
    adapter = FakeAdapter()
    client = FakeClient(machine, [{"status": "sent"}])

    with pytest.raises(DeliveryPreparationError, match="before network"):
        await dispatcher(machine, adapter, client).dispatch(
            "legacy-scope",
            worker_id="worker",
            now=NOW + 2,
        )

    assert client.calls == []
    assert machine.get_request("legacy-scope")["state"] == "failed"


@pytest.mark.asyncio
async def test_scope_is_rechecked_after_dispatch_started_before_provider_io(
    machine: ApprovalStateMachine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enqueue_approved(machine, "last-boundary")
    adapter = FakeAdapter()
    client = FakeClient(machine, [{"status": "sent"}])
    resolver = MutableScopeResolver()
    loader = FrozenRequestLoader(
        machine,
        FakeDecryptor(),
        {("fake", "send"): adapter},
        resolver,
    )
    selected = DeliveryDispatcher(machine, loader, {"fake": client})
    original_mark = machine.mark_dispatch_started

    def mark_then_rotate_scope(*args: Any, **kwargs: Any) -> None:
        original_mark(*args, **kwargs)
        resolver.scope = replace(
            resolver.scope,
            credential_identity_digest="f" * 64,
        )

    monkeypatch.setattr(machine, "mark_dispatch_started", mark_then_rotate_scope)

    with pytest.raises(DeliveryPreparationError, match="before network"):
        await selected.dispatch(
            "last-boundary",
            worker_id="worker",
            now=NOW + 2,
        )

    assert resolver.calls == 3
    assert client.calls == []
    request = machine.get_request("last-boundary")
    assert request["state"] == "failed"
    assert request["failure_reason"] == "execution_scope_changed_before_io"


@pytest.mark.asyncio
async def test_restart_same_credential_ref_new_generation_fails_before_provider_io(
    machine: ApprovalStateMachine,
) -> None:
    enqueue_approved(machine, "credential-generation")
    restarted_database = Database(machine.database.path)
    restarted_database.initialize()
    restarted_machine = ApprovalStateMachine(
        restarted_database,
        notification_user_id="human:test",
    )
    adapter = FakeAdapter()
    client = FakeClient(
        restarted_machine,
        [{"status": "sent"}],
        credential_identity_digest="e" * 64,
    )

    with pytest.raises(DeliveryPreparationError, match="before network"):
        await dispatcher(restarted_machine, adapter, client).dispatch(
            "credential-generation",
            worker_id="restarted-worker",
            now=NOW + 2,
        )

    assert client.credential_ref == "keychain://Signet/fake-provider"
    assert client.calls == []
    assert restarted_machine.get_request("credential-generation")["state"] == "failed"


@pytest.mark.asyncio
async def test_restart_replacement_adapter_with_same_version_fails_before_provider_io(
    machine: ApprovalStateMachine,
) -> None:
    enqueue_approved(machine, "adapter-identity")
    restarted_database = Database(machine.database.path)
    restarted_database.initialize()
    restarted_machine = ApprovalStateMachine(
        restarted_database,
        notification_user_id="human:test",
    )
    adapter = FakeAdapter(adapter_id="fake.replacement")
    client = FakeClient(restarted_machine, [{"status": "sent"}])

    with pytest.raises(DeliveryPreparationError, match="before network"):
        await dispatcher(restarted_machine, adapter, client).dispatch(
            "adapter-identity",
            worker_id="restarted-worker",
            now=NOW + 2,
        )

    assert adapter.adapter_version == "1"
    assert client.calls == []
    assert restarted_machine.get_request("adapter-identity")["state"] == "failed"


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
    task = asyncio.create_task(selected.dispatch("cancelled", worker_id="worker", now=NOW + 2))
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


@pytest.mark.asyncio
async def test_blocking_adapter_preparation_does_not_stall_event_loop(
    machine: ApprovalStateMachine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enqueue_approved(machine, "blocking-preparation")
    adapter = FakeAdapter()
    client = FakeClient(machine, [{"status": "sent"}])
    selected = dispatcher(machine, adapter, client)
    started = threading.Event()
    release = threading.Event()
    original_prepare = adapter.prepare_for_execution

    def blocking_prepare(request: AdapterRequest) -> dict[str, Any]:
        started.set()
        if not release.wait(timeout=5):
            raise AssertionError("blocking adapter preparation was not released")
        return original_prepare(request)

    monkeypatch.setattr(adapter, "prepare_for_execution", blocking_prepare)
    safety_release = threading.Timer(3, release.set)
    safety_release.start()
    waiting_started_at = time.monotonic()
    try:
        dispatching = asyncio.create_task(
            selected.dispatch(
                "blocking-preparation",
                worker_id="worker",
                now=NOW + 2,
            )
        )
        assert await asyncio.to_thread(started.wait, 1)
        assert time.monotonic() - waiting_started_at < 2
        assert not release.is_set()
        await asyncio.wait_for(asyncio.sleep(0), timeout=1)
        release.set()
        result = await dispatching
    finally:
        release.set()
        safety_release.cancel()

    assert result.outcome.value == "succeeded"
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_preparation_thread_finishes_before_cancellation_propagates(
    machine: ApprovalStateMachine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enqueue_approved(machine, "cancel-blocking-preparation")
    adapter = FakeAdapter()
    client = FakeClient(machine, [{"status": "sent"}])
    selected = dispatcher(machine, adapter, client)
    started = threading.Event()
    release = threading.Event()
    original_prepare = adapter.prepare_for_execution

    def blocking_prepare(request: AdapterRequest) -> dict[str, Any]:
        started.set()
        if not release.wait(timeout=5):
            raise AssertionError("cancelled adapter preparation was not released")
        return original_prepare(request)

    monkeypatch.setattr(adapter, "prepare_for_execution", blocking_prepare)
    safety_release = threading.Timer(3, release.set)
    safety_release.start()
    try:
        dispatching = asyncio.create_task(
            selected.dispatch(
                "cancel-blocking-preparation",
                worker_id="worker",
                now=NOW + 2,
            )
        )
        assert await asyncio.to_thread(started.wait, 1)
        dispatching.cancel()
        await asyncio.sleep(0.05)
        assert not dispatching.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await dispatching
    finally:
        release.set()
        safety_release.cancel()

    assert client.calls == []
    assert machine.get_request("cancel-blocking-preparation")["state"] == "failed"
