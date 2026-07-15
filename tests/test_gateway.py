from __future__ import annotations

import asyncio
import copy
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import mcp.types as types
import pytest
from mcp.shared.exceptions import McpError
from mcp.shared.memory import create_connected_server_and_client_session

from signet.adapters.base import ApprovalAdapter
from signet.credential_broker import Secret
from signet.crypto import PayloadCipher
from signet.db import Database
from signet.freezer import RequestFreezer
from signet.gateway import (
    GatewayCallPipeline,
    GatewayError,
    LocalInvocation,
    _stored_pending_call_result,
)
from signet.mcp_mirror import (
    SIGNET_INVOCATION_ID_META,
    AliasToolSurface,
    SchemaMirror,
    derive_invocation_identity,
    raw_model,
)
from signet.models import EnqueueRequest, EnqueueResult
from signet.policy import parse_policy
from signet.state_machine import ApprovalStateMachine

MASTER_KEY = "gateway-test-master-key-material-000000000001"
KEY_REFERENCE = "keychain://Signet/gateway-test-payload"


def _tool(
    name: str,
    *,
    required: str | None = None,
    output_required: str = "id",
    description: str | None = None,
) -> dict[str, Any]:
    properties = {required: {"type": "string"}} if required is not None else {}
    return {
        "name": name,
        "description": description or f"Reviewed {name}",
        "inputSchema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": False,
            "required": [required] if required is not None else [],
            "properties": properties,
        },
        "outputSchema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": True,
            "required": [output_required],
            "properties": {output_required: {"type": "string"}},
        },
    }


class FakeDownstream:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.entered = asyncio.Event()
        self.gate: asyncio.Event | None = None
        self.cancelled = False
        self.result: dict[str, Any] = {
            "content": [{"type": "text", "text": '{"id":"remote-id"}'}],
            "structuredContent": {"id": "remote-id", "nullable": None},
            "isError": False,
            "x-provider-extension": None,
        }

    async def call_tool_raw(self, tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self.calls.append((tool_name, copy.deepcopy(dict(arguments))))
        self.entered.set()
        if self.gate is not None:
            try:
                await self.gate.wait()
            except asyncio.CancelledError:
                self.cancelled = True
                raise
        return copy.deepcopy(self.result)


class FakeApprovalAdapter:
    adapter_id = "fake.send.v1"
    adapter_version = "1.0.0"
    downstream_alias = "example"
    tool_name = "send"
    communication_send = True
    supports_idempotency = False
    reconciliation_tools: frozenset[str] = frozenset()
    input_schema: Mapping[str, Any] = {
        "type": "object",
        "required": ["message"],
        "properties": {"message": {"type": "string"}},
    }

    def __init__(self) -> None:
        self.validated: list[dict[str, Any]] = []
        self.canonicalized: list[dict[str, Any]] = []
        self.canonicalized_event = asyncio.Event()

    def validate(self, arguments: Mapping[str, Any]) -> None:
        detached = copy.deepcopy(dict(arguments))
        self.validated.append(detached)
        if detached.get("message") == "adapter-reject":
            raise ValueError("fixture adapter rejection")

    def canonicalize(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        detached = {"message": str(arguments["message"])}
        self.canonicalized.append(detached)
        self.canonicalized_event.set()
        return detached


class LostOnceEnqueuer:
    def __init__(self, machine: ApprovalStateMachine) -> None:
        self.machine = machine
        self.lost = False

    def enqueue(self, request: EnqueueRequest) -> EnqueueResult:
        result = self.machine.enqueue(request)
        if not self.lost:
            self.lost = True
            raise RuntimeError("simulated response loss after commit")
        return result


class GatewayHarness:
    def __init__(
        self,
        tmp_path: Path,
        *,
        local_result: object | None = None,
        lost_once: bool = False,
    ) -> None:
        policy = parse_policy(
            {
                "version": 7,
                "default_mode": "deny",
                "downstreams": {
                    "example": {
                        "transport": "http",
                        "url": "https://provider.test/mcp",
                        "tools": {
                            "read": {
                                "mode": "passthrough",
                                "reviewed_read_only": True,
                            },
                            "local": {
                                "mode": "virtualize_local",
                                "adapter": "fake.local.v1",
                                "account_ref": "example-account",
                            },
                            "send": {
                                "mode": "approval",
                                "adapter": "fake.send.v1",
                                "communication_send": True,
                            },
                            "blocked": {"mode": "deny"},
                        },
                    }
                },
            }
        )
        self.raw_tools = [
            _tool("read", required="query"),
            _tool("local", required="value"),
            _tool("send", required="message"),
            _tool("blocked"),
        ]
        self.mirror = SchemaMirror(policy)
        self.mirror.capture("example", self.raw_tools)
        for tool in self.raw_tools:
            name = tool["name"]
            self.mirror.approve_schema(
                "example",
                name,
                self.mirror.captured_digest("example", name),
            )

        self.database = Database(tmp_path / "gateway.sqlite3")
        self.database.initialize()
        self.machine = ApprovalStateMachine(self.database)
        self.downstream = FakeDownstream()
        self.adapter = FakeApprovalAdapter()
        self.local_calls: list[tuple[dict[str, Any], LocalInvocation]] = []
        self.local_result = (
            {"id": "local-id", "nullable": None} if local_result is None else local_result
        )

        def local_handler(
            arguments: Mapping[str, Any], invocation: LocalInvocation
        ) -> Mapping[str, Any]:
            self.local_calls.append((copy.deepcopy(dict(arguments)), invocation))
            return cast(Mapping[str, Any], self.local_result)

        freezer = RequestFreezer(
            PayloadCipher(Secret(MASTER_KEY), KEY_REFERENCE),
            pending_ttl_seconds=600,
        )
        enqueuer: Any = LostOnceEnqueuer(self.machine) if lost_once else self.machine
        self.pipeline = GatewayCallPipeline(
            mirror=self.mirror,
            downstream_clients={"example": self.downstream},
            local_handlers={"fake.local.v1": local_handler},
            adapters={"fake.send.v1": cast(ApprovalAdapter, self.adapter)},
            freezer=freezer,
            enqueuer=enqueuer,
        )
        self.denied: list[tuple[str, str, str]] = []
        self.surface = AliasToolSurface(
            alias="example",
            mirror=self.mirror,
            call_handler=self.pipeline.handle_call,
            denied_event_handler=lambda namespace, alias, tool: self.denied.append(
                (namespace, alias, tool)
            ),
            namespace_provider=lambda: ("profile:test", {"example"}),
        )

    def request_count(self) -> int:
        with self.database.read() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0])


@pytest.mark.asyncio
async def test_end_to_end_routes_all_modes_and_never_mutates_before_approval(
    tmp_path: Path,
) -> None:
    harness = GatewayHarness(tmp_path)
    async with create_connected_server_and_client_session(harness.surface.server) as client:
        listed = await client.list_tools()
        assert [tool.name for tool in listed.tools] == ["read", "local", "send", "blocked"]

        read = await client.call_tool("read", {"query": "safe"})
        assert raw_model(read) == {
            "content": [{"type": "text", "text": '{"id":"remote-id"}'}],
            "structuredContent": {"id": "remote-id", "nullable": None},
            "isError": False,
            "x-provider-extension": None,
        }

        local = await client.call_tool("local", {"value": "draft"})
        assert local.structuredContent == {"id": "local-id", "nullable": None}
        assert harness.local_calls[0][0] == {"value": "draft"}
        assert harness.local_calls[0][1].namespace == "profile:test"

        approval = await client.call_tool(
            "send",
            {"message": "not yet sent"},
            meta={SIGNET_INVOCATION_ID_META: "send-invocation-001"},
        )
        assert approval.isError is False
        assert approval.structuredContent["status"] == "pending_approval"
        assert harness.request_count() == 1
        assert harness.downstream.calls == [("read", {"query": "safe"})]

        denied = await client.call_tool("blocked", {})
        assert denied.isError is True
        assert denied.structuredContent["error"]["code"] == "policy_denied"
        assert harness.denied == [("profile:test", "example", "blocked")]

        with pytest.raises(McpError) as unknown:
            await client.call_tool("unknown", {})
        assert unknown.value.error.code == types.INVALID_PARAMS


@pytest.mark.asyncio
async def test_invalid_input_fails_before_downstream_or_local_action(tmp_path: Path) -> None:
    harness = GatewayHarness(tmp_path)
    async with create_connected_server_and_client_session(harness.surface.server) as client:
        invalid_read = await client.call_tool("read", {"wrong": "value"})
        invalid_local = await client.call_tool("local", {"wrong": "value"})
        invalid_approval_schema = await client.call_tool("send", {"wrong": "value"})
        invalid_approval = await client.call_tool("send", {"message": "adapter-reject"})
        invalid_denied = await client.call_tool("blocked", {"unexpected": True})

    assert invalid_read.isError is True
    assert invalid_read.structuredContent["error"]["code"] == "invalid_arguments"
    assert invalid_local.isError is True
    assert invalid_local.structuredContent["error"]["code"] == "invalid_arguments"
    assert invalid_approval_schema.isError is True
    assert invalid_approval_schema.structuredContent["error"]["code"] == "invalid_arguments"
    assert invalid_approval.isError is True
    assert invalid_approval.structuredContent["error"]["code"] == "invalid_arguments"
    assert invalid_denied.isError is True
    assert invalid_denied.structuredContent["error"]["code"] == "invalid_arguments"
    assert harness.downstream.calls == []
    assert harness.local_calls == []
    assert harness.denied == []
    assert harness.adapter.validated == [{"message": "adapter-reject"}]
    assert harness.request_count() == 0


@pytest.mark.asyncio
async def test_passthrough_success_must_match_reviewed_output_schema(tmp_path: Path) -> None:
    harness = GatewayHarness(tmp_path)
    harness.downstream.result["structuredContent"] = {"wrong": "shape"}
    async with create_connected_server_and_client_session(harness.surface.server) as client:
        result = await client.call_tool("read", {"query": "safe"})

    assert result.isError is True
    assert result.structuredContent["error"]["code"] == "downstream_failed"
    assert harness.downstream.calls == [("read", {"query": "safe"})]


@pytest.mark.asyncio
async def test_passthrough_provider_error_is_not_forced_through_success_schema(
    tmp_path: Path,
) -> None:
    harness = GatewayHarness(tmp_path)
    harness.downstream.result = {
        "content": [{"type": "text", "text": "provider rejected the read"}],
        "structuredContent": {"provider_error": "fixture"},
        "isError": True,
    }
    async with create_connected_server_and_client_session(harness.surface.server) as client:
        result = await client.call_tool("read", {"query": "safe"})

    assert result.isError is True
    assert result.structuredContent == {"provider_error": "fixture"}


@pytest.mark.parametrize("local_result", [{"wrong": "shape"}, ["not-an-object"]])
@pytest.mark.asyncio
async def test_virtual_result_must_be_an_object_matching_original_output_schema(
    tmp_path: Path, local_result: object
) -> None:
    harness = GatewayHarness(tmp_path, local_result=local_result)
    async with create_connected_server_and_client_session(harness.surface.server) as client:
        result = await client.call_tool("local", {"value": "draft"})
    assert result.isError is True
    assert result.structuredContent["error"]["code"] == "invalid_local_result"
    assert harness.downstream.calls == []


@pytest.mark.asyncio
async def test_approval_requires_the_exact_policy_selected_adapter(tmp_path: Path) -> None:
    harness = GatewayHarness(tmp_path)
    harness.pipeline._adapters.clear()
    async with create_connected_server_and_client_session(harness.surface.server) as client:
        result = await client.call_tool("send", {"message": "safe"})
    assert result.isError is True
    assert result.structuredContent["error"]["code"] == "adapter_unavailable"
    assert harness.request_count() == 0
    assert harness.downstream.calls == []


@pytest.mark.asyncio
async def test_explicit_invocation_replays_same_payload_and_conflicts_on_change(
    tmp_path: Path,
) -> None:
    harness = GatewayHarness(tmp_path)
    meta = {SIGNET_INVOCATION_ID_META: "stable-send-001"}
    async with create_connected_server_and_client_session(harness.surface.server) as client:
        first = await client.call_tool("send", {"message": "same"}, meta=meta)
        replay = await client.call_tool("send", {"message": "same"}, meta=meta)
        conflict = await client.call_tool("send", {"message": "different"}, meta=meta)

    assert raw_model(first) == raw_model(replay)
    assert first.structuredContent["request_id"] == replay.structuredContent["request_id"]
    assert conflict.isError is True
    assert conflict.structuredContent["error"]["code"] == "invocation_conflict"
    assert harness.request_count() == 1
    assert harness.downstream.calls == []
    with harness.database.read() as connection:
        stored_key = str(
            connection.execute("SELECT invocation_key FROM idempotency_records").fetchone()[0]
        )
    assert len(stored_key) == 64
    assert "stable-send-001" not in stored_key


@pytest.mark.asyncio
async def test_lost_response_after_commit_replays_authoritative_stored_pending_result(
    tmp_path: Path,
) -> None:
    harness = GatewayHarness(tmp_path, lost_once=True)
    meta = {SIGNET_INVOCATION_ID_META: "lost-response-001"}
    async with create_connected_server_and_client_session(harness.surface.server) as client:
        with pytest.raises(McpError):
            await client.call_tool("send", {"message": "same"}, meta=meta)
        replay = await client.call_tool("send", {"message": "same"}, meta=meta)

    assert replay.isError is False
    assert replay.structuredContent["status"] == "pending_approval"
    assert harness.request_count() == 1
    stored = harness.machine.get_request(replay.structuredContent["request_id"])
    assert json.loads(bytes(stored["pending_result"])) == replay.structuredContent


@pytest.mark.parametrize(
    "stored_bytes",
    [
        b'{"status":"pending_approval", "request_id":"req_test",'
        b'"expires_at":"2030-01-01T00:00:00Z","message":"wait"}',
        b'{"expires_at":"2030-01-01T00:00:00Z","message":"wait",'
        b'"request_id":"req_wrong","request_id":"req_test",'
        b'"status":"pending_approval"}',
    ],
)
def test_pending_replay_refuses_noncanonical_or_duplicate_stored_bytes(
    stored_bytes: bytes,
) -> None:
    with pytest.raises(GatewayError, match="stored pending"):
        _stored_pending_call_result(
            EnqueueResult(
                request_id="req_test",
                pending_result=stored_bytes,
                created=False,
            )
        )


@pytest.mark.asyncio
async def test_schema_drift_disables_passthrough_before_downstream_call(tmp_path: Path) -> None:
    harness = GatewayHarness(tmp_path)
    drifted = copy.deepcopy(harness.raw_tools)
    drifted[0]["description"] = "unreviewed changed description"
    harness.mirror.capture("example", drifted)
    async with create_connected_server_and_client_session(harness.surface.server) as client:
        result = await client.call_tool("read", {"query": "safe"})
    assert result.isError is True
    assert result.structuredContent["error"]["code"] == "schema_unreviewed"
    assert harness.downstream.calls == []


@pytest.mark.asyncio
async def test_passthrough_cancellation_propagates_to_downstream(tmp_path: Path) -> None:
    harness = GatewayHarness(tmp_path)
    harness.downstream.gate = asyncio.Event()
    async with create_connected_server_and_client_session(harness.surface.server) as client:
        calling = asyncio.create_task(client.call_tool("read", {"query": "safe"}))
        await harness.downstream.entered.wait()
        calling.cancel()
        with pytest.raises(asyncio.CancelledError):
            await calling
        for _ in range(20):
            if harness.downstream.cancelled:
                break
            await asyncio.sleep(0)
    assert harness.downstream.cancelled


@pytest.mark.asyncio
async def test_approval_cancellation_before_commit_enqueues_nothing(tmp_path: Path) -> None:
    harness = GatewayHarness(tmp_path)
    identity = derive_invocation_identity(
        namespace="profile:test",
        alias="example",
        tool="send",
        explicit_id="cancel-before-commit",
        explicit_id_present=True,
        session_scope="unused-session",
        request_id=1,
    )
    calling = asyncio.create_task(
        harness.pipeline.handle_call(
            "example",
            "send",
            {"message": "cancelled"},
            "profile:test",
            identity,
        )
    )
    await harness.adapter.canonicalized_event.wait()
    calling.cancel()
    with pytest.raises(asyncio.CancelledError):
        await calling
    assert harness.request_count() == 0
    assert harness.downstream.calls == []


@pytest.mark.asyncio
async def test_task_augmented_execution_is_rejected_before_pipeline(tmp_path: Path) -> None:
    harness = GatewayHarness(tmp_path)
    async with create_connected_server_and_client_session(harness.surface.server) as client:
        result = await client.send_request(
            types.ClientRequest(
                types.CallToolRequest(
                    params=types.CallToolRequestParams(
                        name="read",
                        arguments={"query": "safe"},
                        task=types.TaskMetadata(),
                    )
                )
            ),
            types.CallToolResult,
        )
    assert result.isError is True
    assert result.structuredContent["error"]["code"] == "task_execution_unsupported"
    assert harness.downstream.calls == []
