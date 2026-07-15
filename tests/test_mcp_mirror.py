from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import mcp.types as types
import pytest
from jsonschema.exceptions import ValidationError
from mcp.shared.exceptions import McpError
from mcp.shared.memory import create_connected_server_and_client_session

from signet.mcp_mirror import (
    PENDING_RESULT_SCHEMA,
    SIGNET_INVOCATION_ID_META,
    AliasToolSurface,
    InvocationIdentity,
    MirrorError,
    RawServerResult,
    SchemaMirror,
    derive_invocation_identity,
    discover_all_tools,
    domain_error_result,
    pending_call_result,
    raw_model,
    validate_lossless_tool,
)
from signet.policy import parse_policy


def _policy() -> Any:
    return parse_policy(
        {
            "version": 1,
            "default_mode": "deny",
            "downstreams": {
                "example": {
                    "transport": "http",
                    "url": "https://example.test/mcp",
                    "tools": {
                        "read": {"mode": "passthrough", "reviewed_read_only": True},
                        "stage": {
                            "mode": "virtualize_local",
                            "adapter": "example.stage",
                            "account_ref": "example-account",
                        },
                        "send": {
                            "mode": "approval",
                            "adapter": "example.send",
                            "communication_send": True,
                        },
                        "delete": {"mode": "deny"},
                    },
                }
            },
        }
    )


def _raw_tool(name: str, *, explicit_null: bool = False) -> dict[str, Any]:
    tool: dict[str, Any] = {
        "name": name,
        "title": f"Title {name}",
        "description": f"Description {name}",
        "inputSchema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "x-nested-unknown": {"kept": True},
        },
        "outputSchema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["id"],
            "properties": {"id": {"type": "string"}},
        },
        "annotations": {"readOnlyHint": False, "x-provider": "kept"},
        "x-provider-extension": {"nested": [1, None, 3]},
    }
    if explicit_null:
        tool["icons"] = None
    return tool


def _review_all(mirror: SchemaMirror) -> None:
    for name in ("read", "stage", "send", "delete"):
        mirror.approve_schema("example", name, mirror.captured_digest("example", name))


def test_tool_roundtrip_preserves_unknown_fields_and_explicit_null() -> None:
    raw = _raw_tool("read", explicit_null=True)
    assert validate_lossless_tool(raw) == raw
    assert raw_model(types.Tool.model_validate(raw)) == raw


def test_mirror_is_unlisted_until_schema_review_and_fails_closed_on_drift() -> None:
    mirror = SchemaMirror(_policy())
    tools = [_raw_tool(name) for name in ("read", "stage", "send", "delete")]
    mirror.capture("example", tools)
    assert mirror.list_tools("example") == []
    _review_all(mirror)
    assert [tool["name"] for tool in mirror.list_tools("example")] == [
        "read",
        "stage",
        "send",
        "delete",
    ]
    drifted = copy.deepcopy(tools)
    drifted[0]["description"] = "changed"
    assert mirror.capture("example", drifted) == {"read"}
    assert "read" not in [tool["name"] for tool in mirror.list_tools("example")]


def test_approval_schema_is_deliberately_replaced_but_other_contracts_are_lossless() -> None:
    mirror = SchemaMirror(_policy())
    raw_tools = [
        _raw_tool(name, explicit_null=True) for name in ("read", "stage", "send", "delete")
    ]
    mirror.capture("example", raw_tools)
    _review_all(mirror)
    listed = {tool["name"]: tool for tool in mirror.list_tools("example")}
    assert listed["read"] == raw_tools[0]
    assert listed["stage"] == raw_tools[1]
    assert listed["delete"] == raw_tools[3]
    assert listed["send"]["outputSchema"] == PENDING_RESULT_SCHEMA
    assert "pending_approval" in listed["send"]["description"]
    for key in raw_tools[2]:
        if key not in {"description", "outputSchema"}:
            assert listed["send"][key] == raw_tools[2][key]


def test_unconfigured_tool_uses_protocol_error_and_explicit_deny_is_callable() -> None:
    mirror = SchemaMirror(_policy())
    mirror.capture("example", [_raw_tool(name) for name in ("read", "stage", "send", "delete")])
    _review_all(mirror)
    with pytest.raises(McpError) as error:
        mirror.require_callable("example", "unknown")
    assert error.value.error.code == types.INVALID_PARAMS
    assert mirror.require_callable("example", "delete").value == "deny"


def test_pending_and_domain_error_wire_shapes() -> None:
    pending = {
        "status": "pending_approval",
        "request_id": "req_01J00000000000000000000000",
        "expires_at": "2026-07-22T09:00:00Z",
        "message": "This action requires human approval.",
    }
    result = pending_call_result(pending)
    assert result["structuredContent"] == pending
    assert result["isError"] is False
    assert types.CallToolResult.model_validate(result)
    error = domain_error_result("stale_version", "Review the current version.")
    assert error["isError"] is True
    assert error["structuredContent"]["error"]["code"] == "stale_version"


def test_runtime_pending_schema_matches_the_normative_fixture() -> None:
    fixture_path = (
        Path(__file__).parents[1] / "spec" / "fixtures" / "gateway-tools-schemas.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert fixture["pending_result_schema"] == PENDING_RESULT_SCHEMA


def test_virtual_result_validates_against_captured_output_schema() -> None:
    mirror = SchemaMirror(_policy())
    mirror.capture("example", [_raw_tool("stage")])
    mirror.approve_schema("example", "stage", mirror.captured_digest("example", "stage"))
    mirror.validate_virtual_result("example", "stage", {"id": "stg_123"})
    with pytest.raises(ValidationError):
        mirror.validate_virtual_result("example", "stage", {"wrong": True})


class _PagedSession:
    def __init__(self) -> None:
        self.calls: list[str | None] = []

    async def list_tools(self, *, params: Any) -> Any:
        cursor = params.cursor if params else None
        self.calls.append(cursor)
        if cursor is None:
            return SimpleNamespace(
                tools=[types.Tool.model_validate(_raw_tool("one"))], nextCursor="next"
            )
        return SimpleNamespace(tools=[types.Tool.model_validate(_raw_tool("two"))], nextCursor=None)


@pytest.mark.asyncio
async def test_discovery_exhausts_pagination() -> None:
    session = _PagedSession()
    tools = await discover_all_tools(session)
    assert [tool["name"] for tool in tools] == ["one", "two"]
    assert session.calls == [None, "next"]


@pytest.mark.asyncio
async def test_discovery_rejects_repeated_cursor() -> None:
    class Repeating:
        async def list_tools(self, *, params: Any) -> Any:
            return SimpleNamespace(tools=[], nextCursor="same")

    with pytest.raises(MirrorError, match="cursor repeated"):
        await discover_all_tools(Repeating())


def test_raw_server_result_uses_exact_raw_serializer() -> None:
    raw = {"tools": [_raw_tool("one", explicit_null=True)], "nextCursor": None}
    result = RawServerResult(raw)
    assert result.model_dump(mode="json", by_alias=True, exclude_none=True) == raw


def test_invocation_identity_digest_is_scoped_by_caller_alias_and_tool() -> None:
    def derive(namespace: str, alias: str, tool: str) -> InvocationIdentity:
        return derive_invocation_identity(
            namespace=namespace,
            alias=alias,
            tool=tool,
            explicit_id="same-explicit-id",
            explicit_id_present=True,
            session_scope="unused",
            request_id=1,
        )

    identities = {
        derive("profile:one", "example", "read").invocation_key,
        derive("profile:two", "example", "read").invocation_key,
        derive("profile:one", "other", "read").invocation_key,
        derive("profile:one", "example", "other").invocation_key,
    }
    assert len(identities) == 4


@pytest.mark.asyncio
async def test_low_level_server_preserves_raw_list_and_error_channels() -> None:
    mirror = SchemaMirror(_policy())
    raw_tools = [
        _raw_tool(name, explicit_null=True)
        for name in ("read", "stage", "send", "delete")
    ]
    mirror.capture("example", raw_tools)
    _review_all(mirror)
    downstream_calls: list[str] = []

    async def call_handler(
        alias: str,
        name: str,
        arguments: Any,
        namespace: str,
        identity: InvocationIdentity,
    ) -> Any:
        del alias, arguments, namespace, identity
        downstream_calls.append(name)
        return {
            "content": [{"type": "text", "text": "ok"}],
            "structuredContent": {"id": "real-id"},
            "isError": False,
            "x-result-extension": None,
        }

    surface = AliasToolSurface(
        alias="example",
        mirror=mirror,
        call_handler=call_handler,
        namespace_provider=lambda: ("profile:test", {"example"}),
    )
    async with create_connected_server_and_client_session(surface.server) as client:
        listed = await client.list_tools()
        dumped = [raw_model(tool) for tool in listed.tools]
        assert dumped[0] == raw_tools[0]
        assert dumped[1] == raw_tools[1]
        assert dumped[2]["outputSchema"] == PENDING_RESULT_SCHEMA
        with pytest.raises(McpError) as unknown:
            await client.call_tool("not_configured", {})
        assert unknown.value.error.code == types.INVALID_PARAMS
        denied = await client.call_tool("delete", {})
        assert denied.isError is True
        assert denied.structuredContent["error"]["code"] == "policy_denied"
        result = await client.call_tool("read", {})
        assert result.isError is False
        assert raw_model(result)["x-result-extension"] is None
    assert downstream_calls == ["read"]


@pytest.mark.asyncio
async def test_surface_passes_hashed_explicit_and_session_request_invocation_identities() -> None:
    mirror = SchemaMirror(_policy())
    mirror.capture("example", [_raw_tool("read")])
    mirror.approve_schema("example", "read", mirror.captured_digest("example", "read"))
    identities: list[InvocationIdentity] = []

    async def call_handler(
        alias: str,
        name: str,
        arguments: Any,
        namespace: str,
        identity: InvocationIdentity,
    ) -> dict[str, Any]:
        del alias, name, arguments, namespace
        identities.append(identity)
        return {
            "content": [{"type": "text", "text": "ok"}],
            "structuredContent": {"id": "real-id"},
            "isError": False,
        }

    surface = AliasToolSurface(
        alias="example",
        mirror=mirror,
        call_handler=call_handler,
        namespace_provider=lambda: ("profile:test", {"example"}),
    )
    async with create_connected_server_and_client_session(surface.server) as client:
        await client.call_tool(
            "read",
            {},
            meta={SIGNET_INVOCATION_ID_META: "invocation-001"},
        )
        await client.call_tool(
            "read",
            {},
            meta={SIGNET_INVOCATION_ID_META: "invocation-001"},
        )
        await client.call_tool("read", {})
        await client.call_tool("read", {})

    assert identities[0].source == identities[1].source == "explicit"
    assert identities[0].invocation_key == identities[1].invocation_key
    assert "invocation-001" not in repr(identities[0])
    assert identities[2].source == identities[3].source == "session_request"
    assert identities[2].invocation_key != identities[3].invocation_key


@pytest.mark.asyncio
async def test_surface_bounds_and_expires_tracked_sessions() -> None:
    now = 1_000.0
    surface = AliasToolSurface(
        alias="mail",
        mirror=SchemaMirror(_policy()),
        call_handler=AsyncMock(),
        tracked_session_limit=2,
        tracked_session_ttl_seconds=60,
        session_clock=lambda: now,
    )
    oldest = AsyncMock()
    current = AsyncMock()
    surface._sessions.update((oldest, current))
    surface._session_last_seen[oldest] = now - 10
    surface._session_last_seen[current] = now
    surface._session_invocation_scopes[oldest] = "old"
    surface._session_invocation_scopes[current] = "current"

    surface._prune_sessions(now)
    assert surface.tracked_session_count == 2

    surface._prune_sessions(now, reserve_new=True)
    assert oldest not in surface._sessions
    assert current in surface._sessions

    now += 61
    assert await surface.notify_list_changed() == 0
    assert surface.tracked_session_count == 0


@pytest.mark.asyncio
async def test_surface_rejects_malformed_explicit_invocation_id_before_handler() -> None:
    mirror = SchemaMirror(_policy())
    mirror.capture("example", [_raw_tool("read")])
    mirror.approve_schema("example", "read", mirror.captured_digest("example", "read"))
    calls = 0

    async def call_handler(
        alias: str,
        name: str,
        arguments: Any,
        namespace: str,
        identity: InvocationIdentity,
    ) -> dict[str, Any]:
        nonlocal calls
        del alias, name, arguments, namespace, identity
        calls += 1
        return {"content": [], "structuredContent": {}, "isError": False}

    surface = AliasToolSurface(
        alias="example",
        mirror=mirror,
        call_handler=call_handler,
        namespace_provider=lambda: ("profile:test", {"example"}),
    )
    async with create_connected_server_and_client_session(surface.server) as client:
        with pytest.raises(McpError) as captured:
            await client.call_tool(
                "read",
                {},
                meta={SIGNET_INVOCATION_ID_META: "contains spaces"},
            )
    assert captured.value.error.code == types.INVALID_PARAMS
    assert calls == 0
