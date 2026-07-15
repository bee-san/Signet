from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import traceback
from collections.abc import AsyncIterator, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anyio
import mcp.types as types
import pytest
from mcp import StdioServerParameters
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_client_server_memory_streams

from signet.config import DownstreamConfig
from signet.credential_broker import MemorySecretStore, SecretReference
from signet.downstream import (
    DownstreamClient,
    DownstreamConfigurationError,
    DownstreamConnectionError,
    DownstreamLifecycleError,
    DownstreamProtocolError,
    structured_adapter_result,
    validate_call_tool_result,
)
from signet.mcp_mirror import raw_model

SECRET = "credential-material-that-must-not-leak"


def _http_config(**changes: Any) -> DownstreamConfig:
    values: dict[str, Any] = {
        "transport": "http",
        "credential_ref": "keychain://Signet/example",
        "url": "https://provider.test/mcp",
        "timeout_seconds": 2,
    }
    values.update(changes)
    return DownstreamConfig(**values)


def _stdio_config(**changes: Any) -> DownstreamConfig:
    values: dict[str, Any] = {
        "transport": "stdio",
        "credential_ref": "keychain://Signet/example",
        "command": ("/opt/signet/bin/provider-mcp", "--mode", "json"),
        "working_directory": Path("/var/empty"),
        "executable_sha256": "a" * 64,
        "execution_snapshot_root": Path("/var/empty/signet-exec"),
        "timeout_seconds": 2,
    }
    values.update(changes)
    return DownstreamConfig(**values)


def _store() -> MemorySecretStore:
    return MemorySecretStore({("Signet", "example"): SECRET})


def _executable_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_fake_stdio_server(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/python3
import json
import os
import shutil
import sys

report = {"environment": dict(os.environ), "helper": shutil.which("signet-parent-helper")}
with open(sys.argv[1], "w", encoding="utf-8") as sink:
    json.dump(report, sink, sort_keys=True)
for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") != "initialize":
        continue
    result = {
        "protocolVersion": request["params"]["protocolVersion"],
        "capabilities": {},
        "serverInfo": {"name": "fake-reviewed-stdio", "version": "1.0.0"},
    }
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
""",
        encoding="utf-8",
    )
    path.chmod(0o700)


def _tool(name: str) -> types.Tool:
    return types.Tool(name=name, inputSchema={"type": "object", "x-provider": None})


def _result(
    structured: Any = None,
    *,
    is_error: bool = False,
    include_structured: bool = True,
) -> types.CallToolResult:
    raw: dict[str, Any] = {
        "content": [{"type": "text", "text": "provider response"}],
        "isError": is_error,
        "x-provider-extension": {"explicit-null": None},
    }
    if include_structured:
        raw["structuredContent"] = (
            {"id": "provider-id", "nested": {"values": [1, None]}}
            if structured is None
            else structured
        )
    return types.CallToolResult.model_validate(raw)


class FakeSession:
    def __init__(
        self,
        events: list[str],
        *,
        result: Any | None = None,
        initialize_error: BaseException | None = None,
        initialize_gate: asyncio.Event | None = None,
        call_gate: asyncio.Event | None = None,
    ) -> None:
        self.events = events
        self.result = result if result is not None else _result()
        self.initialize_error = initialize_error
        self.initialize_gate = initialize_gate
        self.call_gate = call_gate
        self.initialize_count = 0
        self.call_count = 0
        self.list_cursors: list[str | None] = []

    async def __aenter__(self) -> FakeSession:
        self.events.append("session-enter")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback_value: Any,
    ) -> None:
        del exc_type, exc_value, traceback_value
        self.events.append("session-exit")

    async def initialize(self) -> Any:
        self.initialize_count += 1
        self.events.append("initialize")
        if self.initialize_gate is not None:
            self.events.append("initialize-wait")
            await self.initialize_gate.wait()
        if self.initialize_error is not None:
            raise self.initialize_error
        return SimpleNamespace(capabilities=SimpleNamespace(tools=True))

    async def list_tools(self, *, params: Any) -> Any:
        cursor = params.cursor if params is not None else None
        self.list_cursors.append(cursor)
        if cursor is None:
            return SimpleNamespace(tools=[_tool("one")], nextCursor="page-2")
        return SimpleNamespace(tools=[_tool("two")], nextCursor=None)

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        del name, arguments
        self.call_count += 1
        self.events.append("call")
        if self.call_gate is not None:
            try:
                await self.call_gate.wait()
            finally:
                self.events.append("call-finished")
        if callable(self.result):
            return self.result()
        return self.result


class FakeFactories:
    def __init__(self, session: FakeSession) -> None:
        self.session = session
        self.events = session.events
        self.http_calls: list[tuple[str, dict[str, str], float]] = []
        self.stdio_parameters: list[StdioServerParameters] = []
        self.session_timeouts: list[timedelta] = []

    @asynccontextmanager
    async def http(
        self, url: str, headers: Mapping[str, str], timeout: float
    ) -> AsyncIterator[tuple[Any, Any, Any]]:
        self.http_calls.append((url, dict(headers), timeout))
        self.events.append("transport-enter")
        try:
            yield object(), object(), lambda: "session-id"
        finally:
            self.events.append("transport-exit")

    @asynccontextmanager
    async def stdio(self, parameters: StdioServerParameters) -> AsyncIterator[tuple[Any, Any]]:
        self.stdio_parameters.append(parameters)
        self.events.append("transport-enter")
        try:
            yield object(), object()
        finally:
            self.events.append("transport-exit")

    def session_factory(
        self, read: Any, write: Any, timeout: timedelta
    ) -> AbstractAsyncContextManager[FakeSession]:
        del read, write
        self.session_timeouts.append(timeout)
        return self.session

    def client(self, *, alias: str = "example", stdio: bool = False) -> DownstreamClient:
        return DownstreamClient(
            alias,
            _stdio_config() if stdio else _http_config(),
            _store(),
            http_connector=self.http,
            stdio_connector=self.stdio,
            session_factory=self.session_factory,
        )


@pytest.mark.asyncio
async def test_http_lifecycle_initializes_once_discovers_pages_and_detaches_results() -> None:
    events: list[str] = []
    session = FakeSession(events)
    factories = FakeFactories(session)
    client = factories.client()

    with pytest.raises(DownstreamLifecycleError, match="not initialized"):
        await client.discover_tools()
    with pytest.raises(DownstreamLifecycleError, match="not initialized"):
        await client.call_tool("read", {})

    async with client as running:
        assert running is client
        assert await client.start() is client
        assert client.is_running
        assert session.initialize_count == 1
        assert factories.http_calls == [
            (
                "https://provider.test/mcp",
                {"Authorization": f"Bearer {SECRET}"},
                2.0,
            )
        ]
        assert factories.session_timeouts == [timedelta(seconds=2)]

        tools = await client.discover_all_tools()
        assert [tool["name"] for tool in tools] == ["one", "two"]
        assert session.list_cursors == [None, "page-2"]

        raw = await client.call_tool_raw("read", {"query": {"value": 1}})
        expected_raw = raw_model(session.result)
        assert raw == expected_raw
        assert raw["x-provider-extension"] == {"explicit-null": None}
        raw["structuredContent"]["nested"]["values"].append("changed")
        assert raw_model(session.result) == expected_raw

        adapter_result = await client.call_tool("read", {})
        assert adapter_result == {
            "id": "provider-id",
            "nested": {"values": [1, None]},
            "isError": False,
        }

    assert client.state == "closed"
    assert events == [
        "transport-enter",
        "session-enter",
        "initialize",
        "call",
        "call",
        "session-exit",
        "transport-exit",
    ]
    await client.close()
    with pytest.raises(DownstreamLifecycleError, match="current lifecycle state"):
        await client.start()
    with pytest.raises(DownstreamLifecycleError, match="not initialized"):
        await client.call_tool("read", {})


@pytest.mark.asyncio
async def test_discovery_rejects_a_repeated_pagination_cursor_at_client_boundary() -> None:
    class RepeatingSession(FakeSession):
        async def list_tools(self, *, params: Any) -> Any:
            del params
            return SimpleNamespace(tools=[], nextCursor="same")

    client = FakeFactories(RepeatingSession([])).client()
    async with client:
        with pytest.raises(DownstreamProtocolError, match="discovery was malformed"):
            await client.discover_tools()


@pytest.mark.asyncio
async def test_stdio_uses_pinned_direct_argv_and_minimal_redacted_alias_environment() -> None:
    events: list[str] = []
    factories = FakeFactories(FakeSession(events))
    client = factories.client(alias="whatsapp-local", stdio=True)

    async with client:
        parameters = factories.stdio_parameters[0]
        assert parameters.command == "/opt/signet/bin/provider-mcp"
        assert parameters.args == ["--mode", "json"]
        assert parameters.cwd == Path("/var/empty")
        assert parameters.env == {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "SIGNET_DOWNSTREAM_WHATSAPP_LOCAL_CREDENTIAL": SECRET,
        }
        assert SECRET not in parameters.args
        assert SECRET not in repr(parameters)
        assert SECRET not in repr(client)
        assert "keychain://" not in repr(client)


@pytest.mark.asyncio
async def test_official_stdio_launcher_uses_verified_snapshot_and_exact_clean_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "provider-mcp"
    environment_report = tmp_path / "environment.json"
    _write_fake_stdio_server(executable)
    malicious_path = tmp_path / "parent-path"
    malicious_path.mkdir()
    helper = malicious_path / "signet-parent-helper"
    helper.write_text("#!/bin/sh\necho hijacked\n", encoding="utf-8")
    helper.chmod(0o700)
    for name, value in {
        "HOME": "/parent/home-must-not-leak",
        "LOGNAME": "parent-logname-must-not-leak",
        "PATH": str(malicious_path),
        "SHELL": "/parent/shell-must-not-leak",
        "TERM": "parent-term-must-not-leak",
        "USER": "parent-user-must-not-leak",
        "SIGNET_PARENT_SECRET": "must-not-leak",
    }.items():
        monkeypatch.setenv(name, value)

    client = DownstreamClient(
        "example",
        _stdio_config(
            command=(str(executable), str(environment_report)),
            working_directory=tmp_path,
            executable_sha256=_executable_digest(executable),
            execution_snapshot_root=tmp_path / "snapshots",
            test_only_allow_script=True,
        ),
        _store(),
    )
    async with client:
        assert client.is_running

    report = json.loads(environment_report.read_text(encoding="utf-8"))
    assert report == {
        "environment": {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "SIGNET_DOWNSTREAM_EXAMPLE_CREDENTIAL": SECRET,
        },
        "helper": None,
    }
    assert list((tmp_path / "snapshots").iterdir()) == []


@pytest.mark.asyncio
async def test_official_stdio_launcher_rejects_symlinked_executable(tmp_path: Path) -> None:
    executable = tmp_path / "provider-mcp-real"
    _write_fake_stdio_server(executable)
    symlink = tmp_path / "provider-mcp"
    symlink.symlink_to(executable)
    client = DownstreamClient(
        "example",
        _stdio_config(
            command=(str(symlink), str(tmp_path / "unused.json")),
            working_directory=tmp_path,
            executable_sha256=_executable_digest(executable),
            execution_snapshot_root=tmp_path / "snapshots",
            test_only_allow_script=True,
        ),
        _store(),
    )
    with pytest.raises(DownstreamConnectionError, match="initialization failed"):
        await client.start()
    await client.close()


@pytest.mark.asyncio
async def test_initialize_failure_closes_partial_stack_and_redacts_provider_exception() -> None:
    events: list[str] = []
    session = FakeSession(
        events,
        initialize_error=RuntimeError(f"provider rejected {SECRET}"),
    )
    client = FakeFactories(session).client()

    with pytest.raises(DownstreamConnectionError) as captured:
        await client.start()
    rendered = "".join(
        traceback.format_exception(
            type(captured.value), captured.value, captured.value.__traceback__
        )
    )
    assert SECRET not in rendered
    assert SECRET not in repr(captured.value)
    assert events == [
        "transport-enter",
        "session-enter",
        "initialize",
        "session-exit",
        "transport-exit",
    ]
    assert client.state == "failed"
    with pytest.raises(DownstreamLifecycleError):
        await client.start()
    await client.close()
    assert client.state == "closed"


@pytest.mark.asyncio
async def test_start_cancellation_propagates_and_closes_partial_stack() -> None:
    events: list[str] = []
    never = asyncio.Event()
    session = FakeSession(events, initialize_gate=never)
    client = FakeFactories(session).client()

    starting = asyncio.create_task(client.start())
    while "initialize-wait" not in events:
        await asyncio.sleep(0)
    starting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await starting
    assert client.state == "failed"
    assert events[-2:] == ["session-exit", "transport-exit"]
    await client.close()


@pytest.mark.asyncio
async def test_call_cancellation_is_not_wrapped_and_client_remains_usable() -> None:
    events: list[str] = []
    never = asyncio.Event()
    session = FakeSession(events, call_gate=never)
    client = FakeFactories(session).client()
    await client.start()

    calling = asyncio.create_task(client.call_tool("read", {}))
    while "call" not in events:
        await asyncio.sleep(0)
    calling.cancel()
    with pytest.raises(asyncio.CancelledError):
        await calling
    assert client.is_running
    assert "call-finished" in events
    await client.close()


@pytest.mark.asyncio
async def test_close_cancels_in_flight_call_before_transport_shutdown() -> None:
    events: list[str] = []
    never = asyncio.Event()
    session = FakeSession(events, call_gate=never)
    client = FakeFactories(session).client()
    await client.start()
    calling = asyncio.create_task(client.call_tool("read", {}))
    while "call" not in events:
        await asyncio.sleep(0)

    await client.close()
    with pytest.raises(asyncio.CancelledError):
        await calling
    assert events.index("call-finished") < events.index("session-exit")
    assert events.index("session-exit") < events.index("transport-exit")
    assert client.state == "closed"


@pytest.mark.asyncio
async def test_close_cancellation_is_propagated_after_same_task_transport_cleanup() -> None:
    exit_started = asyncio.Event()
    release_exit = asyncio.Event()

    class SlowExitSession(FakeSession):
        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback_value: Any,
        ) -> None:
            del exc_type, exc_value, traceback_value
            self.events.append("session-exit-wait")
            exit_started.set()
            await release_exit.wait()
            self.events.append("session-exit")

    events: list[str] = []
    client = FakeFactories(SlowExitSession(events)).client()
    await client.start()
    closing = asyncio.create_task(client.close())
    await exit_started.wait()
    closing.cancel()
    await asyncio.sleep(0)
    assert not closing.done()
    release_exit.set()

    with pytest.raises(asyncio.CancelledError):
        await closing
    assert events[-2:] == ["session-exit", "transport-exit"]
    assert client.state == "closed"


@pytest.mark.asyncio
async def test_clients_have_independent_sessions_and_lifecycles() -> None:
    first_events: list[str] = []
    second_events: list[str] = []
    first = FakeFactories(FakeSession(first_events)).client(alias="first")
    second = FakeFactories(FakeSession(second_events)).client(alias="second")
    await first.start()
    await second.start()

    await first.close()
    assert first.state == "closed"
    assert second.is_running
    assert (await second.call_tool("read", {}))["id"] == "provider-id"
    assert "session-exit" not in second_events
    await second.close()


def test_complete_raw_result_validation_is_lossless_and_detached() -> None:
    raw = {
        "content": [{"type": "text", "text": '{"id":"one"}'}],
        "structuredContent": {"id": "one"},
        "isError": False,
        "_meta": {"x-provider": None},
        "x-result-extension": [1, None, {"kept": True}],
    }
    captured = validate_call_tool_result(raw)
    assert captured == raw
    captured["x-result-extension"][2]["kept"] = False
    assert raw["x-result-extension"][2]["kept"] is True


@pytest.mark.parametrize(
    "malformed",
    [
        None,
        [],
        {"structuredContent": {}},
        {"content": [], "structuredContent": [], "isError": False},
        {"content": [], "structuredContent": {}, "isError": 0},
        {"content": [], "structuredContent": {}, "isError": False, "task": {}},
        {
            "content": [],
            "structuredContent": {},
            "isError": False,
            "_meta": {"io.modelcontextprotocol/related-task": {"taskId": "task-1"}},
        },
    ],
)
def test_raw_result_rejects_non_objects_malformed_values_and_tasks(malformed: Any) -> None:
    with pytest.raises(DownstreamProtocolError):
        validate_call_tool_result(malformed)


@pytest.mark.parametrize(
    "structured,is_error",
    [
        ({"isError": True}, False),
        ({"isError": False}, True),
        ({"isError": "false"}, False),
        ({"is_error": True}, False),
        ({"is_error": 1}, True),
    ],
)
def test_adapter_result_rejects_contradictory_error_markers(
    structured: dict[str, Any], is_error: bool
) -> None:
    raw = raw_model(_result(structured, is_error=is_error))
    with pytest.raises(DownstreamProtocolError, match="contradictory"):
        structured_adapter_result(raw)


@pytest.mark.asyncio
async def test_raw_passthrough_allows_content_only_but_adapter_boundary_rejects_it() -> None:
    events: list[str] = []
    content_only = _result(include_structured=False)
    client = FakeFactories(FakeSession(events, result=content_only)).client()
    async with client:
        assert await client.call_tool_raw("legacy", {}) == raw_model(content_only)
        with pytest.raises(DownstreamProtocolError, match="structuredContent"):
            await client.call_tool("legacy", {})


def test_stdio_configuration_rejects_shells_relative_paths_and_unbounded_argv() -> None:
    for command in (
        ("provider-mcp",),
        ("/bin/sh", "-c", "provider-mcp"),
        ("/opt/provider", *("argument" for _ in range(65))),
    ):
        with pytest.raises(DownstreamConfigurationError):
            DownstreamClient("example", _stdio_config(command=command), _store())


@pytest.mark.parametrize(
    "changes",
    [
        {"executable_sha256": None},
        {"execution_snapshot_root": None},
        {"execution_snapshot_root": Path("relative")},
    ],
)
def test_stdio_configuration_requires_reviewed_executable_inputs(changes: dict[str, Any]) -> None:
    with pytest.raises(DownstreamConfigurationError, match="stdio downstream"):
        DownstreamClient("example", _stdio_config(**changes), _store())


@pytest.mark.parametrize(
    "url",
    [
        "https://provider.test:invalid/mcp",
        "https://provider.test/mcp?credential=forbidden",
        "http://provider.test/mcp",
        "https://user@provider.test/mcp",
    ],
)
def test_http_configuration_rejects_ambiguous_or_unsafe_urls(url: str) -> None:
    with pytest.raises(DownstreamConfigurationError, match="endpoint"):
        DownstreamClient("example", _http_config(url=url), _store())


@pytest.mark.asyncio
async def test_secret_lookup_failure_is_generic_and_connector_is_never_called() -> None:
    class FailingStore:
        def get(self, reference: SecretReference) -> Any:
            del reference
            raise RuntimeError(f"missing {SECRET}")

    events: list[str] = []
    factories = FakeFactories(FakeSession(events))
    client = DownstreamClient(
        "example",
        _http_config(),
        FailingStore(),
        http_connector=factories.http,
        stdio_connector=factories.stdio,
        session_factory=factories.session_factory,
    )
    with pytest.raises(DownstreamConnectionError) as captured:
        await client.start()
    assert SECRET not in str(captured.value)
    assert factories.http_calls == []
    assert events == []
    await client.close()


def test_result_fixtures_are_not_mutated_by_validation() -> None:
    raw = raw_model(_result())
    original = copy.deepcopy(raw)
    structured_adapter_result(raw)
    assert raw == original


@pytest.mark.asyncio
async def test_injected_memory_transport_uses_the_pinned_sdk_session_end_to_end() -> None:
    server = FastMCP("fake-downstream")

    @server.tool()
    def read(value: int) -> dict[str, Any]:
        return {"id": "sdk-result", "value": value}

    observed_headers: dict[str, str] = {}

    @asynccontextmanager
    async def memory_connector(
        url: str, headers: Mapping[str, str], timeout: float
    ) -> AsyncIterator[tuple[Any, Any, Any]]:
        del url, timeout
        observed_headers.update(headers)
        low_level = server._mcp_server
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            server_read, server_write = server_streams
            async with anyio.create_task_group() as task_group:
                task_group.start_soon(
                    low_level.run,
                    server_read,
                    server_write,
                    low_level.create_initialization_options(),
                )
                try:
                    yield client_streams[0], client_streams[1], lambda: None
                finally:
                    task_group.cancel_scope.cancel()

    client = DownstreamClient(
        "example",
        _http_config(),
        _store(),
        http_connector=memory_connector,
    )
    async with client:
        assert [tool["name"] for tool in await client.discover_tools()] == ["read"]
        assert await client.call_tool("read", {"value": 7}) == {
            "id": "sdk-result",
            "value": 7,
            "isError": False,
        }
    assert observed_headers == {"Authorization": f"Bearer {SECRET}"}
