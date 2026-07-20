from __future__ import annotations

import asyncio
import copy
import hashlib
import ipaddress
import json
import ssl
import traceback
from collections.abc import AsyncIterator, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import anyio
import httpx
import mcp.types as types
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from mcp import ClientSession, StdioServerParameters
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
    _bounded_response_hook,
    _BoundedHTTPResponseStream,
    _official_stdio_connector,
    pinned_tls_http_connector,
    structured_adapter_result,
    validate_call_tool_result,
)
from signet.mcp_mirror import raw_model
from signet.reviewed_process import _TEST_ONLY_SCRIPT_CAPABILITY

SECRET = "credential-material-that-must-not-leak"


def _write_self_signed_tls_identity(
    directory: Path,
    *,
    name: str,
    certificate_authority: bool = False,
) -> tuple[Path, Path, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=certificate_authority, path_length=None), True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_path = directory / f"{name}.pem"
    key_path = directory / f"{name}-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    digest = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
    return certificate_path, key_path, digest


@pytest.mark.asyncio
async def test_pinned_tls_rejects_wrong_peer_before_sending_bearer_header(tmp_path: Path) -> None:
    reviewed_cert, _, reviewed_digest = _write_self_signed_tls_identity(
        tmp_path,
        name="reviewed",
    )
    wrong_cert, wrong_key, _ = _write_self_signed_tls_identity(tmp_path, name="wrong")
    received_application_bytes = 0

    async def record_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal received_application_bytes
        received_application_bytes += len(await reader.read(65_536))
        writer.close()
        await writer.wait_closed()

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(wrong_cert, wrong_key)
    server = await asyncio.start_server(
        record_request,
        "127.0.0.1",
        0,
        ssl=server_context,
    )
    port = server.sockets[0].getsockname()[1]
    connector = pinned_tls_http_connector(
        reviewed_cert.read_bytes(),
        reviewed_digest,
    )
    try:
        with pytest.raises(BaseExceptionGroup):
            async with connector(
                f"https://127.0.0.1:{port}/mcp",
                {"Authorization": f"Bearer {SECRET}"},
                0.2,
                1_048_576,
            ) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
    finally:
        server.close()
        await server.wait_closed()

    assert received_application_bytes == 0


@pytest.mark.asyncio
async def test_pinned_tls_allows_reviewed_peer_to_receive_bearer_header(
    tmp_path: Path,
) -> None:
    reviewed_cert, reviewed_key, reviewed_digest = _write_self_signed_tls_identity(
        tmp_path,
        name="reviewed-peer",
    )
    received_headers = b""

    async def receive_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal received_headers
        try:
            received_headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=1)
            writer.write(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(reviewed_cert, reviewed_key)
    server = await asyncio.start_server(
        receive_request,
        host="127.0.0.1",
        port=0,
        ssl=server_context,
    )
    port = server.sockets[0].getsockname()[1]
    connector = pinned_tls_http_connector(
        reviewed_cert.read_bytes(),
        reviewed_digest,
    )
    try:
        with pytest.raises(BaseExceptionGroup):
            async with connector(
                f"https://127.0.0.1:{port}/mcp",
                {"Authorization": f"Bearer {SECRET}"},
                0.2,
                1_048_576,
            ) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
    finally:
        server.close()
        await server.wait_closed()

    assert f"Authorization: Bearer {SECRET}\r\n".encode("ascii") in received_headers


def test_pinned_tls_requires_one_reviewed_leaf_certificate(tmp_path: Path) -> None:
    leaf, _, digest = _write_self_signed_tls_identity(tmp_path, name="leaf")
    authority, _, authority_digest = _write_self_signed_tls_identity(
        tmp_path,
        name="authority",
        certificate_authority=True,
    )

    with pytest.raises(DownstreamConfigurationError, match="identity"):
        pinned_tls_http_connector(leaf.read_bytes(), "0" * 64)
    with pytest.raises(DownstreamConfigurationError, match="leaf"):
        pinned_tls_http_connector(authority.read_bytes(), authority_digest)
    with pytest.raises(DownstreamConfigurationError, match="exactly one"):
        pinned_tls_http_connector(leaf.read_bytes() * 2, digest)


def _http_config(**changes: Any) -> DownstreamConfig:
    values: dict[str, Any] = {
        "transport": "http",
        "credential_ref": "keychain://Signet/example",
        "credential_identity_digest": "c" * 64,
        "url": "https://provider.test/mcp",
        "timeout_seconds": 2,
    }
    values.update(changes)
    return DownstreamConfig(**values)


def _stdio_config(**changes: Any) -> DownstreamConfig:
    values: dict[str, Any] = {
        "transport": "stdio",
        "credential_ref": "keychain://Signet/example",
        "credential_identity_digest": "c" * 64,
        "command": ("/opt/signet/bin/provider-mcp", "--mode", "json"),
        "working_directory": Path.home().resolve(),
        "executable_sha256": "a" * 64,
        "execution_snapshot_root": Path("/var/empty/signet-exec").resolve(),
        "timeout_seconds": 2,
    }
    values.update(changes)
    return DownstreamConfig(**values)


def test_credential_generation_identity_is_explicit_and_rotates_with_inventory() -> None:
    original = DownstreamClient("example", _http_config(), _store())
    rotated = DownstreamClient(
        "example",
        _http_config(credential_identity_digest="d" * 64),
        _store(),
    )

    assert original.credential_identity_digest == "c" * 64
    assert rotated.credential_identity_digest == "d" * 64


@asynccontextmanager
async def _test_script_stdio_connector(parameters: Any) -> AsyncIterator[tuple[Any, ...]]:
    async with _official_stdio_connector(
        parameters,
        _test_capability=_TEST_ONLY_SCRIPT_CAPABILITY,
    ) as streams:
        yield streams


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


def _write_oversized_stdio_server(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/python3
import json
import sys
import time

if sys.argv[1] == "partial":
    sys.stdout.write("x" * 2048)
    sys.stdout.flush()
    time.sleep(30)
else:
    for line in sys.stdin:
        request = json.loads(line)
        if request.get("method") != "initialize":
            continue
        result = {
            "protocolVersion": request["params"]["protocolVersion"],
            "capabilities": {},
            "serverInfo": {"name": "oversized", "version": "1.0.0"},
            "padding": "x" * 2048,
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
        self.http_calls: list[tuple[str, dict[str, str], float, int]] = []
        self.stdio_parameters: list[StdioServerParameters] = []
        self.session_timeouts: list[timedelta] = []

    @asynccontextmanager
    async def http(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
        output_limit: int,
    ) -> AsyncIterator[tuple[Any, Any, Any]]:
        self.http_calls.append((url, dict(headers), timeout, output_limit))
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
                1_048_576,
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
async def test_discovery_passes_configured_byte_and_time_bounds_to_mirror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    async def bounded_discovery(session: Any, **bounds: Any) -> list[dict[str, Any]]:
        del session
        observed.update(bounds)
        return []

    monkeypatch.setattr("signet.downstream._discover_all_tools", bounded_discovery)
    events: list[str] = []
    factories = FakeFactories(FakeSession(events))
    client = DownstreamClient(
        "example",
        _http_config(timeout_seconds=1.25, output_limit_bytes=1234),
        _store(),
        http_connector=factories.http,
        stdio_connector=factories.stdio,
        session_factory=factories.session_factory,
    )
    async with client:
        assert await client.discover_all_tools() == []
    assert observed == {"max_aggregate_bytes": 1234, "timeout_seconds": 1.25}


@pytest.mark.asyncio
async def test_stdio_uses_pinned_direct_argv_and_minimal_redacted_alias_environment(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    factories = FakeFactories(FakeSession(events))
    tmp_path.chmod(0o700)
    client = DownstreamClient(
        "whatsapp-local",
        _stdio_config(working_directory=tmp_path),
        _store(),
        http_connector=factories.http,
        stdio_connector=factories.stdio,
        session_factory=factories.session_factory,
    )

    async with client:
        parameters = factories.stdio_parameters[0]
        assert parameters.command == "/opt/signet/bin/provider-mcp"
        assert parameters.args == ["--mode", "json"]
        assert parameters.cwd == tmp_path
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
        ),
        _store(),
        stdio_connector=_test_script_stdio_connector,
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
        ),
        _store(),
        stdio_connector=_test_script_stdio_connector,
    )
    with pytest.raises(DownstreamConnectionError, match="initialization failed"):
        await client.start()
    await client.close()


@pytest.mark.parametrize("mode", ["partial", "json"])
@pytest.mark.asyncio
async def test_official_stdio_launcher_rejects_oversized_frames_before_parsing(
    tmp_path: Path, mode: str
) -> None:
    executable = tmp_path / "provider-mcp"
    _write_oversized_stdio_server(executable)
    client = DownstreamClient(
        "example",
        _stdio_config(
            command=(str(executable), mode),
            working_directory=tmp_path,
            executable_sha256=_executable_digest(executable),
            execution_snapshot_root=tmp_path / "snapshots",
            output_limit_bytes=1024,
        ),
        _store(),
        stdio_connector=_test_script_stdio_connector,
    )
    with pytest.raises(DownstreamConnectionError, match="initialization failed"):
        await client.start()
    await client.close()
    assert list((tmp_path / "snapshots").iterdir()) == []


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
    raw = cast(
        dict[str, Any],
        {
            "content": [{"type": "text", "text": '{"id":"one"}'}],
            "structuredContent": {"id": "one"},
            "isError": False,
            "_meta": {"x-provider": None},
            "x-result-extension": [1, None, {"kept": True}],
        },
    )
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


def test_serialized_downstream_config_cannot_enable_script_execution() -> None:
    values = _stdio_config().model_dump()
    values["test_only_allow_script"] = True

    with pytest.raises(ValueError, match="test_only_allow_script"):
        DownstreamConfig(**values)


def test_stdio_configuration_requires_explicit_existing_private_canonical_working_directory(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    symlink = tmp_path / "linked"
    symlink.symlink_to(private, target_is_directory=True)
    noncanonical = private / ".." / "private"
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o770)
    unsafe.chmod(0o770)

    for working_directory in (
        None,
        Path("relative"),
        tmp_path / "missing",
        symlink,
        noncanonical,
        unsafe,
    ):
        with pytest.raises(DownstreamConfigurationError, match="stdio"):
            DownstreamClient(
                "example",
                _stdio_config(working_directory=working_directory),
                _store(),
            )


def test_stdio_configuration_rejects_foreign_owned_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    monkeypatch.setattr("signet.reviewed_process.os.geteuid", lambda: private.stat().st_uid + 1)

    with pytest.raises(DownstreamConfigurationError, match="mode-0700"):
        DownstreamClient(
            "example",
            _stdio_config(working_directory=private),
            _store(),
        )


@pytest.mark.asyncio
async def test_stdio_launcher_rejects_working_directory_replaced_after_configuration(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider-mcp"
    _write_fake_stdio_server(executable)
    working_directory = tmp_path / "working"
    working_directory.mkdir(mode=0o700)
    original = tmp_path / "original"
    client = DownstreamClient(
        "example",
        _stdio_config(
            command=(str(executable), str(tmp_path / "unused.json")),
            working_directory=working_directory,
            executable_sha256=_executable_digest(executable),
            execution_snapshot_root=tmp_path / "snapshots",
        ),
        _store(),
        stdio_connector=_test_script_stdio_connector,
    )
    working_directory.rename(original)
    working_directory.mkdir(mode=0o700)

    with pytest.raises(DownstreamConnectionError, match="initialization failed"):
        await client.start()
    await client.close()


@pytest.mark.asyncio
async def test_stdio_launcher_binds_checked_working_directory_across_last_moment_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "provider-mcp"
    _write_fake_stdio_server(executable)
    working_directory = tmp_path / "working"
    working_directory.mkdir(mode=0o700)
    original = tmp_path / "original"
    real_open_process = anyio.open_process
    swapped = False

    async def swap_then_open(*args: Any, **kwargs: Any) -> Any:
        nonlocal swapped
        if not swapped:
            working_directory.rename(original)
            working_directory.mkdir(mode=0o700)
            swapped = True
        return await real_open_process(*args, **kwargs)

    monkeypatch.setattr("signet.downstream.anyio.open_process", swap_then_open)
    client = DownstreamClient(
        "example",
        _stdio_config(
            command=(str(executable), "environment.json"),
            working_directory=working_directory,
            executable_sha256=_executable_digest(executable),
            execution_snapshot_root=tmp_path / "snapshots",
        ),
        _store(),
        stdio_connector=_test_script_stdio_connector,
    )

    async with client:
        assert client.is_running

    assert (original / "environment.json").is_file()
    assert not (working_directory / "environment.json").exists()


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
        url: str,
        headers: Mapping[str, str],
        timeout: float,
        output_limit: int,
    ) -> AsyncIterator[tuple[Any, Any, Any]]:
        del url, timeout, output_limit
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


class _ChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self.chunks = chunks
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_http_json_stream_is_bounded_before_body_buffering() -> None:
    source = _ChunkStream((b'{"value":"', b"x" * 20, b'"}'))
    bounded = _BoundedHTTPResponseStream(
        source,
        limit_bytes=16,
        event_stream=False,
    )
    with pytest.raises(DownstreamProtocolError, match="HTTP response exceeds"):
        async for _chunk in bounded:
            pass
    await bounded.aclose()
    assert source.closed


@pytest.mark.asyncio
async def test_http_sse_stream_bounds_each_event_and_resets_on_delimiter() -> None:
    valid_source = _ChunkStream((b"data: 1234\n\n", b"data: 5678\r\n\r\n"))
    valid = _BoundedHTTPResponseStream(
        valid_source,
        limit_bytes=16,
        event_stream=True,
    )
    assert b"".join([chunk async for chunk in valid]) == (b"data: 1234\n\ndata: 5678\r\n\r\n")

    oversized = _BoundedHTTPResponseStream(
        _ChunkStream((b"data: ", b"x" * 20)),
        limit_bytes=16,
        event_stream=True,
    )
    with pytest.raises(DownstreamProtocolError, match="SSE event exceeds"):
        async for _chunk in oversized:
            pass


@pytest.mark.asyncio
async def test_http_stream_rejects_compression_before_decompression() -> None:
    source = _ChunkStream((b"compressed",))
    response = httpx.Response(
        200,
        headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
        stream=source,
    )
    hook = _bounded_response_hook(32)
    with pytest.raises(DownstreamProtocolError, match="compressed"):
        await hook(response)
    assert source.closed
