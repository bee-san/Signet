from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, cast

import httpx
import mcp.types as types
import pytest
from argon2 import PasswordHasher
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from starlette.testclient import TestClient

from signet.app import main
from signet.credential_broker import IssuedToken, TokenRegistry
from signet.gateway_tools import GatewayPrincipal, GatewayToolSurface
from signet.mcp_mirror import AliasToolSurface, InvocationIdentity, SchemaMirror
from signet.policy import parse_policy
from signet.runtime import (
    APPROVALS_ALIAS,
    MCPRuntime,
    RegistryTokenVerifier,
    RuntimeAssemblyError,
    assemble_mcp_runtime,
    gateway_principal_provider,
)


@dataclass(frozen=True, slots=True)
class AuthFixture:
    registry: TokenRegistry
    all_aliases: IssuedToken
    same_profile_second_token: IssuedToken
    approvals_only: IssuedToken
    fastmail_only: IssuedToken


@dataclass(slots=True)
class FakeGatewayTools:
    principals: list[GatewayPrincipal]

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "whoami",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "maxProperties": 0,
                },
            }
        ]

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        principal: GatewayPrincipal,
    ) -> dict[str, Any]:
        assert name == "whoami"
        assert arguments == {}
        self.principals.append(principal)
        value = {"namespace": principal.namespace, "user_id": principal.user_id}
        return {
            "content": [{"type": "text", "text": json.dumps(value, separators=(",", ":"))}],
            "structuredContent": value,
            "isError": False,
        }


@dataclass(slots=True)
class RuntimeHarness:
    runtime: MCPRuntime
    alias_calls: list[tuple[str, str, dict[str, Any], str]]
    gateway_tools: FakeGatewayTools
    alias_surface: AliasToolSurface


@pytest.fixture(scope="module")
def auth() -> AuthFixture:
    registry = TokenRegistry(
        password_hasher=PasswordHasher(
            time_cost=1,
            memory_cost=32,
            parallelism=1,
            hash_len=16,
            salt_len=8,
        )
    )
    return AuthFixture(
        registry=registry,
        all_aliases=registry.issue("profile:one", {"fastmail", APPROVALS_ALIAS}),
        same_profile_second_token=registry.issue(
            "profile:one", {"fastmail", APPROVALS_ALIAS}
        ),
        approvals_only=registry.issue("profile:one", {APPROVALS_ALIAS}),
        fastmail_only=registry.issue("profile:one", {"fastmail"}),
    )


def alias_surface(
    call_handler: Callable[
        [str, str, dict[str, Any], str],
        Any,
    ],
) -> AliasToolSurface:
    policy = parse_policy(
        {
            "version": 1,
            "default_mode": "deny",
            "downstreams": {
                "fastmail": {
                    "transport": "http",
                    "url": "https://provider.example.test/mcp",
                    "tools": {
                        "read_mail": {
                            "mode": "passthrough",
                            "reviewed_read_only": True,
                        }
                    },
                }
            },
        }
    )
    mirror = SchemaMirror(policy)
    mirror.capture(
        "fastmail",
        [
            {
                "name": "read_mail",
                "description": "Read safe fixture metadata.",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "maxProperties": 0,
                },
            }
        ],
    )
    digest = mirror.captured_digest("fastmail", "read_mail")
    mirror.approve_schema("fastmail", "read_mail", digest)

    async def invoke(
        alias: str,
        tool: str,
        arguments: Any,
        namespace: str,
        identity: InvocationIdentity,
    ) -> dict[str, Any]:
        del identity
        result = call_handler(alias, tool, dict(arguments), namespace)
        if asyncio.iscoroutine(result):
            return cast(dict[str, Any], await result)
        return cast(dict[str, Any], result)

    return AliasToolSurface(alias="fastmail", mirror=mirror, call_handler=invoke)


def make_runtime(
    auth: AuthFixture,
    *,
    handler: Callable[[str, str, dict[str, Any], str], Any] | None = None,
    json_response: bool = False,
) -> RuntimeHarness:
    calls: list[tuple[str, str, dict[str, Any], str]] = []

    def default_handler(
        alias: str,
        tool: str,
        arguments: dict[str, Any],
        namespace: str,
    ) -> dict[str, Any]:
        calls.append((alias, tool, arguments, namespace))
        value = {"status": "read", "namespace": namespace}
        return {
            "content": [{"type": "text", "text": json.dumps(value, separators=(",", ":"))}],
            "structuredContent": value,
            "isError": False,
        }

    selected_handler = handler or default_handler
    gateway_tools = FakeGatewayTools([])
    approvals = GatewayToolSurface(
        tools=cast(Any, gateway_tools),
        principal_provider=gateway_principal_provider("human:one"),
    )
    surface = alias_surface(selected_handler)
    runtime = assemble_mcp_runtime(
        aliases={"fastmail": surface},
        approvals=approvals,
        tokens=auth.registry,
        json_response=json_response,
    )
    return RuntimeHarness(runtime, calls, gateway_tools, surface)


@asynccontextmanager
async def http_client(
    runtime: MCPRuntime,
    token: IssuedToken | None = None,
) -> AsyncIterator[httpx.AsyncClient]:
    headers = {"Authorization": f"Bearer {token.token}"} if token is not None else {}
    async with runtime.app.router.lifespan_context(runtime.app), httpx.AsyncClient(
        transport=httpx.ASGITransport(app=runtime.app),
        base_url="http://localhost:8789",
        headers=headers,
    ) as client:
        yield client


def initialize_message() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": types.LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "runtime-test", "version": "1"},
        },
    }


def test_assembly_is_injected_local_only_and_uses_one_manager_per_path(
    auth: AuthFixture,
) -> None:
    harness = make_runtime(auth)

    assert set(harness.runtime.managers) == {"fastmail", APPROVALS_ALIAS}
    assert harness.runtime.managers["fastmail"].stateless is False
    assert harness.runtime.managers[APPROVALS_ALIAS].stateless is True
    assert harness.runtime.allowed_hosts == frozenset(
        {"127.0.0.1", "127.0.0.1:8789", "localhost", "localhost:8789"}
    )
    assert harness.alias_calls == []
    assert harness.gateway_tools.principals == []

    with pytest.raises(RuntimeAssemblyError, match="loopback"):
        assemble_mcp_runtime(
            aliases={},
            approvals=GatewayToolSurface(
                tools=cast(Any, FakeGatewayTools([])),
                principal_provider=gateway_principal_provider("human:one"),
            ),
            tokens=auth.registry,
            bind_host="0.0.0.0",
        )


def test_health_is_privacy_safe_host_guarded_and_has_no_ui_routes(auth: AuthFixture) -> None:
    harness = make_runtime(auth)
    with TestClient(harness.runtime.app, base_url="http://localhost:8789") as client:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
        assert response.headers["cache-control"] == "no-store"
        assert "fastmail" not in response.text

        assert client.get("/").status_code == 404
        assert client.get("/docs").status_code == 404
        assert client.get("/mcp").status_code == 404
        rejected = client.get("/healthz", headers={"Host": "attacker.example"})
        assert rejected.status_code == 421
        assert "fastmail" not in rejected.text


def test_mcp_listener_rejects_declared_oversized_body_before_auth(auth: AuthFixture) -> None:
    harness = make_runtime(auth)
    with TestClient(harness.runtime.app, base_url="http://localhost:8789") as client:
        response = client.post(
            "/mcp/fastmail",
            content=b"{}",
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(16 * 1024 * 1024 + 1),
            },
        )
    assert response.status_code == 413
    assert response.headers["cache-control"] == "no-store"
    assert harness.alias_calls == []


@pytest.mark.asyncio
async def test_bearer_auth_alias_scope_and_transport_security(auth: AuthFixture) -> None:
    harness = make_runtime(auth)
    async with http_client(harness.runtime) as client:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        missing = await client.post(
            "/mcp/fastmail", headers=headers, json=initialize_message()
        )
        assert missing.status_code == 401
        assert missing.headers["www-authenticate"].startswith("Bearer")

        wrong_scope = await client.post(
            "/mcp/fastmail",
            headers={
                **headers,
                "Authorization": f"Bearer {auth.approvals_only.token}",
            },
            json=initialize_message(),
        )
        assert wrong_scope.status_code == 401

        bad_host = await client.post(
            "/mcp/fastmail",
            headers={
                **headers,
                "Host": "attacker.example",
                "Authorization": f"Bearer {auth.all_aliases.token}",
            },
            json=initialize_message(),
        )
        assert bad_host.status_code == 421

        bad_origin = await client.post(
            "/mcp/fastmail",
            headers={
                **headers,
                "Origin": "https://attacker.example",
                "Authorization": f"Bearer {auth.all_aliases.token}",
            },
            json=initialize_message(),
        )
        assert bad_origin.status_code == 403


@pytest.mark.asyncio
async def test_stateful_alias_preserves_exact_profile_namespace(auth: AuthFixture) -> None:
    harness = make_runtime(auth)
    async with (
        http_client(harness.runtime, auth.all_aliases) as client,
        streamable_http_client(
            "http://localhost:8789/mcp/fastmail", http_client=client
        ) as (read_stream, write_stream, get_session_id),
        ClientSession(read_stream, write_stream) as session,
    ):
        initialized = await session.initialize()
        assert initialized.serverInfo.name == "Signet"
        assert get_session_id() is not None
        listed = await session.list_tools()
        assert [tool.name for tool in listed.tools] == ["read_mail"]
        result = await session.call_tool("read_mail", {})
        assert result.isError is False
        assert result.structuredContent == {
            "status": "read",
            "namespace": "profile:one",
        }

    assert harness.alias_calls == [
        ("fastmail", "read_mail", {}, "profile:one")
    ]


@pytest.mark.asyncio
async def test_stateful_session_is_bound_to_token_and_delete_cancels_it(
    auth: AuthFixture,
) -> None:
    harness = make_runtime(auth)
    session_id: str | None = None
    async with http_client(harness.runtime, auth.all_aliases) as client:
        async with (
            streamable_http_client(
                "http://localhost:8789/mcp/fastmail",
                http_client=client,
                terminate_on_close=False,
            ) as (read_stream, write_stream, get_session_id),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            session_id = get_session_id()
            assert session_id is not None

        stolen = await client.delete(
            "/mcp/fastmail",
            headers={
                "Authorization": f"Bearer {auth.same_profile_second_token.token}",
                "Mcp-Session-Id": session_id,
            },
        )
        assert stolen.status_code == 404

        cancelled = await client.delete(
            "/mcp/fastmail",
            headers={"Mcp-Session-Id": session_id},
        )
        assert cancelled.status_code == 200
        assert session_id not in harness.runtime.managers["fastmail"]._server_instances
        assert harness.alias_surface.tracked_session_count == 0


@pytest.mark.asyncio
async def test_client_cancellation_reaches_in_flight_tool_handler(auth: AuthFixture) -> None:
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def slow_handler(
        alias: str,
        tool: str,
        arguments: dict[str, Any],
        namespace: str,
    ) -> dict[str, Any]:
        del alias, tool, arguments, namespace
        started.set()
        try:
            await asyncio.Future()
        finally:
            cancelled.set()

    harness = make_runtime(auth, handler=slow_handler)
    async with (
        http_client(harness.runtime, auth.all_aliases) as client,
        streamable_http_client(
            "http://localhost:8789/mcp/fastmail",
            http_client=client,
            terminate_on_close=False,
        ) as (read_stream, write_stream, get_session_id),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        task = asyncio.create_task(session.call_tool("read_mail", {}))
        await asyncio.wait_for(started.wait(), timeout=2)
        session_id = get_session_id()
        assert session_id is not None
        response = await client.delete(
            "/mcp/fastmail", headers={"Mcp-Session-Id": session_id}
        )
        assert response.status_code == 200
        await asyncio.wait_for(cancelled.wait(), timeout=2)
        task.cancel()
        with pytest.raises((asyncio.CancelledError, RuntimeError)):
            await task


@pytest.mark.asyncio
async def test_approvals_surface_is_stateless_and_uses_active_profile(auth: AuthFixture) -> None:
    harness = make_runtime(auth)
    async with (
        http_client(harness.runtime, auth.approvals_only) as client,
        streamable_http_client(
            "http://localhost:8789/mcp/approvals", http_client=client
        ) as (read_stream, write_stream, get_session_id),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        assert get_session_id() is None
        listed = await session.list_tools()
        assert [tool.name for tool in listed.tools] == ["whoami"]
        result = await session.call_tool("whoami", {})
        assert result.structuredContent == {
            "namespace": "profile:one",
            "user_id": "human:one",
        }

    assert harness.gateway_tools.principals == [
        GatewayPrincipal(namespace="profile:one", user_id="human:one")
    ]


@pytest.mark.asyncio
async def test_json_mode_and_default_sse_mode_are_both_supported(auth: AuthFixture) -> None:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    sse_harness = make_runtime(auth)
    async with http_client(sse_harness.runtime, auth.all_aliases) as client:
        response = await client.post(
            "/mcp/fastmail", headers=headers, json=initialize_message()
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")

    json_harness = make_runtime(auth, json_response=True)
    async with http_client(json_harness.runtime, auth.all_aliases) as client:
        response = await client.post(
            "/mcp/fastmail", headers=headers, json=initialize_message()
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers.get("mcp-session-id")


@pytest.mark.asyncio
async def test_registry_verifier_redacts_raw_token_and_enforces_alias(auth: AuthFixture) -> None:
    verifier = RegistryTokenVerifier(auth.registry, alias="fastmail")
    verified = await verifier.verify_token(auth.all_aliases.token)
    assert verified is not None
    assert verified.token == "<redacted>"
    assert verified.claims == {
        "iss": "signet:local",
        "namespace": "profile:one",
        "allowed_aliases": [APPROVALS_ALIAS, "fastmail"],
        "token_id": auth.all_aliases.token_id,
    }
    assert auth.all_aliases.token not in repr(verified)
    assert await RegistryTokenVerifier(
        auth.registry, alias="fastmail"
    ).verify_token(auth.approvals_only.token) is None


def test_cli_requires_explicit_factory_and_mcp_loopback() -> None:
    with pytest.raises(SystemExit):
        main([])
    with pytest.raises(SystemExit):
        main(["serve-mcp"])
    with pytest.raises(SystemExit):
        main(
            [
                "serve-mcp",
                "--factory",
                "tests.factories:create_mcp",
                "--host",
                "0.0.0.0",
            ]
        )
    with pytest.raises(SystemExit):
        main(["serve-web", "--factory", "not a factory"])


@pytest.mark.parametrize(
    ("command", "default_port"),
    [("serve-mcp", 8789), ("serve-web", 8790)],
)
def test_cli_runs_only_the_explicit_factory(command: str, default_port: int) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    def runner(app: str, **kwargs: Any) -> None:
        calls.append((app, kwargs))

    main(
        [command, "--factory", "tests.factories:create_app"],
        runner=runner,
    )

    assert calls == [
        (
            "tests.factories:create_app",
            {
                "factory": True,
                "host": "127.0.0.1",
                "port": default_port,
                "server_header": False,
            },
        )
    ]
