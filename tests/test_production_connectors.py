from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

import pytest

from signet.canonical import canonical_json, sha256_hex
from signet.mcp_mirror import tool_schema_digest
from signet.production_connectors import (
    CredentialBoundClient,
    ProductionConnectorError,
    ProviderSessionPool,
)


class _RecordingClient:
    def __init__(self, *, secret: str = "provider-secret-value") -> None:
        self.secret = secret
        self.events: list[str] = []

    async def start(self) -> None:
        self.events.append("start")

    async def close(self) -> None:
        self.events.append("close")

    async def call_tool(self, tool_name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        self.events.append(f"call:{tool_name}")
        return {"arguments": dict(arguments)}

    async def call_tool_raw(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.events.append(f"raw:{tool_name}")
        return {"arguments": dict(arguments)}

    def __repr__(self) -> str:
        return f"_RecordingClient(secret={self.secret!r})"


class _FailingStartClient(_RecordingClient):
    async def start(self) -> None:
        self.events.append("start")
        raise RuntimeError(self.secret)


class _BlockingStartClient(_RecordingClient):
    def __init__(self) -> None:
        super().__init__()
        self.start_entered = asyncio.Event()

    async def start(self) -> None:
        self.events.append("start")
        self.start_entered.set()
        await asyncio.Event().wait()


class _CancellingCleanupClient(_BlockingStartClient):
    async def close(self) -> None:
        self.events.append("close")
        raise asyncio.CancelledError


class _CancellingCloseClient(_RecordingClient):
    async def close(self) -> None:
        self.events.append("close")
        raise asyncio.CancelledError


class _RuntimeFailingClient(_RecordingClient):
    def __init__(self) -> None:
        super().__init__()
        self.running = False

    @property
    def is_running(self) -> bool:
        return self.running

    async def start(self) -> None:
        self.events.append("start")
        self.running = True

    async def close(self) -> None:
        self.events.append("close")
        self.running = False


class _SlowCloseClient(_RecordingClient):
    def __init__(self) -> None:
        super().__init__()
        self.close_started = asyncio.Event()
        self.closed = asyncio.Event()

    async def close(self) -> None:
        self.close_started.set()
        await asyncio.sleep(0.05)
        self.events.append("close")
        self.closed.set()


class _DiscoveringClient(_RecordingClient):
    def __init__(
        self,
        *,
        tools: list[dict[str, object]] | None = None,
        initialization_identity: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self._tools = tools or [_send_email_tool()]
        self.initialization_identity = dict(
            initialization_identity
            or {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "fake-fastmail", "version": "1.0.0"},
                "capabilities": {"tools": {}},
            }
        )

    async def discover_all_tools(self) -> list[dict[str, object]]:
        return self._tools


def _send_email_tool() -> dict[str, object]:
    return {
        "name": "send_email",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {},
        },
    }


def _server_identity_digest(client: _DiscoveringClient) -> str:
    return sha256_hex(canonical_json(dict(client.initialization_identity)))


@pytest.mark.asyncio
async def test_credential_bound_client_forwards_without_exposing_credential_material() -> None:
    delegate = _RecordingClient()
    client = CredentialBoundClient(
        alias="whatsapp",
        credential_identity_digest="a" * 64,
        delegate=delegate,
    )

    assert client.credential_identity_digest == "a" * 64
    assert await client.call_tool("send_text", {"to": "+15551234567"}) == {
        "arguments": {"to": "+15551234567"}
    }
    assert await client.call_tool_raw("send_text", {"to": "+15551234567"}) == {
        "arguments": {"to": "+15551234567"}
    }
    assert delegate.events == ["call:send_text", "raw:send_text"]
    assert delegate.secret not in repr(client)
    assert "redacted" in repr(client)


@pytest.mark.asyncio
async def test_credential_bound_client_reports_only_its_current_lifecycle_generation() -> None:
    delegate = _RuntimeFailingClient()
    client = CredentialBoundClient(
        alias="whatsapp",
        credential_identity_digest="a" * 64,
        delegate=delegate,
    )

    assert client.is_running is False
    await client.start()
    assert client.is_running is True
    delegate.running = False
    assert client.is_running is False
    await client.close()
    assert client.is_running is False


@pytest.mark.parametrize(
    ("alias", "digest"),
    (("bad alias", "a" * 64), ("whatsapp", "not-a-digest")),
)
def test_credential_bound_client_rejects_ambiguous_identity(alias: str, digest: str) -> None:
    with pytest.raises(ValueError, match="identity"):
        CredentialBoundClient(alias=alias, credential_identity_digest=digest, delegate=object())


@pytest.mark.asyncio
async def test_provider_session_pool_shares_one_lifecycle_across_consumers() -> None:
    delegate = _RecordingClient()
    pool = ProviderSessionPool({"fastmail": delegate})

    async with pool.run():
        async with pool.run():
            assert delegate.events == ["start"]
        assert delegate.events == ["start"]

    assert delegate.events == ["start", "close"]


@pytest.mark.asyncio
async def test_provider_session_pool_fails_holder_when_a_live_client_terminates() -> None:
    client = _RuntimeFailingClient()
    pool = ProviderSessionPool({"fastmail": client})
    entered = asyncio.Event()

    async def serve() -> None:
        async with pool.run():
            entered.set()
            await asyncio.Event().wait()

    holder = asyncio.create_task(serve())
    await entered.wait()
    assert pool.active is True

    client.running = False
    await asyncio.sleep(0.1)

    assert holder.done()
    with pytest.raises(asyncio.CancelledError):
        await holder
    assert pool.active is False
    assert client.events == ["start", "close"]


@pytest.mark.asyncio
async def test_provider_session_pool_repeated_cancellation_awaits_client_cleanup() -> None:
    client = _SlowCloseClient()
    pool = ProviderSessionPool({"fastmail": client})
    entered = asyncio.Event()

    async def hold_session() -> None:
        async with pool.run():
            entered.set()
            await asyncio.Event().wait()

    holder = asyncio.create_task(hold_session())
    await entered.wait()
    holder.cancel()
    await client.close_started.wait()
    holder.cancel()

    with pytest.raises(asyncio.CancelledError):
        await holder

    assert client.closed.is_set()
    assert pool.active is False
    assert client.events == ["start", "close"]


@pytest.mark.asyncio
async def test_provider_session_pool_rolls_back_and_redacts_start_failure() -> None:
    first = _RecordingClient()
    second = _FailingStartClient(secret="never-leak-this-secret")
    pool = ProviderSessionPool({"fastmail": first, "whatsapp": second})

    with pytest.raises(ProductionConnectorError) as captured:
        async with pool.run():
            raise AssertionError("unreachable")

    assert first.events == ["start", "close"]
    assert second.events == ["start", "close"]
    assert second.secret not in str(captured.value)
    assert second.secret not in repr(captured.value)


@pytest.mark.asyncio
async def test_provider_session_pool_cancellation_rolls_back_without_reactivation() -> None:
    client = _BlockingStartClient()
    pool = ProviderSessionPool({"fastmail": client})

    async def activate() -> None:
        async with pool.run():
            pytest.fail("cancelled startup must not activate the provider")

    starting = asyncio.create_task(activate())
    await client.start_entered.wait()
    starting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await starting

    assert client.events == ["start", "close"]


@pytest.mark.asyncio
async def test_provider_session_pool_preserves_cancellation_when_cleanup_cancels() -> None:
    client = _CancellingCleanupClient()
    pool = ProviderSessionPool({"fastmail": client})

    async def activate() -> None:
        async with pool.run():
            pytest.fail("cancelled startup must not activate the provider")

    starting = asyncio.create_task(activate())
    await client.start_entered.wait()
    starting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await starting

    assert client.events == ["start", "close"]


@pytest.mark.asyncio
async def test_provider_session_pool_preserves_active_call_cancellation_when_close_cancels() -> (
    None
):
    client = _CancellingCloseClient()
    pool = ProviderSessionPool({"fastmail": client})

    with pytest.raises(asyncio.CancelledError):
        async with pool.run():
            raise asyncio.CancelledError

    assert client.events == ["start", "close"]


@pytest.mark.asyncio
async def test_provider_session_pool_rejects_calls_after_failed_start_without_leaking_details() -> (
    None
):
    failing = _FailingStartClient(secret="never-leak-this-secret")
    pool = ProviderSessionPool({"fastmail": failing})

    for _ in range(2):
        with pytest.raises(ProductionConnectorError, match="fastmail"):
            async with pool.run():
                raise AssertionError("unreachable")

    assert failing.events == ["start", "close", "start", "close"]


@pytest.mark.asyncio
async def test_provider_session_pool_rejects_live_schema_drift_before_use() -> None:
    client = _DiscoveringClient()
    pool = ProviderSessionPool(
        {"fastmail": client},
        expected_schema_digests={"fastmail": {"send_email": "f" * 64}},
    )

    with pytest.raises(ProductionConnectorError, match="startup failed") as captured:
        async with pool.run():
            pytest.fail("schema drift must prevent provider activation")

    assert "schema drift" not in str(captured.value)
    assert client.events == ["start", "close"]


@pytest.mark.asyncio
async def test_provider_session_pool_binds_exact_initialize_identity_and_tool_set() -> None:
    client = _DiscoveringClient()
    pool = ProviderSessionPool(
        {"fastmail": client},
        expected_schema_digests={
            "fastmail": {"send_email": tool_schema_digest(_send_email_tool())}
        },
        expected_server_identity_digests={
            "fastmail": _server_identity_digest(client),
        },
    )

    async with pool.run():
        assert client.events == ["start"]

    assert client.events == ["start", "close"]


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", ["initialize", "extra_tool"])
async def test_provider_session_pool_rejects_unreviewed_live_identity(
    drift: str,
) -> None:
    reviewed = _DiscoveringClient()
    live_tools = [_send_email_tool()]
    live_identity = dict(reviewed.initialization_identity)
    if drift == "initialize":
        live_identity["serverInfo"] = {"name": "fake-fastmail", "version": "2.0.0"}
    else:
        live_tools.append(
            {
                "name": "unreviewed_admin_tool",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {},
                },
            }
        )
    client = _DiscoveringClient(tools=live_tools, initialization_identity=live_identity)
    pool = ProviderSessionPool(
        {"fastmail": client},
        expected_schema_digests={
            "fastmail": {"send_email": tool_schema_digest(_send_email_tool())}
        },
        expected_server_identity_digests={
            "fastmail": _server_identity_digest(reviewed),
        },
    )

    with pytest.raises(ProductionConnectorError, match="startup failed"):
        async with pool.run():
            pytest.fail("unreviewed provider identity must prevent activation")

    assert client.events == ["start", "close"]
