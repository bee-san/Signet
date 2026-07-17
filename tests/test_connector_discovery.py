from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from signet.canonical import canonical_json
from signet.connector_discovery import (
    ConnectorDiscoveryError,
    ConnectorDiscoveryService,
    LiveToolsPage,
    strict_fixture_json,
)
from signet.db import Database
from signet.integration_store import SQLiteIntegrationStore
from signet.mcp_mirror import tool_schema_digest
from signet.plugin_manifest import load_reference_discovery_fixture, load_reference_plugin

NOW = 2_100_000_000


@pytest.fixture
def store(tmp_path: Path) -> SQLiteIntegrationStore:
    database = Database(tmp_path / "approval.sqlite3")
    database.initialize()
    result = SQLiteIntegrationStore(database)
    result.install_plugin(load_reference_plugin("fastmail"), installed_at=NOW)
    result.configure_connector(
        plugin_id="signet.fastmail",
        connector_id="fastmail",
        alias="mail",
        config={"transport": "stdio", "command_ref": "fake-fastmail"},
        configured_at=NOW + 1,
    )
    return result


def tool(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"Fake {name}",
        "inputSchema": {"type": "object", "additionalProperties": False},
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    }


class FakeLiveClient:
    def __init__(self) -> None:
        self.initialize_calls = 0
        self.list_cursors: list[str | None] = []
        self.call_tool_calls = 0

    async def initialize(self) -> dict[str, Any]:
        self.initialize_calls += 1
        return {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "fake-fastmail", "version": "1.0"},
        }

    async def list_tools(self, cursor: str | None) -> LiveToolsPage:
        self.list_cursors.append(cursor)
        if cursor is None:
            return LiveToolsPage((tool("search_email"),), "second")
        assert cursor == "second"
        return LiveToolsPage((tool("read_email"),), None)

    async def call_tool(self, _name: str, _arguments: dict[str, Any]) -> None:
        self.call_tool_calls += 1
        raise AssertionError("staged discovery must never invoke tools/call")


class ReconfiguringLiveClient(FakeLiveClient):
    def __init__(self, store: SQLiteIntegrationStore) -> None:
        super().__init__()
        self._store = store

    async def initialize(self) -> dict[str, Any]:
        self._store.configure_connector(
            plugin_id="signet.fastmail",
            connector_id="fastmail",
            alias="mail",
            config={"transport": "stdio", "command_ref": "replacement-fastmail"},
            configured_at=NOW + 2,
        )
        return await super().initialize()


@pytest.mark.asyncio
async def test_fixture_discovery_is_staged_unreviewed_and_removal_is_durable(
    store: SQLiteIntegrationStore,
) -> None:
    service = ConnectorDiscoveryService.staged(store)
    fixture = load_reference_discovery_fixture("fastmail")

    outcome = await service.discover_fixture("mail", fixture, discovered_at=NOW + 2)
    assert outcome.discovery.source == "fixture"
    assert outcome.discovery.tool_count == 5
    assert not outcome.schema_refresh.list_changed
    assert store.current_valid_review("mail", "search_email") is None
    with store.database.read() as connection:
        assert connection.execute("SELECT count(*) FROM schema_cache").fetchone()[0] == 0

    removed = await service.discover_fixture("mail", {"tools": []}, discovered_at=NOW + 3)
    assert removed.discovery.tool_count == 0
    assert all(not item.present for item in store.current_tools("mail", include_removed=True))
    with store.database.read() as connection:
        assert connection.execute("SELECT count(*) FROM schema_cache").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_staged_discovery_never_mutates_live_schema_cache(
    store: SQLiteIntegrationStore,
) -> None:
    service = ConnectorDiscoveryService.staged(store)
    live_tool = tool("live_read")
    live_digest = tool_schema_digest(live_tool)
    with store.database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO schema_cache(
                downstream_alias, tool_name, schema_digest, tool_schema_json,
                discovered_at, review_state, reviewed_at, present
            ) VALUES (?, ?, ?, ?, ?, 'approved', ?, 1)
            """,
            (
                "mail",
                "live_read",
                live_digest,
                canonical_json(live_tool),
                NOW,
                NOW,
            ),
        )
    with store.database.read() as connection:
        before = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM schema_cache ORDER BY downstream_alias, tool_name"
            )
        )

    outcome = await service.discover_fixture(
        "mail",
        load_reference_discovery_fixture("fastmail"),
        discovered_at=NOW + 2,
    )

    with store.database.read() as connection:
        after = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM schema_cache ORDER BY downstream_alias, tool_name"
            )
        )
    assert after == before
    assert outcome.schema_refresh.changed_tools
    assert not outcome.schema_refresh.list_changed
    assert outcome.schema_refresh.notifications_sent == 0


@pytest.mark.asyncio
async def test_live_discovery_requires_opt_in_paginates_and_never_calls_tools(
    store: SQLiteIntegrationStore,
) -> None:
    service = ConnectorDiscoveryService.staged(store)
    client = FakeLiveClient()

    with pytest.raises(ConnectorDiscoveryError, match="explicit"):
        await service.discover_live("mail", client, live_discovery=False, discovered_at=NOW + 2)
    assert client.initialize_calls == 0

    outcome = await service.discover_live(
        "mail", client, live_discovery=True, discovered_at=NOW + 3
    )
    assert outcome.discovery.tool_count == 2
    assert client.initialize_calls == 1
    assert client.list_cursors == [None, "second"]
    assert client.call_tool_calls == 0
    assert [item.tool_name for item in store.current_tools("mail")] == [
        "read_email",
        "search_email",
    ]


@pytest.mark.asyncio
async def test_live_discovery_rejects_connector_generation_changed_during_network_io(
    store: SQLiteIntegrationStore,
) -> None:
    service = ConnectorDiscoveryService.staged(store)
    original_config_digest = store.active_connector("mail").config_digest

    with pytest.raises(ConnectorDiscoveryError, match="connector changed during discovery"):
        await service.discover_live(
            "mail",
            ReconfiguringLiveClient(store),
            live_discovery=True,
            discovered_at=NOW + 3,
            expected_config_digest=original_config_digest,
        )

    assert store.current_tools("mail") == ()
    with store.database.read() as connection:
        run_count = connection.execute("SELECT count(*) FROM connector_discovery_runs").fetchone()[
            0
        ]
    assert run_count == 0


class RepeatingCursorClient(FakeLiveClient):
    async def list_tools(self, cursor: str | None) -> LiveToolsPage:
        self.list_cursors.append(cursor)
        return LiveToolsPage((), "repeat")


class HangingClient(FakeLiveClient):
    async def initialize(self) -> dict[str, Any]:
        self.initialize_calls += 1
        await asyncio.sleep(60)
        raise AssertionError("sleep should be cancelled")


@pytest.mark.asyncio
async def test_live_failures_are_bounded_recorded_and_leave_no_current_tools(
    store: SQLiteIntegrationStore,
) -> None:
    repeated = RepeatingCursorClient()
    service = ConnectorDiscoveryService.staged(store, timeout_seconds=0.01)
    with pytest.raises(ConnectorDiscoveryError, match="cursor"):
        await service.discover_live("mail", repeated, live_discovery=True, discovered_at=NOW + 2)
    assert repeated.call_tool_calls == 0

    hanging = HangingClient()
    with pytest.raises(ConnectorDiscoveryError, match="timed out"):
        await service.discover_live("mail", hanging, live_discovery=True, discovered_at=NOW + 3)
    assert hanging.call_tool_calls == 0
    assert store.current_tools("mail") == ()
    with store.database.read() as connection:
        errors = connection.execute(
            """
            SELECT error_code FROM connector_discovery_runs
            WHERE status = 'failed' ORDER BY discovered_at
            """
        ).fetchall()
    assert [row["error_code"] for row in errors] == ["protocol_error", "timeout"]


@pytest.mark.asyncio
async def test_live_cancellation_propagates_without_recording_a_failure(
    store: SQLiteIntegrationStore,
) -> None:
    service = ConnectorDiscoveryService.staged(store)
    task = asyncio.create_task(
        service.discover_live("mail", HangingClient(), live_discovery=True, discovered_at=NOW + 2)
    )
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert store.discovery_detail("mail") is None


def test_fixture_parser_rejects_duplicate_nonfinite_and_unbounded_input() -> None:
    with pytest.raises(ConnectorDiscoveryError, match="duplicate"):
        strict_fixture_json(b'{"tools":[],"tools":[]}')
    with pytest.raises(ConnectorDiscoveryError, match="non-finite"):
        strict_fixture_json(b'{"tools":[],"value":NaN}')
    with pytest.raises(ConnectorDiscoveryError, match="byte limit"):
        strict_fixture_json(b'{"tools":[]}', max_bytes=2)
    with pytest.raises(ValueError, match="byte limit"):
        strict_fixture_json(b'{"tools":[]}', max_bytes=0)
