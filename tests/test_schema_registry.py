from __future__ import annotations

import asyncio
import copy
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from signet.db import Database
from signet.mcp_mirror import (
    AliasToolSurface,
    SchemaDriftError,
    SchemaMirror,
    tool_schema_digest,
)
from signet.policy import parse_policy
from signet.schema_registry import (
    DurableSchemaRegistry,
    SchemaPublicationError,
    SchemaRegistryError,
)

NOW = 1_900_000_000


def raw_tool(name: str = "read") -> dict[str, Any]:
    return {
        "name": name,
        "description": f"Read with {name}",
        "inputSchema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": False,
        },
        "outputSchema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["value"],
            "properties": {"value": {"type": "string"}},
            "additionalProperties": False,
        },
        "x-provider-contract": {"retained": True},
    }


def policy(*, digest: str | None = None, virtualize: bool = False) -> Any:
    tool: dict[str, Any] = (
        {
            "mode": "virtualize_local",
            "adapter": "example.local.v1",
            "account_ref": "example-account",
        }
        if virtualize
        else {"mode": "passthrough", "reviewed_read_only": True}
    )
    if digest is not None:
        tool["schema_digest"] = digest
    return parse_policy(
        {
            "version": 1,
            "default_mode": "deny",
            "downstreams": {
                "example": {
                    "transport": "http",
                    "url": "https://provider.example.test/mcp",
                    "tools": {"read": tool},
                }
            },
        }
    )


def assembly(
    tmp_path: Path,
    *,
    configured_digest: str | None = None,
    virtualize: bool = False,
    database: Database | None = None,
) -> tuple[Database, SchemaMirror, AliasToolSurface, DurableSchemaRegistry]:
    selected = database or Database(tmp_path / "approval.db")
    if database is None:
        selected.initialize()
    mirror = SchemaMirror(policy(digest=configured_digest, virtualize=virtualize))
    surface = AliasToolSurface(
        alias="example",
        mirror=mirror,
        call_handler=AsyncMock(),
        namespace_provider=lambda: ("profile:test", {"example"}),
        session_clock=lambda: 1.0,
    )
    registry = DurableSchemaRegistry(
        database=selected,
        mirror=mirror,
        surfaces={"example": surface},
    )
    return selected, mirror, surface, registry


def tracked_session(surface: AliasToolSurface, *, failure: bool = False) -> AsyncMock:
    session = AsyncMock()
    if failure:
        session.send_tool_list_changed.side_effect = RuntimeError("private provider failure")
    surface._sessions.add(session)
    surface._session_last_seen[session] = 1.0
    return session


@pytest.mark.asyncio
async def test_capture_review_restart_and_drift_are_durable_and_fail_closed(
    tmp_path: Path,
) -> None:
    database, mirror, surface, registry = assembly(tmp_path)
    session = tracked_session(surface)
    original = raw_tool()

    captured = await registry.refresh("example", [original], discovered_at=NOW)
    assert captured.changed_tools == ("read",)
    assert not captured.list_changed
    assert mirror.list_tools("example") == []
    session.send_tool_list_changed.assert_not_awaited()

    reviewed = await registry.review_current(
        "example", "read", tool_schema_digest(original), reviewed_at=NOW + 1
    )
    assert reviewed.list_changed
    assert reviewed.notifications_sent == 1
    assert [tool["name"] for tool in mirror.list_tools("example")] == ["read"]
    session.send_tool_list_changed.assert_awaited_once()

    _, restored_mirror, _, restored = assembly(tmp_path, database=database)
    restored.restore()
    assert restored_mirror.list_tools("example") == [original]

    changed = copy.deepcopy(original)
    changed["description"] = "Semantically changed provider contract"
    drift = await registry.refresh("example", [changed], discovered_at=NOW + 2)
    assert drift.changed_tools == ("read",)
    assert drift.list_changed
    assert mirror.list_tools("example") == []
    with database.read() as connection:
        row = connection.execute(
            "SELECT schema_digest, review_state, present FROM schema_cache"
        ).fetchone()
    assert tuple(row) == (tool_schema_digest(changed), "disabled_drift", 1)

    _, restarted_mirror, _, restarted = assembly(tmp_path, database=database)
    restarted.restore()
    assert restarted_mirror.list_tools("example") == []


@pytest.mark.asyncio
async def test_configured_digest_stays_disabled_when_list_notification_fails(
    tmp_path: Path,
) -> None:
    tool = raw_tool()
    database, mirror, surface, registry = assembly(
        tmp_path, configured_digest=tool_schema_digest(tool)
    )
    failed = tracked_session(surface, failure=True)

    with pytest.raises(SchemaPublicationError, match="remain disabled"):
        await registry.refresh("example", [tool], discovered_at=NOW)

    assert mirror.list_tools("example") == []
    failed.send_tool_list_changed.assert_awaited_once()
    assert failed not in surface._sessions
    with database.read() as connection:
        row = connection.execute(
            "SELECT review_state, reviewed_at, present FROM schema_cache"
        ).fetchone()
    assert tuple(row) == ("disabled_drift", None, 1)


@pytest.mark.asyncio
async def test_virtualized_schema_without_object_output_cannot_be_durably_reviewed(
    tmp_path: Path,
) -> None:
    database, mirror, _, registry = assembly(tmp_path, virtualize=True)
    tool = raw_tool("read")
    tool.pop("outputSchema")
    await registry.refresh("example", [tool], discovered_at=NOW)

    with pytest.raises(SchemaDriftError, match="object output schema"):
        await registry.review_current(
            "example",
            "read",
            tool_schema_digest(tool),
            reviewed_at=NOW + 1,
        )

    assert mirror.list_tools("example") == []
    with database.read() as connection:
        row = connection.execute("SELECT review_state, reviewed_at FROM schema_cache").fetchone()
    assert tuple(row) == ("unreviewed", None)


@pytest.mark.asyncio
async def test_configured_virtual_digest_is_not_persisted_as_reviewed_without_output_schema(
    tmp_path: Path,
) -> None:
    tool = raw_tool("read")
    tool.pop("outputSchema")
    database, mirror, _, registry = assembly(
        tmp_path,
        configured_digest=tool_schema_digest(tool),
        virtualize=True,
    )

    with pytest.raises(SchemaDriftError, match="object output schema"):
        await registry.refresh("example", [tool], discovered_at=NOW)

    assert mirror.list_tools("example") == []
    with database.read() as connection:
        count = int(connection.execute("SELECT count(*) FROM schema_cache").fetchone()[0])
    assert count == 0


@pytest.mark.asyncio
async def test_manual_review_rolls_back_if_any_connected_session_cannot_be_notified(
    tmp_path: Path,
) -> None:
    database, mirror, surface, registry = assembly(tmp_path)
    tool = raw_tool()
    await registry.refresh("example", [tool], discovered_at=NOW)
    tracked_session(surface, failure=True)

    with pytest.raises(SchemaPublicationError, match="review remains disabled"):
        await registry.review_current(
            "example", "read", tool_schema_digest(tool), reviewed_at=NOW + 1
        )

    assert mirror.list_tools("example") == []
    with database.read() as connection:
        row = connection.execute("SELECT review_state, reviewed_at FROM schema_cache").fetchone()
    assert tuple(row) == ("unreviewed", None)


@pytest.mark.asyncio
async def test_removed_tool_is_retained_as_absent_drift_and_never_restored(
    tmp_path: Path,
) -> None:
    tool = raw_tool()
    database, mirror, surface, registry = assembly(
        tmp_path, configured_digest=tool_schema_digest(tool)
    )
    session = tracked_session(surface)
    await registry.refresh("example", [tool], discovered_at=NOW)
    assert [value["name"] for value in mirror.list_tools("example")] == ["read"]

    removed = await registry.refresh("example", [], discovered_at=NOW + 1)
    assert removed.list_changed
    assert removed.changed_tools == ("read",)
    assert mirror.list_tools("example") == []
    assert session.send_tool_list_changed.await_count == 2
    with database.read() as connection:
        row = connection.execute(
            "SELECT review_state, reviewed_at, present FROM schema_cache"
        ).fetchone()
    assert tuple(row) == ("disabled_drift", None, 0)

    _, restored_mirror, _, restored = assembly(
        tmp_path,
        configured_digest=tool_schema_digest(tool),
        database=database,
    )
    restored.restore()
    assert restored_mirror.list_tools("example") == []


def test_corrupt_cached_schema_disables_a_previously_exposed_tool(tmp_path: Path) -> None:
    tool = raw_tool()
    digest = tool_schema_digest(tool)
    database, mirror, _, registry = assembly(tmp_path, configured_digest=digest)
    mirror.capture("example", [tool])
    mirror.approve_schema("example", "read", digest)
    assert mirror.list_tools("example")
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO schema_cache(
                downstream_alias, tool_name, schema_digest, tool_schema_json,
                discovered_at, review_state, reviewed_at, present
            ) VALUES ('example', 'read', ?, x'7b7d', ?, 'approved', ?, 1)
            """,
            (digest, NOW, NOW),
        )

    with pytest.raises(SchemaRegistryError, match="integrity review"):
        registry.restore()
    assert mirror.list_tools("example") == []


@pytest.mark.asyncio
async def test_capture_rejects_invalid_scope_bounds_and_duplicate_tools(tmp_path: Path) -> None:
    _, _, _, registry = assembly(tmp_path)
    tool = raw_tool()
    with pytest.raises(ValueError, match="scope"):
        await registry.refresh("Example", [tool], discovered_at=NOW)
    with pytest.raises(ValueError, match="scope"):
        await registry.refresh("example", [tool], discovered_at=True)
    with pytest.raises(SchemaRegistryError, match="tool name"):
        await registry.refresh("example", [tool, tool], discovered_at=NOW)

    _, _, _, tiny = assembly(tmp_path / "tiny")
    tiny._max_aggregate_bytes = 10
    with pytest.raises(SchemaRegistryError, match="byte limit"):
        await tiny.refresh("example", [tool], discovered_at=NOW)


@pytest.mark.asyncio
async def test_schema_publication_waits_for_parallel_calls_and_blocks_new_calls(
    tmp_path: Path,
) -> None:
    _, _, surface, _ = assembly(tmp_path)
    first_started = asyncio.Event()
    second_started = asyncio.Event()
    release_readers = asyncio.Event()
    writer_started = asyncio.Event()
    release_writer = asyncio.Event()
    late_reader_started = asyncio.Event()

    async def reader(started: asyncio.Event) -> None:
        async with surface._schema_change_lock.read():
            started.set()
            await release_readers.wait()

    async def writer() -> None:
        async with surface.schema_change_guard():
            writer_started.set()
            await release_writer.wait()

    async def late_reader() -> None:
        async with surface._schema_change_lock.read():
            late_reader_started.set()

    first = asyncio.create_task(reader(first_started))
    second = asyncio.create_task(reader(second_started))
    await asyncio.gather(first_started.wait(), second_started.wait())
    publishing = asyncio.create_task(writer())
    await asyncio.sleep(0)
    assert not writer_started.is_set()
    late = asyncio.create_task(late_reader())
    await asyncio.sleep(0)
    assert not late_reader_started.is_set()

    release_readers.set()
    await asyncio.gather(first, second, writer_started.wait())
    assert not late_reader_started.is_set()
    release_writer.set()
    await asyncio.gather(publishing, late)
    assert late_reader_started.is_set()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["refresh", "review"])
async def test_schema_registry_writer_contention_does_not_stall_event_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    database, _, _, registry = assembly(tmp_path)
    tool = raw_tool()
    digest = tool_schema_digest(tool)
    entered = threading.Event()
    original: Any
    if operation == "review":
        await registry.refresh("example", [tool], discovered_at=NOW)
        original = registry._mark_reviewed

        def blocked_operation(*args: Any, **kwargs: Any) -> Any:
            entered.set()
            return original(*args, **kwargs)

        monkeypatch.setattr(registry, "_mark_reviewed", blocked_operation)
    else:
        original = registry._capture

        def blocked_operation(*args: Any, **kwargs: Any) -> Any:
            entered.set()
            return original(*args, **kwargs)

        monkeypatch.setattr(registry, "_capture", blocked_operation)

    writer = sqlite3.connect(database.path, check_same_thread=False)
    writer.execute("BEGIN IMMEDIATE")

    def release_writer() -> None:
        if writer.in_transaction:
            writer.rollback()

    safety_release = threading.Timer(3, release_writer)
    safety_release.start()
    waiting_started_at = time.monotonic()
    try:
        if operation == "review":
            running = asyncio.create_task(
                registry.review_current(
                    "example",
                    "read",
                    digest,
                    reviewed_at=NOW + 1,
                )
            )
        else:
            running = asyncio.create_task(registry.refresh("example", [tool], discovered_at=NOW))
        assert await asyncio.to_thread(entered.wait, 1)
        assert time.monotonic() - waiting_started_at < 2
        assert not running.done()
        await asyncio.wait_for(asyncio.sleep(0), timeout=1)
        safety_release.cancel()
        release_writer()
        result = await running
    finally:
        safety_release.cancel()
        release_writer()
        writer.close()

    assert result.changed_tools == ("read",)
