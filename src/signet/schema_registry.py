"""Durable, fail-closed publication of reviewed downstream tool schemas."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Never

import mcp.types as types

from signet.async_support import run_sync_non_abandoning as _run_sync
from signet.canonical import canonical_json
from signet.db import Database
from signet.mcp_mirror import (
    AliasToolSurface,
    ListChangedNotificationError,
    SchemaMirror,
    raw_model,
    tool_schema_digest,
    validate_lossless_tool,
)

_ALIAS_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


class SchemaRegistryError(RuntimeError):
    """A cached schema or its publication boundary is invalid."""


class SchemaPublicationError(SchemaRegistryError):
    """A reviewed schema could not be announced without failing open."""


@dataclass(frozen=True, slots=True)
class SchemaRefresh:
    alias: str
    changed_tools: tuple[str, ...]
    list_changed: bool
    notifications_sent: int


@dataclass(frozen=True, slots=True)
class _ReviewSnapshot:
    review_state: str
    reviewed_at: int | None


class DurableSchemaRegistry:
    """Join exact schema capture, SQLite review state, and upstream publication."""

    def __init__(
        self,
        *,
        database: Database,
        mirror: SchemaMirror,
        surfaces: Mapping[str, AliasToolSurface],
        max_tools_per_alias: int = 512,
        max_aggregate_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        if max_tools_per_alias < 1 or max_tools_per_alias > 10_000:
            raise ValueError("schema registry tool limit is invalid")
        if max_aggregate_bytes < 1 or max_aggregate_bytes > 64 * 1024 * 1024:
            raise ValueError("schema registry byte limit is invalid")
        for alias, surface in surfaces.items():
            if (
                _ALIAS_PATTERN.fullmatch(alias) is None
                or surface.alias != alias
                or surface.mirror is not mirror
            ):
                raise ValueError("schema registry surfaces must use the exact shared mirror")
        self._database = database
        self._mirror = mirror
        self._surfaces = dict(surfaces)
        self._max_tools_per_alias = max_tools_per_alias
        self._max_aggregate_bytes = max_aggregate_bytes
        self._staged_locks: dict[str, asyncio.Lock] = {}

    def restore(self) -> None:
        """Restore only present, integrity-checked schemas before serving traffic."""

        with self._database.read() as connection:
            rows = connection.execute(
                """
                SELECT downstream_alias, tool_name, schema_digest, tool_schema_json,
                       review_state
                FROM schema_cache
                WHERE present = 1
                ORDER BY downstream_alias, tool_name
                """
            ).fetchall()

        grouped: dict[str, list[Any]] = {}
        for row in rows:
            alias = str(row["downstream_alias"])
            if _ALIAS_PATTERN.fullmatch(alias) is None:
                self._disable_configured_tools()
                raise SchemaRegistryError("the durable schema cache contains an invalid alias")
            grouped.setdefault(alias, []).append(row)

        aliases = set(grouped) | set(self._mirror.policy.downstreams)
        try:
            for alias in aliases:
                selected = grouped.get(alias, [])
                if len(selected) > self._max_tools_per_alias:
                    raise SchemaRegistryError("the durable schema cache exceeds its tool limit")
                raw_tools = [self._decode_row(row) for row in selected]
                if sum(len(canonical_json(tool)) for tool in raw_tools) > self._max_aggregate_bytes:
                    raise SchemaRegistryError("the durable schema cache exceeds its byte limit")
                self._mirror.capture(alias, raw_tools)
                for row in selected:
                    tool = str(row["tool_name"])
                    digest = str(row["schema_digest"])
                    if row["review_state"] == "approved":
                        self._mirror.approve_schema(alias, tool, digest)
                    else:
                        self._mirror.disable_schema(alias, tool)
        except Exception as exc:
            self._disable_configured_tools()
            if isinstance(exc, SchemaRegistryError):
                raise
            raise SchemaRegistryError("the durable schema cache failed integrity review") from None

    def capture_reviewed(
        self,
        alias: str,
        tools: Sequence[Mapping[str, Any] | types.Tool],
        *,
        discovered_at: int,
    ) -> tuple[str, ...]:
        """Persist schemas already bound to the active policy while services are stopped."""

        return tuple(
            sorted(
                self._capture(
                    alias,
                    tools,
                    discovered_at=discovered_at,
                )
            )
        )

    async def refresh(
        self,
        alias: str,
        tools: Sequence[Mapping[str, Any] | types.Tool],
        *,
        discovered_at: int,
    ) -> SchemaRefresh:
        """Persist one complete discovery and announce any exposed-list change."""

        if _ALIAS_PATTERN.fullmatch(alias) is None or not _valid_timestamp(discovered_at):
            raise ValueError("schema discovery scope is invalid")
        surface = self._surface(alias)
        async with surface.schema_change_guard():
            before = await _run_sync(self._listed_digest, alias)
            try:
                changed = await _run_sync(
                    self._capture,
                    alias,
                    tools,
                    discovered_at=discovered_at,
                )
            except asyncio.CancelledError:
                await _run_sync(self._disable_alias, alias)
                raise
            sent = 0
            try:
                after = await _run_sync(self._listed_digest, alias)
                list_changed = before != after
                if list_changed:
                    sent = await surface.notify_list_changed(strict=True)
            except asyncio.CancelledError:
                await _run_sync(self._disable_changed, alias, changed)
                raise
            except ListChangedNotificationError:
                await _run_sync(self._disable_changed, alias, changed)
                raise SchemaPublicationError(
                    "schema discovery was stored but its exposed tools remain disabled"
                ) from None
            except Exception:
                await _run_sync(self._disable_changed, alias, changed)
                raise
            return SchemaRefresh(
                alias=alias,
                changed_tools=tuple(sorted(changed)),
                list_changed=list_changed,
                notifications_sent=sent,
            )

    async def refresh_staged(
        self,
        alias: str,
        tools: Sequence[Mapping[str, Any] | types.Tool],
        *,
        discovered_at: int,
    ) -> SchemaRefresh:
        """Persist discovery while explicitly refusing every schema review.

        Staged plugin onboarding must never inherit a policy-file digest or a prior
        approval.  If the alias already has an upstream surface, disabling an exposed
        tool is published through the same strict list-change boundary as ``refresh``.
        An unmounted staged alias uses only an internal writer lock.
        """

        if _ALIAS_PATTERN.fullmatch(alias) is None or not _valid_timestamp(discovered_at):
            raise ValueError("schema discovery scope is invalid")
        surface = self._surfaces.get(alias)
        guard = surface.schema_change_guard() if surface is not None else self._staged_guard(alias)
        async with guard:
            before = await _run_sync(self._listed_digest, alias)
            try:
                changed = await _run_sync(
                    self._capture,
                    alias,
                    tools,
                    discovered_at=discovered_at,
                    force_unreviewed=True,
                )
            except asyncio.CancelledError:
                await _run_sync(self._disable_alias, alias)
                raise
            after = await _run_sync(self._listed_digest, alias)
            list_changed = before != after
            sent = 0
            if list_changed and surface is not None:
                try:
                    sent = await surface.notify_list_changed(strict=True)
                except asyncio.CancelledError:
                    await _run_sync(self._disable_alias, alias)
                    raise
                except ListChangedNotificationError:
                    await _run_sync(self._disable_alias, alias)
                    raise SchemaPublicationError(
                        "staged schema discovery was stored but remains disabled"
                    ) from None
            return SchemaRefresh(
                alias=alias,
                changed_tools=tuple(sorted(changed)),
                list_changed=list_changed,
                notifications_sent=sent,
            )

    async def review_current(
        self,
        alias: str,
        tool: str,
        digest: str,
        *,
        reviewed_at: int,
    ) -> SchemaRefresh:
        """Publish one exact current digest, rolling back in memory on any failure."""

        if (
            _ALIAS_PATTERN.fullmatch(alias) is None
            or not tool
            or not re.fullmatch(r"[a-f0-9]{64}", digest)
        ):
            raise ValueError("schema review scope is invalid")
        surface = self._surface(alias)
        if not _valid_timestamp(reviewed_at):
            raise ValueError("schema review timestamp is invalid")
        snapshot = await _run_sync(self._review_snapshot, alias, tool, digest)

        async with surface.schema_change_guard():
            sent = 0
            try:
                before = await _run_sync(self._listed_digest, alias)
                await _run_sync(self._mirror.approve_schema, alias, tool, digest)
                after = await _run_sync(self._listed_digest, alias)
                list_changed = before != after
                if list_changed:
                    sent = await surface.notify_list_changed(strict=True)
                await _run_sync(
                    self._mark_reviewed,
                    alias,
                    tool,
                    digest,
                    reviewed_at=reviewed_at,
                )
            except BaseException as exc:
                await _run_sync(
                    self._restore_review,
                    alias,
                    tool,
                    digest,
                    snapshot,
                )
                if isinstance(exc, ListChangedNotificationError):
                    raise SchemaPublicationError(
                        "schema review remains disabled because list notification failed"
                    ) from None
                raise
            return SchemaRefresh(
                alias=alias,
                changed_tools=(tool,),
                list_changed=list_changed,
                notifications_sent=sent,
            )

    def _listed_digest(self, alias: str) -> bytes:
        return canonical_json(self._mirror.list_tools(alias))

    def _review_snapshot(self, alias: str, tool: str, digest: str) -> _ReviewSnapshot:
        with self._database.read() as connection:
            row = connection.execute(
                """
                SELECT schema_digest, review_state, reviewed_at
                FROM schema_cache
                WHERE downstream_alias = ? AND tool_name = ? AND present = 1
                """,
                (alias, tool),
            ).fetchone()
        if row is None or row["schema_digest"] != digest:
            raise SchemaRegistryError("only the current present schema digest can be reviewed")
        return _ReviewSnapshot(
            review_state=str(row["review_state"]),
            reviewed_at=row["reviewed_at"],
        )

    def _mark_reviewed(
        self,
        alias: str,
        tool: str,
        digest: str,
        *,
        reviewed_at: int,
    ) -> None:
        with self._database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE schema_cache
                SET review_state = 'approved', reviewed_at = ?
                WHERE downstream_alias = ? AND tool_name = ?
                  AND schema_digest = ? AND present = 1
                """,
                (reviewed_at, alias, tool, digest),
            )
            if cursor.rowcount != 1:
                raise SchemaRegistryError("the schema changed during review")

    def _restore_review(
        self,
        alias: str,
        tool: str,
        digest: str,
        snapshot: _ReviewSnapshot,
    ) -> None:
        with self._database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE schema_cache
                SET review_state = ?, reviewed_at = ?
                WHERE downstream_alias = ? AND tool_name = ?
                  AND schema_digest = ? AND present = 1
                """,
                (
                    snapshot.review_state,
                    snapshot.reviewed_at,
                    alias,
                    tool,
                    digest,
                ),
            )
            if cursor.rowcount != 1:
                raise SchemaRegistryError("the schema changed during review rollback")
        if snapshot.review_state == "approved":
            self._mirror.approve_schema(alias, tool, digest)
        else:
            self._mirror.disable_schema(alias, tool)

    def _capture(
        self,
        alias: str,
        tools: Sequence[Mapping[str, Any] | types.Tool],
        *,
        discovered_at: int,
        force_unreviewed: bool = False,
    ) -> set[str]:
        if _ALIAS_PATTERN.fullmatch(alias) is None or not _valid_timestamp(discovered_at):
            raise ValueError("schema discovery scope is invalid")
        if len(tools) > self._max_tools_per_alias:
            raise SchemaRegistryError("schema discovery exceeds its tool limit")

        raw_tools: list[dict[str, Any]] = []
        encoded: dict[str, bytes] = {}
        aggregate = 0
        for candidate in tools:
            raw = raw_model(candidate) if isinstance(candidate, types.Tool) else dict(candidate)
            raw = validate_lossless_tool(raw)
            name = raw.get("name")
            if not isinstance(name, str) or not name or name in encoded:
                raise SchemaRegistryError("schema discovery contains an invalid tool name")
            material = canonical_json(raw)
            aggregate += len(material)
            if aggregate > self._max_aggregate_bytes:
                raise SchemaRegistryError("schema discovery exceeds its byte limit")
            encoded[name] = material
            raw_tools.append(raw)

        # Validate the complete set before either the durable or live mirror changes.
        staging = SchemaMirror(self._mirror.policy)
        staging.capture(alias, raw_tools)
        for raw in raw_tools:
            name = str(raw["name"])
            digest = tool_schema_digest(raw)
            configured = self._mirror.policy.configured(alias, name)
            if (
                not force_unreviewed
                and configured is not None
                and configured.schema_digest == digest
            ):
                staging.approve_schema(alias, name, digest)

        changed: set[str] = set()
        states: dict[str, tuple[str, str]] = {}
        with self._database.transaction() as connection:
            old_rows = {
                str(row["tool_name"]): row
                for row in connection.execute(
                    """
                    SELECT tool_name, schema_digest, review_state, reviewed_at, present
                    FROM schema_cache WHERE downstream_alias = ?
                    """,
                    (alias,),
                )
            }
            for raw in raw_tools:
                name = str(raw["name"])
                digest = tool_schema_digest(raw)
                previous = old_rows.get(name)
                policy = self._mirror.policy.configured(alias, name)
                configured_review = (
                    not force_unreviewed and policy is not None and policy.schema_digest == digest
                )
                if force_unreviewed:
                    state = "unreviewed"
                    reviewed_at_value: int | None = None
                elif configured_review:
                    state = "approved"
                    reviewed_at_value = discovered_at
                elif previous is None:
                    state = "unreviewed"
                    reviewed_at_value = None
                elif previous["schema_digest"] == digest and bool(previous["present"]):
                    state = str(previous["review_state"])
                    reviewed_at_value = previous["reviewed_at"]
                else:
                    state = "disabled_drift"
                    reviewed_at_value = None
                if (
                    previous is None
                    or previous["schema_digest"] != digest
                    or not bool(previous["present"])
                    or (force_unreviewed and previous["review_state"] == "approved")
                ):
                    changed.add(name)
                connection.execute(
                    """
                    INSERT INTO schema_cache(
                        downstream_alias, tool_name, schema_digest, tool_schema_json,
                        discovered_at, review_state, reviewed_at, present
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(downstream_alias, tool_name) DO UPDATE SET
                        schema_digest = excluded.schema_digest,
                        tool_schema_json = excluded.tool_schema_json,
                        discovered_at = excluded.discovered_at,
                        review_state = excluded.review_state,
                        reviewed_at = excluded.reviewed_at,
                        present = 1
                    """,
                    (
                        alias,
                        name,
                        digest,
                        encoded[name],
                        discovered_at,
                        state,
                        reviewed_at_value,
                    ),
                )
                states[name] = (digest, state)

            removed = set(old_rows) - set(encoded)
            if removed:
                connection.execute(
                    """
                    UPDATE schema_cache
                    SET present = 0, review_state = 'disabled_drift', reviewed_at = NULL,
                        discovered_at = ?
                    WHERE downstream_alias = ?
                      AND tool_name IN (SELECT value FROM json_each(?))
                    """,
                    (
                        discovered_at,
                        alias,
                        json.dumps(sorted(removed), separators=(",", ":")),
                    ),
                )
                changed.update(removed)

        self._mirror.capture(alias, raw_tools)
        for name, (digest, state) in states.items():
            if state == "approved":
                self._mirror.approve_schema(alias, name, digest)
            else:
                self._mirror.disable_schema(alias, name)
        return changed

    @asynccontextmanager
    async def _staged_guard(self, alias: str) -> AsyncIterator[None]:
        lock = self._staged_locks.setdefault(alias, asyncio.Lock())
        async with lock:
            yield

    def _disable_changed(self, alias: str, changed: set[str]) -> None:
        if not changed:
            return
        with self._database.transaction() as connection:
            for tool in changed:
                connection.execute(
                    """
                    UPDATE schema_cache
                    SET review_state = 'disabled_drift', reviewed_at = NULL
                    WHERE downstream_alias = ? AND tool_name = ? AND present = 1
                    """,
                    (alias, tool),
                )
                self._mirror.disable_schema(alias, tool)

    def _disable_alias(self, alias: str) -> None:
        with self._database.transaction() as connection:
            rows = connection.execute(
                """
                SELECT tool_name FROM schema_cache
                WHERE downstream_alias = ? AND present = 1
                """,
                (alias,),
            ).fetchall()
            connection.execute(
                """
                UPDATE schema_cache
                SET review_state = 'disabled_drift', reviewed_at = NULL
                WHERE downstream_alias = ? AND present = 1
                """,
                (alias,),
            )
        for row in rows:
            self._mirror.disable_schema(alias, str(row["tool_name"]))

    def _decode_row(self, row: Any) -> dict[str, Any]:
        blob = row["tool_schema_json"]
        if not isinstance(blob, bytes) or not blob or len(blob) > self._max_aggregate_bytes:
            raise SchemaRegistryError("the durable schema cache contains invalid bytes")
        try:
            value = json.loads(blob, parse_constant=_reject_json_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise SchemaRegistryError("the durable schema cache contains invalid JSON") from None
        if not isinstance(value, dict):
            raise SchemaRegistryError("the durable schema cache contains a non-object tool")
        raw = validate_lossless_tool(value)
        if raw.get("name") != row["tool_name"] or tool_schema_digest(raw) != row["schema_digest"]:
            raise SchemaRegistryError("the durable schema cache digest does not match")
        return raw

    def _surface(self, alias: str) -> AliasToolSurface:
        surface = self._surfaces.get(alias)
        if surface is None or _ALIAS_PATTERN.fullmatch(alias) is None:
            raise SchemaRegistryError("no reviewed upstream surface exists for this alias")
        return surface

    def _disable_configured_tools(self) -> None:
        for alias, downstream in self._mirror.policy.downstreams.items():
            for tool in downstream.tools:
                self._mirror.disable_schema(alias, tool)


def _valid_timestamp(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _reject_json_constant(value: str) -> Never:
    raise ValueError(f"invalid JSON constant: {value}")
