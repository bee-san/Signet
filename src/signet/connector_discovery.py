"""Fixture-first staged connector discovery with an init/list-only live boundary."""

from __future__ import annotations

import asyncio
import copy
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

import mcp.types as types

from signet.canonical import canonical_json, sha256_hex
from signet.effects import annotation_evidence, heuristic_evidence, plugin_evidence
from signet.integration_store import (
    ConnectorGenerationChangedError,
    DiscoveryRecord,
    IntegrationStoreError,
    SQLiteIntegrationStore,
)
from signet.mcp_mirror import MirrorError, SchemaMirror, raw_model, validate_lossless_tool
from signet.policy import parse_policy
from signet.schema_registry import DurableSchemaRegistry, SchemaRefresh


class ConnectorDiscoveryError(RuntimeError):
    """A fixture or bounded live discovery did not produce a safe complete snapshot."""


@dataclass(frozen=True, slots=True)
class LiveToolsPage:
    tools: tuple[Mapping[str, Any] | types.Tool, ...]
    next_cursor: str | None = None


class InitListDiscoveryClient(Protocol):
    """Deliberately excludes call_tool, resources, prompts, sampling, and elicitation."""

    async def initialize(self) -> Mapping[str, Any]: ...

    async def list_tools(self, cursor: str | None) -> LiveToolsPage: ...


class MCPDiscoverySessionAdapter:
    """Expose only MCP initialization and tools/list from an initialized SDK session."""

    def __init__(self, session: Any) -> None:
        self._session = session

    async def initialize(self) -> Mapping[str, Any]:
        result = await self._session.initialize()
        return raw_model(result)

    async def list_tools(self, cursor: str | None) -> LiveToolsPage:
        params = types.PaginatedRequestParams(cursor=cursor) if cursor is not None else None
        result = await self._session.list_tools(params=params)
        return LiveToolsPage(
            tools=tuple(result.tools),
            next_cursor=result.nextCursor,
        )


@dataclass(frozen=True, slots=True)
class DiscoveryOutcome:
    discovery: DiscoveryRecord
    schema_refresh: SchemaRefresh


class ConnectorDiscoveryService:
    @classmethod
    def staged(
        cls,
        store: SQLiteIntegrationStore,
        *,
        max_pages: int = 32,
        max_tools: int = 512,
        max_aggregate_bytes: int = 8 * 1024 * 1024,
        timeout_seconds: float = 30.0,
    ) -> ConnectorDiscoveryService:
        """Construct an inert registry with no configured or mounted tool surface."""

        mirror = SchemaMirror(
            parse_policy({"version": 1, "default_mode": "deny", "downstreams": {}})
        )
        registry = DurableSchemaRegistry(
            database=store.database,
            mirror=mirror,
            surfaces={},
            max_tools_per_alias=max_tools,
            max_aggregate_bytes=max_aggregate_bytes,
        )
        registry.restore()
        return cls(
            store,
            registry,
            max_pages=max_pages,
            max_tools=max_tools,
            max_aggregate_bytes=max_aggregate_bytes,
            timeout_seconds=timeout_seconds,
        )

    def __init__(
        self,
        store: SQLiteIntegrationStore,
        schema_registry: DurableSchemaRegistry,
        *,
        max_pages: int = 32,
        max_tools: int = 512,
        max_aggregate_bytes: int = 8 * 1024 * 1024,
        timeout_seconds: float = 30.0,
    ) -> None:
        if (
            max_pages < 1
            or max_pages > 256
            or max_tools < 1
            or max_tools > 10_000
            or max_aggregate_bytes < 1
            or max_aggregate_bytes > 64 * 1024 * 1024
            or timeout_seconds <= 0
            or timeout_seconds > 120
        ):
            raise ValueError("connector discovery bounds are invalid")
        self._store = store
        self._schema_registry = schema_registry
        self._max_pages = max_pages
        self._max_tools = max_tools
        self._max_aggregate_bytes = max_aggregate_bytes
        self._timeout_seconds = timeout_seconds

    async def discover_fixture(
        self,
        alias: str,
        document: Mapping[str, Any],
        *,
        discovered_at: int,
    ) -> DiscoveryOutcome:
        """Discover from an already supplied complete fixture; this is the default path."""

        detached = copy.deepcopy(dict(document))
        tools = _fixture_tools(detached)
        fixture_bytes = canonical_json(detached)
        if len(fixture_bytes) > self._max_aggregate_bytes:
            raise ConnectorDiscoveryError("discovery fixture exceeds its byte limit")
        connector = self._store.active_connector(alias)
        initialize_result = {
            "capabilities": {"tools": {}},
            "protocolVersion": "fixture-v1",
            "serverInfo": {
                "name": f"fixture:{connector.plugin.plugin_id}:{connector.connector_id}",
                "version": connector.plugin.plugin_version,
            },
            "x-signet-fixture-sha256": sha256_hex(fixture_bytes),
        }
        return await self._commit(
            alias,
            source="fixture",
            initialize_result=initialize_result,
            tools=tools,
            discovered_at=discovered_at,
            expected_config_digest=connector.config_digest,
        )

    async def discover_live(
        self,
        alias: str,
        client: InitListDiscoveryClient,
        *,
        live_discovery: bool,
        discovered_at: int,
        expected_config_digest: str | None = None,
    ) -> DiscoveryOutcome:
        """Perform the explicitly opted-in init plus bounded tools/list sequence."""

        if live_discovery is not True:
            raise ConnectorDiscoveryError("live discovery requires an explicit opt-in")
        connector = self._store.active_connector(alias)
        selected_config_digest = expected_config_digest or connector.config_digest
        if connector.config_digest != selected_config_digest:
            raise ConnectorDiscoveryError("connector changed during discovery")
        try:
            async with asyncio.timeout(self._timeout_seconds):
                initialize_result = dict(await client.initialize())
                _validate_initialize_result(initialize_result)
                tools = await self._list_all(
                    client,
                    initial_bytes=len(canonical_json(initialize_result)),
                )
            return await self._commit(
                alias,
                source="live",
                initialize_result=initialize_result,
                tools=tools,
                discovered_at=discovered_at,
                expected_config_digest=selected_config_digest,
            )
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            self._record_failure(
                alias,
                "live",
                "timeout",
                discovered_at,
                expected_config_digest=selected_config_digest,
            )
            raise ConnectorDiscoveryError("live tools/list discovery timed out") from None
        except ConnectorDiscoveryError as exc:
            self._record_failure(
                alias,
                "live",
                "protocol_error",
                discovered_at,
                expected_config_digest=selected_config_digest,
            )
            raise exc
        except Exception:
            self._record_failure(
                alias,
                "live",
                "connection_error",
                discovered_at,
                expected_config_digest=selected_config_digest,
            )
            raise ConnectorDiscoveryError("live connector discovery failed") from None

    async def _list_all(
        self,
        client: InitListDiscoveryClient,
        *,
        initial_bytes: int,
    ) -> list[dict[str, Any]]:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        names: set[str] = set()
        tools: list[dict[str, Any]] = []
        aggregate = initial_bytes
        for _page_number in range(self._max_pages):
            page = await client.list_tools(cursor)
            if not isinstance(page, LiveToolsPage):
                raise ConnectorDiscoveryError("live tools/list returned an invalid page")
            if len(tools) + len(page.tools) > self._max_tools:
                raise ConnectorDiscoveryError("live tools/list exceeded its tool limit")
            for model in page.tools:
                candidate = raw_model(model) if isinstance(model, types.Tool) else dict(model)
                raw = validate_lossless_tool(candidate)
                name = raw.get("name")
                if not isinstance(name, str) or not name or name in names:
                    raise ConnectorDiscoveryError(
                        "live tools/list contained an invalid or duplicate tool name"
                    )
                aggregate += len(canonical_json(raw))
                if aggregate > self._max_aggregate_bytes:
                    raise ConnectorDiscoveryError("live tools/list exceeded its byte limit")
                names.add(name)
                tools.append(raw)
            next_cursor = page.next_cursor
            if next_cursor is None:
                return tools
            if (
                not isinstance(next_cursor, str)
                or not next_cursor
                or len(next_cursor.encode("utf-8")) > 1024
                or next_cursor in seen_cursors
            ):
                raise ConnectorDiscoveryError("live tools/list returned an invalid cursor")
            aggregate += len(next_cursor.encode("utf-8"))
            if aggregate > self._max_aggregate_bytes:
                raise ConnectorDiscoveryError("live tools/list exceeded its byte limit")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise ConnectorDiscoveryError("live tools/list exceeded its page limit")

    async def _commit(
        self,
        alias: str,
        *,
        source: Literal["fixture", "live"],
        initialize_result: Mapping[str, Any],
        tools: Sequence[Mapping[str, Any]],
        discovered_at: int,
        expected_config_digest: str,
    ) -> DiscoveryOutcome:
        _validate_initialize_result(initialize_result, fixture=source == "fixture")
        raw_tools = [validate_lossless_tool(tool) for tool in tools]
        if len(raw_tools) > self._max_tools:
            raise ConnectorDiscoveryError("discovery exceeded its tool limit")
        # Compile every schema against the same limits used by the runtime before persistence.
        validation_mirror = SchemaMirror(
            parse_policy({"version": 1, "default_mode": "deny", "downstreams": {}})
        )
        try:
            validation_mirror.capture(alias, raw_tools)
        except MirrorError as exc:
            raise ConnectorDiscoveryError("discovery contains an unsafe tool schema") from exc

        try:
            connector = self._store.active_connector(alias)
        except IntegrationStoreError as exc:
            raise ConnectorDiscoveryError("connector changed during discovery") from exc
        if connector.config_digest != expected_config_digest:
            raise ConnectorDiscoveryError("connector changed during discovery")
        mappings = {
            mapping.tool_name: mapping for mapping in self._store.mappings_for_connector(connector)
        }
        evidence = {}
        for tool in raw_tools:
            name = str(tool["name"])
            packet = [annotation_evidence(tool), heuristic_evidence(tool)]
            mapping = mappings.get(name)
            if mapping is not None:
                packet.append(plugin_evidence(mapping.action_id, mapping.proposed_effect))
            evidence[name] = tuple(packet)
        try:
            discovery = self._store.record_discovery(
                alias=alias,
                source=source,
                initialize_result=initialize_result,
                tools=raw_tools,
                evidence=evidence,
                discovered_at=discovered_at,
                expected_config_digest=expected_config_digest,
            )
        except ConnectorGenerationChangedError as exc:
            raise ConnectorDiscoveryError("connector changed during discovery") from exc
        refresh = await self._schema_registry.refresh_staged(
            alias,
            raw_tools,
            discovered_at=discovered_at,
        )
        return DiscoveryOutcome(discovery=discovery, schema_refresh=refresh)

    def _record_failure(
        self,
        alias: str,
        source: Literal["fixture", "live"],
        error_code: str,
        discovered_at: int,
        *,
        expected_config_digest: str,
    ) -> None:
        try:
            self._store.record_discovery_failure(
                alias,
                source=source,
                error_code=error_code,
                discovered_at=discovered_at,
                expected_config_digest=expected_config_digest,
            )
        except Exception:
            # The original bounded discovery error is more useful and no failed run is current.
            return


def _fixture_tools(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    if set(document) == {"tools"}:
        selected = document["tools"]
    elif set(document) == {"result"} and isinstance(document.get("result"), Mapping):
        result = document["result"]
        if set(result) - {"tools", "nextCursor"} or result.get("nextCursor") is not None:
            raise ConnectorDiscoveryError("fixture tools/list result is incomplete or unsupported")
        selected = result.get("tools")
    else:
        raise ConnectorDiscoveryError("fixture must contain one complete tools/list result")
    if not isinstance(selected, list):
        raise ConnectorDiscoveryError("fixture tools must be an array")
    result_tools: list[dict[str, Any]] = []
    for item in selected:
        if not isinstance(item, Mapping):
            raise ConnectorDiscoveryError("fixture tool must be an object")
        result_tools.append(copy.deepcopy(dict(item)))
    return result_tools


def _validate_initialize_result(
    value: Mapping[str, Any],
    *,
    fixture: bool = False,
) -> None:
    try:
        encoded = canonical_json(dict(value))
    except Exception:
        raise ConnectorDiscoveryError("connector initialization identity is invalid JSON") from None
    server = value.get("serverInfo")
    protocol = value.get("protocolVersion")
    if (
        len(encoded) > 1024 * 1024
        or not isinstance(server, Mapping)
        or not isinstance(server.get("name"), str)
        or not server.get("name")
        or not isinstance(server.get("version"), str)
        or not server.get("version")
        or not isinstance(protocol, str)
        or not protocol
        or (fixture and protocol != "fixture-v1")
    ):
        raise ConnectorDiscoveryError("connector initialization identity is incomplete")


def strict_fixture_json(document: bytes, *, max_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
    """Parse a fixture with duplicate-key and non-finite-number rejection."""

    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or max_bytes < 1
        or max_bytes > 64 * 1024 * 1024
    ):
        raise ValueError("fixture byte limit is invalid")
    if not isinstance(document, bytes) or not document or len(document) > max_bytes:
        raise ConnectorDiscoveryError("fixture is empty or exceeds its byte limit")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ConnectorDiscoveryError("fixture contains a duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ConnectorDiscoveryError("fixture contains a non-finite number")

    try:
        parsed = json.loads(
            document.decode("utf-8", errors="strict"),
            object_pairs_hook=unique,
            parse_constant=reject_constant,
        )
    except ConnectorDiscoveryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ConnectorDiscoveryError("fixture is not strict UTF-8 JSON") from None
    if not isinstance(parsed, dict):
        raise ConnectorDiscoveryError("fixture root must be an object")
    return parsed
