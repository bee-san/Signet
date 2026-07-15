"""Lossless MCP tool discovery, mirroring, and low-level server handlers."""

from __future__ import annotations

import copy
import inspect
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

import mcp.types as types
from jsonschema import Draft202012Validator
from mcp.server.lowlevel import Server
from mcp.server.models import InitializationOptions
from mcp.shared.exceptions import McpError
from pydantic import PrivateAttr, model_serializer

from signet.canonical import canonical_json, sha256_hex
from signet.policy import PolicyMode, PolicySnapshot

PENDING_RESULT_SCHEMA: dict[str, Any] = {
    "$id": "https://signet.local/schemas/pending-result-v1.json",
    "type": "object",
    "additionalProperties": False,
    "required": ["status", "request_id", "expires_at", "message"],
    "properties": {
        "status": {"const": "pending_approval"},
        "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"},
        "expires_at": {"type": "string", "format": "date-time"},
        "message": {"type": "string", "minLength": 1},
    },
}


class MirrorError(RuntimeError):
    pass


class SchemaDriftError(MirrorError):
    pass


class DomainToolError(MirrorError):
    def __init__(self, code: str, message: str, *, details: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})


class RawServerResult(types.ServerResult):
    """Bypass the SDK's exclude-none serializer for captured MCP results."""

    _raw_result: dict[str, Any] = PrivateAttr()

    def __init__(self, raw_result: Mapping[str, Any]):
        super().__init__(root=types.EmptyResult())
        self._raw_result = copy.deepcopy(dict(raw_result))

    @model_serializer(mode="plain")
    def serialize_raw_result(self) -> dict[str, Any]:
        return copy.deepcopy(self._raw_result)


def raw_model(model: Any) -> dict[str, Any]:
    """Dump a Pydantic MCP model while retaining explicit null and extra fields."""

    raw = model.model_dump(mode="json", by_alias=True, exclude_unset=True)
    if not isinstance(raw, dict):
        raise MirrorError("captured MCP value was not an object")
    return cast(dict[str, Any], raw)


def validate_lossless_tool(raw: Mapping[str, Any]) -> dict[str, Any]:
    captured = copy.deepcopy(dict(raw))
    round_tripped = raw_model(types.Tool.model_validate(captured))
    if round_tripped != captured:
        raise MirrorError("the pinned MCP SDK changed a captured Tool definition")
    return captured


def tool_schema_digest(raw: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json(dict(raw)))


def pending_call_result(pending: Mapping[str, Any]) -> dict[str, Any]:
    pending_value = copy.deepcopy(dict(pending))
    Draft202012Validator(PENDING_RESULT_SCHEMA).validate(pending_value)
    serialized = json.dumps(pending_value, ensure_ascii=False, separators=(",", ":"))
    return {
        "content": [{"type": "text", "text": serialized}],
        "structuredContent": pending_value,
        "isError": False,
    }


def domain_error_result(
    code: str,
    message: str,
    *,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details:
        value["error"]["details"] = dict(details)
    serialized = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return {
        "content": [{"type": "text", "text": serialized}],
        "structuredContent": value,
        "isError": True,
    }


@dataclass(frozen=True, slots=True)
class CapturedTool:
    alias: str
    name: str
    raw: dict[str, Any]
    digest: str


class SchemaMirror:
    """Capture raw downstream definitions and expose only reviewed exact policies."""

    def __init__(self, policy: PolicySnapshot) -> None:
        self._policy = policy
        self._captured: dict[tuple[str, str], CapturedTool] = {}
        self._reviewed_digests: dict[tuple[str, str], str] = {}
        self._drifted: set[tuple[str, str]] = set()

    @property
    def policy(self) -> PolicySnapshot:
        return self._policy

    def apply_policy(self, policy: PolicySnapshot) -> set[str]:
        aliases = set(self._policy.downstreams) | set(policy.downstreams)
        changed = {
            alias
            for alias in aliases
            if self._policy.downstreams.get(alias) != policy.downstreams.get(alias)
        }
        self._policy = policy
        return changed

    def capture(self, alias: str, tools: Sequence[Mapping[str, Any] | types.Tool]) -> set[str]:
        seen: set[str] = set()
        changed: set[str] = set()
        for tool in tools:
            raw = raw_model(tool) if isinstance(tool, types.Tool) else dict(tool)
            raw = validate_lossless_tool(raw)
            name = raw.get("name")
            if not isinstance(name, str) or not name or name in seen:
                raise MirrorError("downstream tools/list contained a missing or duplicate name")
            seen.add(name)
            digest = tool_schema_digest(raw)
            key = (alias, name)
            previous = self._captured.get(key)
            self._captured[key] = CapturedTool(alias=alias, name=name, raw=raw, digest=digest)
            reviewed = self._reviewed_digests.get(key)
            if reviewed is not None and reviewed != digest:
                self._drifted.add(key)
                changed.add(name)
            elif reviewed == digest:
                self._drifted.discard(key)
            if previous is not None and previous.digest != digest:
                changed.add(name)
        for key in tuple(self._captured):
            if key[0] == alias and key[1] not in seen:
                del self._captured[key]
                self._drifted.add(key)
                changed.add(key[1])
        return changed

    def approve_schema(self, alias: str, tool: str, digest: str) -> None:
        key = (alias, tool)
        captured = self._captured.get(key)
        if captured is None or captured.digest != digest:
            raise SchemaDriftError("only the currently captured schema digest can be reviewed")
        self._reviewed_digests[key] = digest
        self._drifted.discard(key)

    def captured_digest(self, alias: str, tool: str) -> str:
        try:
            return self._captured[(alias, tool)].digest
        except KeyError as exc:
            raise MirrorError("tool has not been discovered") from exc

    def is_enabled(self, alias: str, tool: str) -> bool:
        key = (alias, tool)
        captured = self._captured.get(key)
        configured = self._policy.configured(alias, tool)
        if captured is None or configured is None or key in self._drifted:
            return False
        reviewed = configured.schema_digest or self._reviewed_digests.get(key)
        return reviewed == captured.digest

    def list_tools(self, alias: str) -> list[dict[str, Any]]:
        downstream = self._policy.downstreams.get(alias)
        if downstream is None:
            return []
        listed: list[dict[str, Any]] = []
        for name in downstream.tools:
            if not self.is_enabled(alias, name):
                continue
            captured = self._captured[(alias, name)]
            configured = downstream.tools[name]
            raw = copy.deepcopy(captured.raw)
            if _advertises_task_support(raw):
                continue
            if configured.mode is PolicyMode.APPROVAL:
                raw["outputSchema"] = copy.deepcopy(PENDING_RESULT_SCHEMA)
                note = (
                    "Human-gated by Signet. Returns pending_approval after durable queueing; "
                    "the downstream action has not occurred."
                )
                description = raw.get("description")
                raw["description"] = f"{description}\n\n{note}" if description else note
                execution = raw.get("execution")
                if isinstance(execution, dict):
                    execution["taskSupport"] = "forbidden"
            listed.append(raw)
        return listed

    def require_callable(self, alias: str, tool: str) -> PolicyMode:
        configured = self._policy.configured(alias, tool)
        if configured is None:
            raise McpError(
                types.ErrorData(code=types.INVALID_PARAMS, message=f"Unknown tool: {tool}")
            )
        if not self.is_enabled(alias, tool):
            raise DomainToolError(
                "schema_unreviewed",
                "The tool is disabled until its current schema has been reviewed.",
            )
        if _advertises_task_support(self._captured[(alias, tool)].raw):
            raise DomainToolError(
                "task_execution_unsupported",
                "The downstream tool advertises task execution, which this gateway does not proxy.",
            )
        return configured.mode

    def validate_virtual_result(self, alias: str, tool: str, result: Any) -> None:
        raw = self._captured[(alias, tool)].raw
        schema = raw.get("outputSchema")
        if isinstance(schema, dict):
            Draft202012Validator(schema).validate(result)


def _advertises_task_support(raw: Mapping[str, Any]) -> bool:
    execution = raw.get("execution")
    if not isinstance(execution, Mapping):
        return False
    task_support = execution.get("taskSupport")
    return task_support not in (None, "forbidden")


async def discover_all_tools(session: Any) -> list[dict[str, Any]]:
    """Exhaust tools/list pagination while detecting loops and duplicates."""

    cursor: str | None = None
    cursors: set[str] = set()
    names: set[str] = set()
    tools: list[dict[str, Any]] = []
    while True:
        params = types.PaginatedRequestParams(cursor=cursor) if cursor is not None else None
        page = await session.list_tools(params=params)
        for model in page.tools:
            raw = validate_lossless_tool(raw_model(model))
            name = raw["name"]
            if name in names:
                raise MirrorError(f"duplicate downstream tool name: {name}")
            names.add(name)
            tools.append(raw)
        next_cursor = page.nextCursor
        if next_cursor is None:
            return tools
        if next_cursor in cursors:
            raise MirrorError("downstream tools/list pagination cursor repeated")
        cursors.add(next_cursor)
        cursor = next_cursor


ToolCallHandler = Callable[[str, str, Mapping[str, Any], str], Awaitable[dict[str, Any]]]
DeniedEventHandler = Callable[[str, str, str], Awaitable[None] | None]
NamespaceProvider = Callable[[], tuple[str, set[str] | frozenset[str]]]


class LosslessToolServer(Server[None, Any]):
    """Low-level server that advertises only tools with list-change support."""

    def create_initialization_options(
        self,
        notification_options: Any | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
    ) -> InitializationOptions:
        return InitializationOptions(
            server_name=self.name,
            server_version=self.version or "0.1.0",
            capabilities=types.ServerCapabilities(tools=types.ToolsCapability(listChanged=True)),
            instructions=self.instructions,
            website_url=self.website_url,
            icons=self.icons,
        )


class AliasToolSurface:
    def __init__(
        self,
        *,
        alias: str,
        mirror: SchemaMirror,
        call_handler: ToolCallHandler,
        denied_event_handler: DeniedEventHandler | None = None,
        namespace_provider: NamespaceProvider | None = None,
    ) -> None:
        self.alias = alias
        self.mirror = mirror
        self.call_handler = call_handler
        self.denied_event_handler = denied_event_handler
        self.namespace_provider = namespace_provider
        self.server: LosslessToolServer = LosslessToolServer("Signet", version="0.1.0")
        self._sessions: set[Any] = set()
        self.server.request_handlers[types.ListToolsRequest] = self._list_tools
        self.server.request_handlers[types.CallToolRequest] = self._call_tool

    def _namespace(self) -> str:
        if self.namespace_provider is not None:
            namespace, allowed_aliases = self.namespace_provider()
            if self.alias not in allowed_aliases:
                raise McpError(types.ErrorData(code=types.INVALID_REQUEST, message="Unauthorized"))
            return namespace
        request = self.server.request_context.request
        user = request.scope.get("user") if request is not None else None
        access_token = getattr(user, "access_token", None)
        claims = getattr(access_token, "claims", None) or {}
        raw_namespace = claims.get("namespace")
        allowed_aliases = claims.get("allowed_aliases", [])
        if not isinstance(raw_namespace, str) or self.alias not in allowed_aliases:
            raise McpError(types.ErrorData(code=types.INVALID_REQUEST, message="Unauthorized"))
        return raw_namespace

    def _remember_session(self) -> None:
        self._sessions.add(self.server.request_context.session)

    async def _list_tools(self, request: types.ListToolsRequest) -> types.ServerResult:
        del request
        self._namespace()
        self._remember_session()
        return RawServerResult({"tools": self.mirror.list_tools(self.alias)})

    async def _call_tool(self, request: types.CallToolRequest) -> types.ServerResult:
        namespace = self._namespace()
        self._remember_session()
        name = request.params.name
        arguments = request.params.arguments or {}
        try:
            mode = self.mirror.require_callable(self.alias, name)
            if mode is PolicyMode.DENY:
                if self.denied_event_handler:
                    result = self.denied_event_handler(namespace, self.alias, name)
                    if inspect.isawaitable(result):
                        await result
                return RawServerResult(
                    domain_error_result(
                        "policy_denied",
                        "This reviewed tool is denied by Signet policy.",
                    )
                )
            raw_result = await self.call_handler(self.alias, name, arguments, namespace)
            types.CallToolResult.model_validate(raw_result)
            return RawServerResult(raw_result)
        except DomainToolError as exc:
            return RawServerResult(domain_error_result(exc.code, exc.message, details=exc.details))

    async def notify_list_changed(self) -> int:
        sent = 0
        stale: list[Any] = []
        for session in tuple(self._sessions):
            try:
                await session.send_tool_list_changed()
                sent += 1
            except Exception:
                stale.append(session)
        for session in stale:
            self._sessions.discard(session)
        return sent
