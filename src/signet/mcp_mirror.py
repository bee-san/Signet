"""Lossless MCP tool discovery, mirroring, and low-level server handlers."""

from __future__ import annotations

import copy
import inspect
import json
import re
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

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
SIGNET_INVOCATION_ID_META = "io.signet/invocation-id"
_EXPLICIT_INVOCATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_MAX_IDENTITY_COMPONENT_BYTES = 512


class MirrorError(RuntimeError):
    pass


class SchemaDriftError(MirrorError):
    pass


class InvocationIdentityError(MirrorError):
    pass


class DomainToolError(MirrorError):
    def __init__(self, code: str, message: str, *, details: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})


@dataclass(frozen=True, slots=True, repr=False)
class InvocationIdentity:
    """A one-way, caller/tool-scoped key suitable for durable idempotency."""

    invocation_key: str
    source: Literal["explicit", "session_request"]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.invocation_key, str)
            or not _SHA256_RE.fullmatch(self.invocation_key)
            or not isinstance(self.source, str)
            or self.source not in {"explicit", "session_request"}
        ):
            raise InvocationIdentityError("invocation identity is invalid")

    def __repr__(self) -> str:
        return f"InvocationIdentity(source={self.source!r}, invocation_key=<redacted>)"


def derive_invocation_identity(
    *,
    namespace: str,
    alias: str,
    tool: str,
    explicit_id: object | None,
    explicit_id_present: bool,
    session_scope: str,
    request_id: str | int,
) -> InvocationIdentity:
    """Validate identity inputs and return only their domain-separated digest."""

    for value in (namespace, alias, tool):
        if not _bounded_identity_text(value):
            raise InvocationIdentityError("invocation scope is invalid")
    if explicit_id_present:
        if not isinstance(explicit_id, str) or not _EXPLICIT_INVOCATION_ID_RE.fullmatch(
            explicit_id
        ):
            raise InvocationIdentityError("explicit invocation ID is invalid")
        source: Literal["explicit", "session_request"] = "explicit"
        source_value: object = explicit_id
    else:
        if not _bounded_identity_text(session_scope):
            raise InvocationIdentityError("session invocation scope is invalid")
        if isinstance(request_id, bool) or not isinstance(request_id, str | int):
            raise InvocationIdentityError("JSON-RPC request ID is invalid")
        if isinstance(request_id, str):
            if not _bounded_identity_text(request_id):
                raise InvocationIdentityError("JSON-RPC request ID is invalid")
            normalized_request_id: object = {"kind": "string", "value": request_id}
        else:
            if request_id < -(2**63) or request_id > 2**63 - 1:
                raise InvocationIdentityError("JSON-RPC request ID is invalid")
            normalized_request_id = {"kind": "integer", "value": request_id}
        source = "session_request"
        source_value = {
            "session_scope": session_scope,
            "request_id": normalized_request_id,
        }
    material = canonical_json(
        {
            "domain": "signet/invocation-identity/v1",
            "namespace": namespace,
            "alias": alias,
            "tool": tool,
            "source": source,
            "value": source_value,
        }
    )
    return InvocationIdentity(invocation_key=sha256_hex(material), source=source)


def _bounded_identity_text(value: object) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    try:
        return len(value.encode("utf-8")) <= _MAX_IDENTITY_COMPONENT_BYTES
    except UnicodeError:
        return False


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

    def validate_input(self, alias: str, tool: str, arguments: Mapping[str, Any]) -> None:
        """Validate exact call arguments against the captured reviewed input schema."""

        captured = self._captured.get((alias, tool))
        if captured is None:
            raise DomainToolError(
                "schema_unreviewed",
                "The tool is disabled until its current schema has been reviewed.",
            )
        schema = captured.raw.get("inputSchema")
        if not isinstance(schema, dict):
            raise DomainToolError(
                "schema_invalid",
                "The reviewed downstream input schema is invalid.",
            )
        try:
            validator = Draft202012Validator(schema)
            validator.check_schema(schema)
            valid = validator.is_valid(copy.deepcopy(dict(arguments)))
        except Exception:
            raise DomainToolError(
                "schema_invalid",
                "The reviewed downstream input schema is invalid.",
            ) from None
        if not valid:
            raise DomainToolError(
                "invalid_arguments",
                "Tool arguments do not match the reviewed input schema.",
            )

    def validate_virtual_result(self, alias: str, tool: str, result: Any) -> None:
        raw = self._captured[(alias, tool)].raw
        schema = raw.get("outputSchema")
        if isinstance(schema, dict):
            Draft202012Validator(schema).validate(result)

    def validate_downstream_result(
        self,
        alias: str,
        tool: str,
        result: Mapping[str, Any],
    ) -> None:
        """Enforce a reviewed output schema for successful passthrough results."""

        if result.get("isError", False) is True:
            return
        raw = self._captured[(alias, tool)].raw
        schema = raw.get("outputSchema")
        if schema is None:
            return
        if not isinstance(schema, dict):
            raise SchemaDriftError("the reviewed output schema is invalid")
        structured = result.get("structuredContent")
        if not isinstance(structured, Mapping):
            raise SchemaDriftError("a successful result omitted structured content")
        try:
            validator = Draft202012Validator(schema)
            validator.check_schema(schema)
            validator.validate(copy.deepcopy(dict(structured)))
        except Exception:
            raise SchemaDriftError(
                "the downstream result does not match the reviewed output schema"
            ) from None


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


ToolCallHandler = Callable[
    [str, str, Mapping[str, Any], str, InvocationIdentity],
    Awaitable[dict[str, Any]],
]
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
        tracked_session_limit: int = 1_024,
        tracked_session_ttl_seconds: float = 35 * 60,
        session_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if tracked_session_limit < 1 or tracked_session_limit > 10_000:
            raise ValueError("tracked MCP session limit is invalid")
        if tracked_session_ttl_seconds < 60 or tracked_session_ttl_seconds > 24 * 60 * 60:
            raise ValueError("tracked MCP session TTL is invalid")
        self.alias = alias
        self.mirror = mirror
        self.call_handler = call_handler
        self.denied_event_handler = denied_event_handler
        self.namespace_provider = namespace_provider
        self.server: LosslessToolServer = LosslessToolServer("Signet", version="0.1.0")
        self._sessions: set[Any] = set()
        self._session_invocation_scopes: dict[Any, str] = {}
        self._session_ids: dict[str, Any] = {}
        self._session_last_seen: dict[Any, float] = {}
        self._tracked_session_limit = tracked_session_limit
        self._tracked_session_ttl_seconds = tracked_session_ttl_seconds
        self._session_clock = session_clock
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
        session = self.server.request_context.session
        now = self._session_clock()
        self._prune_sessions(now, reserve_new=session not in self._sessions)
        self._sessions.add(session)
        self._session_invocation_scopes.setdefault(session, secrets.token_urlsafe(24))
        self._session_last_seen[session] = now
        request = self.server.request_context.request
        if request is not None:
            session_id = _scope_header(request.scope, b"mcp-session-id")
            if session_id is not None and 1 <= len(session_id) <= 128:
                previous = self._session_ids.get(session_id)
                if previous is not None and previous is not session:
                    self._forget_session(previous)
                self._session_ids[session_id] = session

    @property
    def tracked_session_count(self) -> int:
        return len(self._sessions)

    def retire_session(self, session_id: str) -> bool:
        """Forget a transport session after an authenticated SDK termination."""

        session = self._session_ids.pop(session_id, None)
        if session is None:
            return False
        self._forget_session(session)
        return True

    def _prune_sessions(self, now: float, *, reserve_new: bool = False) -> None:
        stale = [
            session
            for session, last_seen in self._session_last_seen.items()
            if now - last_seen >= self._tracked_session_ttl_seconds
        ]
        for session in stale:
            self._forget_session(session)
        capacity = self._tracked_session_limit - int(reserve_new)
        overflow = len(self._sessions) - capacity
        if overflow > 0:
            oldest = sorted(
                self._sessions,
                key=lambda session: self._session_last_seen.get(session, 0.0),
            )[:overflow]
            for session in oldest:
                self._forget_session(session)

    def _forget_session(self, session: Any) -> None:
        self._sessions.discard(session)
        self._session_invocation_scopes.pop(session, None)
        self._session_last_seen.pop(session, None)
        for session_id, candidate in tuple(self._session_ids.items()):
            if candidate is session:
                del self._session_ids[session_id]

    def _invocation_identity(self, namespace: str, tool: str) -> InvocationIdentity:
        context = self.server.request_context
        meta = (
            context.meta.model_dump(mode="json", by_alias=True, exclude_unset=True)
            if context.meta is not None
            else {}
        )
        explicit_present = SIGNET_INVOCATION_ID_META in meta
        session_scope = self._session_invocation_scopes[context.session]
        try:
            return derive_invocation_identity(
                namespace=namespace,
                alias=self.alias,
                tool=tool,
                explicit_id=meta.get(SIGNET_INVOCATION_ID_META),
                explicit_id_present=explicit_present,
                session_scope=session_scope,
                request_id=context.request_id,
            )
        except InvocationIdentityError:
            raise McpError(
                types.ErrorData(
                    code=types.INVALID_PARAMS,
                    message="Invalid Signet invocation identity",
                )
            ) from None

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
            if request.params.task is not None:
                raise DomainToolError(
                    "task_execution_unsupported",
                    "Task-augmented tool execution is not supported.",
                )
            invocation_identity = self._invocation_identity(namespace, name)
            self.mirror.validate_input(self.alias, name, arguments)
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
            raw_result = await self.call_handler(
                self.alias,
                name,
                arguments,
                namespace,
                invocation_identity,
            )
            types.CallToolResult.model_validate(raw_result)
            return RawServerResult(raw_result)
        except DomainToolError as exc:
            return RawServerResult(domain_error_result(exc.code, exc.message, details=exc.details))

    async def notify_list_changed(self) -> int:
        self._prune_sessions(self._session_clock())
        sent = 0
        stale: list[Any] = []
        for session in tuple(self._sessions):
            try:
                await session.send_tool_list_changed()
                sent += 1
            except Exception:
                stale.append(session)
        for session in stale:
            self._forget_session(session)
        return sent


def _scope_header(scope: Mapping[str, Any], name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if bytes(key).lower() == name:
            try:
                return bytes(value).decode("ascii")
            except UnicodeDecodeError:
                return None
    return None
