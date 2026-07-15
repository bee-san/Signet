"""Lossless MCP tool discovery, mirroring, and low-level server handlers."""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
import math
import re
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Literal, cast

import mcp.types as types
from jsonschema import Draft202012Validator
from mcp.server.lowlevel import Server
from mcp.server.models import InitializationOptions
from mcp.shared.exceptions import McpError
from pydantic import PrivateAttr, model_serializer
from referencing import Registry
from referencing.exceptions import NoSuchResource

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
_SCHEMA_REFERENCE_KEYS = frozenset({"$dynamicRef", "$recursiveRef", "$ref"})
_SCHEMA_COMBINATOR_KEYS = frozenset({"allOf", "anyOf", "oneOf"})
_MAX_SCHEMA_NODES = 4_096
_MAX_SCHEMA_DEPTH = 32
_MAX_SCHEMA_BYTES = 256 * 1024
_MAX_SCHEMA_SCALAR_BYTES = 16 * 1024
_MAX_SCHEMA_COMBINATOR_BRANCHES = 16
_MAX_SCHEMA_COMBINATOR_BRANCHES_TOTAL = 64
_MAX_SCHEMA_REFERENCES = 32
_MAX_SCHEMA_PATTERNS = 16
_MAX_PATTERN_BYTES = 1_024
_MAX_PATTERN_EXPANDED_ATOMS = 4_096
_MAX_CAPTURE_SCHEMA_VALIDATORS = 1_024
_MAX_CAPTURE_SCHEMA_BYTES = 8 * 1024 * 1024
_MAX_CAPTURE_SCHEMA_NODES = 65_536
_MAX_CAPTURE_SCHEMA_PATTERNS = 512
_MAX_CAPTURE_PATTERN_BYTES = 128 * 1024
_MAX_CAPTURE_PATTERN_EXPANDED_ATOMS = 65_536
_MAX_CAPTURE_SCHEMA_COMBINATOR_BRANCHES = 1_024
_MAX_CAPTURE_SCHEMA_REFERENCES = 1_024
_MAX_JSON_INTEGER_BITS = 4_096
_MAX_UNIQUE_ITEMS = 256
_MAX_INSTANCE_NODES = 20_000
_MAX_INSTANCE_DEPTH = 64
_MAX_INSTANCE_KEY_BYTES = 4 * 1024
_MAX_INSTANCE_SCALAR_BYTES = 8 * 1024 * 1024
_MAX_INSTANCE_SCALAR_BYTES_TOTAL = 16 * 1024 * 1024

_SCHEMA_SINGLE_KEYWORDS = frozenset(
    {
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    }
)
_SCHEMA_MAP_KEYWORDS = frozenset(
    {"$defs", "definitions", "dependentSchemas", "patternProperties", "properties"}
)
_SCHEMA_LIST_KEYWORDS = _SCHEMA_COMBINATOR_KEYS | frozenset({"prefixItems"})

_SchemaPosition = Literal["data", "schema", "schema_list", "schema_map"]


class MirrorError(RuntimeError):
    pass


class SchemaDriftError(MirrorError):
    pass


class InvocationIdentityError(MirrorError):
    pass


class ListChangedNotificationError(MirrorError):
    pass


class _ValidationComplexityError(MirrorError):
    pass


class DomainToolError(MirrorError):
    def __init__(self, code: str, message: str, *, details: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})


class _AsyncReadWriteLock:
    """Allow concurrent calls while schema publication takes exclusive ownership."""

    def __init__(self) -> None:
        self._condition = asyncio.Condition()
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    @asynccontextmanager
    async def read(self) -> AsyncIterator[None]:
        async with self._condition:
            while self._writer or self._waiting_writers:
                await self._condition.wait()
            self._readers += 1
        try:
            yield
        finally:
            async with self._condition:
                self._readers -= 1
                if self._readers == 0:
                    self._condition.notify_all()

    @asynccontextmanager
    async def write(self) -> AsyncIterator[None]:
        async with self._condition:
            self._waiting_writers += 1
            try:
                while self._writer or self._readers:
                    await self._condition.wait()
                self._writer = True
            finally:
                self._waiting_writers -= 1
        try:
            yield
        finally:
            async with self._condition:
                self._writer = False
                self._condition.notify_all()


def _reject_schema_retrieval(uri: str) -> Any:
    raise NoSuchResource(uri)


_CLOSED_SCHEMA_REGISTRY: Registry[Any] = Registry(  # type: ignore[call-arg]
    retrieve=_reject_schema_retrieval
)


@dataclass(frozen=True, slots=True)
class _SchemaValidationWork:
    nodes: int
    patterns: int
    pattern_bytes: int
    pattern_expanded_atoms: int
    combinator_branches: int
    references: int


@dataclass(slots=True)
class _CaptureSchemaBudget:
    validators: int = 0
    schema_bytes: int = 0
    nodes: int = 0
    patterns: int = 0
    pattern_bytes: int = 0
    pattern_expanded_atoms: int = 0
    combinator_branches: int = 0
    references: int = 0

    def consume(self, work: _SchemaValidationWork, *, schema_bytes: int) -> None:
        validators = self.validators + 1
        total_schema_bytes = self.schema_bytes + schema_bytes
        nodes = self.nodes + work.nodes
        patterns = self.patterns + work.patterns
        pattern_bytes = self.pattern_bytes + work.pattern_bytes
        pattern_expanded_atoms = self.pattern_expanded_atoms + work.pattern_expanded_atoms
        combinator_branches = self.combinator_branches + work.combinator_branches
        references = self.references + work.references
        if (
            validators > _MAX_CAPTURE_SCHEMA_VALIDATORS
            or total_schema_bytes > _MAX_CAPTURE_SCHEMA_BYTES
            or nodes > _MAX_CAPTURE_SCHEMA_NODES
            or patterns > _MAX_CAPTURE_SCHEMA_PATTERNS
            or pattern_bytes > _MAX_CAPTURE_PATTERN_BYTES
            or pattern_expanded_atoms > _MAX_CAPTURE_PATTERN_EXPANDED_ATOMS
            or combinator_branches > _MAX_CAPTURE_SCHEMA_COMBINATOR_BRANCHES
            or references > _MAX_CAPTURE_SCHEMA_REFERENCES
        ):
            raise SchemaDriftError(
                "captured JSON schemas exceed the aggregate validation work limit"
            )
        self.validators = validators
        self.schema_bytes = total_schema_bytes
        self.nodes = nodes
        self.patterns = patterns
        self.pattern_bytes = pattern_bytes
        self.pattern_expanded_atoms = pattern_expanded_atoms
        self.combinator_branches = combinator_branches
        self.references = references


def _closed_schema_validator(
    schema: Mapping[str, Any],
    *,
    capture_budget: _CaptureSchemaBudget | None = None,
) -> Draft202012Validator:
    work = _validate_schema_complexity(schema)
    try:
        encoded = canonical_json(dict(schema))
    except Exception:
        raise SchemaDriftError("the reviewed JSON schema is invalid") from None
    if len(encoded) > _MAX_SCHEMA_BYTES:
        raise SchemaDriftError("the reviewed JSON schema exceeds its byte limit")
    if capture_budget is not None:
        capture_budget.consume(work, schema_bytes=len(encoded))
    return _compile_closed_schema(encoded)


@lru_cache(maxsize=64)
def _compile_closed_schema(encoded: bytes) -> Draft202012Validator:
    schema = json.loads(encoded)
    try:
        Draft202012Validator.check_schema(schema)
    except Exception:
        raise SchemaDriftError("the reviewed JSON schema is invalid") from None
    return Draft202012Validator(schema, registry=_CLOSED_SCHEMA_REGISTRY)


def _validate_schema_complexity(schema: Mapping[str, Any]) -> _SchemaValidationWork:
    nodes = 0
    combinator_branches = 0
    patterns = 0
    pattern_bytes = 0
    pattern_expanded_atoms = 0
    references: list[str] = []
    active_containers: set[int] = set()
    stack: list[tuple[Any, int, bool, _SchemaPosition]] = [(schema, 0, False, "schema")]

    while stack:
        value, depth, exiting, position = stack.pop()
        if exiting:
            active_containers.remove(id(value))
            continue
        nodes += 1
        if nodes > _MAX_SCHEMA_NODES or depth > _MAX_SCHEMA_DEPTH:
            raise SchemaDriftError("the reviewed JSON schema exceeds structural limits")

        if isinstance(value, Mapping):
            if position == "schema_list":
                raise SchemaDriftError("the reviewed JSON schema is invalid")
            container_id = id(value)
            if container_id in active_containers:
                raise SchemaDriftError("the reviewed JSON schema contains a cycle")
            active_containers.add(container_id)
            stack.append((value, depth, True, position))
            nodes += len(value)
            if nodes > _MAX_SCHEMA_NODES:
                raise SchemaDriftError("the reviewed JSON schema exceeds structural limits")

            if position == "schema" and value.get("uniqueItems") is True:
                max_items = value.get("maxItems")
                if (
                    isinstance(max_items, bool)
                    or not isinstance(max_items, int)
                    or max_items < 0
                    or max_items > _MAX_UNIQUE_ITEMS
                ):
                    raise SchemaDriftError(
                        "reviewed uniqueItems schemas require a bounded maxItems"
                    )

            for key, child in value.items():
                if not isinstance(key, str):
                    raise SchemaDriftError("the reviewed JSON schema is invalid")
                _bounded_schema_text(key)
                if position == "schema_map":
                    stack.append((child, depth + 1, False, "schema"))
                    continue
                if position == "data":
                    stack.append((child, depth + 1, False, "data"))
                    continue
                if key in {"$dynamicRef", "$recursiveRef"}:
                    raise SchemaDriftError(
                        "reviewed JSON schemas do not support dynamic references"
                    )
                if key == "$id" and depth != 0:
                    raise SchemaDriftError(
                        "reviewed JSON schemas do not support nested identifiers"
                    )
                if key == "$ref":
                    if not isinstance(child, str) or not child.startswith("#/"):
                        raise SchemaDriftError(
                            "reviewed JSON schemas may only use in-document references"
                        )
                    references.append(child)
                    if len(references) > _MAX_SCHEMA_REFERENCES:
                        raise SchemaDriftError(
                            "the reviewed JSON schema exceeds its reference limit"
                        )
                elif key == "pattern":
                    if not isinstance(child, str):
                        raise SchemaDriftError("the reviewed JSON schema is invalid")
                    patterns += 1
                    if patterns > _MAX_SCHEMA_PATTERNS:
                        raise SchemaDriftError("the reviewed JSON schema exceeds its pattern limit")
                    child_bytes, child_atoms = _validate_linear_pattern(child)
                    pattern_bytes += child_bytes
                    pattern_expanded_atoms += child_atoms
                elif key == "patternProperties":
                    if not isinstance(child, Mapping):
                        raise SchemaDriftError("the reviewed JSON schema is invalid")
                    patterns += len(child)
                    if patterns > _MAX_SCHEMA_PATTERNS:
                        raise SchemaDriftError("the reviewed JSON schema exceeds its pattern limit")
                    for pattern in child:
                        if not isinstance(pattern, str):
                            raise SchemaDriftError("the reviewed JSON schema is invalid")
                        child_bytes, child_atoms = _validate_linear_pattern(pattern)
                        pattern_bytes += child_bytes
                        pattern_expanded_atoms += child_atoms
                elif key in _SCHEMA_COMBINATOR_KEYS:
                    if not isinstance(child, list):
                        raise SchemaDriftError("the reviewed JSON schema is invalid")
                    if len(child) > _MAX_SCHEMA_COMBINATOR_BRANCHES:
                        raise SchemaDriftError(
                            "the reviewed JSON schema exceeds its combinator limit"
                        )
                    combinator_branches += len(child)
                    if combinator_branches > _MAX_SCHEMA_COMBINATOR_BRANCHES_TOTAL:
                        raise SchemaDriftError(
                            "the reviewed JSON schema exceeds its combinator limit"
                        )
                stack.append((child, depth + 1, False, _schema_keyword_position(key)))
        elif isinstance(value, list):
            if position not in {"data", "schema_list"}:
                raise SchemaDriftError("the reviewed JSON schema is invalid")
            container_id = id(value)
            if container_id in active_containers:
                raise SchemaDriftError("the reviewed JSON schema contains a cycle")
            active_containers.add(container_id)
            stack.append((value, depth, True, position))
            child_position: _SchemaPosition = "schema" if position == "schema_list" else "data"
            stack.extend((child, depth + 1, False, child_position) for child in reversed(value))
        elif isinstance(value, str):
            if position != "data":
                raise SchemaDriftError("the reviewed JSON schema is invalid")
            _bounded_schema_text(value)
        elif isinstance(value, bool):
            if position not in {"data", "schema"}:
                raise SchemaDriftError("the reviewed JSON schema is invalid")
        elif value is None:
            if position != "data":
                raise SchemaDriftError("the reviewed JSON schema is invalid")
            continue
        elif isinstance(value, int):
            if position != "data":
                raise SchemaDriftError("the reviewed JSON schema is invalid")
            if value.bit_length() > _MAX_JSON_INTEGER_BITS:
                raise SchemaDriftError("the reviewed JSON schema exceeds scalar limits")
        elif isinstance(value, float):
            if position != "data":
                raise SchemaDriftError("the reviewed JSON schema is invalid")
            if not math.isfinite(value):
                raise SchemaDriftError("the reviewed JSON schema is invalid")
        else:
            raise SchemaDriftError("the reviewed JSON schema is invalid")

    for reference in references:
        target = _resolve_schema_reference(schema, reference)
        if _contains_schema_reference(target):
            raise SchemaDriftError(
                "reviewed in-document references may not be recursive or chained"
            )
    return _SchemaValidationWork(
        nodes=nodes,
        patterns=patterns,
        pattern_bytes=pattern_bytes,
        pattern_expanded_atoms=pattern_expanded_atoms,
        combinator_branches=combinator_branches,
        references=len(references),
    )


def _schema_keyword_position(keyword: str) -> _SchemaPosition:
    if keyword in _SCHEMA_SINGLE_KEYWORDS:
        return "schema"
    if keyword in _SCHEMA_MAP_KEYWORDS:
        return "schema_map"
    if keyword in _SCHEMA_LIST_KEYWORDS:
        return "schema_list"
    return "data"


def _bounded_schema_text(value: str) -> None:
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise SchemaDriftError("the reviewed JSON schema is invalid") from None
    if size > _MAX_SCHEMA_SCALAR_BYTES:
        raise SchemaDriftError("the reviewed JSON schema exceeds scalar limits")


def _resolve_schema_reference(schema: Mapping[str, Any], reference: str) -> Any:
    if "%" in reference:
        raise SchemaDriftError("reviewed in-document references must use JSON Pointer syntax")
    target: Any = schema
    position: _SchemaPosition = "schema"
    for encoded_token in reference[2:].split("/"):
        if re.search(r"~(?![01])", encoded_token):
            raise SchemaDriftError("reviewed in-document references must use JSON Pointer syntax")
        token = encoded_token.replace("~1", "/").replace("~0", "~")
        if isinstance(target, Mapping) and token in target:
            if position == "schema":
                position = _schema_keyword_position(token)
            elif position == "schema_map":
                position = "schema"
            elif position != "data":
                raise SchemaDriftError("reviewed JSON schema reference does not resolve")
            target = target[token]
        elif isinstance(target, list) and token.isascii() and token.isdecimal():
            if len(token) > 6 or (len(token) > 1 and token.startswith("0")):
                raise SchemaDriftError("reviewed JSON schema reference does not resolve")
            index = int(token)
            if index >= len(target):
                raise SchemaDriftError("reviewed JSON schema reference does not resolve")
            if position == "schema_list":
                position = "schema"
            elif position != "data":
                raise SchemaDriftError("reviewed JSON schema reference does not resolve")
            target = target[index]
        else:
            raise SchemaDriftError("reviewed JSON schema reference does not resolve")
    if position != "schema":
        raise SchemaDriftError("reviewed JSON schema reference does not resolve to a subschema")
    return target


def _contains_schema_reference(value: Any) -> bool:
    remaining = _MAX_SCHEMA_NODES
    stack: list[tuple[Any, _SchemaPosition]] = [(value, "schema")]
    while stack:
        remaining -= 1
        if remaining < 0:
            raise SchemaDriftError("the reviewed JSON schema exceeds structural limits")
        child, position = stack.pop()
        if isinstance(child, Mapping):
            if position == "schema" and any(key in _SCHEMA_REFERENCE_KEYS for key in child):
                return True
            if position == "schema":
                stack.extend(
                    (nested, _schema_keyword_position(key))
                    for key, nested in child.items()
                    if _schema_keyword_position(key) != "data"
                )
            elif position == "schema_map":
                stack.extend((nested, "schema") for nested in child.values())
        elif isinstance(child, list) and position == "schema_list":
            stack.extend((nested, "schema") for nested in child)
    return False


def _validate_linear_pattern(pattern: str) -> tuple[int, int]:
    try:
        pattern_bytes = len(pattern.encode("utf-8"))
        if pattern_bytes > _MAX_PATTERN_BYTES:
            raise SchemaDriftError("reviewed JSON schema pattern exceeds its byte limit")
    except UnicodeError:
        raise SchemaDriftError("the reviewed JSON schema pattern is invalid") from None

    index = 0
    variable_repeats = 0
    variable_repeat_end: int | None = None
    expanded_atoms = 0
    can_quantify = False
    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            index = _consume_safe_pattern_escape(pattern, index)
            expanded_atoms += 1
            can_quantify = pattern[index - 1] not in "AbBZ"
            continue
        if character == "[":
            index = _consume_safe_character_class(pattern, index)
            expanded_atoms += 1
            can_quantify = True
            continue
        if character in "()|":
            raise SchemaDriftError("reviewed JSON schema pattern is outside the linear-time subset")
        if character in "*+?":
            if not can_quantify:
                raise SchemaDriftError("the reviewed JSON schema pattern is invalid")
            variable_repeats += 1
            can_quantify = False
            index += 1
            variable_repeat_end = index
        elif character == "{":
            if not can_quantify:
                raise SchemaDriftError("the reviewed JSON schema pattern is invalid")
            repeat = re.match(r"\{([0-9]+)(?:,([0-9]*))?\}", pattern[index:])
            if repeat is None:
                raise SchemaDriftError("the reviewed JSON schema pattern is invalid")
            minimum_text, maximum_text = repeat.groups()
            minimum = int(minimum_text)
            maximum = (
                minimum if maximum_text is None else (int(maximum_text) if maximum_text else None)
            )
            if maximum is not None and maximum < minimum:
                raise SchemaDriftError("the reviewed JSON schema pattern is invalid")
            variable = maximum is None or maximum != minimum
            if variable:
                variable_repeats += 1
            expanded_atoms += (maximum if maximum is not None else minimum) - 1
            can_quantify = False
            index += repeat.end()
            if variable:
                variable_repeat_end = index
        elif character == "^":
            if index != 0:
                raise SchemaDriftError("the reviewed JSON schema pattern is invalid")
            can_quantify = False
            index += 1
        elif character == "$":
            if index != len(pattern) - 1:
                raise SchemaDriftError("the reviewed JSON schema pattern is invalid")
            can_quantify = False
            index += 1
        else:
            expanded_atoms += 1
            can_quantify = True
            index += 1

        if variable_repeats > 1 or expanded_atoms > _MAX_PATTERN_EXPANDED_ATOMS:
            raise SchemaDriftError("reviewed JSON schema pattern is outside the linear-time subset")

    try:
        re.compile(pattern)
    except re.error:
        raise SchemaDriftError("the reviewed JSON schema pattern is invalid") from None
    if pattern and not (pattern.startswith("^") or pattern.startswith(r"\A")):
        raise SchemaDriftError("reviewed JSON schema pattern is outside the linear-time subset")
    if variable_repeat_end is not None and pattern[variable_repeat_end:] not in {
        "",
        "$",
        r"\Z",
    }:
        raise SchemaDriftError("reviewed JSON schema pattern is outside the linear-time subset")
    return pattern_bytes, expanded_atoms


def _consume_safe_pattern_escape(pattern: str, index: int) -> int:
    if index + 1 >= len(pattern):
        raise SchemaDriftError("the reviewed JSON schema pattern is invalid")
    escaped = pattern[index + 1]
    if escaped.isalnum() and escaped not in "AbBdDsSwWZ":
        raise SchemaDriftError("reviewed JSON schema pattern is outside the linear-time subset")
    return index + 2


def _consume_safe_character_class(pattern: str, index: int) -> int:
    cursor = index + 1
    if cursor < len(pattern) and pattern[cursor] == "^":
        cursor += 1
    has_content = False
    while cursor < len(pattern):
        character = pattern[cursor]
        if character == "]" and has_content:
            return cursor + 1
        if character == "[":
            raise SchemaDriftError("reviewed JSON schema pattern is outside the linear-time subset")
        if character == "\\":
            cursor = _consume_safe_pattern_escape(pattern, cursor)
        else:
            cursor += 1
        has_content = True
    raise SchemaDriftError("the reviewed JSON schema pattern is invalid")


def _validate_instance_complexity(value: Any) -> None:
    nodes = 0
    scalar_bytes = 0
    active_containers: set[int] = set()
    stack: list[tuple[Any, int, bool]] = [(value, 0, False)]
    while stack:
        child, depth, exiting = stack.pop()
        if exiting:
            active_containers.remove(id(child))
            continue
        nodes += 1
        if nodes > _MAX_INSTANCE_NODES or depth > _MAX_INSTANCE_DEPTH:
            raise _ValidationComplexityError("JSON value exceeds validation complexity limits")
        if isinstance(child, Mapping):
            container_id = id(child)
            if container_id in active_containers:
                raise _ValidationComplexityError("JSON value contains a cycle")
            active_containers.add(container_id)
            stack.append((child, depth, True))
            nodes += len(child)
            if nodes > _MAX_INSTANCE_NODES:
                raise _ValidationComplexityError("JSON value exceeds validation complexity limits")
            for key, nested in child.items():
                if not isinstance(key, str):
                    raise _ValidationComplexityError("JSON object key is invalid")
                try:
                    key_bytes = len(key.encode("utf-8"))
                except UnicodeError:
                    raise _ValidationComplexityError("JSON object key is invalid") from None
                if key_bytes > _MAX_INSTANCE_KEY_BYTES:
                    raise _ValidationComplexityError("JSON object key exceeds its byte limit")
                scalar_bytes += key_bytes
                stack.append((nested, depth + 1, False))
        elif isinstance(child, list):
            container_id = id(child)
            if container_id in active_containers:
                raise _ValidationComplexityError("JSON value contains a cycle")
            active_containers.add(container_id)
            stack.append((child, depth, True))
            stack.extend((nested, depth + 1, False) for nested in reversed(child))
        elif isinstance(child, str):
            try:
                size = len(child.encode("utf-8"))
            except UnicodeError:
                raise _ValidationComplexityError("JSON string is invalid") from None
            if size > _MAX_INSTANCE_SCALAR_BYTES:
                raise _ValidationComplexityError("JSON string exceeds its byte limit")
            scalar_bytes += size
        elif isinstance(child, bool) or child is None:
            continue
        elif isinstance(child, int):
            if child.bit_length() > _MAX_JSON_INTEGER_BITS:
                raise _ValidationComplexityError("JSON integer exceeds its size limit")
        elif isinstance(child, float):
            if not math.isfinite(child):
                raise _ValidationComplexityError("JSON number is invalid")
        else:
            raise _ValidationComplexityError("value is outside the JSON data model")
        if scalar_bytes > _MAX_INSTANCE_SCALAR_BYTES_TOTAL:
            raise _ValidationComplexityError("JSON value exceeds its scalar byte limit")


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
    _closed_schema_validator(PENDING_RESULT_SCHEMA).validate(pending_value)
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
    input_validator: Draft202012Validator
    output_validator: Draft202012Validator | None


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
        prepared: list[CapturedTool] = []
        capture_budget = _CaptureSchemaBudget()
        for tool in tools:
            candidate = raw_model(tool) if isinstance(tool, types.Tool) else dict(tool)
            name = candidate.get("name")
            if not isinstance(name, str) or not name or name in seen:
                raise MirrorError("downstream tools/list contained a missing or duplicate name")
            seen.add(name)
            input_schema = candidate.get("inputSchema")
            if not isinstance(input_schema, Mapping):
                raise SchemaDriftError("the reviewed JSON schema is invalid")
            input_validator = _closed_schema_validator(
                input_schema,
                capture_budget=capture_budget,
            )
            output_schema = candidate.get("outputSchema")
            if output_schema is not None and not isinstance(output_schema, Mapping):
                raise SchemaDriftError("the reviewed JSON schema is invalid")
            output_validator = (
                _closed_schema_validator(output_schema, capture_budget=capture_budget)
                if isinstance(output_schema, Mapping)
                else None
            )
            raw = validate_lossless_tool(candidate)
            prepared.append(
                CapturedTool(
                    alias=alias,
                    name=name,
                    raw=raw,
                    digest=tool_schema_digest(raw),
                    input_validator=input_validator,
                    output_validator=output_validator,
                )
            )

        changed: set[str] = set()
        for captured in prepared:
            key = (alias, captured.name)
            previous = self._captured.get(key)
            self._captured[key] = captured
            reviewed = self._reviewed_digests.get(key)
            if reviewed is not None and reviewed != captured.digest:
                self._drifted.add(key)
                changed.add(captured.name)
            elif reviewed == captured.digest:
                self._drifted.discard(key)
            if previous is not None and previous.digest != captured.digest:
                changed.add(captured.name)
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

    def disable_schema(self, alias: str, tool: str) -> None:
        """Fail one captured tool closed without discarding its review material."""

        self._drifted.add((alias, tool))

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
        try:
            _validate_instance_complexity(arguments)
            valid = captured.input_validator.is_valid(copy.deepcopy(dict(arguments)))
        except _ValidationComplexityError:
            raise DomainToolError(
                "invalid_arguments",
                "Tool arguments exceed reviewed validation limits.",
            ) from None
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
        validator = self._captured[(alias, tool)].output_validator
        if validator is not None:
            _validate_instance_complexity(result)
            validator.validate(copy.deepcopy(result))

    def validate_downstream_result(
        self,
        alias: str,
        tool: str,
        result: Mapping[str, Any],
    ) -> None:
        """Enforce a reviewed output schema for successful passthrough results."""

        if result.get("isError", False) is True:
            return
        validator = self._captured[(alias, tool)].output_validator
        if validator is None:
            return
        structured = result.get("structuredContent")
        if not isinstance(structured, Mapping):
            raise SchemaDriftError("a successful result omitted structured content")
        try:
            _validate_instance_complexity(structured)
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


async def discover_all_tools(
    session: Any,
    *,
    max_pages: int = 32,
    max_tools: int = 512,
    max_aggregate_bytes: int = 8 * 1024 * 1024,
    timeout_seconds: float = 30.0,
) -> list[dict[str, Any]]:
    """Exhaust tools/list pagination while detecting loops and duplicates."""

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
        raise ValueError("downstream discovery bounds are invalid")
    cursor: str | None = None
    cursors: set[str] = set()
    names: set[str] = set()
    tools: list[dict[str, Any]] = []
    aggregate_bytes = 0
    page_count = 0
    try:
        async with asyncio.timeout(timeout_seconds):
            while True:
                if page_count >= max_pages:
                    raise MirrorError("downstream tools/list exceeded the page limit")
                page_count += 1
                params = types.PaginatedRequestParams(cursor=cursor) if cursor is not None else None
                page = await session.list_tools(params=params)
                if len(tools) + len(page.tools) > max_tools:
                    raise MirrorError("downstream tools/list exceeded the tool limit")
                for model in page.tools:
                    raw = validate_lossless_tool(raw_model(model))
                    name = raw["name"]
                    if name in names:
                        raise MirrorError(f"duplicate downstream tool name: {name}")
                    try:
                        encoded_size = len(
                            json.dumps(
                                raw,
                                ensure_ascii=False,
                                allow_nan=False,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        )
                    except (TypeError, ValueError):
                        raise MirrorError("downstream tools/list contained invalid JSON") from None
                    aggregate_bytes += encoded_size
                    if aggregate_bytes > max_aggregate_bytes:
                        raise MirrorError("downstream tools/list exceeded the aggregate byte limit")
                    names.add(name)
                    tools.append(raw)
                next_cursor = page.nextCursor
                if next_cursor is None:
                    return tools
                if not isinstance(next_cursor, str) or not next_cursor:
                    raise MirrorError("downstream tools/list returned an invalid cursor")
                cursor_size = len(next_cursor.encode("utf-8"))
                if cursor_size > 1_024:
                    raise MirrorError("downstream tools/list cursor exceeded its limit")
                aggregate_bytes += cursor_size
                if aggregate_bytes > max_aggregate_bytes:
                    raise MirrorError("downstream tools/list exceeded the aggregate byte limit")
                if next_cursor in cursors:
                    raise MirrorError("downstream tools/list pagination cursor repeated")
                cursors.add(next_cursor)
                cursor = next_cursor
    except TimeoutError:
        raise MirrorError("downstream tools/list discovery timed out") from None


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
        self._schema_change_lock = _AsyncReadWriteLock()
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
        self._admit_session(session, now)
        self._session_last_seen[session] = now
        request = self.server.request_context.request
        if request is not None:
            session_id = _scope_header(request.scope, b"mcp-session-id")
            if session_id is not None and 1 <= len(session_id) <= 128:
                previous = self._session_ids.get(session_id)
                if previous is not None and previous is not session:
                    self._forget_session(previous)
                self._session_ids[session_id] = session
                self._session_invocation_scopes[session] = _stable_session_scope(
                    self.alias, session_id
                )

    @property
    def session_tracking_ttl_seconds(self) -> float:
        return self._tracked_session_ttl_seconds

    @property
    def tracked_session_limit(self) -> int:
        return self._tracked_session_limit

    def _admit_session(self, session: Any, now: float) -> None:
        self._prune_sessions(now)
        if session not in self._sessions and len(self._sessions) >= self._tracked_session_limit:
            raise McpError(
                types.ErrorData(
                    code=types.INVALID_REQUEST,
                    message="The Signet MCP session limit is reached.",
                )
            )
        self._sessions.add(session)
        self._session_invocation_scopes.setdefault(session, secrets.token_urlsafe(24))

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

    def _prune_sessions(self, now: float) -> None:
        stale = [
            session
            for session, last_seen in self._session_last_seen.items()
            if now - last_seen >= self._tracked_session_ttl_seconds
        ]
        for session in stale:
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
        async with self._schema_change_lock.read():
            self._namespace()
            self._remember_session()
            return RawServerResult({"tools": self.mirror.list_tools(self.alias)})

    async def _call_tool(self, request: types.CallToolRequest) -> types.ServerResult:
        async with self._schema_change_lock.read():
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
                return RawServerResult(
                    domain_error_result(exc.code, exc.message, details=exc.details)
                )

    @asynccontextmanager
    async def schema_change_guard(self) -> AsyncIterator[None]:
        """Exclude calls and list reads while a reviewed schema is published."""

        async with self._schema_change_lock.write():
            yield

    async def notify_list_changed(self, *, strict: bool = False) -> int:
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
        if strict and stale:
            raise ListChangedNotificationError(
                "one or more upstream tool-list notifications failed"
            )
        return sent


def _scope_header(scope: Mapping[str, Any], name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if bytes(key).lower() == name:
            try:
                return bytes(value).decode("ascii")
            except UnicodeDecodeError:
                return None
    return None


def _stable_session_scope(alias: str, session_id: str) -> str:
    return sha256_hex(
        canonical_json(
            {
                "alias": alias,
                "domain": "signet/mcp-session-scope/v1",
                "session_id": session_id,
            }
        )
    )
