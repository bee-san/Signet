"""Strict, data-only manifests for staged MCP integrations.

Manifests are local JSON documents.  This module deliberately performs no URL
fetching, package installation, executable resolution, credential lookup, or MCP
dispatch.  Its only outputs are an immutable validated model, canonical JSON
bytes, and the SHA-256 digest of those bytes.
"""

from __future__ import annotations

import copy
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Any, Literal, Never, Self, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from signet.canonical import canonical_json, sha256_hex

MAX_MANIFEST_BYTES = 512 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 50_000
MAX_JSON_STRING_BYTES = 64 * 1024

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_PLUGIN_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_VERSION_RE = re.compile(r"^[0-9][A-Za-z0-9.+_-]*$")
_CONNECTOR_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_TOOL_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]*$")
_ACTION_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_COMMAND_REF_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SECRET_LIKE_TEXT = re.compile(
    r"(?ix)(?:"
    r"authorization\s*[:=]\s*bearer\s+\S+|"
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)"
    r"\s*[:=]\s*\S+|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"-----BEGIN\s+[A-Z ]*PRIVATE\s+KEY-----|"
    r"\b(?:sk|xox[baprs]|gh[pousr])-[A-Za-z0-9_-]{12,}|"
    r"[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@"
    r")"
)
_UNSAFE_SAFE_RESULT_LEAVES = frozenset(
    {
        "authorization",
        "cookie",
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
    }
)

REFERENCE_PLUGIN_IDS = ("fastmail", "telegram", "whatsapp")

TriState = bool | Literal["unknown"]
ConnectorTransport = Literal["streamable_http", "stdio"]
AdapterRequirement = Literal["generic_json_staged", "provider_specific"]
WorkerOperation = Literal[
    "identity",
    "validate_schema",
    "canonicalize",
    "review_summary",
    "redact",
    "classify_fake_outcome",
]


class PluginManifestError(ValueError):
    """A manifest is unsafe, malformed, unsupported, or not hash-pinned."""


class MutationEffect(StrEnum):
    NONE = "none"
    ADDITIVE = "additive"
    MUTATING = "mutating"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class EffectProfile(_StrictModel):
    """Independent effect conclusions; evidence is stored outside this model."""

    mutation: MutationEffect
    external_communication: TriState
    code_execution: TriState
    privilege_change: TriState
    open_world: TriState
    idempotent: TriState


class ConnectorTemplate(_StrictModel):
    connector_id: str
    display_name: str
    protocol: Literal["mcp"] = "mcp"
    transports: tuple[ConnectorTransport, ...] = Field(min_length=1, max_length=2)
    requires_mcp_shim: bool

    @field_validator("connector_id")
    @classmethod
    def connector_id_is_exact(cls, value: str) -> str:
        return _identifier(
            value,
            pattern=_CONNECTOR_ID_RE,
            maximum=64,
            label="connector ID",
        )

    @field_validator("display_name")
    @classmethod
    def connector_display_name_is_bounded(cls, value: str) -> str:
        return _text(value, maximum=160, label="connector display name")

    @field_validator("transports")
    @classmethod
    def connector_transports_are_unique(
        cls, value: tuple[ConnectorTransport, ...]
    ) -> tuple[ConnectorTransport, ...]:
        if len(value) != len(set(value)):
            raise ValueError("connector transports must be unique")
        return value


class ToolMapping(_StrictModel):
    connector_id: str
    tool_name: str
    action_id: str
    display_label: str
    sensitive_json_paths: tuple[str, ...] = Field(max_length=128)
    safe_result_fields: tuple[str, ...] = Field(max_length=128)
    proposed_effects: EffectProfile
    adapter_requirement: AdapterRequirement

    @field_validator("connector_id")
    @classmethod
    def mapping_connector_id_is_exact(cls, value: str) -> str:
        return _identifier(
            value,
            pattern=_CONNECTOR_ID_RE,
            maximum=64,
            label="mapping connector ID",
        )

    @field_validator("tool_name")
    @classmethod
    def tool_name_is_exact(cls, value: str) -> str:
        return _identifier(
            value,
            pattern=_TOOL_NAME_RE,
            maximum=256,
            label="tool name",
        )

    @field_validator("action_id")
    @classmethod
    def action_id_is_exact(cls, value: str) -> str:
        return _identifier(
            value,
            pattern=_ACTION_ID_RE,
            maximum=128,
            label="action ID",
        )

    @field_validator("display_label")
    @classmethod
    def display_label_is_bounded(cls, value: str) -> str:
        return _text(value, maximum=200, label="tool display label")

    @field_validator("sensitive_json_paths")
    @classmethod
    def sensitive_paths_are_exact(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _json_pointer_list(value, safe_results=False)

    @field_validator("safe_result_fields")
    @classmethod
    def safe_fields_are_exact(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _json_pointer_list(value, safe_results=True)


class WorkerMetadata(_StrictModel):
    """A reference to a separately reviewed worker, never an executable path."""

    command_ref: str
    executable_sha256: str
    protocol_version: Literal[1]
    operations: tuple[WorkerOperation, ...] = Field(min_length=1, max_length=6)

    @field_validator("command_ref")
    @classmethod
    def command_reference_is_opaque(cls, value: str) -> str:
        return _identifier(
            value,
            pattern=_COMMAND_REF_RE,
            maximum=128,
            label="worker command reference",
        )

    @field_validator("executable_sha256")
    @classmethod
    def executable_digest_is_exact(cls, value: str) -> str:
        if _SHA256_RE.fullmatch(value) is None:
            raise ValueError("worker executable digest must be lowercase SHA-256")
        return value

    @field_validator("operations")
    @classmethod
    def worker_operations_are_unique(
        cls, value: tuple[WorkerOperation, ...]
    ) -> tuple[WorkerOperation, ...]:
        if len(value) != len(set(value)):
            raise ValueError("worker operations must be unique")
        return value


class PluginManifest(_StrictModel):
    plugin_manifest_version: Literal[1]
    plugin_id: str
    plugin_version: str
    display_name: str
    description: str
    connectors: tuple[ConnectorTemplate, ...] = Field(min_length=1, max_length=32)
    tool_mappings: tuple[ToolMapping, ...] = Field(min_length=1, max_length=1024)
    worker: WorkerMetadata | None = None

    @field_validator("plugin_id")
    @classmethod
    def plugin_id_is_exact(cls, value: str) -> str:
        return _identifier(value, pattern=_PLUGIN_ID_RE, maximum=128, label="plugin ID")

    @field_validator("plugin_version")
    @classmethod
    def plugin_version_is_exact(cls, value: str) -> str:
        return _identifier(value, pattern=_VERSION_RE, maximum=64, label="plugin version")

    @field_validator("display_name")
    @classmethod
    def plugin_display_name_is_bounded(cls, value: str) -> str:
        return _text(value, maximum=160, label="plugin display name")

    @field_validator("description")
    @classmethod
    def plugin_description_is_bounded(cls, value: str) -> str:
        return _text(value, maximum=4096, label="plugin description")

    @model_validator(mode="after")
    def identities_are_unique_and_resolved(self) -> Self:
        connector_ids = tuple(connector.connector_id for connector in self.connectors)
        if len(connector_ids) != len(set(connector_ids)):
            raise ValueError("connector IDs must be unique")
        available = set(connector_ids)
        mapping_keys: set[tuple[str, str]] = set()
        action_ids: set[str] = set()
        referenced: set[str] = set()
        for mapping in self.tool_mappings:
            if mapping.connector_id not in available:
                raise ValueError("tool mapping references an unknown connector")
            key = (mapping.connector_id, mapping.tool_name)
            if key in mapping_keys:
                raise ValueError("tool mappings must use unique exact tool names")
            if mapping.action_id in action_ids:
                raise ValueError("tool mapping action IDs must be unique")
            mapping_keys.add(key)
            action_ids.add(mapping.action_id)
            referenced.add(mapping.connector_id)
        if referenced != available:
            raise ValueError("every connector must have at least one exact tool mapping")
        return self


@dataclass(frozen=True, slots=True)
class ValidatedPluginManifest:
    manifest: PluginManifest
    canonical_bytes: bytes
    sha256: str


def parse_plugin_manifest(document: bytes) -> ValidatedPluginManifest:
    """Validate manifest bytes and return their normalized canonical identity."""

    raw = _parse_json(document, label="plugin manifest")
    if not isinstance(raw, dict):
        raise PluginManifestError("plugin manifest root must be an object")
    version = raw.get("plugin_manifest_version")
    if version != 1 or isinstance(version, bool):
        raise PluginManifestError("unsupported plugin manifest version")
    _reject_secret_like_values(raw)
    try:
        parsed_bytes = canonical_json(raw)
        manifest = PluginManifest.model_validate_json(parsed_bytes, strict=True)
    except ValidationError as exc:
        raise PluginManifestError("plugin manifest schema is invalid") from exc
    except (TypeError, ValueError) as exc:
        raise PluginManifestError("plugin manifest is not canonicalizable JSON") from exc
    canonical_bytes = canonical_json(manifest.model_dump(mode="json", exclude_none=True))
    return ValidatedPluginManifest(
        manifest=manifest,
        canonical_bytes=canonical_bytes,
        sha256=sha256_hex(canonical_bytes),
    )


def load_plugin_manifest(
    path: str | os.PathLike[str],
    *,
    expected_sha256: str,
) -> ValidatedPluginManifest:
    """Read one bounded local file and require its canonical SHA-256 pin."""

    expected = _validated_sha256(expected_sha256)
    validated = parse_plugin_manifest(_read_bounded_regular(Path(path)))
    if not hmac.compare_digest(validated.sha256, expected):
        raise PluginManifestError("plugin manifest canonical SHA-256 does not match")
    return validated


def load_reference_plugin(plugin_id: str) -> ValidatedPluginManifest:
    """Load a staged reference manifest shipped inside the Signet package."""

    selected = _reference_id(plugin_id)
    try:
        document = (
            resources.files("signet.reference_plugins")
            .joinpath(selected, "manifest.json")
            .read_bytes()
        )
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise PluginManifestError("reference plugin resource is unavailable") from exc
    return parse_plugin_manifest(document)


def load_reference_discovery_fixture(plugin_id: str) -> dict[str, Any]:
    """Load detached fake MCP discovery data for a staged reference plugin."""

    selected = _reference_id(plugin_id)
    try:
        document = (
            resources.files("signet.reference_plugins")
            .joinpath(selected, "tools-list.json")
            .read_bytes()
        )
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise PluginManifestError("reference discovery resource is unavailable") from exc
    parsed = _parse_json(document, label="reference discovery fixture")
    if not isinstance(parsed, dict):
        raise PluginManifestError("reference discovery fixture root must be an object")
    return cast(dict[str, Any], copy.deepcopy(parsed))


def _parse_json(document: bytes, *, label: str) -> Any:
    if not isinstance(document, bytes) or not document or len(document) > MAX_MANIFEST_BYTES:
        raise PluginManifestError(f"{label} exceeds its byte limit or is empty")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise PluginManifestError(f"{label} contains a duplicate JSON key")
            value[key] = item
        return value

    try:
        value = json.loads(
            document.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_constant=_reject_json_constant,
        )
    except PluginManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PluginManifestError(f"{label} is not strict UTF-8 JSON") from exc
    _validate_json_bounds(value, label=label)
    return value


def _read_bounded_regular(path: Path) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size < 1
            or opened.st_size > MAX_MANIFEST_BYTES
        ):
            raise PluginManifestError("plugin manifest must be a bounded regular local file")
        chunks: list[bytes] = []
        remaining = MAX_MANIFEST_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        document = b"".join(chunks)
        after = os.fstat(descriptor)
        try:
            current = path.lstat()
        except OSError as exc:
            raise PluginManifestError("plugin manifest changed while it was read") from exc
        if (
            len(document) > MAX_MANIFEST_BYTES
            or _file_identity(opened) != _file_identity(after)
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise PluginManifestError("plugin manifest changed while it was read")
        return document
    except PluginManifestError:
        raise
    except (OSError, ValueError) as exc:
        raise PluginManifestError(
            "plugin manifest is unavailable or not a safe local file"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_json_bounds(value: Any, *, label: str) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise PluginManifestError(f"{label} exceeds its structural limits")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 256:
                    raise PluginManifestError(f"{label} contains an invalid object key")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > MAX_JSON_STRING_BYTES:
                raise PluginManifestError(f"{label} contains an oversized string")
        elif isinstance(item, float):
            raise PluginManifestError(f"{label} contains an unsupported number")
        elif item is not None and not isinstance(item, (bool, int)):
            raise PluginManifestError(f"{label} contains a non-JSON value")

    visit(value, 0)


def _reject_secret_like_values(value: Any) -> None:
    def visit(item: Any) -> None:
        if isinstance(item, str):
            if _SECRET_LIKE_TEXT.search(item):
                raise PluginManifestError("plugin manifest contains credential-like material")
        elif isinstance(item, dict):
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)


def _text(value: str, *, maximum: int, label: str) -> str:
    if (
        not value
        or value.strip() != value
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or _SECRET_LIKE_TEXT.search(value)
    ):
        raise ValueError(f"{label} is invalid or unbounded")
    return value


def _identifier(value: str, *, pattern: re.Pattern[str], maximum: int, label: str) -> str:
    if (
        len(value.encode("utf-8")) > maximum
        or pattern.fullmatch(value) is None
        or "*" in value
        or "?" in value
    ):
        raise ValueError(f"{label} must be an exact bounded identifier")
    return value


def _json_pointer_list(values: tuple[str, ...], *, safe_results: bool) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise ValueError("JSON paths must be unique")
    for value in values:
        segments = _json_pointer_segments(value)
        if safe_results and segments[-1].lower() in _UNSAFE_SAFE_RESULT_LEAVES:
            raise ValueError("credential-bearing result fields cannot be marked safe")
    return values


def _json_pointer_segments(value: str) -> tuple[str, ...]:
    if (
        not value.startswith("/")
        or len(value.encode("utf-8")) > 1024
        or "*" in value
        or "?" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("JSON paths must be exact bounded JSON Pointers")
    raw_segments = value[1:].split("/")
    if not raw_segments or len(raw_segments) > MAX_JSON_DEPTH:
        raise ValueError("JSON path depth is invalid")
    decoded: list[str] = []
    for raw_segment in raw_segments:
        if not raw_segment:
            raise ValueError("JSON path segments cannot be empty")
        index = 0
        while index < len(raw_segment):
            if raw_segment[index] == "~":
                if index + 1 >= len(raw_segment) or raw_segment[index + 1] not in {"0", "1"}:
                    raise ValueError("JSON path contains an invalid escape")
                index += 2
            else:
                index += 1
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        if segment in {".", ".."} or any(marker in segment for marker in ("[", "]", "$")):
            raise ValueError("JSON path contains wildcard or traversal syntax")
        decoded.append(segment)
    return tuple(decoded)


def _validated_sha256(value: str) -> str:
    if _SHA256_RE.fullmatch(value) is None:
        raise PluginManifestError("expected plugin digest must be lowercase SHA-256")
    return value


def _reference_id(value: str) -> str:
    if value not in REFERENCE_PLUGIN_IDS:
        raise PluginManifestError("unknown reference plugin")
    return value


def _reject_json_constant(value: str) -> Never:
    raise ValueError(f"unsupported JSON constant: {value}")
