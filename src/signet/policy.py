"""Deny-by-default exact policy resolution and guarded promotions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml


class PolicyError(ValueError):
    pass


class PolicyMode(StrEnum):
    PASSTHROUGH = "passthrough"
    VIRTUALIZE_LOCAL = "virtualize_local"
    APPROVAL = "approval"
    DENY = "deny"


_ROOT_FIELDS = frozenset(
    {"version", "default_mode", "mode_contracts", "downstreams", "policy_changes"}
)
_DOWNSTREAM_FIELDS = frozenset(
    {
        "transport",
        "url",
        "command_ref",
        "credential_ref",
        "schema_review",
        "account_ref",
        "wrapper_contract",
        "tools",
    }
)
_TOOL_FIELDS = frozenset(
    {
        "mode",
        "adapter",
        "reviewed_read_only",
        "communication_send",
        "schema_digest",
        "limits",
        "account_ref",
        "reviewed_classification",
    }
)


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    alias: str
    tool: str
    mode: PolicyMode
    adapter: str | None = None
    reviewed_read_only: bool = False
    communication_send: bool = False
    schema_digest: str | None = None
    limits: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DownstreamPolicy:
    alias: str
    transport: str
    tools: dict[str, ToolPolicy]
    url: str | None = None
    command_ref: str | None = None
    credential_ref: str | None = None


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    version: int
    default_mode: PolicyMode
    downstreams: dict[str, DownstreamPolicy]

    def configured(self, alias: str, tool: str) -> ToolPolicy | None:
        downstream = self.downstreams.get(alias)
        return downstream.tools.get(tool) if downstream else None

    def resolve(self, alias: str, tool: str) -> PolicyMode:
        configured = self.configured(alias, tool)
        return configured.mode if configured else self.default_mode

    def is_listed(self, alias: str, tool: str) -> bool:
        """Only configured tools are listed; explicit deny remains discoverable."""

        return self.configured(alias, tool) is not None


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise PolicyError(f"{label} must be a non-empty, trimmed string")
    if "*" in value:
        raise PolicyError(f"{label} may not contain wildcards")
    return value


def _reject_unknown_fields(value: dict[Any, Any], allowed: frozenset[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        names = ", ".join(sorted(repr(item) for item in unknown))
        raise PolicyError(f"{label} contains unknown fields: {names}")


def _http_url(value: Any, label: str) -> str:
    url = _nonempty_string(value, label)
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        raise PolicyError(f"{label} must be an HTTPS or loopback HTTP URL") from None
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port is not None
        and not 1 <= port <= 65535
    ):
        raise PolicyError(f"{label} must be an HTTPS or loopback HTTP URL")
    loopback = parsed.hostname == "localhost"
    try:
        loopback = loopback or ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname == "localhost"
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise PolicyError(f"{label} must be an HTTPS or loopback HTTP URL")
    return url


def parse_policy(data: Any) -> PolicySnapshot:
    if not isinstance(data, dict):
        raise PolicyError("policy root must be an object")
    _reject_unknown_fields(data, _ROOT_FIELDS, "policy root")
    version = data.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise PolicyError("version must be a positive integer")
    try:
        default_mode = PolicyMode(data.get("default_mode", "deny"))
    except ValueError as exc:
        raise PolicyError("default_mode is invalid") from exc
    if default_mode is not PolicyMode.DENY:
        raise PolicyError("default_mode must be deny")
    raw_downstreams = data.get("downstreams", {})
    if not isinstance(raw_downstreams, dict):
        raise PolicyError("downstreams must be an object")

    downstreams: dict[str, DownstreamPolicy] = {}
    for raw_alias, raw_downstream in raw_downstreams.items():
        alias = _nonempty_string(raw_alias, "downstream alias")
        if not isinstance(raw_downstream, dict):
            raise PolicyError(f"downstreams.{alias} must be an object")
        _reject_unknown_fields(
            raw_downstream,
            _DOWNSTREAM_FIELDS,
            f"downstreams.{alias}",
        )
        transport = raw_downstream.get("transport")
        if transport not in {"http", "stdio"}:
            raise PolicyError(f"downstreams.{alias}.transport must be http or stdio")
        raw_url = raw_downstream.get("url")
        raw_command_ref = raw_downstream.get("command_ref")
        if transport == "http":
            url = _http_url(raw_url, f"downstreams.{alias}.url")
            if raw_command_ref is not None:
                raise PolicyError(f"downstreams.{alias}.command_ref is stdio-only")
            command_ref = None
        else:
            command_ref = _nonempty_string(
                raw_command_ref,
                f"downstreams.{alias}.command_ref",
            )
            if raw_url is not None:
                raise PolicyError(f"downstreams.{alias}.url is HTTP-only")
            url = None
        raw_credential_ref = raw_downstream.get("credential_ref")
        credential_ref = (
            _nonempty_string(raw_credential_ref, f"downstreams.{alias}.credential_ref")
            if raw_credential_ref is not None
            else None
        )
        if credential_ref is not None and not credential_ref.startswith("keychain://"):
            raise PolicyError(f"downstreams.{alias}.credential_ref must use keychain://")
        raw_tools = raw_downstream.get("tools", {})
        if not isinstance(raw_tools, dict):
            raise PolicyError(f"downstreams.{alias}.tools must be an object")
        tools: dict[str, ToolPolicy] = {}
        for raw_name, raw_tool in raw_tools.items():
            name = _nonempty_string(raw_name, f"downstreams.{alias} tool")
            if not isinstance(raw_tool, dict):
                raise PolicyError(f"downstreams.{alias}.tools.{name} must be an object")
            _reject_unknown_fields(
                raw_tool,
                _TOOL_FIELDS,
                f"downstreams.{alias}.tools.{name}",
            )
            raw_mode = raw_tool.get("mode")
            if not isinstance(raw_mode, str):
                raise PolicyError(f"invalid mode for {alias}/{name}")
            try:
                mode = PolicyMode(raw_mode)
            except ValueError as exc:
                raise PolicyError(f"invalid mode for {alias}/{name}") from exc
            reviewed_read_only = raw_tool.get("reviewed_read_only", False)
            communication_send = raw_tool.get("communication_send", False)
            if not isinstance(reviewed_read_only, bool) or not isinstance(communication_send, bool):
                raise PolicyError(f"classification flags for {alias}/{name} must be booleans")
            if mode is PolicyMode.PASSTHROUGH and (
                communication_send or not reviewed_read_only
            ):
                raise PolicyError(
                    f"passthrough requires reviewed read-only classification for {alias}/{name}"
                )
            adapter_value = raw_tool.get("adapter")
            adapter = (
                _nonempty_string(adapter_value, f"adapter for {alias}/{name}")
                if adapter_value is not None
                else None
            )
            if mode in {PolicyMode.APPROVAL, PolicyMode.VIRTUALIZE_LOCAL} and adapter is None:
                raise PolicyError(f"{mode.value} requires an adapter for {alias}/{name}")
            schema_digest_value = raw_tool.get("schema_digest")
            schema_digest = (
                _nonempty_string(schema_digest_value, f"schema digest for {alias}/{name}")
                if schema_digest_value is not None
                else None
            )
            if schema_digest is not None and (
                len(schema_digest) != 64
                or any(character not in "0123456789abcdef" for character in schema_digest)
            ):
                raise PolicyError(f"schema digest for {alias}/{name} must be lowercase SHA-256")
            limits = raw_tool.get("limits", {})
            if not isinstance(limits, dict) or any(
                not isinstance(key, str)
                or not key
                or not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
                for key, value in limits.items()
            ):
                raise PolicyError(f"limits for {alias}/{name} must be positive integers")
            tools[name] = ToolPolicy(
                alias=alias,
                tool=name,
                mode=mode,
                adapter=adapter,
                reviewed_read_only=reviewed_read_only,
                communication_send=communication_send,
                schema_digest=schema_digest,
                limits=dict(limits),
            )
        downstreams[alias] = DownstreamPolicy(
            alias=alias,
            transport=transport,
            tools=tools,
            url=url,
            command_ref=command_ref,
            credential_ref=credential_ref,
        )
    return PolicySnapshot(version=version, default_mode=default_mode, downstreams=downstreams)


def load_policy(path: Path) -> PolicySnapshot:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return parse_policy(yaml.safe_load(handle))
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML in {path}") from exc


class PolicyEngine:
    """In-memory applied snapshot with an auditable promotion callback."""

    def __init__(
        self,
        snapshot: PolicySnapshot,
        *,
        on_change: Callable[[PolicySnapshot, ToolPolicy, ToolPolicy, str], None] | None = None,
    ) -> None:
        self._snapshot = snapshot
        self._on_change = on_change

    @property
    def snapshot(self) -> PolicySnapshot:
        return self._snapshot

    def promote(
        self,
        alias: str,
        tool: str,
        mode: PolicyMode,
        *,
        actor: str,
        reviewed_read_only: bool | None = None,
    ) -> PolicySnapshot:
        current = self._snapshot.configured(alias, tool)
        if current is None:
            raise PolicyError("only a discovered, reviewed tool can be promoted")
        effective_read_only = (
            current.reviewed_read_only if reviewed_read_only is None else reviewed_read_only
        )
        if mode is PolicyMode.PASSTHROUGH and (
            current.communication_send or not effective_read_only
        ):
            raise PolicyError("passthrough is limited to reviewed read-only tools")
        if mode in {PolicyMode.APPROVAL, PolicyMode.VIRTUALIZE_LOCAL} and not current.adapter:
            raise PolicyError(f"{mode.value} requires a reviewed adapter")
        updated = replace(current, mode=mode, reviewed_read_only=effective_read_only)
        old_downstream = self._snapshot.downstreams[alias]
        new_tools = dict(old_downstream.tools)
        new_tools[tool] = updated
        new_downstreams = dict(self._snapshot.downstreams)
        new_downstreams[alias] = replace(old_downstream, tools=new_tools)
        snapshot = replace(
            self._snapshot,
            version=self._snapshot.version + 1,
            downstreams=new_downstreams,
        )
        if self._on_change:
            self._on_change(snapshot, current, updated, actor)
        self._snapshot = snapshot
        return snapshot
