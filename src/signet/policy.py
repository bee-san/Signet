"""Deny-by-default exact policy resolution and guarded promotions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml


class PolicyError(ValueError):
    pass


class PolicyMode(StrEnum):
    PASSTHROUGH = "passthrough"
    VIRTUALIZE_LOCAL = "virtualize_local"
    APPROVAL = "approval"
    DENY = "deny"


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


def parse_policy(data: Any) -> PolicySnapshot:
    if not isinstance(data, dict):
        raise PolicyError("policy root must be an object")
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
        transport = raw_downstream.get("transport")
        if transport not in {"http", "stdio"}:
            raise PolicyError(f"downstreams.{alias}.transport must be http or stdio")
        if transport == "http" and not raw_downstream.get("url"):
            raise PolicyError(f"downstreams.{alias}.url is required for HTTP")
        if transport == "stdio" and not raw_downstream.get("command_ref"):
            raise PolicyError(f"downstreams.{alias}.command_ref is required for stdio")
        raw_tools = raw_downstream.get("tools", {})
        if not isinstance(raw_tools, dict):
            raise PolicyError(f"downstreams.{alias}.tools must be an object")
        tools: dict[str, ToolPolicy] = {}
        for raw_name, raw_tool in raw_tools.items():
            name = _nonempty_string(raw_name, f"downstreams.{alias} tool")
            if not isinstance(raw_tool, dict):
                raise PolicyError(f"downstreams.{alias}.tools.{name} must be an object")
            try:
                mode = PolicyMode(raw_tool.get("mode"))
            except (TypeError, ValueError) as exc:
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
            if mode in {PolicyMode.APPROVAL, PolicyMode.VIRTUALIZE_LOCAL} and not raw_tool.get(
                "adapter"
            ):
                raise PolicyError(f"{mode.value} requires an adapter for {alias}/{name}")
            limits = raw_tool.get("limits", {})
            if not isinstance(limits, dict) or any(
                not isinstance(v, int) or isinstance(v, bool) or v <= 0 for v in limits.values()
            ):
                raise PolicyError(f"limits for {alias}/{name} must be positive integers")
            tools[name] = ToolPolicy(
                alias=alias,
                tool=name,
                mode=mode,
                adapter=raw_tool.get("adapter"),
                reviewed_read_only=reviewed_read_only,
                communication_send=communication_send,
                schema_digest=raw_tool.get("schema_digest"),
                limits=dict(limits),
            )
        downstreams[alias] = DownstreamPolicy(
            alias=alias,
            transport=transport,
            tools=tools,
            url=raw_downstream.get("url"),
            command_ref=raw_downstream.get("command_ref"),
            credential_ref=raw_downstream.get("credential_ref"),
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
