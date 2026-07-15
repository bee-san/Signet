"""Deny-by-default exact policy resolution and guarded promotions."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from signet.canonical import canonical_json


class PolicyError(ValueError):
    pass


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found a duplicate mapping key",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


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
_SCHEMA_REVIEW_FIELDS = frozenset(
    {"source", "fixture_status", "fail_closed_on_digest_change"}
)
_WRAPPER_CONTRACT_FIELDS = frozenset(
    {
        "id",
        "ownership",
        "executable",
        "executable_version",
        "output",
        "shell_interpolation",
        "fixture_source",
    }
)
_POLICY_CHANGE_FIELDS = frozenset(
    {
        "approval_channel",
        "require_fresh_human_confirmation",
        "passthrough_requires_reviewed_read_only",
        "communication_sends_may_be_passthrough",
    }
)
_LIMIT_MAXIMUMS = {
    "payload_bytes": 16 * 1024 * 1024,
    "pending_requests": 100_000,
    "requests_per_minute": 10_000,
}


@dataclass(frozen=True, slots=True)
class SchemaReviewPolicy:
    source: str
    fixture_status: str
    fail_closed_on_digest_change: bool


@dataclass(frozen=True, slots=True)
class WrapperContract:
    contract_id: str
    ownership: str
    executable: str
    executable_version: str
    output: str
    shell_interpolation: str
    fixture_source: str


@dataclass(frozen=True, slots=True)
class PolicyChangeContract:
    approval_channel: str
    require_fresh_human_confirmation: bool
    passthrough_requires_reviewed_read_only: bool
    communication_sends_may_be_passthrough: bool


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
    account_ref: str | None = None
    reviewed_classification: str | None = None


@dataclass(frozen=True, slots=True)
class DownstreamPolicy:
    alias: str
    transport: str
    tools: dict[str, ToolPolicy]
    url: str | None = None
    command_ref: str | None = None
    credential_ref: str | None = None
    schema_review: SchemaReviewPolicy | None = None
    account_ref: str | None = None
    wrapper_contract: WrapperContract | None = None


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    version: int
    default_mode: PolicyMode
    downstreams: dict[str, DownstreamPolicy]
    mode_contracts: dict[PolicyMode, dict[str, Any]] = field(default_factory=dict)
    policy_changes: PolicyChangeContract | None = None

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


def _mode_contracts(value: Any) -> dict[PolicyMode, dict[str, Any]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyError("mode_contracts must be an object")
    expected: dict[str, dict[str, Any]] = {
        "passthrough": {
            "exposure": "reviewed_tools_only",
            "downstream_calls": "immediate",
            "result_contract": "downstream_verbatim",
        },
        "virtualize_local": {
            "exposure": "reviewed_tools_only",
            "downstream_calls": 0,
            "standalone_approval": False,
            "result_contract": "captured_downstream_output_schema",
            "storage": "local_only",
            "scope_fields": ["adapter", "account", "caller_namespace"],
            "staging": {
                "root": "var/staging",
                "path_rule": "descendants_only",
                "reject_absolute_paths": True,
                "reject_parent_traversal": True,
                "reject_symlinks": True,
                "reject_hardlinks": True,
            },
        },
        "approval": {
            "exposure": "reviewed_tools_only",
            "downstream_calls_before_approval": 0,
            "result_contract": "gateway_pending_result",
        },
        "deny": {
            "exposure": "explicit_reviewed_only",
            "downstream_calls": 0,
            "result_contract": "call_tool_error",
        },
    }
    if set(value) != set(expected):
        raise PolicyError("mode_contracts must declare exactly the four reviewed modes")
    contracts: dict[PolicyMode, dict[str, Any]] = {}
    for name, reviewed in expected.items():
        candidate = value.get(name)
        if candidate != reviewed:
            raise PolicyError(f"mode_contracts.{name} does not match the runtime contract")
        contracts[PolicyMode(name)] = dict(candidate)
    return contracts


def _schema_review(value: Any, label: str) -> SchemaReviewPolicy | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must be an object")
    _reject_unknown_fields(value, _SCHEMA_REVIEW_FIELDS, label)
    if set(value) != _SCHEMA_REVIEW_FIELDS:
        raise PolicyError(f"{label} must declare every schema review field")
    source = _nonempty_string(value["source"], f"{label}.source")
    fixture_status = _nonempty_string(
        value["fixture_status"], f"{label}.fixture_status"
    )
    fail_closed = value["fail_closed_on_digest_change"]
    if fail_closed is not True:
        raise PolicyError(f"{label}.fail_closed_on_digest_change must be true")
    return SchemaReviewPolicy(source, fixture_status, True)


def _wrapper_contract(value: Any, label: str) -> WrapperContract | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must be an object")
    _reject_unknown_fields(value, _WRAPPER_CONTRACT_FIELDS, label)
    if set(value) != _WRAPPER_CONTRACT_FIELDS:
        raise PolicyError(f"{label} must declare every wrapper contract field")
    contract_id = _nonempty_string(value["id"], f"{label}.id")
    executable = _nonempty_string(value["executable"], f"{label}.executable")
    if not Path(executable).is_absolute():
        raise PolicyError(f"{label}.executable must be absolute")
    exact_values = {
        "ownership": "gateway",
        "output": "json_only",
        "shell_interpolation": "forbidden",
    }
    for field_name, expected in exact_values.items():
        if value[field_name] != expected:
            raise PolicyError(f"{label}.{field_name} must be {expected}")
    return WrapperContract(
        contract_id=contract_id,
        ownership="gateway",
        executable=executable,
        executable_version=_nonempty_string(
            value["executable_version"], f"{label}.executable_version"
        ),
        output="json_only",
        shell_interpolation="forbidden",
        fixture_source=_nonempty_string(
            value["fixture_source"], f"{label}.fixture_source"
        ),
    )


def _policy_changes(value: Any) -> PolicyChangeContract | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise PolicyError("policy_changes must be an object")
    _reject_unknown_fields(value, _POLICY_CHANGE_FIELDS, "policy_changes")
    expected = {
        "approval_channel": "web_only",
        "require_fresh_human_confirmation": True,
        "passthrough_requires_reviewed_read_only": True,
        "communication_sends_may_be_passthrough": False,
    }
    if value != expected:
        raise PolicyError("policy_changes must match the enforced promotion contract")
    return PolicyChangeContract(
        approval_channel="web_only",
        require_fresh_human_confirmation=True,
        passthrough_requires_reviewed_read_only=True,
        communication_sends_may_be_passthrough=False,
    )


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
    mode_contracts = _mode_contracts(data.get("mode_contracts"))
    policy_changes = _policy_changes(data.get("policy_changes"))
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
        schema_review = _schema_review(
            raw_downstream.get("schema_review"),
            f"downstreams.{alias}.schema_review",
        )
        account_value = raw_downstream.get("account_ref")
        account_ref = (
            _nonempty_string(account_value, f"downstreams.{alias}.account_ref")
            if account_value is not None
            else None
        )
        wrapper_contract = _wrapper_contract(
            raw_downstream.get("wrapper_contract"),
            f"downstreams.{alias}.wrapper_contract",
        )
        if wrapper_contract is not None and transport != "stdio":
            raise PolicyError(f"downstreams.{alias}.wrapper_contract is stdio-only")
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
            unknown_limits = set(limits) - set(_LIMIT_MAXIMUMS)
            if unknown_limits:
                raise PolicyError(
                    f"limits for {alias}/{name} contain unsupported keys: "
                    + ", ".join(sorted(unknown_limits))
                )
            for limit_name, limit_value in limits.items():
                if limit_value > _LIMIT_MAXIMUMS[limit_name]:
                    raise PolicyError(
                        f"limit {limit_name} for {alias}/{name} exceeds its safe maximum"
                    )
            tool_account_value = raw_tool.get("account_ref")
            tool_account_ref = (
                _nonempty_string(tool_account_value, f"account reference for {alias}/{name}")
                if tool_account_value is not None
                else None
            )
            classification_value = raw_tool.get("reviewed_classification")
            reviewed_classification = (
                _nonempty_string(
                    classification_value,
                    f"reviewed classification for {alias}/{name}",
                )
                if classification_value is not None
                else None
            )
            if reviewed_classification is not None and mode is not PolicyMode.DENY:
                raise PolicyError(
                    f"reviewed classification is only valid for denied tool {alias}/{name}"
                )
            if mode is PolicyMode.VIRTUALIZE_LOCAL and tool_account_ref is None:
                raise PolicyError(f"virtualize_local requires account_ref for {alias}/{name}")
            tools[name] = ToolPolicy(
                alias=alias,
                tool=name,
                mode=mode,
                adapter=adapter,
                reviewed_read_only=reviewed_read_only,
                communication_send=communication_send,
                schema_digest=schema_digest,
                limits=dict(limits),
                account_ref=tool_account_ref,
                reviewed_classification=reviewed_classification,
            )
        downstreams[alias] = DownstreamPolicy(
            alias=alias,
            transport=transport,
            tools=tools,
            url=url,
            command_ref=command_ref,
            credential_ref=credential_ref,
            schema_review=schema_review,
            account_ref=account_ref,
            wrapper_contract=wrapper_contract,
        )
    return PolicySnapshot(
        version=version,
        default_mode=default_mode,
        downstreams=downstreams,
        mode_contracts=mode_contracts,
        policy_changes=policy_changes,
    )


def load_policy(path: Path) -> PolicySnapshot:
    try:
        return parse_policy_yaml(path.read_bytes())
    except UnicodeDecodeError as exc:
        raise PolicyError(f"invalid UTF-8 YAML in {path}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML in {path}") from exc


def parse_policy_yaml(document: bytes) -> PolicySnapshot:
    if not isinstance(document, bytes) or not document:
        raise PolicyError("policy YAML must be non-empty bytes")
    return parse_policy(
        yaml.load(document.decode("utf-8", errors="strict"), Loader=_UniqueKeySafeLoader)
    )


def policy_document(snapshot: PolicySnapshot) -> dict[str, Any]:
    """Return the complete strict document represented by a parsed snapshot."""

    document: dict[str, Any] = {
        "version": snapshot.version,
        "default_mode": snapshot.default_mode.value,
    }
    if snapshot.mode_contracts:
        document["mode_contracts"] = {
            mode.value: copy.deepcopy(contract)
            for mode, contract in snapshot.mode_contracts.items()
        }
    downstreams: dict[str, Any] = {}
    for alias, downstream in snapshot.downstreams.items():
        downstream_data: dict[str, Any] = {"transport": downstream.transport}
        if downstream.url is not None:
            downstream_data["url"] = downstream.url
        if downstream.command_ref is not None:
            downstream_data["command_ref"] = downstream.command_ref
        if downstream.credential_ref is not None:
            downstream_data["credential_ref"] = downstream.credential_ref
        if downstream.schema_review is not None:
            downstream_data["schema_review"] = {
                "source": downstream.schema_review.source,
                "fixture_status": downstream.schema_review.fixture_status,
                "fail_closed_on_digest_change": (
                    downstream.schema_review.fail_closed_on_digest_change
                ),
            }
        if downstream.account_ref is not None:
            downstream_data["account_ref"] = downstream.account_ref
        if downstream.wrapper_contract is not None:
            contract = downstream.wrapper_contract
            downstream_data["wrapper_contract"] = {
                "id": contract.contract_id,
                "ownership": contract.ownership,
                "executable": contract.executable,
                "executable_version": contract.executable_version,
                "output": contract.output,
                "shell_interpolation": contract.shell_interpolation,
                "fixture_source": contract.fixture_source,
            }
        tools: dict[str, Any] = {}
        for name, tool in downstream.tools.items():
            tool_data: dict[str, Any] = {
                "mode": tool.mode.value,
                "reviewed_read_only": tool.reviewed_read_only,
                "communication_send": tool.communication_send,
                "limits": dict(tool.limits),
            }
            if tool.adapter is not None:
                tool_data["adapter"] = tool.adapter
            if tool.schema_digest is not None:
                tool_data["schema_digest"] = tool.schema_digest
            if tool.account_ref is not None:
                tool_data["account_ref"] = tool.account_ref
            if tool.reviewed_classification is not None:
                tool_data["reviewed_classification"] = tool.reviewed_classification
            tools[name] = tool_data
        downstream_data["tools"] = tools
        downstreams[alias] = downstream_data
    document["downstreams"] = downstreams
    if snapshot.policy_changes is not None:
        changes = snapshot.policy_changes
        document["policy_changes"] = {
            "approval_channel": changes.approval_channel,
            "require_fresh_human_confirmation": changes.require_fresh_human_confirmation,
            "passthrough_requires_reviewed_read_only": (
                changes.passthrough_requires_reviewed_read_only
            ),
            "communication_sends_may_be_passthrough": (
                changes.communication_sends_may_be_passthrough
            ),
        }
    return document


def dump_policy(snapshot: PolicySnapshot) -> bytes:
    """Serialize a strict snapshot deterministically for durable writeback."""

    return yaml.safe_dump(
        policy_document(snapshot),
        allow_unicode=False,
        default_flow_style=False,
        sort_keys=False,
    ).encode("utf-8")


def policy_config_hash(snapshot: PolicySnapshot) -> str:
    """Hash the semantic strict policy document, independent of YAML layout."""

    return hashlib.sha256(canonical_json(policy_document(snapshot))).hexdigest()


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

    def restore_durable_snapshot(self, snapshot: PolicySnapshot) -> None:
        """Replace runtime state with an already verified durable snapshot."""

        if not isinstance(snapshot, PolicySnapshot):
            raise TypeError("durable policy snapshot is invalid")
        self._snapshot = snapshot

    def promote(
        self,
        alias: str,
        tool: str,
        mode: PolicyMode,
        *,
        actor: str,
        reviewed_read_only: bool | None = None,
    ) -> PolicySnapshot:
        snapshot, current, updated = self.preview_promotion(
            alias,
            tool,
            mode,
            reviewed_read_only=reviewed_read_only,
        )
        self.install_reviewed_snapshot(snapshot, current, updated, actor=actor)
        return snapshot

    def preview_promotion(
        self,
        alias: str,
        tool: str,
        mode: PolicyMode,
        *,
        reviewed_read_only: bool | None = None,
    ) -> tuple[PolicySnapshot, ToolPolicy, ToolPolicy]:
        """Build one guarded next version without mutating active policy."""

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
        if updated == current:
            raise PolicyError("policy promotion must change one reviewed tool mode")
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
        return snapshot, current, updated

    def install_reviewed_snapshot(
        self,
        snapshot: PolicySnapshot,
        previous: ToolPolicy,
        updated: ToolPolicy,
        *,
        actor: str,
    ) -> None:
        """Install a snapshot already committed by the durable policy boundary."""

        if (
            snapshot.version != self._snapshot.version + 1
            or previous != self._snapshot.configured(previous.alias, previous.tool)
            or updated != snapshot.configured(updated.alias, updated.tool)
        ):
            raise PolicyError("reviewed policy snapshot is stale or inconsistent")
        self._snapshot = snapshot
        if self._on_change:
            self._on_change(snapshot, previous, updated, actor)
