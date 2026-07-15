"""Bounded, offline operations helpers for onboarding and cutover preparation.

This module never discovers a live service or scans the host.  Every operation
consumes an explicitly supplied, size-bounded fixture.  That constraint keeps
normal development and CI incapable of contacting a provider or inspecting
credentials while still making the later human-run inventory review repeatable.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from signet.mcp_mirror import tool_schema_digest, validate_lossless_tool
from signet.policy import load_policy

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_TOOLS = 512
MAX_INVENTORY_RECORDS = 4096
MAX_JSON_DEPTH = 32
MAX_TEXT_BYTES = 64 * 1024

_ALIAS_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_TOOL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_SAFE_EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/ -]{0,255}$")
_SENSITIVE_TEXT = re.compile(
    r"(?i)(?:authorization\s*[:=]\s*bearer\s+\S+|"
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*\S+|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
_FINGERPRINT_TEXT = re.compile(r"(?i)(?:sha(?:256|512)?\s*:|\b[a-f0-9]{32,}\b)")
_SENSITIVE_KEY = re.compile(
    r"(?i)^(?:authorization|cookie|password|passwd|secret|token|api[_-]?key|access[_-]?token)$"
)


class OperationsError(ValueError):
    """A supplied offline artifact is unsafe, malformed, or incomplete."""


Classification = Literal["likely_read", "likely_write", "unknown"]


@dataclass(frozen=True, slots=True)
class ReadinessResult:
    ready: Literal[False]
    inputs_complete: bool
    disposition: Literal["blocked", "human_review_required"]
    authorizes_live_changes: Literal[False]
    blockers: tuple[str, ...]
    checks: dict[str, bool]

    def as_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "inputs_complete": self.inputs_complete,
            "disposition": self.disposition,
            "authorizes_live_changes": self.authorizes_live_changes,
            "blockers": list(self.blockers),
            "checks": dict(sorted(self.checks.items())),
        }


INVENTORY_KINDS = frozenset(
    {
        "hermes_profile",
        "config",
        "environment_file",
        "launchd_plist",
        "cron",
        "script",
        "skill",
        "backup",
        "browser_session",
        "native_adapter",
        "terminal_path",
        "sdk_path",
        "jmap_path",
        "webhook",
        "shell_environment",
        "direct_mcp_url",
        "credential_reference",
    }
)
_INVENTORY_STATUSES = frozenset({"active", "disabled", "present", "absent", "unknown"})
_INVENTORY_CAPABILITIES = frozenset(
    {"write", "send", "credential", "provider_session", "read_only", "unknown"}
)
_INVENTORY_ROUTES = frozenset({"signet", "direct", "not_applicable", "unknown"})
_COVERAGE_STATUSES = frozenset({"complete", "not_applicable", "unknown"})
_BYPASS_CAPABILITIES = frozenset({"write", "send", "credential", "provider_session"})

LIVE_PREREQUISITES = (
    "human_cutover_authorization",
    "web_authenticator_enrolled",
    "downstream_credentials_enrolled",
    "live_schema_digests_reviewed",
    "bypass_inventory_reviewed",
    "backup_restore_drill_verified",
    "route_diffs_approved",
    "funnel_disabled",
)

_READ_PREFIXES = frozenset(
    {"get", "list", "read", "search", "find", "fetch", "query", "inspect", "status", "health"}
)
_WRITE_PREFIXES = frozenset(
    {
        "send",
        "create",
        "update",
        "set",
        "delete",
        "remove",
        "post",
        "publish",
        "upload",
        "execute",
        "run",
        "deploy",
        "grant",
        "revoke",
        "invite",
        "transfer",
        "pay",
        "move",
        "rename",
    }
)
_SEND_WORDS = frozenset({"send", "message", "email", "mail", "whatsapp", "sms", "post", "publish"})
_REQUIRED_FAKE_COUNTS = {
    "validated": 0,
    "durably_queued": 0,
    "denied": 0,
    "expired": 0,
    "cancelled": 0,
    "stale_approval": 0,
    "approved": 1,
}


def read_json_fixture(path: Path, *, max_bytes: int = MAX_INPUT_BYTES) -> Any:
    """Read strict JSON from a regular local file without following a symlink."""

    if max_bytes < 1 or max_bytes > MAX_INPUT_BYTES:
        raise OperationsError("fixture byte limit is invalid")
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
                raise OperationsError("offline fixture must be a bounded regular file")
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise OperationsError(
            "offline fixture is unavailable or not a bounded regular file"
        ) from exc
    if len(raw) > max_bytes or _file_identity(before) != _file_identity(after):
        raise OperationsError("offline fixture changed while reading or exceeds its byte limit")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise OperationsError("offline fixture contains a duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(_: str) -> None:
        raise OperationsError("offline fixture contains a non-finite number")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=invalid_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperationsError("offline fixture is not strict UTF-8 JSON") from exc
    _validate_json_bounds(value)
    return value


def capture_discovery_fixture(alias: str, document: Any) -> dict[str, Any]:
    """Normalize an already captured MCP tools/list response without network I/O."""

    _require_alias(alias)
    tools = _extract_tools(document)
    if not tools or len(tools) > MAX_TOOLS:
        raise OperationsError("discovery fixture must contain between 1 and 512 tools")
    captured: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in tools:
        if not isinstance(value, Mapping):
            raise OperationsError("every discovered tool must be an object")
        raw = copy.deepcopy(dict(value))
        _reject_secret_material(raw)
        try:
            exact = validate_lossless_tool(raw)
        except Exception as exc:
            raise OperationsError(
                "discovery fixture contains an invalid MCP tool definition"
            ) from exc
        name = exact.get("name")
        if not isinstance(name, str) or _TOOL_RE.fullmatch(name) is None or name in seen:
            raise OperationsError(
                "discovery fixture contains a missing, invalid, or duplicate tool name"
            )
        seen.add(name)
        captured.append(
            {
                "name": name,
                "schema_digest": tool_schema_digest(exact),
                "definition": exact,
            }
        )
    captured.sort(key=lambda item: cast(str, item["name"]))
    return {
        "fixture_version": 1,
        "alias": alias,
        "source": "provided_offline_tools_list",
        "network_used": False,
        "tools": captured,
    }


def classify_tools(capture: Any) -> dict[str, Any]:
    """Produce heuristic review hints; every resulting policy mode remains deny."""

    normalized = _validated_capture(capture)
    classifications: list[dict[str, Any]] = []
    for item in normalized["tools"]:
        definition = cast(dict[str, Any], item["definition"])
        name = cast(str, item["name"])
        classification, signals = _classify(definition)
        words = _name_words(name)
        send_like = bool(words & _SEND_WORDS)
        classifications.append(
            {
                "name": name,
                "schema_digest": item["schema_digest"],
                "candidate_classification": classification,
                "signals": signals,
                "review_status": "human_required",
                "generated_mode": "deny",
                "send_like": send_like,
                "adapter_review_required_for_approval": (
                    send_like or classification == "likely_write"
                ),
                "reconciliation_characterization_required": (
                    send_like or classification == "likely_write"
                ),
            }
        )
    return {
        "fixture_version": 1,
        "alias": normalized["alias"],
        "automatic_enablement": False,
        "classifications": classifications,
    }


def generate_deny_policy(
    capture: Any,
    *,
    transport: Literal["http", "stdio"],
) -> dict[str, Any]:
    """Generate a parseable policy mapping in which every captured tool is denied."""

    normalized = _validated_capture(capture)
    alias = cast(str, normalized["alias"])
    downstream: dict[str, Any] = {
        "transport": transport,
        "credential_ref": f"keychain://Signet/{alias}",
        "tools": {
            item["name"]: {
                "mode": "deny",
                "schema_digest": item["schema_digest"],
            }
            for item in normalized["tools"]
        },
    }
    if transport == "http":
        downstream["url"] = f"https://{alias}.replace.invalid/mcp"
    elif transport == "stdio":
        downstream["command_ref"] = f"configured-{alias}-launcher"
    else:
        raise OperationsError("transport must be http or stdio")
    return {
        "version": 1,
        "default_mode": "deny",
        "downstreams": {alias: downstream},
    }


def build_fake_adapter_contract_input(
    capture: Any,
    *,
    tool: str,
    arguments: Any,
) -> dict[str, Any]:
    """Build an inert contract-test input after validating the captured schema."""

    normalized = _validated_capture(capture)
    if not isinstance(arguments, dict):
        raise OperationsError("fake adapter arguments must be an object")
    _reject_secret_material(arguments)
    selected = next((item for item in normalized["tools"] if item["name"] == tool), None)
    if selected is None:
        raise OperationsError("fake adapter tool is not present in the captured fixture")
    definition = cast(dict[str, Any], selected["definition"])
    schema = definition.get("inputSchema")
    if not isinstance(schema, dict):
        raise OperationsError("captured tool has no object input schema")
    try:
        validator = Draft202012Validator(schema)
        validator.check_schema(schema)
        validator.validate(arguments)
    except (SchemaError, ValidationError) as exc:
        raise OperationsError("fake arguments do not match the captured input schema") from exc
    return {
        "fixture_version": 1,
        "fixture_identity": f"fake:{normalized['alias']}:{tool}",
        "must_not_dispatch": True,
        "alias": normalized["alias"],
        "tool": tool,
        "schema_digest": selected["schema_digest"],
        "arguments": copy.deepcopy(arguments),
        "required_scenarios": dict(_REQUIRED_FAKE_COUNTS),
        "approved_call_maximum": 1,
    }


def verify_fake_adapter_report(contract_input: Any, report: Any) -> dict[str, Any]:
    """Verify counts emitted by an external fake provider test harness."""

    if not isinstance(contract_input, dict) or not isinstance(report, dict):
        raise OperationsError("fake contract input and report must be objects")
    if set(contract_input) != {
        "fixture_version",
        "fixture_identity",
        "must_not_dispatch",
        "alias",
        "tool",
        "schema_digest",
        "arguments",
        "required_scenarios",
        "approved_call_maximum",
    }:
        raise OperationsError("fake contract input has an invalid shape")
    identity = contract_input.get("fixture_identity")
    alias = contract_input.get("alias")
    tool = contract_input.get("tool")
    schema_digest = contract_input.get("schema_digest")
    if (
        not isinstance(alias, str)
        or _ALIAS_RE.fullmatch(alias) is None
        or not isinstance(tool, str)
        or _TOOL_RE.fullmatch(tool) is None
        or not isinstance(schema_digest, str)
        or _SHA256_RE.fullmatch(schema_digest) is None
        or identity != f"fake:{alias}:{tool}"
    ):
        raise OperationsError("fake contract input has no explicit fake identity")
    if (
        contract_input.get("fixture_version") != 1
        or contract_input.get("must_not_dispatch") is not True
        or contract_input.get("approved_call_maximum") != 1
        or contract_input.get("required_scenarios") != _REQUIRED_FAKE_COUNTS
    ):
        raise OperationsError("fake contract input does not forbid pre-approval dispatch")
    if (
        set(report) != {"fixture_identity", "provider", "network_used", "downstream_call_counts"}
        or report.get("fixture_identity") != identity
        or report.get("provider") != "fake"
    ):
        raise OperationsError("contract report is not bound to the fake fixture")
    expected = contract_input.get("required_scenarios")
    observed = report.get("downstream_call_counts")
    if not isinstance(expected, dict) or not isinstance(observed, dict):
        raise OperationsError("fake contract report has no scenario counts")
    failures: list[str] = []
    network_used = report.get("network_used")
    if not isinstance(network_used, bool):
        raise OperationsError("fake contract report has an invalid network-used marker")
    if network_used:
        failures.append("network_used")
    for scenario, expected_count in expected.items():
        count = observed.get(scenario)
        if isinstance(count, bool) or not isinstance(count, int) or count != expected_count:
            failures.append(cast(str, scenario))
    extra = set(observed) - set(expected)
    if extra:
        failures.append("unexpected_scenarios")
    return {
        "passed": not failures,
        "fixture_identity": identity,
        "alias": alias,
        "tool": tool,
        "schema_digest": schema_digest,
        "failures": sorted(failures),
        "network_used": network_used,
    }


def audit_bypass_inventory(inventory: Any) -> dict[str, Any]:
    """Evaluate a supplied names-and-locations-only inventory for direct write paths."""

    if not isinstance(inventory, dict) or set(inventory) != {
        "fixture_version",
        "source",
        "coverage",
        "records",
    }:
        raise OperationsError("bypass inventory has an invalid top-level shape")
    if inventory.get("fixture_version") != 1 or inventory.get("source") != "provided_metadata_only":
        raise OperationsError("bypass inventory must identify an offline metadata-only source")
    coverage = inventory.get("coverage")
    records = inventory.get("records")
    if not isinstance(coverage, dict) or set(coverage) != INVENTORY_KINDS:
        raise OperationsError("bypass inventory must explicitly cover every required location kind")
    if any(value not in _COVERAGE_STATUSES for value in coverage.values()):
        raise OperationsError("bypass inventory coverage status is invalid")
    if not isinstance(records, list) or len(records) > MAX_INVENTORY_RECORDS:
        raise OperationsError("bypass inventory records are invalid or unbounded")

    findings: list[dict[str, str]] = []
    unresolved = sorted(kind for kind, status in coverage.items() if status == "unknown")
    for raw in records:
        record = _validate_inventory_record(raw)
        active = record["status"] in {"active", "present", "unknown"}
        bypass_capable = record["capability"] in _BYPASS_CAPABILITIES
        routed = record["route"] == "signet"
        if active and (
            record["status"] == "unknown"
            or record["capability"] == "unknown"
            or record["route"] == "unknown"
        ):
            findings.append(_finding(record, "unresolved"))
        elif active and bypass_capable and not routed:
            findings.append(_finding(record, "potential_bypass"))
    findings.sort(key=lambda item: (item["kind"], item["location"], item["name"]))
    return {
        "clean": not findings and not unresolved,
        "metadata_only": True,
        "coverage_complete": not unresolved,
        "unresolved_coverage": unresolved,
        "findings": findings,
        "record_count": len(records),
    }


def assess_cutover_readiness(
    *,
    capture: Any,
    review_manifest: Any,
    fake_contract_results: Any,
    bypass_report: Any,
    live_evidence: Any | None = None,
) -> ReadinessResult:
    """Fail closed unless offline checks and every live prerequisite are explicit."""

    normalized = _validated_capture(capture)
    checks: dict[str, bool] = {}
    manifest_shape = (
        isinstance(review_manifest, dict)
        and set(review_manifest) == {"schema_digests", "modes"}
        and isinstance(review_manifest.get("schema_digests"), dict)
        and isinstance(review_manifest.get("modes"), dict)
    )
    expected = review_manifest.get("schema_digests", {}) if manifest_shape else {}
    modes = review_manifest.get("modes", {}) if manifest_shape else {}
    actual = {item["name"]: item["schema_digest"] for item in normalized["tools"]}
    checks["review_manifest_complete"] = (
        manifest_shape
        and set(modes) == set(actual)
        and all(
            isinstance(mode, str)
            and mode in {"deny", "approval", "passthrough", "virtualize_local"}
            for mode in modes.values()
        )
    )
    checks["schema_digests_match"] = (
        manifest_shape
        and bool(expected)
        and set(expected) == set(actual)
        and all(
            isinstance(value, str)
            and _SHA256_RE.fullmatch(value) is not None
            and actual[name] == value
            for name, value in expected.items()
        )
    )
    required_fake_tools = (
        {name for name, mode in modes.items() if mode == "approval"}
        if checks["review_manifest_complete"]
        else set()
    )
    checks["fake_adapter_contracts_complete"] = _complete_fake_contract_results(
        fake_contract_results,
        alias=cast(str, normalized["alias"]),
        actual_digests=actual,
        required_tools=required_fake_tools,
    )
    bypass_shape = isinstance(bypass_report, dict) and set(bypass_report) == {
        "clean",
        "metadata_only",
        "coverage_complete",
        "unresolved_coverage",
        "findings",
        "record_count",
    }
    checks["bypass_audit_clean"] = (
        bypass_shape
        and bypass_report.get("clean") is True
        and bypass_report.get("metadata_only") is True
        and bypass_report.get("coverage_complete") is True
        and bypass_report.get("unresolved_coverage") == []
        and bypass_report.get("findings") == []
        and isinstance(bypass_report.get("record_count"), int)
        and not isinstance(bypass_report.get("record_count"), bool)
        and 0 <= bypass_report["record_count"] <= MAX_INVENTORY_RECORDS
    )

    evidence = live_evidence if isinstance(live_evidence, dict) else {}
    exact_evidence_shape = set(evidence) == set(LIVE_PREREQUISITES)
    for prerequisite in LIVE_PREREQUISITES:
        item = evidence.get(prerequisite)
        checks[f"live:{prerequisite}"] = exact_evidence_shape and _valid_live_evidence(item)
    blockers = tuple(sorted(name for name, passed in checks.items() if not passed))
    inputs_complete = not blockers
    return ReadinessResult(
        ready=False,
        inputs_complete=inputs_complete,
        disposition="human_review_required" if inputs_complete else "blocked",
        authorizes_live_changes=False,
        blockers=blockers,
        checks=checks,
    )


def write_json_artifact(path: Path, value: Any) -> None:
    _write_artifact(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def write_yaml_artifact(path: Path, value: Any) -> None:
    _write_artifact(path, yaml.safe_dump(value, sort_keys=False, allow_unicode=True))


def main(argv: Sequence[str] | None = None) -> int:
    """Run an explicitly offline operational command."""

    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = _run(args)
    except OperationsError as exc:
        parser.exit(2, f"signet-operations: {exc}\n")
    return result


def _run(args: argparse.Namespace) -> int:
    if args.command == "capture-discovery":
        result = capture_discovery_fixture(args.alias, read_json_fixture(args.input))
        write_json_artifact(args.output, result)
    elif args.command == "classify":
        result = classify_tools(read_json_fixture(args.capture))
        write_json_artifact(args.output, result)
    elif args.command == "generate-policy":
        result = generate_deny_policy(read_json_fixture(args.capture), transport=args.transport)
        write_yaml_artifact(args.output, result)
        load_policy(args.output)
    elif args.command == "fake-contract-input":
        result = build_fake_adapter_contract_input(
            read_json_fixture(args.capture),
            tool=args.tool,
            arguments=read_json_fixture(args.arguments),
        )
        write_json_artifact(args.output, result)
    elif args.command == "verify-fake-contract":
        result = verify_fake_adapter_report(
            read_json_fixture(args.contract), read_json_fixture(args.report)
        )
        write_json_artifact(args.output, result)
        return 0 if result["passed"] else 2
    elif args.command == "audit-bypasses":
        result = audit_bypass_inventory(read_json_fixture(args.inventory))
        write_json_artifact(args.output, result)
        return 0 if result["clean"] else 2
    elif args.command == "cutover-readiness":
        readiness = assess_cutover_readiness(
            capture=read_json_fixture(args.capture),
            review_manifest=read_json_fixture(args.review_manifest),
            fake_contract_results=read_json_fixture(args.fake_results),
            bypass_report=read_json_fixture(args.bypass_report),
            live_evidence=(
                read_json_fixture(args.live_evidence) if args.live_evidence is not None else None
            ),
        )
        write_json_artifact(args.output, readiness.as_dict())
        return 2
    else:  # pragma: no cover - argparse requires one of the commands
        raise AssertionError("unreachable operations command")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m signet.operations",
        description="Bounded offline onboarding and cutover preparation",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    capture = commands.add_parser("capture-discovery")
    capture.add_argument("--alias", required=True)
    capture.add_argument("--input", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True)

    classify = commands.add_parser("classify")
    classify.add_argument("--capture", type=Path, required=True)
    classify.add_argument("--output", type=Path, required=True)

    policy = commands.add_parser("generate-policy")
    policy.add_argument("--capture", type=Path, required=True)
    policy.add_argument("--transport", choices=("http", "stdio"), required=True)
    policy.add_argument("--output", type=Path, required=True)

    fake_input = commands.add_parser("fake-contract-input")
    fake_input.add_argument("--capture", type=Path, required=True)
    fake_input.add_argument("--tool", required=True)
    fake_input.add_argument("--arguments", type=Path, required=True)
    fake_input.add_argument("--output", type=Path, required=True)

    fake_verify = commands.add_parser("verify-fake-contract")
    fake_verify.add_argument("--contract", type=Path, required=True)
    fake_verify.add_argument("--report", type=Path, required=True)
    fake_verify.add_argument("--output", type=Path, required=True)

    audit = commands.add_parser("audit-bypasses")
    audit.add_argument("--inventory", type=Path, required=True)
    audit.add_argument("--output", type=Path, required=True)

    readiness = commands.add_parser("cutover-readiness")
    readiness.add_argument("--capture", type=Path, required=True)
    readiness.add_argument("--review-manifest", type=Path, required=True)
    readiness.add_argument("--fake-results", type=Path, required=True)
    readiness.add_argument("--bypass-report", type=Path, required=True)
    readiness.add_argument("--live-evidence", type=Path)
    readiness.add_argument("--output", type=Path, required=True)
    return parser


def _extract_tools(document: Any) -> list[Any]:
    if not isinstance(document, dict):
        raise OperationsError("discovery input must be a JSON object")
    if set(document) == {"tools"}:
        tools = document["tools"]
    elif set(document) == {"result"} and isinstance(document["result"], dict):
        result = document["result"]
        if set(result) - {"tools", "nextCursor"}:
            raise OperationsError("discovery response contains unsupported result fields")
        if result.get("nextCursor") is not None:
            raise OperationsError("discovery response is incomplete; pagination remains")
        tools = result.get("tools")
    else:
        raise OperationsError("discovery input must contain only tools or a complete result")
    if not isinstance(tools, list):
        raise OperationsError("discovery tools must be an array")
    return tools


def _validated_capture(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "fixture_version",
        "alias",
        "source",
        "network_used",
        "tools",
    }:
        raise OperationsError("captured discovery fixture has an invalid shape")
    if (
        value.get("fixture_version") != 1
        or value.get("source") != "provided_offline_tools_list"
        or value.get("network_used") is not False
    ):
        raise OperationsError("captured discovery fixture is not explicitly offline")
    alias = value.get("alias")
    _require_alias(alias)
    tools = value.get("tools")
    if not isinstance(tools, list) or not tools or len(tools) > MAX_TOOLS:
        raise OperationsError("captured discovery tool list is invalid")
    names: set[str] = set()
    for item in tools:
        if not isinstance(item, dict) or set(item) != {"name", "schema_digest", "definition"}:
            raise OperationsError("captured discovery tool entry is invalid")
        name = item.get("name")
        digest = item.get("schema_digest")
        definition = item.get("definition")
        if (
            not isinstance(name, str)
            or _TOOL_RE.fullmatch(name) is None
            or name in names
            or not isinstance(digest, str)
            or _SHA256_RE.fullmatch(digest) is None
            or not isinstance(definition, dict)
            or definition.get("name") != name
        ):
            raise OperationsError("captured discovery tool identity is invalid")
        _reject_secret_material(definition)
        try:
            verified_definition = validate_lossless_tool(definition)
        except Exception as exc:
            raise OperationsError("captured discovery tool definition is invalid") from exc
        if tool_schema_digest(verified_definition) != digest:
            raise OperationsError("captured discovery schema digest does not match")
        names.add(name)
    return cast(dict[str, Any], copy.deepcopy(value))


def _classify(definition: Mapping[str, Any]) -> tuple[Classification, list[str]]:
    name = cast(str, definition["name"])
    words = _name_words(name)
    annotations = definition.get("annotations")
    read_hint = isinstance(annotations, dict) and annotations.get("readOnlyHint") is True
    destructive_hint = isinstance(annotations, dict) and annotations.get("destructiveHint") is True
    signals: list[str] = []
    if read_hint:
        signals.append("annotation:readOnlyHint=true")
    if destructive_hint:
        signals.append("annotation:destructiveHint=true")
    read_words = sorted(words & _READ_PREFIXES)
    write_words = sorted(words & _WRITE_PREFIXES)
    signals.extend(f"name:{word}" for word in read_words)
    signals.extend(f"name:{word}" for word in write_words)
    if destructive_hint or write_words:
        return "likely_write", signals
    if read_hint or read_words:
        return "likely_read", signals
    return "unknown", signals


def _name_words(name: str) -> set[str]:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return {word for word in re.split(r"[_.-]+", separated.lower()) if word}


def _validate_inventory_record(raw: Any) -> dict[str, str]:
    allowed = {"kind", "name", "location", "status", "capability", "route"}
    if not isinstance(raw, dict) or set(raw) != allowed:
        raise OperationsError("bypass inventory records may contain metadata fields only")
    record: dict[str, str] = {}
    for key in allowed:
        value = raw.get(key)
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 1024:
            raise OperationsError("bypass inventory record contains invalid metadata")
        if (
            "\x00" in value
            or "\r" in value
            or "\n" in value
            or _SENSITIVE_TEXT.search(value)
            or _FINGERPRINT_TEXT.search(value)
        ):
            raise OperationsError("bypass inventory contains secret-like content")
        record[key] = value
    if (
        record["kind"] not in INVENTORY_KINDS
        or record["status"] not in _INVENTORY_STATUSES
        or record["capability"] not in _INVENTORY_CAPABILITIES
        or record["route"] not in _INVENTORY_ROUTES
    ):
        raise OperationsError("bypass inventory record contains an invalid enum")
    return record


def _finding(record: Mapping[str, str], reason: str) -> dict[str, str]:
    return {
        "kind": record["kind"],
        "name": record["name"],
        "location": record["location"],
        "reason": reason,
    }


def _complete_fake_contract_results(
    value: Any,
    *,
    alias: str,
    actual_digests: Mapping[str, str],
    required_tools: set[str],
) -> bool:
    if not isinstance(value, list) or len(value) > MAX_TOOLS:
        return False
    fields = {
        "passed",
        "fixture_identity",
        "alias",
        "tool",
        "schema_digest",
        "failures",
        "network_used",
    }
    observed: set[str] = set()
    for result in value:
        if not isinstance(result, dict) or set(result) != fields:
            return False
        tool = result.get("tool")
        if (
            not isinstance(tool, str)
            or tool not in required_tools
            or tool in observed
            or result.get("passed") is not True
            or result.get("network_used") is not False
            or result.get("failures") != []
            or result.get("alias") != alias
            or result.get("schema_digest") != actual_digests.get(tool)
            or result.get("fixture_identity") != f"fake:{alias}:{tool}"
        ):
            return False
        observed.add(tool)
    return observed == required_tools


def _valid_live_evidence(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"present", "reference"}
        and value.get("present") is True
        and isinstance(value.get("reference"), str)
        and _SAFE_EVIDENCE_RE.fullmatch(value["reference"]) is not None
        and _SENSITIVE_TEXT.search(value["reference"]) is None
    )


def _reject_secret_material(value: Any) -> None:
    def visit(item: Any, *, depth: int = 0) -> None:
        if depth > MAX_JSON_DEPTH:
            raise OperationsError("offline fixture is nested too deeply")
        if isinstance(item, str):
            if len(item.encode("utf-8")) > MAX_TEXT_BYTES:
                raise OperationsError("offline fixture contains an oversized string")
            if _SENSITIVE_TEXT.search(item):
                raise OperationsError("offline fixture contains secret-like material")
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise OperationsError("offline fixture object keys must be strings")
                if _SENSITIVE_KEY.fullmatch(key) and not isinstance(child, dict):
                    raise OperationsError("offline fixture contains secret-like material")
                visit(child, depth=depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth=depth + 1)

    visit(value)


def _validate_json_bounds(value: Any) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > 100_000 or depth > MAX_JSON_DEPTH:
            raise OperationsError("offline fixture exceeds structural limits")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 1024:
                    raise OperationsError("offline fixture contains an invalid object key")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str) and len(item.encode("utf-8")) > MAX_TEXT_BYTES:
            raise OperationsError("offline fixture contains an oversized string")
        elif isinstance(item, float) and not (-sys.float_info.max <= item <= sys.float_info.max):
            raise OperationsError("offline fixture contains a non-finite number")

    visit(value, 0)


def _write_artifact(path: Path, content: str) -> None:
    if not path.name or path.name in {".", ".."}:
        raise OperationsError("output path is invalid")
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            data = content.encode("utf-8")
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:  # pragma: no cover - defensive OS contract check
                    raise OSError("artifact write made no progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as exc:
        raise OperationsError("output artifact already exists") from exc
    except OSError as exc:
        raise OperationsError("output artifact could not be written") from exc


def _require_alias(value: object) -> None:
    if not isinstance(value, str) or _ALIAS_RE.fullmatch(value) is None:
        raise OperationsError("downstream alias is invalid")


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


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
