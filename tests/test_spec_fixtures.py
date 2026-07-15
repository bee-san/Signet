from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker

from signet.policy import PolicyMode, load_policy as load_policy_snapshot
from signet.staging import StagingPathError, confined_staging_path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec"
FIXTURES = SPEC / "fixtures"


def load_json(name: str) -> dict[str, Any]:
    with (FIXTURES / name).open(encoding="utf-8") as fixture_file:
        value = json.load(fixture_file)
    assert isinstance(value, dict)
    return value


def load_policy() -> dict[str, Any]:
    with (SPEC / "policy-v1.yaml").open(encoding="utf-8") as policy_file:
        value = yaml.safe_load(policy_file)
    assert isinstance(value, dict)
    return value


def resolve_mode(policy: dict[str, Any], alias: str, tool: str) -> str:
    downstream = policy["downstreams"].get(alias)
    if downstream is None:
        return policy["default_mode"]
    tool_policy = downstream["tools"].get(tool)
    if tool_policy is None:
        return policy["default_mode"]
    return tool_policy["mode"]


def test_all_json_fixtures_parse() -> None:
    fixture_paths = sorted(FIXTURES.glob("*.json"))
    assert {path.name for path in fixture_paths} == {
        "fastmail-send-input.json",
        "gateway-pending-result.json",
        "gateway-tools-schemas.json",
        "whatsapp-send-input.json",
    }
    for fixture_path in fixture_paths:
        with fixture_path.open(encoding="utf-8") as fixture_file:
            json.load(fixture_file)


def test_policy_locks_exactly_four_modes_and_defaults_to_deny() -> None:
    policy = load_policy()
    assert policy["version"] == 1
    assert policy["default_mode"] == "deny"
    assert set(policy["mode_contracts"]) == {
        "passthrough",
        "virtualize_local",
        "approval",
        "deny",
    }


def test_policy_fixture_parses_through_the_service_policy_loader() -> None:
    snapshot = load_policy_snapshot(SPEC / "policy-v1.yaml")
    assert snapshot.default_mode is PolicyMode.DENY
    assert snapshot.resolve("fastmail", "search_email") is PolicyMode.PASSTHROUGH
    assert snapshot.resolve("fastmail", "send_email") is PolicyMode.APPROVAL
    assert snapshot.resolve("whatsapp", "send_text") is PolicyMode.APPROVAL
    assert snapshot.resolve("whatsapp", "unknown") is PolicyMode.DENY


@pytest.mark.parametrize(
    ("alias", "tool"),
    [
        ("fastmail", "not_discovered"),
        ("whatsapp", "send_unreviewed_media"),
        ("unknown_provider", "send_message"),
    ],
)
def test_unknown_tools_resolve_to_deny(alias: str, tool: str) -> None:
    assert resolve_mode(load_policy(), alias, tool) == "deny"


def test_explicit_deny_and_sends_have_expected_modes() -> None:
    policy = load_policy()
    assert resolve_mode(policy, "fastmail", "delete_email") == "deny"
    assert resolve_mode(policy, "fastmail", "send_email") == "approval"
    assert resolve_mode(policy, "whatsapp", "send_text") == "approval"


def test_provider_input_fixtures_are_inert_and_policy_backed() -> None:
    policy = load_policy()
    cases = (
        ("fastmail", load_json("fastmail-send-input.json")),
        ("whatsapp", load_json("whatsapp-send-input.json")),
    )
    for alias, fixture in cases:
        assert fixture["fixture"]["must_not_dispatch"] is True
        assert isinstance(fixture["arguments"], dict)
        assert fixture["arguments"]
        assert resolve_mode(policy, alias, fixture["tool"]) == "approval"

    fastmail = cases[0][1]
    assert fastmail["fixture"]["schema_status"] == (
        "live_tools_list_capture_required_before_enablement"
    )
    whatsapp = cases[1][1]
    assert (
        whatsapp["fixture"]["contract"]
        == policy["downstreams"]["whatsapp"]["wrapper_contract"]["id"]
    )
    assert set(whatsapp["arguments"]) == {"to", "message"}


def test_gateway_tool_schemas_are_valid_and_complete() -> None:
    fixture = load_json("gateway-tools-schemas.json")
    Draft202012Validator.check_schema(fixture["pending_result_schema"])
    tools = fixture["tools"]
    assert {tool["name"] for tool in tools} == {
        "check_approval_status",
        "list_pending_approvals",
        "approve_request",
        "cancel_request",
        "request_tool_access",
    }
    assert len(tools) == 5
    for tool in tools:
        Draft202012Validator.check_schema(tool["inputSchema"])
        Draft202012Validator.check_schema(tool["outputSchema"])
        assert tool["inputSchema"]["additionalProperties"] is False
        assert tool["outputSchema"]["additionalProperties"] is False


def test_pending_result_matches_normative_schema_without_success_claim() -> None:
    schemas = load_json("gateway-tools-schemas.json")
    pending = load_json("gateway-pending-result.json")
    validator = Draft202012Validator(
        schemas["pending_result_schema"], format_checker=FormatChecker()
    )
    validator.validate(pending)

    assert set(pending) == {"status", "request_id", "expires_at", "message"}
    assert pending["status"] == "pending_approval"
    forbidden_fields = {"success", "sent", "message_id", "provider_id"}
    assert forbidden_fields.isdisjoint(pending)
    serialized = json.dumps(pending).lower()
    assert '"status": "success"' not in serialized
    assert "successfully sent" not in serialized


def test_virtualization_contract_forbids_calls_and_standalone_approvals() -> None:
    policy = load_policy()
    contract = policy["mode_contracts"]["virtualize_local"]
    assert contract["downstream_calls"] == 0
    assert contract["standalone_approval"] is False
    assert contract["storage"] == "local_only"
    assert set(contract["scope_fields"]) == {
        "adapter",
        "account",
        "caller_namespace",
    }

    virtualized = [
        tool
        for downstream in policy["downstreams"].values()
        for tool in downstream["tools"].values()
        if tool["mode"] == "virtualize_local"
    ]
    assert virtualized
    assert all(tool.get("adapter") and tool.get("account_ref") for tool in virtualized)


def test_staging_paths_cannot_escape_root(tmp_path: Path) -> None:
    root = tmp_path / "var" / "staging"
    root.mkdir(parents=True)
    assert confined_staging_path(root, "fastmail/account/object.bin") == (
        root / "fastmail" / "account" / "object.bin"
    )

    for unsafe in ("../outside", "nested/../../outside", "/tmp/outside"):
        with pytest.raises(StagingPathError):
            confined_staging_path(root, unsafe)


def test_staging_paths_reject_symbolic_and_hard_links(tmp_path: Path) -> None:
    root = tmp_path / "staging"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(StagingPathError):
        confined_staging_path(root, "linked/object.bin")

    original = root / "original.bin"
    original.write_bytes(b"inert fixture")
    hardlink = root / "hardlink.bin"
    hardlink.hardlink_to(original)
    with pytest.raises(StagingPathError):
        confined_staging_path(root, "hardlink.bin")
