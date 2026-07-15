from __future__ import annotations

import json
import plistlib
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

from signet.mcp_mirror import tool_schema_digest
from signet.operations import (
    INVENTORY_KINDS,
    LIVE_PREREQUISITES,
    OperationsError,
    assess_cutover_readiness,
    audit_bypass_inventory,
    build_fake_adapter_contract_input,
    capture_discovery_fixture,
    classify_tools,
    generate_deny_policy,
    main,
    read_json_fixture,
    verify_fake_adapter_report,
    write_json_artifact,
)
from signet.policy import PolicyMode, load_policy

ROOT = Path(__file__).resolve().parents[1]


def raw_tool(
    name: str,
    *,
    read_only: bool = False,
    description: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description or f"Fixture tool {name}",
        "inputSchema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": False,
            "required": ["value"],
            "properties": {"value": {"type": "string", "minLength": 1}},
        },
        "outputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
        },
        "annotations": {"readOnlyHint": read_only, "x-provider": "fixture"},
        "x-provider-extension": {"explicitNull": None},
    }


def capture(*tools: dict[str, Any]) -> dict[str, Any]:
    return capture_discovery_fixture("fixture", {"tools": list(tools)})


def complete_inventory(*records: dict[str, str]) -> dict[str, Any]:
    return {
        "fixture_version": 1,
        "source": "provided_metadata_only",
        "coverage": {kind: "complete" for kind in INVENTORY_KINDS},
        "records": list(records),
    }


def passing_fake_result(fixture: dict[str, Any], *, tool: str = "send_message") -> dict[str, Any]:
    contract = build_fake_adapter_contract_input(
        fixture,
        tool=tool,
        arguments={"value": "fake:payload"},
    )
    return verify_fake_adapter_report(
        contract,
        {
            "fixture_identity": contract["fixture_identity"],
            "provider": "fake",
            "network_used": False,
            "downstream_call_counts": dict(contract["required_scenarios"]),
        },
    )


def review_manifest(
    fixture: dict[str, Any],
    *,
    modes: dict[str, str] | None = None,
) -> dict[str, Any]:
    digests = {item["name"]: item["schema_digest"] for item in fixture["tools"]}
    return {
        "schema_digests": digests,
        "modes": modes or {name: "approval" for name in digests},
    }


def record(
    *,
    kind: str = "script",
    name: str = "fixture-script",
    location: str = "/fixture/path",
    status: str = "disabled",
    capability: str = "send",
    route: str = "direct",
) -> dict[str, str]:
    return {
        "kind": kind,
        "name": name,
        "location": location,
        "status": status,
        "capability": capability,
        "route": route,
    }


def test_capture_preserves_lossless_tool_and_runtime_digest() -> None:
    tool = raw_tool("read_item", read_only=True)
    result = capture_discovery_fixture(
        "example",
        {"result": {"tools": [tool], "nextCursor": None}},
    )
    assert result["source"] == "provided_offline_tools_list"
    assert result["network_used"] is False
    assert result["tools"] == [
        {
            "name": "read_item",
            "schema_digest": tool_schema_digest(tool),
            "definition": tool,
        }
    ]


@pytest.mark.parametrize(
    "document",
    [
        {"result": {"tools": [raw_tool("one")], "nextCursor": "more"}},
        {"tools": [raw_tool("same"), raw_tool("same")]},
        {"tools": []},
        {"tools": "not-an-array"},
        {"tools": [raw_tool("bad name")]},
    ],
)
def test_capture_rejects_incomplete_or_ambiguous_discovery(document: Any) -> None:
    with pytest.raises(OperationsError):
        capture_discovery_fixture("example", document)


def test_capture_rejects_secret_like_material() -> None:
    tool = raw_tool("read_item", description="password=fixture-credential-value")
    with pytest.raises(OperationsError, match="secret-like"):
        capture_discovery_fixture("example", {"tools": [tool]})

    tool = raw_tool("read_item")
    tool["_meta"] = {"authorization": "opaque-value"}
    with pytest.raises(OperationsError, match="secret-like"):
        capture_discovery_fixture("example", {"tools": [tool]})


def test_classification_is_advisory_and_never_enables_tools() -> None:
    result = classify_tools(
        capture(
            raw_tool("list_items", read_only=True),
            raw_tool("send_message"),
            raw_tool("deleteMessage"),
            raw_tool("frobnicate"),
        )
    )
    by_name = {item["name"]: item for item in result["classifications"]}
    assert result["automatic_enablement"] is False
    assert {item["generated_mode"] for item in by_name.values()} == {"deny"}
    assert by_name["list_items"]["candidate_classification"] == "likely_read"
    assert by_name["send_message"]["candidate_classification"] == "likely_write"
    assert by_name["send_message"]["adapter_review_required_for_approval"] is True
    assert by_name["send_message"]["reconciliation_characterization_required"] is True
    assert by_name["deleteMessage"]["candidate_classification"] == "likely_write"
    assert by_name["frobnicate"]["candidate_classification"] == "unknown"


@pytest.mark.parametrize("transport", ["http", "stdio"])
def test_generated_policy_parses_and_denies_every_tool(
    tmp_path: Path,
    transport: str,
) -> None:
    policy = generate_deny_policy(
        capture(raw_tool("list_items"), raw_tool("send_message")),
        transport=transport,  # type: ignore[arg-type]
    )
    path = tmp_path / "policy.yaml"
    path.write_text(__import__("yaml").safe_dump(policy, sort_keys=False), encoding="utf-8")
    snapshot = load_policy(path)
    assert snapshot.default_mode is PolicyMode.DENY
    assert snapshot.resolve("fixture", "list_items") is PolicyMode.DENY
    assert snapshot.resolve("fixture", "send_message") is PolicyMode.DENY
    assert snapshot.resolve("fixture", "unknown") is PolicyMode.DENY


def test_fake_adapter_contract_requires_zero_calls_before_approval() -> None:
    fixture = capture(raw_tool("send_message"))
    contract = build_fake_adapter_contract_input(
        fixture,
        tool="send_message",
        arguments={"value": "fake:payload"},
    )
    report = {
        "fixture_identity": contract["fixture_identity"],
        "provider": "fake",
        "network_used": False,
        "downstream_call_counts": dict(contract["required_scenarios"]),
    }
    verified = verify_fake_adapter_report(contract, report)
    assert verified == {
        "passed": True,
        "fixture_identity": "fake:fixture:send_message",
        "alias": "fixture",
        "tool": "send_message",
        "schema_digest": fixture["tools"][0]["schema_digest"],
        "failures": [],
        "network_used": False,
    }

    report["downstream_call_counts"]["durably_queued"] = 1
    failed = verify_fake_adapter_report(contract, report)
    assert failed["passed"] is False
    assert failed["failures"] == ["durably_queued"]

    report["downstream_call_counts"]["durably_queued"] = 0
    report["network_used"] = True
    failed = verify_fake_adapter_report(contract, report)
    assert failed["passed"] is False
    assert failed["failures"] == ["network_used"]
    assert failed["network_used"] is True


def test_fake_adapter_contract_rejects_invalid_arguments_and_nonfake_report() -> None:
    fixture = capture(raw_tool("send_message"))
    with pytest.raises(OperationsError, match="input schema"):
        build_fake_adapter_contract_input(fixture, tool="send_message", arguments={})
    contract = build_fake_adapter_contract_input(
        fixture,
        tool="send_message",
        arguments={"value": "fake:payload"},
    )
    with pytest.raises(OperationsError, match="not bound"):
        verify_fake_adapter_report(
            contract,
            {
                "fixture_identity": contract["fixture_identity"],
                "provider": "live",
                "network_used": False,
                "downstream_call_counts": contract["required_scenarios"],
            },
        )


def test_bypass_audit_reports_only_names_locations_and_reason() -> None:
    report = audit_bypass_inventory(
        complete_inventory(
            record(status="active"),
            record(
                kind="hermes_profile",
                name="managed-profile",
                location="/fixture/profiles/managed.yaml",
                status="active",
                capability="send",
                route="signet",
            ),
            record(
                kind="cron",
                name="old-disabled-job",
                location="/fixture/cron",
                status="disabled",
                capability="write",
                route="direct",
            ),
        )
    )
    assert report["clean"] is False
    assert report["coverage_complete"] is True
    assert report["findings"] == [
        {
            "kind": "script",
            "name": "fixture-script",
            "location": "/fixture/path",
            "reason": "potential_bypass",
        }
    ]
    serialized = json.dumps(report)
    assert "value" not in serialized
    assert "fingerprint" not in serialized


def test_bypass_audit_requires_complete_scope_and_metadata_only_records() -> None:
    inventory = complete_inventory()
    del inventory["coverage"]["browser_session"]
    with pytest.raises(OperationsError, match="cover every"):
        audit_bypass_inventory(inventory)

    inventory = complete_inventory()
    unsafe = record()
    unsafe["value"] = "not-permitted"
    inventory["records"] = [unsafe]
    with pytest.raises(OperationsError, match="metadata fields only"):
        audit_bypass_inventory(inventory)


def test_unknown_bypass_coverage_and_records_fail_closed() -> None:
    inventory = complete_inventory(
        record(status="unknown", capability="unknown", route="unknown")
    )
    inventory["coverage"]["browser_session"] = "unknown"
    report = audit_bypass_inventory(inventory)
    assert report["clean"] is False
    assert report["unresolved_coverage"] == ["browser_session"]
    assert report["findings"][0]["reason"] == "unresolved"

    report = audit_bypass_inventory(
        complete_inventory(
            record(status="active", capability="unknown", route="direct"),
        )
    )
    assert report["clean"] is False
    assert report["findings"][0]["reason"] == "unresolved"


def test_readiness_without_live_evidence_lists_every_human_blocker() -> None:
    fixture = capture(raw_tool("send_message"))
    result = assess_cutover_readiness(
        capture=fixture,
        review_manifest=review_manifest(fixture),
        fake_contract_results=[passing_fake_result(fixture)],
        bypass_report=audit_bypass_inventory(complete_inventory()),
    )
    assert result.ready is False
    assert result.inputs_complete is False
    assert result.authorizes_live_changes is False
    assert result.disposition == "blocked"
    assert result.checks["review_manifest_complete"] is True
    assert result.checks["schema_digests_match"] is True
    assert result.checks["fake_adapter_contracts_complete"] is True
    assert result.checks["bypass_audit_clean"] is True
    assert set(result.blockers) == {f"live:{name}" for name in LIVE_PREREQUISITES}


def test_readiness_rejects_handwritten_underspecified_reports() -> None:
    fixture = capture(raw_tool("send_message"))
    evidence = {
        name: {"present": True, "reference": f"test-only:{name}"}
        for name in LIVE_PREREQUISITES
    }
    result = assess_cutover_readiness(
        capture=fixture,
        review_manifest=review_manifest(fixture),
        fake_contract_results=[{"passed": True, "network_used": False, "failures": []}],
        bypass_report={"clean": True, "metadata_only": True, "coverage_complete": True},
        live_evidence=evidence,
    )
    assert result.ready is False
    assert "fake_adapter_contracts_complete" in result.blockers
    assert "bypass_audit_clean" in result.blockers


def test_readiness_rejects_digest_drift_even_with_schema_only_evidence() -> None:
    fixture = capture(raw_tool("send_message"))
    # This is shape-only test data, not a human authorization or authenticator assertion.
    evidence = {
        name: {"present": True, "reference": f"test-only:{name}"}
        for name in LIVE_PREREQUISITES
    }
    result = assess_cutover_readiness(
        capture=fixture,
        review_manifest={
            "schema_digests": {"send_message": "0" * 64},
            "modes": {"send_message": "approval"},
        },
        fake_contract_results=[passing_fake_result(fixture)],
        bypass_report=audit_bypass_inventory(complete_inventory()),
        live_evidence=evidence,
    )
    assert result.ready is False
    assert result.blockers == ("schema_digests_match",)


def test_complete_readiness_packet_still_requires_human_review() -> None:
    fixture = capture(raw_tool("send_message"))
    # These are schema-only markers and do not simulate a credential or human ceremony.
    evidence = {
        name: {"present": True, "reference": f"test-only:{name}"}
        for name in LIVE_PREREQUISITES
    }
    result = assess_cutover_readiness(
        capture=fixture,
        review_manifest=review_manifest(fixture),
        fake_contract_results=[passing_fake_result(fixture)],
        bypass_report=audit_bypass_inventory(complete_inventory()),
        live_evidence=evidence,
    )
    assert result.ready is False
    assert result.inputs_complete is True
    assert result.disposition == "human_review_required"
    assert result.authorizes_live_changes is False
    assert result.blockers == ()


def test_readiness_requires_fake_contract_for_every_approval_tool() -> None:
    fixture = capture(raw_tool("send_one"), raw_tool("send_two"))
    result = assess_cutover_readiness(
        capture=fixture,
        review_manifest=review_manifest(fixture),
        fake_contract_results=[passing_fake_result(fixture, tool="send_one")],
        bypass_report=audit_bypass_inventory(complete_inventory()),
        live_evidence={
            name: {"present": True, "reference": f"test-only:{name}"}
            for name in LIVE_PREREQUISITES
        },
    )
    assert result.inputs_complete is False
    assert "fake_adapter_contracts_complete" in result.blockers


def test_strict_fixture_reader_rejects_duplicate_keys_and_symlinks(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"tools": [], "tools": []}', encoding="utf-8")
    with pytest.raises(OperationsError, match="duplicate"):
        read_json_fixture(duplicate)

    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(OperationsError, match="regular file"):
        read_json_fixture(link)


def test_artifact_writer_is_private_and_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "private" / "artifact.json"
    write_json_artifact(output, {"safe": True})
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with pytest.raises(OperationsError, match="already exists"):
        write_json_artifact(output, {"safe": False})


def test_cli_cutover_readiness_without_live_evidence_exits_two(tmp_path: Path) -> None:
    fixture = capture(raw_tool("send_message"))
    paths = {
        "capture": fixture,
        "review": review_manifest(fixture),
        "fake": [passing_fake_result(fixture)],
        "bypass": audit_bypass_inventory(complete_inventory()),
    }
    written: dict[str, Path] = {}
    for name, value in paths.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        written[name] = path
    output = tmp_path / "readiness.json"
    assert (
        main(
            [
                "cutover-readiness",
                "--capture",
                str(written["capture"]),
                "--review-manifest",
                str(written["review"]),
                "--fake-results",
                str(written["fake"]),
                "--bypass-report",
                str(written["bypass"]),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["ready"] is False
    assert result["authorizes_live_changes"] is False
    assert result["disposition"] == "blocked"
    assert "live:human_cutover_authorization" in result["blockers"]


def test_launchd_templates_are_separate_loopback_secret_free_agents() -> None:
    launchd = ROOT / "deploy" / "launchd"
    expectations = {
        "ai.hermes.signet.mcp.plist.example": (
            "ai.hermes.signet.mcp",
            "serve-mcp",
            "8789",
        ),
        "ai.hermes.signet.web.plist.example": (
            "ai.hermes.signet.web",
            "serve-web",
            "8790",
        ),
    }
    for filename, (label, command, port) in expectations.items():
        with (launchd / filename).open("rb") as handle:
            value = plistlib.load(handle)
        arguments = value["ProgramArguments"]
        assert value["Label"] == label
        assert value["Umask"] == 0o77
        assert value["ProcessType"] == "Background"
        assert arguments[0].endswith("/.venv/bin/signet")
        assert command in arguments
        assert arguments[arguments.index("--host") + 1] == "127.0.0.1"
        assert arguments[arguments.index("--port") + 1] == port
        serialized = json.dumps(value).lower()
        assert "keychain://" not in serialized
        assert "password" not in serialized
        assert "token" not in serialized
        assert "secret" not in serialized


def test_homepage_template_is_one_normal_secret_free_signet_card() -> None:
    path = ROOT / "deploy" / "homepage" / "services.signet.yaml.example"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, list) and len(value) == 1
    assert list(value[0]) == ["Applications"]
    services = value[0]["Applications"]
    assert isinstance(services, list) and len(services) == 1
    assert list(services[0]) == ["Signet"]
    card = services[0]["Signet"]
    assert set(card) == {"icon", "href", "description", "target"}
    assert card["href"].startswith("https://")
    assert "widget" not in card


def test_hermes_forward_diff_authenticates_every_local_alias_without_a_raw_token() -> None:
    path = ROOT / "deploy" / "hermes" / "managed-routes.forward.diff.example"
    value = path.read_text(encoding="utf-8")
    assert value.count("Authorization: Bearer ${SIGNET_MCP_CALLER_TOKEN}") == 3
    assert value.count("sampling:") == 3
    assert "sgt_" not in value


def test_shipped_operations_skeletons_remain_fail_closed() -> None:
    operations = ROOT / "deploy" / "operations"
    inventory = json.loads(
        (operations / "bypass-inventory.blocked.example.json").read_text(encoding="utf-8")
    )
    report = audit_bypass_inventory(inventory)
    assert report["clean"] is False
    assert set(report["unresolved_coverage"]) == INVENTORY_KINDS

    live = json.loads(
        (operations / "live-evidence.blocked.example.json").read_text(encoding="utf-8")
    )
    assert set(live) == set(LIVE_PREREQUISITES)
    assert all(item == {"present": False, "reference": "not-completed"} for item in live.values())
