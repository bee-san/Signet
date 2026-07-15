from __future__ import annotations

import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import pytest

from signet.adapters import (
    AdapterRequest,
    AdapterTestHarness,
    ApprovalAdapter,
    ExecutionAttempt,
    GenericJSONAdapter,
    Outcome,
    ReadOnlyMCPClient,
    Reconciliation,
    build_schema_fixture,
)
from signet.models import ReadOnlyToolViolation


class FakeClient:
    def __init__(self, result: Mapping[str, Any] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.result = dict(result or {"status": "ok", "id": "provider-safe-id"})

    async def call_tool(
        self, tool_name: str, arguments: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        self.calls.append((tool_name, dict(arguments)))
        return self.result


def request(arguments: Mapping[str, Any]) -> AdapterRequest:
    return AdapterRequest(
        request_id="req_fixture",
        downstream_alias="example",
        tool_name="create_item",
        arguments=arguments,
        account="primary",
        payload_hash="a" * 64,
    )


def attempt() -> ExecutionAttempt:
    return ExecutionAttempt(attempt_id="attempt_fixture", started_at=datetime.now(UTC))


@pytest.mark.asyncio
async def test_read_only_client_rejects_non_allowlisted_tool_before_wire() -> None:
    downstream = FakeClient()
    restricted = ReadOnlyMCPClient(downstream, {"search_items"})

    with pytest.raises(ReadOnlyToolViolation, match="not approved"):
        await restricted.call_tool("create_item", {"side_effect": True})

    assert downstream.calls == []
    assert restricted.reviewed_tools == frozenset({"search_items"})


@pytest.mark.asyncio
async def test_read_only_client_detaches_arguments_and_results() -> None:
    original = {"query": {"value": "needle"}}
    downstream = FakeClient({"items": [{"id": "one"}]})
    restricted = ReadOnlyMCPClient(downstream, {"search_items"})

    result = await restricted.call_tool("search_items", original)
    original["query"]["value"] = "changed"
    downstream.result["items"] = []

    assert downstream.calls == [("search_items", {"query": {"value": "needle"}})]
    assert result == {"items": [{"id": "one"}]}


@pytest.mark.asyncio
async def test_generic_json_fallback_reviews_executes_and_never_reconciles() -> None:
    adapter = GenericJSONAdapter(
        downstream_alias="example",
        tool_name="create_item",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "token"],
            "properties": {"name": {"type": "string"}, "token": {"type": "string"}},
        },
        safe_result_fields=("id", "status"),
        reviewed_dispatch_enabled=True,
    )
    arguments = {"token": "audit-secret", "name": "review this"}
    assert isinstance(adapter, ApprovalAdapter)
    assert adapter.canonicalize(arguments) == {"name": "review this", "token": "audit-secret"}
    summary = adapter.summarize_for_web(arguments)
    assert summary.detail_blocks[0].value == {
        "name": "review this",
        "token": "audit-secret",
    }
    assert "audit-secret" not in repr(adapter.redact_for_audit(arguments))

    downstream = FakeClient({"id": "safe-id", "status": "ok", "body": "not-safe"})
    payload = adapter.prepare_for_execution(request(arguments))
    result = await adapter.execute(downstream, payload)
    assert downstream.calls == [("create_item", arguments)]
    assert result["body"] == "not-safe"
    assert adapter.safe_result_metadata(result) == {"id": "safe-id", "status": "ok"}
    assert adapter.classify_outcome(result) is Outcome.SUCCEEDED

    reconciliation_client = ReadOnlyMCPClient(downstream, set())
    assert (
        await adapter.reconcile(reconciliation_client, request(arguments), attempt())
        is Reconciliation.INCONCLUSIVE
    )
    assert len(downstream.calls) == 1


def test_generic_adapter_schema_fixture_is_secret_free_and_reviewable() -> None:
    adapter = GenericJSONAdapter(
        downstream_alias="example",
        tool_name="create_item",
        reviewed_dispatch_enabled=True,
    )
    fixture = build_schema_fixture(adapter, source="synthetic-test")

    assert fixture["schema_status"] == "review_required"
    assert fixture["adapter"]["reconciliation_tools"] == []
    assert "secret" not in repr(fixture).lower()


@pytest.mark.asyncio
async def test_reusable_adapter_harness_exercises_review_execution_and_reconcile() -> None:
    adapter = GenericJSONAdapter(
        downstream_alias="example",
        tool_name="create_item",
        reviewed_dispatch_enabled=True,
    )
    harness = AdapterTestHarness(adapter, {"name": "fixture"}, account="primary")
    summary = harness.exercise_review_contract()
    downstream = FakeClient({"status": "ok"})

    assert summary.action == "create_item"
    assert await harness.execute(downstream) == {"status": "ok"}
    assert (
        await harness.reconcile(downstream, attempt())
        is Reconciliation.INCONCLUSIVE
    )
    assert downstream.calls == [("create_item", {"name": "fixture"})]


def test_generic_adapter_rejects_schema_mismatch_and_non_json_values() -> None:
    adapter = GenericJSONAdapter(
        downstream_alias="example",
        tool_name="create_item",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["count"],
            "properties": {"count": {"type": "integer"}},
        },
    )
    with pytest.raises(ValueError, match="invalid generic arguments"):
        adapter.validate({"count": "one"})
    with pytest.raises(ValueError, match="JSON object"):
        adapter.validate({"count": float("nan")})


def test_adapter_request_and_attempt_are_deeply_immutable() -> None:
    arguments = {"recipients": [{"address": "first@example.test"}]}
    selected = request(arguments)
    result = {"items": [{"id": "original"}]}
    selected_attempt = ExecutionAttempt(
        attempt_id="attempt-frozen",
        started_at=datetime.now(UTC),
        downstream_result=result,
    )
    arguments["recipients"][0]["address"] = "changed@example.test"
    result["items"][0]["id"] = "changed"

    assert selected.arguments["recipients"][0]["address"] == "first@example.test"
    assert selected_attempt.downstream_result["items"][0]["id"] == "original"
    with pytest.raises(TypeError):
        selected.arguments["new"] = "value"  # type: ignore[index]


def test_wacli_wrapper_import_has_no_package_cycle() -> None:
    completed = subprocess.run(
        [sys.executable, "-c", "import signet.wacli_wrapper"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ({"status": "ok"}, Outcome.SUCCEEDED),
        ({"effect": "none", "status": "failed"}, Outcome.DEFINITE_FAILURE),
        ({"isError": True}, Outcome.OUTCOME_UNKNOWN),
        ({"isError": True, "status": "ok", "sent": True}, Outcome.OUTCOME_UNKNOWN),
        (TimeoutError(), Outcome.OUTCOME_UNKNOWN),
    ],
)
def test_generic_outcome_classifier_is_conservative(result: object, expected: Outcome) -> None:
    adapter = GenericJSONAdapter(downstream_alias="example", tool_name="create_item")
    assert adapter.classify_outcome(result) is expected
