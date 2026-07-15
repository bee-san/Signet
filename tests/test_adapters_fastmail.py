from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from signet.adapters import (
    AdapterRequest,
    AdapterValidationError,
    ExecutionAttempt,
    FastmailAdapter,
    Outcome,
    ReadOnlyMCPClient,
    Reconciliation,
)
from signet.delivery import standardize_safe_metadata
from signet.staging import StagingError, StagingStore
from tests.attachment_fixtures import staging_store as make_staging_store

ROOT = Path(__file__).resolve().parents[1]


class FakeFastmailClient:
    def __init__(self, *, search_result: Mapping[str, Any] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.search_result = dict(search_result or {"messages": []})

    async def call_tool(
        self, tool_name: str, arguments: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        self.calls.append((tool_name, dict(arguments)))
        if tool_name == "upload_attachment":
            return {"attachmentId": "blob-safe-id"}
        if tool_name == "send_email":
            return {
                "messageId": "message-safe-id",
                "threadId": "thread-safe-id",
                "status": "sent",
            }
        if tool_name == "search_email":
            return self.search_result
        raise AssertionError(f"unexpected fake call: {tool_name}")


def fixture_arguments() -> dict[str, Any]:
    with (ROOT / "spec/fixtures/fastmail-send-input.json").open(encoding="utf-8") as handle:
        fixture = json.load(handle)
    return fixture["arguments"]


def adapter_request(arguments: Mapping[str, Any]) -> AdapterRequest:
    return AdapterRequest(
        request_id="req_fastmail_fixture",
        downstream_alias="fastmail",
        tool_name="send_email",
        arguments=arguments,
        account="primary",
        payload_hash="b" * 64,
    )


def staging_store(tmp_path: Path) -> tuple[StagingStore, Path]:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    store = make_staging_store(
        tmp_path / "staging",
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    return store, source_root


def test_fastmail_fixture_validates_and_private_summary_is_complete() -> None:
    adapter = FastmailAdapter(account="primary")
    arguments = fixture_arguments()
    adapter.validate(arguments)
    summary = adapter.summarize_for_web(arguments)
    masked = adapter.masked_destination_summary(arguments)

    assert summary.destination_summary == "recipient@example.test"
    assert masked == "r***@example.test"
    assert summary.destination_summary not in masked
    assert any(block.value == arguments["body"] for block in summary.detail_blocks)
    audit = repr(adapter.redact_for_audit(arguments))
    assert arguments["body"] not in audit
    assert arguments["subject"] not in audit
    assert "recipient_count" in audit


def test_fastmail_agent_summary_is_deterministic_bounded_and_never_full() -> None:
    adapter = FastmailAdapter(account="primary")
    arguments = fixture_arguments()
    raw_recipients = [
        "one@example.test",
        "Two Person <two@elsewhere.test>",
        "three@example.test",
        "four@example.test",
    ]
    arguments.update({"to": raw_recipients, "cc": [], "bcc": []})

    first = adapter.masked_destination_summary(arguments)
    second = adapter.masked_destination_summary(arguments)

    assert first == second
    assert first == "o***@example.test, t***@elsewhere.test, t***@example.test, (+1 more)"
    assert all(recipient not in first for recipient in raw_recipients)


@pytest.mark.parametrize(
    "change",
    [
        {"subject": "header\r\nBcc: attacker@example.test"},
        {"to": ["Recipient <recipient@example.test>"], "cc": ["recipient@example.test"]},
        {"to": [], "cc": [], "bcc": []},
        {"unknown": "not reviewed"},
    ],
)
def test_fastmail_rejects_ambiguous_or_injected_inputs(change: dict[str, Any]) -> None:
    arguments = fixture_arguments()
    arguments.update(change)
    with pytest.raises(AdapterValidationError):
        FastmailAdapter(account="primary").validate(arguments)


def test_fastmail_preserves_exact_executable_address_values() -> None:
    arguments = fixture_arguments()
    arguments["to"] = ['Autumn Example <autumn@ex\u00e4mple.test>']
    arguments["body"] = "Cafe\u0301\r\nsecond line"
    arguments["subject"] = "  exact subject  "
    canonical = FastmailAdapter(account="primary").canonicalize(arguments)
    assert canonical == arguments


@pytest.mark.asyncio
async def test_fastmail_stages_locally_then_uploads_and_sends_once_after_prepare(
    tmp_path: Path,
) -> None:
    store, source_root = staging_store(tmp_path)
    source = source_root / "report.txt"
    source.write_text("inert attachment", encoding="utf-8")
    adapter = FastmailAdapter(
        staging_store=store,
        account="primary",
        reviewed_dispatch_enabled=True,
    )
    downstream = FakeFastmailClient()

    reference = adapter.stage_attachment(
        source,
        filename="report.txt",
        mime_type="text/plain",
    )
    assert downstream.calls == []
    arguments = fixture_arguments()
    arguments["attachments"] = [reference]
    payload = adapter.prepare_for_execution(adapter_request(arguments))
    result = await adapter.execute(downstream, payload)

    assert [call[0] for call in downstream.calls] == ["upload_attachment", "send_email"]
    send_payload = downstream.calls[-1][1]
    assert send_payload["attachments"] == [
        {
            "attachment_id": "blob-safe-id",
            "filename": "report.txt",
            "mime_type": "text/plain",
        }
    ]
    assert adapter.classify_outcome(result) is Outcome.SUCCEEDED
    assert adapter.safe_result_metadata(result) == {
        "message_id": "message-safe-id",
        "provider_status": "sent",
        "thread_id": "thread-safe-id",
    }


def test_fastmail_safe_result_accepts_only_the_reviewed_shape_and_statuses() -> None:
    adapter = FastmailAdapter(account="primary")
    result = {
        "data": {
            "messageId": "m_0123456789.ABC:def@example.test",
            "submissionId": "submission/0123+abc=",
            "threadId": "thread-0123",
            "status": "submitted",
        },
        "isError": False,
    }

    assert adapter.classify_outcome(result) is Outcome.SUCCEEDED
    assert adapter.safe_result_metadata(result) == {
        "message_id": "m_0123456789.ABC:def@example.test",
        "submission_id": "submission/0123+abc=",
        "thread_id": "thread-0123",
        "provider_status": "submitted",
    }


@pytest.mark.parametrize(
    "result",
    [
        {
            "messageId": "message-safe-id",
            "status": "sent",
            "body": "private request content echoed by provider",
        },
        {"messageId": "private request content echoed by provider", "status": "sent"},
        {"messageId": "m" * 257, "status": "sent"},
        {"messageId": "message-safe-id", "status": "private email body"},
        {"messageId": "message-safe-id", "status": "ok"},
        {"message_id": "message-safe-id", "status": "sent"},
        {"messageId": 12345, "status": "sent"},
        {"data": {"data": {"messageId": "message-safe-id", "status": "sent"}}},
        {
            "data": {"messageId": "message-safe-id", "status": "sent"},
            "unexpected": "private request content",
        },
    ],
)
def test_fastmail_safe_result_rejects_echoes_nesting_and_unreviewed_fields(
    result: dict[str, Any],
) -> None:
    adapter = FastmailAdapter(account="primary")

    assert adapter.safe_result_metadata(result) == {}
    assert dict(standardize_safe_metadata(adapter, result)) == {}
    assert adapter.classify_outcome(result) is Outcome.OUTCOME_UNKNOWN


def test_fastmail_rehashes_staged_attachment_before_execution(tmp_path: Path) -> None:
    store, source_root = staging_store(tmp_path)
    source = source_root / "report.txt"
    source.write_text("original", encoding="utf-8")
    adapter = FastmailAdapter(staging_store=store, account="primary")
    reference = adapter.stage_attachment(source, filename="report.txt", mime_type="text/plain")
    store.resolve(reference["staged_id"], adapter="fastmail", account="primary").path.write_text(
        "tampered", encoding="utf-8"
    )
    arguments = fixture_arguments()
    arguments["attachments"] = [reference]

    with pytest.raises(StagingError, match="integrity"):
        adapter.prepare_for_execution(adapter_request(arguments))


def test_fastmail_verified_bytes_survive_staging_store_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, source_root = staging_store(tmp_path)
    source = source_root / "report.txt"
    source.write_bytes(b"restart-safe bytes")
    reference = FastmailAdapter(staging_store=store, account="primary").stage_attachment(
        source,
        filename="report.txt",
        mime_type="text/plain",
    )
    restarted = make_staging_store(
        store.root,
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    adapter = FastmailAdapter(staging_store=restarted, account="primary")
    arguments = fixture_arguments()
    arguments["attachments"] = [reference]

    def reject_path_read(self: Path) -> bytes:
        raise AssertionError(f"unsafe pathname read attempted: {self}")

    monkeypatch.setattr(Path, "read_bytes", reject_path_read)
    payload = adapter.prepare_for_execution(adapter_request(arguments))

    encoded = payload["_signet_resolved_attachments"][0]["content_base64"]
    assert base64.b64decode(encoded, validate=True) == b"restart-safe bytes"


@pytest.mark.asyncio
async def test_fastmail_reconcile_confirms_only_a_captured_provider_identity() -> None:
    adapter = FastmailAdapter(account="primary")
    request = adapter_request(fixture_arguments())
    downstream = FakeFastmailClient(
        search_result={"messages": [{"messageId": "message-safe-id", "folder": "Sent"}]}
    )
    restricted = ReadOnlyMCPClient(downstream, adapter.reconciliation_tools)
    attempt = ExecutionAttempt(
        attempt_id="attempt_fastmail",
        started_at=datetime.now(UTC),
        downstream_result={"messageId": "message-safe-id"},
    )

    assert (
        await adapter.reconcile(restricted, request, attempt)
        is Reconciliation.CONFIRMED_EFFECT
    )
    assert downstream.calls == [
        ("search_email", {"query": "message-safe-id", "folder": "Sent", "limit": 10})
    ]


@pytest.mark.asyncio
async def test_fastmail_reconcile_never_claims_no_effect_from_missing_or_empty_search() -> None:
    adapter = FastmailAdapter(account="primary")
    request = adapter_request(fixture_arguments())
    downstream = FakeFastmailClient()
    restricted = ReadOnlyMCPClient(downstream, adapter.reconciliation_tools)

    missing_identity = ExecutionAttempt(
        attempt_id="attempt_no_identity",
        started_at=datetime.now(UTC),
    )
    assert (
        await adapter.reconcile(restricted, request, missing_identity)
        is Reconciliation.INCONCLUSIVE
    )
    assert downstream.calls == []

    known_identity = ExecutionAttempt(
        attempt_id="attempt_empty_search",
        started_at=datetime.now(UTC),
        downstream_result={"messageId": "not-found"},
    )
    assert (
        await adapter.reconcile(restricted, request, known_identity)
        is Reconciliation.INCONCLUSIVE
    )
    assert adapter.supports_idempotency is False


def test_fastmail_ambiguous_tool_error_remains_unknown() -> None:
    adapter = FastmailAdapter(account="primary")
    assert adapter.classify_outcome({"isError": True, "message": "timeout"}) is (
        Outcome.OUTCOME_UNKNOWN
    )
    assert adapter.classify_outcome(
        {"isError": True, "status": "ok", "messageId": "not-proof"}
    ) is Outcome.OUTCOME_UNKNOWN
    assert adapter.classify_outcome({"id": "attachment-like-id"}) is Outcome.OUTCOME_UNKNOWN


@pytest.mark.asyncio
async def test_fastmail_dispatch_is_disabled_until_provider_review() -> None:
    adapter = FastmailAdapter(account="primary")
    with pytest.raises(Exception, match="not activated"):
        await adapter.execute(FakeFastmailClient(), fixture_arguments())
