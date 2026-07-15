from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

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

    async def call_tool(self, tool_name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
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
    return cast(dict[str, Any], fixture["arguments"])


def adapter_request(arguments: Mapping[str, Any]) -> AdapterRequest:
    return AdapterRequest(
        request_id="req_fastmail_fixture",
        downstream_alias="fastmail",
        tool_name="send_email",
        arguments=arguments,
        account="primary",
        payload_hash="b" * 64,
    )


def sent_search_candidate(
    arguments: Mapping[str, Any],
    *,
    identity: str = "message-safe-id",
) -> dict[str, Any]:
    return {
        "messageId": identity,
        "folder": "Sent",
        "status": "sent",
        "from": arguments["from"],
        "to": arguments["to"],
        "cc": arguments.get("cc", []),
        "bcc": arguments.get("bcc", []),
        "subject": arguments["subject"],
        "body": arguments["body"],
    }


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

    assert summary.destination_summary == "To: recipient@example.test"
    assert masked == "r*** at example.test"
    assert summary.destination_summary not in masked
    assert any(block.value == arguments["body"] for block in summary.detail_blocks)
    recipient_block = next(block for block in summary.detail_blocks if block.label == "Recipients")
    recipient_groups = cast(dict[str, Any], recipient_block.value)
    assert recipient_groups == {
        "to": {
            "count": 1,
            "mailboxes": [
                {
                    "original_executable_mailbox": "recipient@example.test",
                    "display_name": {
                        "present": False,
                        "parsed_label": None,
                        "normalized_label": None,
                        "delivery_target": False,
                    },
                    "delivery_target": {
                        "normalized_addr_spec": "recipient@example.test",
                        "parsed_local_part": "recipient",
                        "normalized_local_part": "recipient",
                        "parsed_domain": "example.test",
                        "normalized_unicode_domain": "example.test",
                        "ascii_idna_punycode_domain": "example.test",
                    },
                    "review_flags": {
                        "unicode_fields": [],
                        "normalization_changes": [],
                    },
                }
            ],
        },
        "cc": {"count": 0, "mailboxes": []},
        "bcc": {"count": 0, "mailboxes": []},
    }
    assert summary.warnings == ()
    audit = repr(adapter.redact_for_audit(arguments))
    assert arguments["body"] not in audit
    assert arguments["subject"] not in audit
    assert "recipient_count" in audit


def test_fastmail_legacy_attachment_type_is_explicitly_unverified() -> None:
    adapter = FastmailAdapter(account="primary")
    arguments = fixture_arguments()
    arguments["attachments"] = [
        {
            "staged_id": "stg_LegacyAttachment01",
            "filename": "disguised.png",
            "mime_type": "text/html",
            "detected_mime": "image/png",
            "size": 12,
            "sha256": "a" * 64,
        }
    ]

    summary = adapter.summarize_for_web(arguments)

    assert any("not byte-verified" in warning for warning in summary.warnings)
    assert not any("Declared and detected MIME differ" in warning for warning in summary.warnings)


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
    assert first == (
        "o*** at example.test, t*** at elsewhere.test, t*** at example.test, (+1 more)"
    )
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


@pytest.mark.asyncio
async def test_fastmail_preserves_exact_executable_address_values() -> None:
    arguments = fixture_arguments()
    arguments["to"] = ["Autumn Example <autumn@ex\u00e4mple.test>"]
    arguments["body"] = "Cafe\u0301\r\nsecond line"
    arguments["subject"] = "  exact subject  "
    adapter = FastmailAdapter(account="primary", reviewed_dispatch_enabled=True)
    downstream = FakeFastmailClient()

    canonical = adapter.canonicalize(arguments)
    prepared = adapter.prepare_for_execution(adapter_request(arguments))
    await adapter.execute(downstream, prepared)

    assert canonical == arguments
    assert downstream.calls == [("send_email", arguments)]


def test_fastmail_recipient_review_exposes_idn_display_name_nfc_and_bcc_context() -> None:
    arguments = fixture_arguments()
    arguments.update(
        {
            "to": ['"Pаypal, Review" <billing@pаypal.test>'],
            "cc": ["Plain Name <plain@example.test>"],
            "bcc": ['"Cafe\u0301, Blind" <blind@exa\u0308mple.test>'],
        }
    )
    adapter = FastmailAdapter(account="primary")

    summary = adapter.summarize_for_web(arguments)
    prepared = adapter.prepare_for_execution(adapter_request(arguments))

    assert summary.destination_summary == "To: 1 recipient; Cc: 1 recipient; Bcc: 1 recipient"
    assert prepared == {**arguments, "_signet_resolved_attachments": []}
    recipient_block = next(block for block in summary.detail_blocks if block.label == "Recipients")
    groups = cast(dict[str, Any], recipient_block.value)

    to_mailbox = groups["to"]["mailboxes"][0]
    assert to_mailbox["original_executable_mailbox"] == arguments["to"][0]
    assert to_mailbox["display_name"] == {
        "present": True,
        "parsed_label": "Pаypal, Review",
        "normalized_label": "Pаypal, Review",
        "delivery_target": False,
    }
    assert to_mailbox["delivery_target"] == {
        "normalized_addr_spec": "billing@xn--pypal-4ve.test",
        "parsed_local_part": "billing",
        "normalized_local_part": "billing",
        "parsed_domain": "pаypal.test",
        "normalized_unicode_domain": "pаypal.test",
        "ascii_idna_punycode_domain": "xn--pypal-4ve.test",
    }
    assert to_mailbox["review_flags"] == {
        "unicode_fields": ["display_name", "domain"],
        "normalization_changes": ["domain_idna_punycode"],
    }

    assert groups["cc"]["count"] == 1
    assert groups["cc"]["mailboxes"][0]["display_name"]["parsed_label"] == "Plain Name"
    bcc_mailbox = groups["bcc"]["mailboxes"][0]
    assert bcc_mailbox["original_executable_mailbox"] == arguments["bcc"][0]
    assert bcc_mailbox["display_name"]["parsed_label"] == "Cafe\u0301, Blind"
    assert bcc_mailbox["display_name"]["normalized_label"] == "Café, Blind"
    assert bcc_mailbox["delivery_target"]["parsed_domain"] == "exa\u0308mple.test"
    assert bcc_mailbox["delivery_target"]["normalized_unicode_domain"] == "exämple.test"
    assert bcc_mailbox["delivery_target"]["ascii_idna_punycode_domain"] == "xn--exmple-cua.test"
    assert bcc_mailbox["delivery_target"]["normalized_addr_spec"] == ("blind@xn--exmple-cua.test")
    assert bcc_mailbox["review_flags"]["normalization_changes"] == [
        "display_name_nfc",
        "domain_nfc",
        "domain_idna_punycode",
    ]

    warnings = "\n".join(summary.warnings)
    assert "Display names are labels only, not delivery targets" in warnings
    assert "To recipient 1 uses Unicode in its domain" in warnings
    assert "visually similar domains can identify a different mailbox" in warnings
    assert "ASCII IDNA/punycode domain" in warnings
    assert "To recipient 1 uses non-ASCII Unicode in its display name" in warnings
    assert "Bcc recipient 1" in warnings
    assert (
        "display-name NFC normalization, domain NFC normalization, domain IDNA/punycode conversion"
        in warnings
    )
    assert "original executable mailbox" in warnings


def test_fastmail_recipient_review_is_complete_and_bounded_at_schema_limit() -> None:
    arguments = fixture_arguments()
    recipients = [
        f'"Person {index:03}" <person{index:03}@example{index:03}.test>' for index in range(100)
    ]
    arguments.update(
        {
            "to": recipients[:34],
            "cc": recipients[34:67],
            "bcc": recipients[67:],
        }
    )

    summary = FastmailAdapter(account="primary").summarize_for_web(arguments)

    assert summary.destination_summary == "To: 34 recipients; Cc: 33 recipients; Bcc: 33 recipients"
    assert len(summary.destination_summary) <= 240
    recipient_block = next(block for block in summary.detail_blocks if block.label == "Recipients")
    groups = cast(dict[str, Any], recipient_block.value)
    assert [groups[field]["count"] for field in ("to", "cc", "bcc")] == [34, 33, 33]
    reviewed_originals = [
        mailbox["original_executable_mailbox"]
        for field in ("to", "cc", "bcc")
        for mailbox in groups[field]["mailboxes"]
    ]
    assert reviewed_originals == recipients
    assert len(json.dumps(groups, ensure_ascii=False)) < 150_000
    assert summary.warnings == (
        "Display names are labels only, not delivery targets. Verify the normalized "
        "addr-spec for every named recipient.",
    )


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
    arguments = fixture_arguments()
    request = adapter_request(arguments)
    downstream = FakeFastmailClient(search_result={"messages": [sent_search_candidate(arguments)]})
    restricted = ReadOnlyMCPClient(downstream, adapter.reconciliation_tools)
    attempt = ExecutionAttempt(
        attempt_id="attempt_fastmail",
        started_at=datetime.now(UTC),
        downstream_result={"messageId": "message-safe-id"},
    )

    assert await adapter.reconcile(restricted, request, attempt) is Reconciliation.CONFIRMED_EFFECT
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
        await adapter.reconcile(restricted, request, known_identity) is Reconciliation.INCONCLUSIVE
    )
    assert adapter.supports_idempotency is False


@pytest.mark.asyncio
async def test_fastmail_reconcile_rejects_unbound_malformed_and_error_hits() -> None:
    adapter = FastmailAdapter(account="primary")
    arguments = fixture_arguments()
    request = adapter_request(arguments)
    attempt = ExecutionAttempt(
        attempt_id="attempt_untrusted_search",
        started_at=datetime.now(UTC),
        downstream_result={"messageId": "message-safe-id"},
    )
    unrelated = sent_search_candidate(arguments)
    unrelated["body"] = "A different message with a stale or wrong provider ID."
    cases: tuple[Mapping[str, Any], ...] = (
        {"messages": [{"messageId": "message-safe-id", "folder": "Sent"}]},
        {"messages": [unrelated]},
        {"messages": [sent_search_candidate(arguments, identity="different-id")]},
        {"messages": ["malformed"]},
        {"messages": [{}] * 11},
        {"isError": True, "messages": [sent_search_candidate(arguments)]},
        {"data": {"is_error": True, "messages": [sent_search_candidate(arguments)]}},
    )

    for search_result in cases:
        downstream = FakeFastmailClient(search_result=search_result)
        restricted = ReadOnlyMCPClient(downstream, adapter.reconciliation_tools)
        assert await adapter.reconcile(restricted, request, attempt) is Reconciliation.INCONCLUSIVE
        assert len(downstream.calls) == 1


@pytest.mark.asyncio
async def test_fastmail_reconcile_with_attachments_requires_characterized_binding() -> None:
    adapter = FastmailAdapter(account="primary")
    arguments = fixture_arguments()
    arguments["attachments"] = [
        {
            "staged_id": "stg_FakeAttachment01",
            "filename": "reviewed.txt",
            "mime_type": "text/plain",
            "detected_mime": "text/plain",
            "size": 7,
            "sha256": "a" * 64,
        }
    ]
    request = adapter_request(arguments)
    downstream = FakeFastmailClient(search_result={"messages": [sent_search_candidate(arguments)]})
    restricted = ReadOnlyMCPClient(downstream, adapter.reconciliation_tools)

    assert (
        await adapter.reconcile(
            restricted,
            request,
            ExecutionAttempt(
                attempt_id="attempt_attachment_search",
                started_at=datetime.now(UTC),
                downstream_result={"messageId": "message-safe-id"},
            ),
        )
        is Reconciliation.INCONCLUSIVE
    )


def test_fastmail_ambiguous_tool_error_remains_unknown() -> None:
    adapter = FastmailAdapter(account="primary")
    assert adapter.classify_outcome({"isError": True, "message": "timeout"}) is (
        Outcome.OUTCOME_UNKNOWN
    )
    assert (
        adapter.classify_outcome({"isError": True, "status": "ok", "messageId": "not-proof"})
        is Outcome.OUTCOME_UNKNOWN
    )
    assert adapter.classify_outcome({"id": "attachment-like-id"}) is Outcome.OUTCOME_UNKNOWN


@pytest.mark.asyncio
async def test_fastmail_dispatch_is_disabled_until_provider_review() -> None:
    adapter = FastmailAdapter(account="primary")
    with pytest.raises(Exception, match="not activated"):
        await adapter.execute(FakeFastmailClient(), fixture_arguments())
