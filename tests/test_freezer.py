from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast

import mcp.types as types
import pytest

from signet.adapters.base import ApprovalAdapter
from signet.canonical import payload_fingerprint
from signet.credential_broker import Secret
from signet.crypto import PayloadCipher
from signet.freezer import RequestFreezer
from signet.models import AttachmentReference

FAKE_MASTER = "fake-freezer-master-key-material-00001"
FAKE_KEY_REFERENCE = "keychain://Signet/fake-freezer-payload-key"
FAKE_ATTACHMENT_HASH = "a" * 64
FAKE_SCHEMA_DIGEST = "b" * 64
FAKE_CREDENTIAL_DIGEST = "c" * 64
FAKE_ACCOUNT_REF = "fake-account"
NOW = datetime(2026, 7, 15, 12, 0, 0, 999_999, tzinfo=UTC)


class CanonicalizingOnlyAdapter:
    adapter_id = "fake.create"
    adapter_version = "adapter-v7"
    downstream_alias = "fake-service"
    tool_name = "create_item"
    communication_send = False
    supports_idempotency = True
    reconciliation_tools: frozenset[str] = frozenset()
    input_schema: Mapping[str, Any] = {"type": "object"}

    def __init__(self) -> None:
        self.methods: list[str] = []

    def canonicalize(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self.methods.append("canonicalize")
        return {
            "count": arguments["count"],
            "name": str(arguments["name"]).strip(),
        }

    def __getattr__(self, name: str) -> Any:
        if name in {
            "validate",
            "summarize_for_web",
            "redact_for_audit",
            "prepare_for_execution",
            "execute",
            "classify_outcome",
            "reconcile",
            "safe_result_metadata",
        }:
            raise AssertionError(f"freezer accessed forbidden adapter method {name}")
        raise AttributeError(name)


def freezer(*, maximum: int = 4096) -> RequestFreezer:
    encryptor = PayloadCipher(
        Secret(FAKE_MASTER),
        FAKE_KEY_REFERENCE,
        max_plaintext_bytes=maximum,
    )
    return RequestFreezer(
        encryptor,
        pending_ttl_seconds=600,
        max_canonical_bytes=maximum,
        clock=lambda: NOW,
    )


def attachment() -> AttachmentReference:
    return AttachmentReference(
        attachment_id="att_Fake001",
        filename="fake-note.txt",
        mime_type="text/plain",
        size_bytes=12,
        sha256=FAKE_ATTACHMENT_HASH,
        storage_path="/tmp/signet-tests/fake-note",
        purge_after=1_800_000_000,
    )


def test_freezer_builds_complete_encrypted_enqueue_data_and_valid_pending_result() -> None:
    adapter = CanonicalizingOnlyAdapter()
    selected = freezer()
    frozen = selected.freeze(
        cast(ApprovalAdapter, adapter),
        {"name": "  private fake item  ", "count": 2},
        origin_namespace="profile:fake-test",
        policy_version=11,
        schema_digest=FAKE_SCHEMA_DIGEST,
        account_ref=FAKE_ACCOUNT_REF,
        credential_identity_digest=FAKE_CREDENTIAL_DIGEST,
        editor_actor="caller:fake-test",
        idempotency_key="fake-upstream-call-001",
        retry_of_request_id="req_FakePrior01",
        attachments=(attachment(),),
    )
    request = frozen.enqueue_request
    expected_payload, expected_hash = payload_fingerprint(
        alias=adapter.downstream_alias,
        tool=adapter.tool_name,
        account_ref=FAKE_ACCOUNT_REF,
        credential_identity_digest=FAKE_CREDENTIAL_DIGEST,
        schema_digest=FAKE_SCHEMA_DIGEST,
        caller_namespace="profile:fake-test",
        arguments={"count": 2, "name": "private fake item"},
        staged_file_hashes=(FAKE_ATTACHMENT_HASH,),
        policy_version=11,
        adapter_id=adapter.adapter_id,
        adapter_version=adapter.adapter_version,
    )

    assert adapter.methods == ["canonicalize"]
    assert re.fullmatch(r"req_[A-Za-z0-9]+", request.request_id)
    assert len(request.request_id.removeprefix("req_")) >= 32
    assert request.downstream_alias == "fake-service"
    assert request.tool_name == "create_item"
    assert request.policy_mode == "approval"
    assert request.origin_namespace == "profile:fake-test"
    assert request.payload_hash == expected_hash
    assert request.payload_fingerprint == expected_hash
    assert request.canonical_size == len(expected_payload)
    assert request.policy_version == "11"
    assert request.adapter_version == "adapter-v7"
    assert request.schema_version == FAKE_SCHEMA_DIGEST
    assert request.editor_actor == "caller:fake-test"
    assert request.encryption_key_ref == FAKE_KEY_REFERENCE
    assert request.idempotency_key == "fake-upstream-call-001"
    assert request.retry_of_request_id == "req_FakePrior01"
    assert request.attachments == (attachment(),)
    assert request.created_at == 1_784_116_800
    assert request.expires_at == request.created_at + 600

    pending = frozen.pending
    assert pending == {
        "status": "pending_approval",
        "request_id": request.request_id,
        "expires_at": "2026-07-15T12:10:00Z",
        "message": (
            "This action requires human approval. Check status with check_approval_status."
        ),
    }
    assert frozen.call_result == frozen.pending_result
    assert frozen.pending_result["structuredContent"] == pending
    assert frozen.pending_result["isError"] is False
    types.CallToolResult.model_validate(frozen.pending_result)

    decrypted = selected._encryptor.decrypt(  # noqa: SLF001 - focused boundary test
        request.encrypted_payload,
        key_reference=request.encryption_key_ref,
        request_id=request.request_id,
        version=1,
        payload_hash=request.payload_hash,
    )
    assert decrypted == expected_payload
    assert b"private fake item" not in request.pending_result


def test_freezer_generates_distinct_secure_ids_without_content_deduplication() -> None:
    adapter = CanonicalizingOnlyAdapter()
    selected = freezer()
    kwargs = {
        "origin_namespace": "profile:fake-test",
        "policy_version": 1,
        "schema_digest": FAKE_SCHEMA_DIGEST,
        "account_ref": FAKE_ACCOUNT_REF,
        "credential_identity_digest": FAKE_CREDENTIAL_DIGEST,
        "editor_actor": "caller:fake-test",
    }
    first = selected.freeze(cast(ApprovalAdapter, adapter), {"name": "same", "count": 1}, **kwargs)
    second = selected.freeze(cast(ApprovalAdapter, adapter), {"name": "same", "count": 1}, **kwargs)

    assert first.request.request_id != second.request.request_id
    assert first.request.payload_fingerprint == second.request.payload_fingerprint
    assert first.request.encrypted_payload != second.request.encrypted_payload
    assert first.request.idempotency_key is None


def test_freezer_uses_utc_and_rejects_naive_clock() -> None:
    selected = RequestFreezer(
        PayloadCipher(Secret(FAKE_MASTER), FAKE_KEY_REFERENCE),
        pending_ttl_seconds=60,
        clock=lambda: datetime(2026, 7, 15, 12, 0, 0),
    )
    adapter = cast(ApprovalAdapter, CanonicalizingOnlyAdapter())
    with pytest.raises(ValueError, match="timezone-aware"):
        selected.freeze(
            adapter,
            {"name": "fake", "count": 1},
            origin_namespace="profile:fake-test",
            policy_version=1,
            schema_digest=FAKE_SCHEMA_DIGEST,
            account_ref=FAKE_ACCOUNT_REF,
            credential_identity_digest=FAKE_CREDENTIAL_DIGEST,
            editor_actor="caller:fake-test",
        )


def test_freezer_rejects_attachment_hash_mismatch_before_canonicalization() -> None:
    adapter = CanonicalizingOnlyAdapter()
    with pytest.raises(ValueError, match="exactly match"):
        freezer().freeze(
            cast(ApprovalAdapter, adapter),
            {"name": "fake", "count": 1},
            origin_namespace="profile:fake-test",
            policy_version=1,
            schema_digest=FAKE_SCHEMA_DIGEST,
            account_ref=FAKE_ACCOUNT_REF,
            credential_identity_digest=FAKE_CREDENTIAL_DIGEST,
            editor_actor="caller:fake-test",
            attachments=(attachment(),),
            staged_file_hashes=("b" * 64,),
        )
    assert adapter.methods == []


def test_freezer_rejects_oversized_canonical_payload_without_returning_partial_data() -> None:
    adapter = cast(ApprovalAdapter, CanonicalizingOnlyAdapter())
    with pytest.raises(ValueError, match="freezer limit"):
        freezer(maximum=64).freeze(
            adapter,
            {"name": "x" * 100, "count": 1},
            origin_namespace="profile:fake-test",
            policy_version=1,
            schema_digest=FAKE_SCHEMA_DIGEST,
            account_ref=FAKE_ACCOUNT_REF,
            credential_identity_digest=FAKE_CREDENTIAL_DIGEST,
            editor_actor="caller:fake-test",
        )


def test_frozen_and_freezer_representations_redact_encrypted_request_data() -> None:
    selected = freezer()
    frozen = selected.freeze(
        cast(ApprovalAdapter, CanonicalizingOnlyAdapter()),
        {"name": "private fake value", "count": 1},
        origin_namespace="profile:fake-test",
        policy_version=1,
        schema_digest=FAKE_SCHEMA_DIGEST,
        account_ref=FAKE_ACCOUNT_REF,
        credential_identity_digest=FAKE_CREDENTIAL_DIGEST,
        editor_actor="caller:fake-test",
    )
    assert repr(frozen) == "FrozenRequest(enqueue_request=<redacted>)"
    assert FAKE_MASTER not in repr(selected)
    assert FAKE_KEY_REFERENCE not in repr(selected)
    with pytest.raises(AttributeError):
        selected.max_canonical_bytes = 10_000  # type: ignore[misc]
