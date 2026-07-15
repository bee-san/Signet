from __future__ import annotations

from datetime import UTC, datetime

import pytest

from signet.access_requests import FrozenAccessRequestFactory
from signet.adapters.base import AdapterRequest, AdapterValidationError, DispatchError
from signet.adapters.tool_access import ToolAccessAdapter
from signet.credential_broker import Secret
from signet.crypto import PayloadCipher
from signet.freezer import RequestFreezer
from signet.gateway_tools import AccessRequestDraft

NOW = 1_800_000_000


def factory() -> FrozenAccessRequestFactory:
    cipher = PayloadCipher(
        Secret("fake-access-request-master-key-material"),
        "keychain://Signet/fake-access-request-key",
    )
    freezer = RequestFreezer(
        cipher,
        pending_ttl_seconds=900,
        clock=lambda: datetime.fromtimestamp(NOW + 99, tz=UTC),
    )
    return FrozenAccessRequestFactory(freezer, policy_version=lambda: 7)


def test_access_request_factory_freezes_exact_gateway_internal_proposal() -> None:
    request = factory().freeze(
        AccessRequestDraft(
            origin_namespace="profile:one",
            alias="fastmail",
            tool="search_email",
            reason="Need reviewed read access",
            actor="mcp:profile:one",
            created_at=NOW,
        )
    )

    assert request.downstream_alias == "gateway"
    assert request.tool_name == "request_tool_access"
    assert request.policy_mode == "approval"
    assert request.gateway_internal is True
    assert request.origin_namespace == "profile:one"
    assert request.created_at == NOW
    assert request.expires_at == NOW + 900
    assert request.policy_version == "7"
    assert request.encrypted_payload
    assert b"Need reviewed read access" not in request.encrypted_payload


def test_denied_event_is_private_argument_free_and_deduplicated_by_policy_scope() -> None:
    selected = factory()
    first = selected.freeze_denied_event(
        origin_namespace="profile:one",
        alias="fastmail",
        tool="delete_email",
        actor="mcp:profile:one",
        created_at=NOW,
    )
    replay = selected.freeze_denied_event(
        origin_namespace="profile:one",
        alias="fastmail",
        tool="delete_email",
        actor="mcp:profile:one",
        created_at=NOW + 1,
    )
    other = selected.freeze_denied_event(
        origin_namespace="profile:one",
        alias="fastmail",
        tool="delete_mailbox",
        actor="mcp:profile:one",
        created_at=NOW,
    )

    assert first.gateway_internal is True
    assert first.idempotency_key == replay.idempotency_key
    assert first.payload_fingerprint == replay.payload_fingerprint
    assert first.idempotency_key != other.idempotency_key
    assert first.retry_of_request_id is None
    assert b"delete_email" not in first.encrypted_payload


def test_tool_access_adapter_is_reviewable_but_structurally_non_dispatchable() -> None:
    adapter = ToolAccessAdapter()
    proposal = {
        "alias": "fastmail",
        "tool": "search_email",
        "reason": "Need read access",
    }
    assert adapter.canonicalize(proposal) == proposal
    summary = adapter.summarize_for_web(proposal)
    assert summary.destination_summary == "fastmail.search_email"
    assert summary.detail_blocks[1].value == "Need read access"
    assert adapter.redact_for_audit(proposal)["reason"] == "<redacted>"

    request = AdapterRequest(
        request_id="req_FakeAccess",
        downstream_alias="gateway",
        tool_name="request_tool_access",
        arguments=proposal,
        account="gateway",
        payload_hash="a" * 64,
    )
    with pytest.raises(AdapterValidationError, match="never downstream"):
        adapter.prepare_for_execution(request)


@pytest.mark.anyio
async def test_tool_access_adapter_cannot_execute() -> None:
    adapter = ToolAccessAdapter()
    with pytest.raises(DispatchError, match="cannot be dispatched") as raised:
        await adapter.execute(object(), {"alias": "a", "tool": "b", "reason": "c"})  # type: ignore[arg-type]
    assert raised.value.dispatch_may_have_occurred is False


@pytest.mark.parametrize(
    "proposal",
    [
        {"alias": "Fastmail", "tool": "read", "reason": "valid"},
        {"alias": "fastmail", "tool": "../read", "reason": "valid"},
        {"alias": "fastmail", "tool": "read", "reason": " surrounded "},
        {"alias": "fastmail", "tool": "read", "reason": "bad\x00control"},
        {"alias": "fastmail", "tool": "read", "reason": "valid", "mode": "passthrough"},
    ],
)
def test_tool_access_adapter_rejects_ambiguous_or_retargeted_proposals(
    proposal: dict[str, str],
) -> None:
    with pytest.raises(AdapterValidationError):
        ToolAccessAdapter().canonicalize(proposal)


def test_access_request_factory_rejects_invalid_active_policy_version() -> None:
    selected = factory()
    selected._policy_version = lambda: 0  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match="policy version"):
        selected.freeze(
            AccessRequestDraft(
                origin_namespace="profile:one",
                alias="fastmail",
                tool="search_email",
                reason="Need access",
                actor="mcp:profile:one",
                created_at=NOW,
            )
        )
