from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import mcp.types as types
import pytest
from mcp.shared.exceptions import McpError
from mcp.shared.memory import create_connected_server_and_client_session

from signet.auth import (
    TOTP_PROOF_DOMAIN,
    ActionBinding,
    AttemptReservation,
    AuthenticationRateLimited,
    InMemoryAttemptLimiter,
    ProofCapability,
    source_rate_limit_key,
    totp_proof_claims,
    totp_rate_limit_key,
)
from signet.db import Database
from signet.gateway_tools import (
    GATEWAY_TOOL_DEFINITIONS,
    AccessRequestDraft,
    GatewayPrincipal,
    GatewayTools,
    GatewayToolSurface,
    SafeRequestSummary,
)
from signet.mcp_mirror import raw_model
from signet.models import (
    ApprovalConfirmation,
    ConfirmationKind,
    EnqueueRequest,
    OutcomeClassification,
)
from signet.state_machine import ApprovalStateMachine
from signet.totp import InvalidTotp, TotpNotEnrolled, VerifiedTotp

NOW = 1_800_000_000
# This value is schema-only test data. No authenticator or production verifier is used.
FAKE_SCHEMA_PROOF = "000000"
TEST_CAPABILITIES = ProofCapability(b"test-only-proof-capability-key-0001")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def enqueue_request(
    request_id: str,
    *,
    namespace: str = "profile:one",
    payload: str = "body-one",
    created_at: int = NOW,
    expires_at: int = NOW + 600,
    gateway_internal: bool = False,
    editor_actor: str | None = None,
) -> EnqueueRequest:
    return EnqueueRequest(
        request_id=request_id,
        downstream_alias="gateway" if gateway_internal else "fastmail",
        tool_name="request_tool_access" if gateway_internal else "send_email",
        policy_mode="approval",
        origin_namespace=namespace,
        encrypted_payload=b"fake:ciphertext",
        payload_hash=digest(payload),
        payload_fingerprint=digest(f"fingerprint:{payload}"),
        pending_result=b'{"status":"pending_approval"}',
        created_at=created_at,
        expires_at=expires_at,
        policy_version="policy-1",
        adapter_version="adapter-1",
        schema_version="schema-1",
        editor_actor=editor_actor or f"caller:{namespace}",
        canonical_size=len(payload),
        gateway_internal=gateway_internal,
    )


class FakeSummaries:
    def __init__(self) -> None:
        self.values: dict[str, SafeRequestSummary] = {}
        self.calls: list[tuple[str, int, str]] = []
        self.failures: set[str] = set()

    def add(
        self,
        request_id: str,
        *,
        service: str = "Fastmail",
        tool: str = "send_email",
        destination: str = "a*** at example.test",
    ) -> None:
        self.values[request_id] = SafeRequestSummary(service, tool, destination)

    def get(self, request_id: str, *, version: int, payload_hash: str) -> SafeRequestSummary:
        self.calls.append((request_id, version, payload_hash))
        if request_id in self.failures:
            raise ValueError("fake corrupt encrypted payload")
        return self.values[request_id]


@pytest.mark.parametrize(
    ("service", "tool", "destination"),
    (
        ("Fastmail\nforged", "send_email", "masked"),
        ("Fastmail", "send_email\x7fforged", "masked"),
        ("Fastmail", "send_email", "masked\tforged"),
    ),
)
def test_safe_request_summary_rejects_control_characters(
    service: str,
    tool: str,
    destination: str,
) -> None:
    with pytest.raises(ValueError, match="public bounds"):
        SafeRequestSummary(service, tool, destination)


class FakeTotpVerifier:
    def __init__(
        self,
        *,
        error: Exception | None = None,
        use_id: str = "fake:totp-use:one",
        binding_override: ActionBinding | None = None,
        on_verify: Callable[[ActionBinding], None] | None = None,
    ) -> None:
        self.error = error
        self.use_id = use_id
        self.binding_override = binding_override
        self.on_verify = on_verify
        self.calls: list[tuple[str, ActionBinding, int]] = []
        self.consumed_successes: list[VerifiedTotp] = []

    def verify(
        self,
        user_id: str,
        proof: str,
        *,
        binding: ActionBinding,
        now: int,
        source_id: str,
        session_id: str | None,
        http_method: str,
    ) -> VerifiedTotp:
        del proof
        self.calls.append((user_id, binding, now))
        if self.error is not None:
            raise self.error
        if self.on_verify is not None:
            self.on_verify(binding)
        selected_binding = self.binding_override or binding
        rate_key = totp_rate_limit_key(user_id)
        source_key = source_rate_limit_key(source_id)
        reservation = AttemptReservation(
            attempt_id="fake:attempt:opaque",
            scope_keys=(rate_key, source_key),
        )
        capability = TEST_CAPABILITIES.seal(
            TOTP_PROOF_DOMAIN,
            totp_proof_claims(
                credential_id="fake:credential",
                credential_user_id=user_id,
                user_id=user_id,
                use_id=self.use_id,
                binding=selected_binding,
                path="web" if http_method == "POST" else "mcp",
                session_id=session_id,
                http_method=http_method,
                rate_limit_key=rate_key,
                attempt_id=reservation.attempt_id,
                attempt_scope_keys=reservation.scope_keys,
            ),
        )
        return VerifiedTotp(
            credential_id="fake:credential",
            user_id=user_id,
            use_id=self.use_id,
            binding=selected_binding,
            session_id=session_id,
            http_method=http_method,
            rate_limit_key=rate_key,
            attempt_reservation=reservation,
            capability=capability,
        )

    def record_consumed_success(self, proof: VerifiedTotp, *, now: int) -> None:
        del now
        self.consumed_successes.append(proof)


class RateLimitedFakeTotpVerifier:
    """Exercise the shared limiter without consulting an authenticator provider."""

    def __init__(self) -> None:
        self.limiter = InMemoryAttemptLimiter(lock_schedule=((2, 60),))

    def verify(
        self,
        user_id: str,
        proof: str,
        *,
        binding: ActionBinding,
        now: int,
        source_id: str,
        session_id: str | None,
        http_method: str,
    ) -> VerifiedTotp:
        del proof, binding, session_id, http_method
        reservation = self.limiter.reserve(
            totp_rate_limit_key(user_id),
            source_key=source_rate_limit_key(source_id),
            now=now,
        )
        self.limiter.record_failure(reservation, now=now)
        raise InvalidTotp("fake:invalid")

    def record_consumed_success(self, proof: VerifiedTotp, *, now: int) -> None:
        raise AssertionError(f"unexpected fake success at {now}: {proof!r}")


class FakeAccessRequests:
    def __init__(self, summaries: FakeSummaries) -> None:
        self.summaries = summaries
        self.drafts: list[AccessRequestDraft] = []

    def freeze(self, draft: AccessRequestDraft) -> EnqueueRequest:
        self.drafts.append(draft)
        request_id = f"req_Access{len(self.drafts)}"
        self.summaries.add(
            request_id,
            service="Signet",
            tool="request_tool_access",
            destination=f"{draft.alias}.{draft.tool}",
        )
        return enqueue_request(
            request_id,
            namespace=draft.origin_namespace,
            payload=f"{draft.alias}:{draft.tool}:{draft.reason}",
            created_at=draft.created_at,
            expires_at=draft.created_at + 900,
            gateway_internal=True,
            editor_actor=draft.actor,
        )


@dataclass(slots=True)
class Harness:
    machine: ApprovalStateMachine
    summaries: FakeSummaries
    totp: FakeTotpVerifier
    access_requests: FakeAccessRequests
    tools: GatewayTools


@pytest.fixture
def machine(tmp_path: Path) -> ApprovalStateMachine:
    database = Database(tmp_path / "approvals.sqlite3")
    database.initialize()
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO auth_credentials(
                credential_id, user_id, kind, secret_reference, enrolled_at
            ) VALUES (
                'fake:credential', 'human:one', 'totp',
                'keychain://Signet/gateway-test', ?
            )
            """,
            (NOW,),
        )
    return ApprovalStateMachine(
        database,
        capabilities=TEST_CAPABILITIES,
        notification_user_id="human:one",
    )


def make_harness(
    machine: ApprovalStateMachine,
    *,
    totp: FakeTotpVerifier | None = None,
) -> Harness:
    summaries = FakeSummaries()
    verifier = totp or FakeTotpVerifier()
    access_requests = FakeAccessRequests(summaries)
    tools = GatewayTools(
        state_machine=machine,
        totp_verifier=verifier,
        summaries=summaries,
        access_requests=access_requests,
        clock=lambda: NOW + 10,
    )
    return Harness(machine, summaries, verifier, access_requests, tools)


def own_principal() -> GatewayPrincipal:
    return GatewayPrincipal(namespace="profile:one", user_id="human:one")


def foreign_principal() -> GatewayPrincipal:
    return GatewayPrincipal(namespace="profile:two", user_id="human:one")


def mcp_confirmation(request_id: str, *, use_id: str) -> ApprovalConfirmation:
    binding = ActionBinding("approve", request_id, 1, digest("body-one"))
    rate_key = totp_rate_limit_key("human:one")
    source_key = source_rate_limit_key("gateway-direct-test")
    attempt_id = "gateway-direct-attempt-opaque"
    capability = TEST_CAPABILITIES.seal(
        TOTP_PROOF_DOMAIN,
        totp_proof_claims(
            credential_id="fake:credential",
            credential_user_id="human:one",
            user_id="human:one",
            use_id=use_id,
            binding=binding,
            path="mcp",
            session_id=None,
            http_method="MCP",
            rate_limit_key=rate_key,
            attempt_id=attempt_id,
            attempt_scope_keys=(rate_key, source_key),
        ),
    )
    return ApprovalConfirmation(
        kind=ConfirmationKind.TOTP,
        use_id=use_id,
        path="mcp",
        capability=capability,
        user_id="human:one",
        action="approve",
        bound_request_id=request_id,
        bound_version=1,
        bound_payload_hash=digest("body-one"),
        session_id=None,
        http_method="MCP",
        attempt_id=attempt_id,
        attempt_scope_keys=(rate_key, source_key),
        rate_limit_key=rate_key,
        credential_id="fake:credential",
        credential_user_id="human:one",
    )


def web_confirmation(
    machine: ApprovalStateMachine,
    request_id: str,
    *,
    use_id: str,
    action: str = "approve",
    prospective_payload_hash: str | None = None,
) -> ApprovalConfirmation:
    session_id = "fake-web-session-identifier-000001"
    with machine.database.transaction() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO auth_users(user_id, created_at) VALUES (?, ?)",
            ("human:one", NOW),
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO web_sessions(
                session_id, user_id, auth_method, auth_generation,
                created_at, last_seen_at, absolute_expires_at
            ) VALUES (?, ?, 'fake-test', 0, ?, ?, ?)
            """,
            (session_id, "human:one", NOW, NOW, NOW + 600),
        )
    binding = ActionBinding(
        action,
        request_id,
        1,
        digest("body-one"),
        prospective_payload_hash,
    )
    rate_key = totp_rate_limit_key("human:one")
    source_key = source_rate_limit_key("gateway-web-test")
    attempt_id = "gateway-web-attempt-opaque"
    capability = TEST_CAPABILITIES.seal(
        TOTP_PROOF_DOMAIN,
        totp_proof_claims(
            credential_id="fake:credential",
            credential_user_id="human:one",
            user_id="human:one",
            use_id=use_id,
            binding=binding,
            path="web",
            session_id=session_id,
            http_method="POST",
            rate_limit_key=rate_key,
            attempt_id=attempt_id,
            attempt_scope_keys=(rate_key, source_key),
        ),
    )
    return ApprovalConfirmation(
        kind=ConfirmationKind.TOTP,
        use_id=use_id,
        path="web",
        capability=capability,
        user_id="human:one",
        action=action,
        bound_request_id=request_id,
        bound_version=1,
        bound_payload_hash=digest("body-one"),
        prospective_payload_hash=prospective_payload_hash,
        session_id=session_id,
        http_method="POST",
        attempt_id=attempt_id,
        attempt_scope_keys=(rate_key, source_key),
        rate_limit_key=rate_key,
        credential_id="fake:credential",
        credential_user_id="human:one",
    )


def error_code(result: dict[str, Any]) -> str:
    assert result["isError"] is True
    types.CallToolResult.model_validate(result)
    structured = result["structuredContent"]
    assert json.loads(result["content"][0]["text"]) == structured
    return str(structured["error"]["code"])


def structured(result: dict[str, Any]) -> dict[str, Any]:
    assert result["isError"] is False
    types.CallToolResult.model_validate(result)
    value = result["structuredContent"]
    assert json.loads(result["content"][0]["text"]) == value
    return value


def test_gateway_tool_definitions_match_normative_fixture_and_are_defensive_copies() -> None:
    fixture_path = Path(__file__).parents[1] / "spec/fixtures/gateway-tools-schemas.json"
    fixture = json.loads(fixture_path.read_text())

    assert fixture["tools"] == GATEWAY_TOOL_DEFINITIONS


def test_list_tools_returns_a_defensive_copy(machine: ApprovalStateMachine) -> None:
    harness = make_harness(machine)
    listed = harness.tools.list_tools()
    listed[0]["description"] = "mutated by caller"

    assert harness.tools.list_tools() == GATEWAY_TOOL_DEFINITIONS


@pytest.mark.asyncio
async def test_list_pending_is_caller_scoped_masked_and_omits_expired(
    machine: ApprovalStateMachine,
) -> None:
    harness = make_harness(machine)
    machine.enqueue(enqueue_request("req_Own"))
    machine.enqueue(enqueue_request("req_Foreign", namespace="profile:two"))
    machine.enqueue(enqueue_request("req_Expired", created_at=NOW - 100, expires_at=NOW + 5))
    harness.summaries.add("req_Own")
    harness.summaries.add("req_Foreign", destination="foreign@example.test")
    harness.summaries.add("req_Expired", destination="expired@example.test")

    result = structured(
        await harness.tools.call_tool("list_pending_approvals", {}, principal=own_principal())
    )

    assert result == {
        "requests": [
            {
                "request_id": "req_Own",
                "service": "Fastmail",
                "tool": "send_email",
                "destination_summary": "a*** at example.test",
                "summary_available": True,
                "age_seconds": 10,
                "expires_at": "2027-01-15T08:10:00Z",
                "version_hash_prefix": digest("body-one")[:12],
            }
        ],
        "next_cursor": None,
        "has_more": False,
    }
    assert harness.summaries.calls == [("req_Own", 1, digest("body-one"))]


@pytest.mark.asyncio
async def test_blocking_gateway_queue_read_does_not_stall_the_event_loop(
    machine: ApprovalStateMachine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = make_harness(machine)
    original = harness.tools._pending_requests
    started = threading.Event()
    release = threading.Event()

    def blocking_pending_requests(*args: Any, **kwargs: Any) -> Any:
        started.set()
        if not release.wait(timeout=5):
            raise AssertionError("blocking queue read test was not released")
        return original(*args, **kwargs)

    monkeypatch.setattr(harness.tools, "_pending_requests", blocking_pending_requests)
    safety_release = threading.Timer(3, release.set)
    safety_release.start()
    try:
        calling = asyncio.create_task(
            harness.tools.call_tool("list_pending_approvals", {}, principal=own_principal())
        )
        assert await asyncio.to_thread(started.wait, 1)
        assert not release.is_set()
        await asyncio.wait_for(asyncio.sleep(0), timeout=1)
        release.set()
        result = await calling
    finally:
        release.set()
        safety_release.cancel()

    assert structured(result) == {"requests": [], "next_cursor": None, "has_more": False}


@pytest.mark.asyncio
async def test_list_pending_is_hard_bounded_and_keyset_paginated(
    machine: ApprovalStateMachine,
) -> None:
    harness = make_harness(machine)
    request_ids = [f"req_Page{index:02d}" for index in range(30)]
    for index, request_id in enumerate(reversed(request_ids)):
        machine.enqueue(
            enqueue_request(
                request_id,
                payload=f"page-body-{index}",
                created_at=NOW,
            )
        )
        harness.summaries.add(request_id)

    first = structured(
        await harness.tools.call_tool("list_pending_approvals", {}, principal=own_principal())
    )

    assert [item["request_id"] for item in first["requests"]] == request_ids[:10]
    assert first["has_more"] is True
    assert isinstance(first["next_cursor"], str)
    assert len(harness.summaries.calls) == 10

    second = structured(
        await harness.tools.call_tool(
            "list_pending_approvals",
            {"cursor": first["next_cursor"], "limit": 25},
            principal=own_principal(),
        )
    )

    assert [item["request_id"] for item in second["requests"]] == request_ids[10:]
    assert second["has_more"] is False
    assert second["next_cursor"] is None
    assert len(harness.summaries.calls) == 30


@pytest.mark.asyncio
async def test_list_pending_rejects_oversized_pages_and_invalid_cursors(
    machine: ApprovalStateMachine,
) -> None:
    harness = make_harness(machine)

    with pytest.raises(McpError):
        await harness.tools.call_tool(
            "list_pending_approvals", {"limit": 26}, principal=own_principal()
        )
    with pytest.raises(McpError):
        await harness.tools.call_tool(
            "list_pending_approvals", {"cursor": "bad"}, principal=own_principal()
        )
    assert harness.summaries.calls == []


@pytest.mark.asyncio
async def test_list_pending_isolates_corrupt_or_unmasked_private_summaries(
    machine: ApprovalStateMachine,
) -> None:
    harness = make_harness(machine)
    for request_id in ("req_Corrupt", "req_Good", "req_Unmasked"):
        machine.enqueue(enqueue_request(request_id, payload=request_id))
    harness.summaries.failures.add("req_Corrupt")
    harness.summaries.add("req_Good", destination="g*** at example.test")
    raw_destination = "a***@example.test"
    harness.summaries.add("req_Unmasked", destination=raw_destination)

    result = structured(
        await harness.tools.call_tool(
            "list_pending_approvals", {"limit": 3}, principal=own_principal()
        )
    )

    by_id = {item["request_id"]: item for item in result["requests"]}
    assert by_id["req_Good"]["destination_summary"] == "g*** at example.test"
    assert by_id["req_Good"]["summary_available"] is True
    for request_id in ("req_Corrupt", "req_Unmasked"):
        assert by_id[request_id]["summary_available"] is False
        assert "unavailable" in by_id[request_id]["destination_summary"].lower()
    assert raw_destination not in json.dumps(result)
    assert len(harness.summaries.calls) == 3


@pytest.mark.asyncio
async def test_whatsapp_summary_validation_rejects_clear_digits_outside_final_four(
    machine: ApprovalStateMachine,
) -> None:
    harness = make_harness(machine)
    machine.enqueue(enqueue_request("req_WhatsAppLeaked"))
    with machine.database.transaction() as connection:
        connection.execute(
            """
            UPDATE approval_requests
            SET downstream_alias = 'whatsapp', tool_name = 'send_text'
            WHERE request_id = 'req_WhatsAppLeaked'
            """
        )
    leaked = "+15551234567***"
    harness.summaries.add(
        "req_WhatsAppLeaked",
        service="WhatsApp",
        tool="send_text",
        destination=leaked,
    )

    result = structured(
        await harness.tools.call_tool(
            "list_pending_approvals",
            {},
            principal=own_principal(),
        )
    )

    assert result["requests"][0]["summary_available"] is False
    assert leaked not in json.dumps(result)


@pytest.mark.parametrize(
    "destination",
    ("+*******2030", "*******0123@s.whatsapp.net"),
)
@pytest.mark.asyncio
async def test_whatsapp_summary_validation_accepts_owned_adapter_masks(
    machine: ApprovalStateMachine,
    destination: str,
) -> None:
    harness = make_harness(machine)
    machine.enqueue(enqueue_request("req_WhatsAppMasked"))
    with machine.database.transaction() as connection:
        connection.execute(
            """
            UPDATE approval_requests
            SET downstream_alias = 'whatsapp', tool_name = 'send_text'
            WHERE request_id = 'req_WhatsAppMasked'
            """
        )
    harness.summaries.add(
        "req_WhatsAppMasked",
        service="WhatsApp",
        tool="send_text",
        destination=destination,
    )

    result = structured(
        await harness.tools.call_tool(
            "list_pending_approvals",
            {},
            principal=own_principal(),
        )
    )

    assert result["requests"][0]["summary_available"] is True
    assert result["requests"][0]["destination_summary"] == destination


@pytest.mark.asyncio
async def test_unknown_and_foreign_ids_are_indistinguishable_for_all_scoped_tools(
    machine: ApprovalStateMachine,
) -> None:
    harness = make_harness(machine)
    machine.enqueue(enqueue_request("req_Foreign", namespace="profile:two"))
    approve_arguments = {
        "totp_code": FAKE_SCHEMA_PROOF,
        "expected_version_hash": digest("body-one")[:12],
    }

    for name, base in (
        ("check_approval_status", {}),
        ("cancel_request", {}),
        ("approve_request", approve_arguments),
    ):
        foreign = await harness.tools.call_tool(
            name,
            {"request_id": "req_Foreign", **base},
            principal=own_principal(),
        )
        unknown = await harness.tools.call_tool(
            name,
            {"request_id": "req_Unknown", **base},
            principal=own_principal(),
        )
        assert foreign == unknown
        assert error_code(foreign) == "request_not_found"

    assert harness.totp.calls == []
    assert machine.get_request("req_Foreign")["state"] == "pending_approval"


@pytest.mark.asyncio
async def test_check_status_returns_authoritative_safe_outcome_metadata(
    machine: ApprovalStateMachine,
) -> None:
    harness = make_harness(machine)
    machine.enqueue(enqueue_request("req_Status"))
    harness.summaries.add("req_Status")
    machine.approve(
        "req_Status",
        expected_version=1,
        expected_payload_hash=digest("body-one"),
        confirmation=mcp_confirmation("req_Status", use_id="fake:status-use"),
        actor="fake:mcp",
        now=NOW + 1,
    )
    lease = machine.claim_execution(
        "req_Status", worker_id="fake:worker", now=NOW + 2, lease_seconds=30
    )
    machine.mark_dispatch_started(lease, now=NOW + 3)
    machine.record_outcome(
        lease,
        classification=OutcomeClassification.SUCCEEDED,
        now=NOW + 4,
        safe_outcome={"message_id": "provider-message-1", "status": "sent"},
    )

    result = structured(
        await harness.tools.call_tool(
            "check_approval_status",
            {"request_id": "req_Status"},
            principal=own_principal(),
        )
    )

    assert result["status"] == "succeeded"
    assert result["service"] == "Fastmail"
    assert result["tool"] == "send_email"
    assert result["destination_summary"] == "a*** at example.test"
    assert result["summary_available"] is True
    assert result["version"] == 1
    assert result["safe_result_metadata"] == {
        "message_id": "sgref_07055ac0b625e7c7fb975c3f283ef742",
        "status": "sent",
    }


@pytest.mark.asyncio
async def test_approve_binds_exact_revision_consumes_once_and_returns_safe_receipt(
    machine: ApprovalStateMachine,
) -> None:
    harness = make_harness(machine)
    machine.enqueue(enqueue_request("req_Approve"))
    harness.summaries.add("req_Approve")

    result = structured(
        await harness.tools.call_tool(
            "approve_request",
            {
                "request_id": "req_Approve",
                "totp_code": FAKE_SCHEMA_PROOF,
                "expected_version_hash": digest("body-one")[:12],
            },
            principal=own_principal(),
        )
    )

    expected_binding = ActionBinding(
        action="approve",
        request_id="req_Approve",
        version=1,
        payload_hash=digest("body-one"),
    )
    assert harness.totp.calls == [("human:one", expected_binding, NOW + 10)]
    assert len(harness.totp.consumed_successes) == 1
    assert result == {
        "status": "approved",
        "request_id": "req_Approve",
        "tool": "send_email",
        "destination_summary": "a*** at example.test",
        "version": 1,
        "version_hash_prefix": digest("body-one")[:12],
        "approval_notification_queued": True,
    }
    assert machine.get_request("req_Approve")["state"] == "approved"
    with machine.database.read() as connection:
        consumed = connection.execute(
            "SELECT request_id, version, payload_hash, path FROM confirmation_consumptions"
        ).fetchall()
        attempts = connection.execute("SELECT * FROM execution_attempts").fetchall()
        notifications = connection.execute(
            """
            SELECT kind, service, action FROM notification_outbox
            WHERE request_id = 'req_Approve' ORDER BY created_at, kind
            """
        ).fetchall()
    assert [tuple(row) for row in consumed] == [("req_Approve", 1, digest("body-one"), "mcp")]
    assert attempts == []
    assert [tuple(row) for row in notifications] == [
        ("new_pending", "fastmail", "send_email"),
        ("mcp_approved", "fastmail", "send_email"),
    ]


@pytest.mark.asyncio
async def test_approval_fails_closed_when_summary_is_corrupt_or_unmasked(
    machine: ApprovalStateMachine,
) -> None:
    for request_id, corrupt in (("req_CorruptReceipt", True), ("req_RawReceipt", False)):
        harness = make_harness(machine)
        machine.enqueue(enqueue_request(request_id, payload=request_id))
        if corrupt:
            harness.summaries.failures.add(request_id)
        else:
            harness.summaries.add(
                request_id,
                destination="a***@example.test",
            )

        result = await harness.tools.call_tool(
            "approve_request",
            {
                "request_id": request_id,
                "totp_code": FAKE_SCHEMA_PROOF,
                "expected_version_hash": digest(request_id)[:12],
            },
            principal=own_principal(),
        )

        assert error_code(result) == "private_summary_unavailable"
        assert "a***@example.test" not in json.dumps(result)
        assert machine.get_request(request_id)["state"] == "pending_approval"
        assert harness.totp.consumed_successes == []


@pytest.mark.asyncio
async def test_stale_hash_is_rejected_before_totp_and_downstream_state(
    machine: ApprovalStateMachine,
) -> None:
    harness = make_harness(machine)
    machine.enqueue(enqueue_request("req_Edited"))
    machine.edit(
        "req_Edited",
        expected_version=1,
        expected_payload_hash=digest("body-one"),
        encrypted_payload=b"fake:new-ciphertext",
        payload_hash=digest("body-two"),
        canonical_size=8,
        policy_version="policy-1",
        adapter_version="adapter-1",
        schema_version="schema-1",
        editor_actor="human:web",
        confirmation=web_confirmation(
            machine,
            "req_Edited",
            use_id="fake:edit-stale-hash",
            action="edit",
            prospective_payload_hash=digest("body-two"),
        ),
        now=NOW + 1,
    )

    result = await harness.tools.call_tool(
        "approve_request",
        {
            "request_id": "req_Edited",
            "totp_code": FAKE_SCHEMA_PROOF,
            "expected_version_hash": digest("body-one")[:12],
        },
        principal=own_principal(),
    )

    assert error_code(result) == "stale_version"
    assert harness.totp.calls == []
    row = machine.get_request("req_Edited")
    assert (row["state"], row["current_version"]) == ("pending_approval", 2)
    with machine.database.read() as connection:
        assert connection.execute("SELECT * FROM execution_attempts").fetchall() == []
        consumptions = connection.execute(
            "SELECT use_id, action FROM confirmation_consumptions"
        ).fetchall()
    assert [tuple(row) for row in consumptions] == [("fake:edit-stale-hash", "edit")]


@pytest.mark.asyncio
async def test_expired_request_returns_stable_error_before_totp(
    machine: ApprovalStateMachine,
) -> None:
    machine.enqueue(enqueue_request("req_ExpiredApproval", expires_at=NOW + 5))
    harness = make_harness(machine)

    result = await harness.tools.call_tool(
        "approve_request",
        {
            "request_id": "req_ExpiredApproval",
            "totp_code": FAKE_SCHEMA_PROOF,
            "expected_version_hash": digest("body-one")[:12],
        },
        principal=own_principal(),
    )

    assert error_code(result) == "request_expired"
    assert harness.totp.calls == []
    assert machine.get_request("req_ExpiredApproval")["state"] == "pending_approval"


@pytest.mark.asyncio
async def test_edit_racing_after_verification_rolls_back_confirmation_consumption(
    machine: ApprovalStateMachine,
) -> None:
    machine.enqueue(enqueue_request("req_Race"))

    def edit_after_verification(binding: ActionBinding) -> None:
        machine.edit(
            "req_Race",
            expected_version=1,
            expected_payload_hash=str(binding.payload_hash),
            encrypted_payload=b"fake:new-ciphertext",
            payload_hash=digest("body-two"),
            canonical_size=8,
            policy_version="policy-1",
            adapter_version="adapter-1",
            schema_version="schema-1",
            editor_actor="human:web",
            confirmation=web_confirmation(
                machine,
                "req_Race",
                use_id="fake:edit-race",
                action="edit",
                prospective_payload_hash=digest("body-two"),
            ),
            now=NOW + 10,
        )

    harness = make_harness(machine, totp=FakeTotpVerifier(on_verify=edit_after_verification))
    harness.summaries.add("req_Race")
    result = await harness.tools.call_tool(
        "approve_request",
        {
            "request_id": "req_Race",
            "totp_code": FAKE_SCHEMA_PROOF,
            "expected_version_hash": digest("body-one")[:12],
        },
        principal=own_principal(),
    )

    assert error_code(result) == "stale_version"
    assert harness.totp.consumed_successes == []
    with machine.database.read() as connection:
        consumptions = connection.execute(
            "SELECT use_id, action FROM confirmation_consumptions"
        ).fetchall()
        assert connection.execute("SELECT * FROM execution_attempts").fetchall() == []
    assert [tuple(row) for row in consumptions] == [("fake:edit-race", "edit")]


@pytest.mark.asyncio
async def test_proof_bound_to_request_a_cannot_approve_request_b(
    machine: ApprovalStateMachine,
) -> None:
    machine.enqueue(enqueue_request("req_B"))
    request_a_binding = ActionBinding(
        action="approve",
        request_id="req_A",
        version=1,
        payload_hash=digest("body-one"),
    )
    harness = make_harness(
        machine,
        totp=FakeTotpVerifier(binding_override=request_a_binding),
    )

    result = await harness.tools.call_tool(
        "approve_request",
        {
            "request_id": "req_B",
            "totp_code": FAKE_SCHEMA_PROOF,
            "expected_version_hash": digest("body-one")[:12],
        },
        principal=own_principal(),
    )

    assert error_code(result) == "totp_binding_invalid"
    assert machine.get_request("req_B")["state"] == "pending_approval"
    with machine.database.read() as connection:
        assert connection.execute("SELECT * FROM confirmation_consumptions").fetchall() == []


@pytest.mark.asyncio
async def test_totp_use_replayed_from_web_path_is_rejected_atomically(
    machine: ApprovalStateMachine,
) -> None:
    use_id = "fake:shared-use"
    machine.enqueue(enqueue_request("req_Web"))
    machine.enqueue(enqueue_request("req_Mcp"))
    machine.approve(
        "req_Web",
        expected_version=1,
        expected_payload_hash=digest("body-one"),
        confirmation=web_confirmation(machine, "req_Web", use_id=use_id),
        actor="human:web",
        now=NOW + 1,
    )
    harness = make_harness(machine, totp=FakeTotpVerifier(use_id=use_id))
    harness.summaries.add("req_Mcp")

    result = await harness.tools.call_tool(
        "approve_request",
        {
            "request_id": "req_Mcp",
            "totp_code": FAKE_SCHEMA_PROOF,
            "expected_version_hash": digest("body-one")[:12],
        },
        principal=own_principal(),
    )

    assert error_code(result) == "totp_replayed"
    assert machine.get_request("req_Mcp")["state"] == "pending_approval"
    assert harness.totp.consumed_successes == []
    with machine.database.read() as connection:
        consumed = connection.execute("SELECT request_id FROM confirmation_consumptions").fetchall()
        attempts = connection.execute("SELECT * FROM execution_attempts").fetchall()
    assert [row["request_id"] for row in consumed] == ["req_Web"]
    assert attempts == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_code"),
    [
        (TotpNotEnrolled("fake:not-enrolled"), "totp_not_enrolled"),
        (InvalidTotp("fake:invalid"), "totp_invalid"),
        (AuthenticationRateLimited(45), "totp_locked"),
    ],
)
async def test_totp_failures_are_stable_errors_with_no_transition(
    machine: ApprovalStateMachine,
    failure: Exception,
    expected_code: str,
) -> None:
    machine.enqueue(enqueue_request("req_Failure"))
    harness = make_harness(machine, totp=FakeTotpVerifier(error=failure))

    result = await harness.tools.call_tool(
        "approve_request",
        {
            "request_id": "req_Failure",
            "totp_code": FAKE_SCHEMA_PROOF,
            "expected_version_hash": digest("body-one")[:12],
        },
        principal=own_principal(),
    )

    assert error_code(result) == expected_code
    assert machine.get_request("req_Failure")["state"] == "pending_approval"
    with machine.database.read() as connection:
        assert connection.execute("SELECT * FROM confirmation_consumptions").fetchall() == []
        assert connection.execute("SELECT * FROM execution_attempts").fetchall() == []
        assert (
            connection.execute(
                "SELECT count(*) FROM notification_outbox WHERE kind = 'mcp_approved'"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.asyncio
async def test_failed_proofs_escalate_to_shared_lockout_without_state_change(
    machine: ApprovalStateMachine,
) -> None:
    machine.enqueue(enqueue_request("req_Lockout"))
    verifier = RateLimitedFakeTotpVerifier()
    summaries = FakeSummaries()
    tools = GatewayTools(
        state_machine=machine,
        totp_verifier=verifier,
        summaries=summaries,
        access_requests=FakeAccessRequests(summaries),
        clock=lambda: NOW + 10,
    )
    arguments = {
        "request_id": "req_Lockout",
        "totp_code": FAKE_SCHEMA_PROOF,
        "expected_version_hash": digest("body-one")[:12],
    }

    first = await tools.call_tool("approve_request", arguments, principal=own_principal())
    second = await tools.call_tool("approve_request", arguments, principal=own_principal())
    locked = await tools.call_tool("approve_request", arguments, principal=own_principal())

    assert [error_code(item) for item in (first, second, locked)] == [
        "totp_invalid",
        "totp_invalid",
        "totp_locked",
    ]
    assert locked["structuredContent"]["error"]["details"] == {"retry_after": 60}
    assert machine.get_request("req_Lockout")["state"] == "pending_approval"
    with machine.database.read() as connection:
        assert connection.execute("SELECT * FROM confirmation_consumptions").fetchall() == []
        assert connection.execute("SELECT * FROM execution_attempts").fetchall() == []


@pytest.mark.asyncio
async def test_cancel_is_scoped_and_audited_without_totp(machine: ApprovalStateMachine) -> None:
    harness = make_harness(
        machine,
        totp=FakeTotpVerifier(error=TotpNotEnrolled("fake:not-enrolled")),
    )
    machine.enqueue(enqueue_request("req_Cancel"))

    result = structured(
        await harness.tools.call_tool(
            "cancel_request",
            {"request_id": "req_Cancel"},
            principal=own_principal(),
        )
    )

    assert result == {"status": "cancelled", "request_id": "req_Cancel"}
    assert harness.totp.calls == []
    assert machine.get_request("req_Cancel")["state"] == "cancelled"
    assert machine.list_events("req_Cancel")[-1]["actor"] == "mcp:profile:one"


@pytest.mark.asyncio
async def test_access_request_is_gateway_internal_web_only_and_needs_no_totp(
    machine: ApprovalStateMachine,
) -> None:
    harness = make_harness(
        machine,
        totp=FakeTotpVerifier(error=TotpNotEnrolled("fake:not-enrolled")),
    )

    result = structured(
        await harness.tools.call_tool(
            "request_tool_access",
            {
                "alias": "fastmail",
                "tool": "search_mail",
                "reason": "Need reviewed read access",
            },
            principal=own_principal(),
        )
    )

    assert result == {
        "status": "pending_approval",
        "request_id": "req_Access1",
        "expires_at": "2027-01-15T08:15:10Z",
        "message": "Tool access was requested and is waiting for web approval.",
        "approval_channel": "web_only",
    }
    assert harness.totp.calls == []
    assert harness.access_requests.drafts == [
        AccessRequestDraft(
            origin_namespace="profile:one",
            alias="fastmail",
            tool="search_mail",
            reason="Need reviewed read access",
            actor="mcp:profile:one",
            created_at=NOW + 10,
        )
    ]
    stored = machine.get_request("req_Access1")
    assert stored["origin_namespace"] == "profile:one"
    assert stored["gateway_internal"] == 1
    assert stored["state"] == "pending_approval"

    refusal = await harness.tools.call_tool(
        "approve_request",
        {
            "request_id": "req_Access1",
            "totp_code": FAKE_SCHEMA_PROOF,
            "expected_version_hash": str(stored["current_payload_hash"])[:12],
        },
        principal=own_principal(),
    )
    assert error_code(refusal) == "web_only"
    assert harness.totp.calls == []
    assert machine.get_request("req_Access1")["state"] == "pending_approval"


@pytest.mark.asyncio
async def test_malformed_arguments_and_unknown_tools_are_protocol_errors(
    machine: ApprovalStateMachine,
) -> None:
    harness = make_harness(machine)

    with pytest.raises(McpError):
        await harness.tools.call_tool(
            "approve_request",
            {
                "request_id": "req_Bad",
                "totp_code": "fake:not-a-code",
                "expected_version_hash": digest("body-one")[:12],
            },
            principal=own_principal(),
        )
    with pytest.raises(McpError):
        await harness.tools.call_tool("unknown_tool", {}, principal=own_principal())


@pytest.mark.asyncio
async def test_gateway_surface_round_trips_exact_tools_and_error_channels(
    machine: ApprovalStateMachine,
) -> None:
    harness = make_harness(machine)
    surface = GatewayToolSurface(tools=harness.tools, principal_provider=own_principal)

    async with create_connected_server_and_client_session(surface.server) as client:
        listed = await client.list_tools()
        assert [raw_model(tool) for tool in listed.tools] == GATEWAY_TOOL_DEFINITIONS

        missing = await client.call_tool("check_approval_status", {"request_id": "req_Unknown"})
        assert missing.isError is True
        assert missing.structuredContent["error"]["code"] == "request_not_found"

        with pytest.raises(McpError) as malformed:
            await client.call_tool("check_approval_status", {"request_id": "invalid"})
        assert malformed.value.error.code == types.INVALID_PARAMS
