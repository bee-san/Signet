"""Bounded, non-sensitive reasons for durable human decisions."""

from __future__ import annotations

from types import MappingProxyType
from typing import Literal

type DecisionAction = Literal["approve", "deny"]

APPROVAL_REASON_LABELS = MappingProxyType(
    {
        "exact_request_approved": "Exact content, destination, and scope reviewed and approved",
        "expected_and_authorized": "Expected request and within the reviewer's authority",
        "mcp_chat_confirmation": "Approved through the bound MCP chat confirmation",
        "authenticated_exact_review": "Approved after authenticated exact-request review",
    }
)
DENIAL_REASON_LABELS = MappingProxyType(
    {
        "wrong_destination": "Recipient or destination is incorrect",
        "unexpected_content_or_scope": "Content or scope is not what was expected",
        "duplicate_request": "Request appears to duplicate another action",
        "unsafe_or_disallowed": "Request is unsafe or disallowed by policy",
        "insufficient_authority": "Reviewer is not authorized to approve this request",
        "request_no_longer_needed": "Request is no longer needed",
        "authenticated_denial": "Denied by an authenticated human reviewer",
    }
)
RETAINED_REASON_LABELS = MappingProxyType(
    {
        "legacy_unstructured_reason": (
            "Legacy decision reason unavailable after the structured-reason privacy upgrade"
        ),
    }
)
DECISION_REASON_LABELS = MappingProxyType(
    {**APPROVAL_REASON_LABELS, **DENIAL_REASON_LABELS, **RETAINED_REASON_LABELS}
)

MAX_DECISION_NOTE_CHARS = max(map(len, DECISION_REASON_LABELS))
MAX_DECISION_NOTE_BYTES = MAX_DECISION_NOTE_CHARS


def normalize_decision_note(value: str | None) -> str | None:
    """Return an exact known reason code; arbitrary audit text is forbidden."""

    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("decision reason must be a known reason code")
    if value not in DECISION_REASON_LABELS:
        raise ValueError("decision reason must be a known reason code")
    return value


def reason_for_action(
    action: DecisionAction,
    value: str | None,
    *,
    confirmation_path: str | None = None,
) -> str:
    """Validate an action-specific reason, supplying truthful protocol defaults."""

    normalized = normalize_decision_note(value)
    if normalized is None:
        if action == "approve":
            normalized = (
                "mcp_chat_confirmation"
                if confirmation_path == "mcp"
                else "authenticated_exact_review"
            )
        else:
            normalized = "authenticated_denial"
    allowed = APPROVAL_REASON_LABELS if action == "approve" else DENIAL_REASON_LABELS
    if normalized not in allowed:
        raise ValueError("decision reason does not match the selected action")
    return normalized


def decision_reason_label(value: str) -> str:
    """Return the stable display label for a validated durable reason code."""

    try:
        return DECISION_REASON_LABELS[value]
    except (KeyError, TypeError):
        raise ValueError("decision reason is unavailable") from None
