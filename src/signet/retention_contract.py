"""Shared durable identifiers for the fake-only unknown-content purge path."""

from __future__ import annotations

import hashlib
import json

FAKE_UNKNOWN_PURGE_AUTHORIZED_ACTION = "fake_only_unknown_content_purge_authorized"
FAKE_UNKNOWN_PURGE_AUTHORIZED_DETAILS = (
    '{"acknowledged_possible_external_effect":true,"fake_only":true}'
)
FAKE_UNKNOWN_PURGE_COMPLETED_ACTION = "fake_only_unknown_content_purge_completed"

_PURGE_INTENTS = frozenset({"attachments", "sensitive_rows", "encryption_key"})


def fake_unknown_purge_job_key(
    *,
    request_id: str,
    version: int,
    payload_hash: str,
    intent: str,
) -> str:
    """Return the exact idempotency identity for one fake-only purge job."""

    if intent not in _PURGE_INTENTS:
        raise ValueError("fake-only purge intent is invalid")
    identity = json.dumps(
        [request_id, version, payload_hash],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"fake_unknown:{intent}:{digest}"
