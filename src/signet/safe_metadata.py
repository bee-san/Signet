"""Privacy-safe projection of reviewed downstream result metadata."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from signet.canonical import canonical_json

PROVIDER_IDENTIFIER_FIELDS = frozenset(
    {"provider_id", "message_id", "submission_id", "thread_id", "chat_message_id"}
)


def public_safe_metadata(value: Mapping[str, Any]) -> dict[str, Any]:
    """Replace provider-controlled identifiers with non-steerable references."""

    projected = dict(value)
    for field in PROVIDER_IDENTIFIER_FIELDS:
        identifier = projected.get(field)
        if field not in projected or identifier is None:
            continue
        material = canonical_json(
            {
                "domain": "signet/public-provider-reference/v1",
                "field": field,
                "value": identifier,
            }
        )
        projected[field] = f"sgref_{hashlib.sha256(material).hexdigest()[:32]}"
    return projected
