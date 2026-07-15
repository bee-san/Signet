"""Validation shared by web decision capture and durable event persistence."""

from __future__ import annotations

import unicodedata

MAX_DECISION_NOTE_CHARS = 1_000
MAX_DECISION_NOTE_BYTES = 4_000


def normalize_decision_note(value: str | None) -> str | None:
    """Return a canonical optional note, rejecting unsafe or oversized text."""

    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("decision rationale must be text")
    if len(value) > MAX_DECISION_NOTE_CHARS or len(value.encode("utf-8")) > MAX_DECISION_NOTE_BYTES:
        raise ValueError("decision rationale is too long")
    normalized = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized:
        return None
    if (
        len(normalized) > MAX_DECISION_NOTE_CHARS
        or len(normalized.encode("utf-8")) > MAX_DECISION_NOTE_BYTES
    ):
        raise ValueError("decision rationale is too long")
    if any(
        character != "\n" and unicodedata.category(character).startswith("C")
        for character in normalized
    ):
        raise ValueError("decision rationale contains unsupported control characters")
    return normalized
