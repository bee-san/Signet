"""Exact-value canonical JSON and payload fingerprints.

Display normalization belongs in adapters.  This module deliberately preserves
every executable string byte-for-byte (after UTF-8 encoding), including line
endings, whitespace, and Unicode normalization form.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented as deterministic JSON."""


def _validate_json(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError(f"{path}: non-finite numbers are forbidden")
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: object keys must be strings")
            _validate_json(child, f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _validate_json(child, f"{path}[{index}]")
        return
    raise CanonicalizationError(f"{path}: unsupported JSON value {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return a stable UTF-8 JSON representation without changing values."""

    _validate_json(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_text(value: Any) -> str:
    return canonical_json(value).decode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_fingerprint(
    *,
    alias: str,
    tool: str,
    account_ref: str | None,
    credential_identity_digest: str | None,
    schema_digest: str,
    caller_namespace: str,
    arguments: Mapping[str, Any],
    staged_file_hashes: Sequence[str] = (),
    policy_version: int,
    adapter_id: str,
    adapter_version: str,
) -> tuple[bytes, str]:
    """Freeze an executable call and return its canonical bytes and SHA-256."""

    envelope = {
        "account_ref": account_ref,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "alias": alias,
        "arguments": dict(arguments),
        "caller_namespace": caller_namespace,
        "credential_identity_digest": credential_identity_digest,
        "policy_version": policy_version,
        "schema_digest": schema_digest,
        "staged_file_hashes": list(staged_file_hashes),
        "tool": tool,
    }
    frozen = canonical_json(envelope)
    return frozen, sha256_hex(frozen)


def version_hash_prefix(payload_hash: str, length: int = 12) -> str:
    if length < 8 or length > 64:
        raise ValueError("version hash prefix length must be between 8 and 64")
    if len(payload_hash) != 64 or any(ch not in "0123456789abcdef" for ch in payload_hash):
        raise ValueError("payload hash must be a lowercase SHA-256 hex digest")
    return payload_hash[:length]
