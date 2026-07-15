from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from signet.canonical import CanonicalizationError, canonical_json, payload_fingerprint
from signet.policy import PolicyError, PolicyMode, load_policy, parse_policy
from signet.staging import StagingError, StagingStore


def test_canonical_json_preserves_exact_strings_and_null_vs_omitted() -> None:
    composed = "\u00e9"
    decomposed = "e\u0301"
    first = canonical_json({"body": "line 1\r\n line 2 ", "value": None, "u": composed})
    second = canonical_json({"body": "line 1\n line 2 ", "u": decomposed})
    assert first != second
    assert b'"value":null' in first
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1: "bad"}, b"bytes"])
def test_canonical_json_rejects_non_json_values(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json(value)


def test_payload_fingerprint_binds_every_execution_dimension() -> None:
    base = dict(
        alias="fastmail",
        tool="send_email",
        arguments={"to": ["a@example.test"], "body": "hello"},
        staged_file_hashes=("a" * 64,),
        policy_version=1,
        adapter_version="1",
    )
    frozen, fingerprint = payload_fingerprint(**base)
    assert fingerprint == hashlib.sha256(frozen).hexdigest()
    for key, replacement in {
        "alias": "other",
        "tool": "other",
        "arguments": {"to": ["b@example.test"], "body": "hello"},
        "staged_file_hashes": ("b" * 64,),
        "policy_version": 2,
        "adapter_version": "2",
    }.items():
        changed = dict(base)
        changed[key] = replacement
        assert payload_fingerprint(**changed)[1] != fingerprint


def _policy() -> dict:
    return {
        "version": 1,
        "default_mode": "deny",
        "downstreams": {
            "mail": {
                "transport": "http",
                "url": "https://example.test/mcp",
                "tools": {
                    "search": {"mode": "passthrough", "reviewed_read_only": True},
                    "send": {
                        "mode": "approval",
                        "adapter": "mail.send",
                        "communication_send": True,
                    },
                    "remove": {"mode": "deny"},
                },
            }
        },
    }


def test_policy_is_exact_and_unknown_is_unlisted_deny() -> None:
    policy = parse_policy(_policy())
    assert policy.resolve("mail", "search") is PolicyMode.PASSTHROUGH
    assert policy.resolve("mail", "remove") is PolicyMode.DENY
    assert policy.is_listed("mail", "remove")
    assert policy.resolve("mail", "unknown") is PolicyMode.DENY
    assert not policy.is_listed("mail", "unknown")
    assert policy.resolve("unknown", "search") is PolicyMode.DENY


def test_checked_in_policy_is_accepted_by_the_runtime_parser() -> None:
    policy = load_policy(Path(__file__).parents[1] / "spec" / "policy-v1.yaml")
    assert policy.resolve("fastmail", "send_email") is PolicyMode.APPROVAL
    assert policy.resolve("whatsapp", "send_text") is PolicyMode.APPROVAL


def test_policy_never_trusts_annotations_or_wildcards() -> None:
    policy = _policy()
    policy["downstreams"]["mail"]["tools"]["unsafe"] = {
        "mode": "passthrough",
        "annotations": {"readOnlyHint": True},
    }
    with pytest.raises(PolicyError, match="reviewed read-only"):
        parse_policy(policy)
    policy = _policy()
    policy["downstreams"]["mail"]["tools"]["*"] = {"mode": "deny"}
    with pytest.raises(PolicyError, match="wildcards"):
        parse_policy(policy)


def test_communication_send_cannot_be_passthrough() -> None:
    policy = _policy()
    policy["downstreams"]["mail"]["tools"]["send"] = {
        "mode": "passthrough",
        "reviewed_read_only": True,
        "communication_send": True,
    }
    with pytest.raises(PolicyError, match="passthrough"):
        parse_policy(policy)


def test_staging_is_private_scoped_and_integrity_checked(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "note.txt"
    source.write_bytes(b"private body")
    store = StagingStore(
        tmp_path / "staging",
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    record = store.stage_path(
        source,
        adapter="fastmail",
        account="primary",
        filename="note.txt",
        declared_mime="text/plain",
    )
    assert stat_mode(record.path) == 0o600
    assert store.resolve(record.opaque_id, adapter="fastmail", account="primary") == record
    with pytest.raises(StagingError, match="not found"):
        store.resolve(record.opaque_id, adapter="fastmail", account="other")
    record.path.write_bytes(b"changed")
    with pytest.raises(StagingError, match="integrity"):
        store.resolve(record.opaque_id, adapter="fastmail", account="primary")


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777


def test_staging_rejects_links_traversal_and_outside_roots(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "data.bin"
    source.write_bytes(b"data")
    store = StagingStore(
        tmp_path / "staging",
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    with pytest.raises(StagingError, match="path"):
        store.stage_path(
            source,
            adapter="a",
            account="b",
            filename="../escape",
            declared_mime="application/octet-stream",
        )
    symlink = source_root / "link"
    symlink.symlink_to(source)
    with pytest.raises((StagingError, OSError)):
        store.stage_path(
            symlink,
            adapter="a",
            account="b",
            filename="link",
            declared_mime="application/octet-stream",
        )
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    with pytest.raises(StagingError, match="outside"):
        store.stage_path(
            outside,
            adapter="a",
            account="b",
            filename="outside",
            declared_mime="application/octet-stream",
        )
