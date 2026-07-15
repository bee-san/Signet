from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable
from pathlib import Path
from threading import Event, Thread
from typing import Any

import pytest
import yaml

from signet.canonical import CanonicalizationError, canonical_json, payload_fingerprint
from signet.models import AttachmentReference, EnqueueRequest, InvalidTransition
from signet.policy import PolicyError, PolicyMode, load_policy, parse_policy
from signet.staging import StagingError
from signet.state_machine import ApprovalStateMachine
from tests.attachment_fixtures import attachment_cipher, staging_store


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
    assert policy.policy_changes is not None
    assert policy.policy_changes.approval_channel == "web_only"
    assert set(policy.mode_contracts) == set(PolicyMode)
    fastmail = policy.downstreams["fastmail"]
    assert fastmail.schema_review is not None
    assert fastmail.schema_review.fail_closed_on_digest_change
    assert fastmail.account_ref == "configured-account"
    assert fastmail.tools["upload_attachment"].account_ref == "configured-account"
    assert fastmail.tools["delete_email"].reviewed_classification == "destructive"
    wrapper = policy.downstreams["whatsapp"].wrapper_contract
    assert wrapper is not None
    assert wrapper.contract_id == "signet.wacli.send-text.v1"
    assert wrapper.shell_interpolation == "forbidden"


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda document: document["mode_contracts"]["approval"].update(
                {"downstream_calls_before_approval": 1}
            ),
            "runtime contract",
        ),
        (
            lambda document: document["downstreams"]["fastmail"]["schema_review"].update(
                {"fail_closed_on_digest_change": False}
            ),
            "must be true",
        ),
        (
            lambda document: document["downstreams"]["whatsapp"]["wrapper_contract"].update(
                {"shell_interpolation": "allowed"}
            ),
            "must be forbidden",
        ),
        (
            lambda document: document["policy_changes"].update(
                {"communication_sends_may_be_passthrough": True}
            ),
            "enforced promotion contract",
        ),
    ],
)
def test_security_contract_fields_cannot_be_silently_weakened(
    mutator: Callable[[dict[str, Any]], None],
    message: str,
) -> None:
    document = yaml.safe_load(
        (Path(__file__).parents[1] / "spec" / "policy-v1.yaml").read_text(encoding="utf-8")
    )
    mutator(document)
    with pytest.raises(PolicyError, match=message):
        parse_policy(document)


def test_policy_never_trusts_annotations_or_wildcards() -> None:
    policy = _policy()
    policy["downstreams"]["mail"]["tools"]["unsafe"] = {
        "mode": "passthrough",
        "annotations": {"readOnlyHint": True},
    }
    with pytest.raises(PolicyError, match="unknown fields"):
        parse_policy(policy)
    policy = _policy()
    policy["downstreams"]["mail"]["tools"]["*"] = {"mode": "deny"}
    with pytest.raises(PolicyError, match="wildcards"):
        parse_policy(policy)


def test_policy_rejects_unknown_or_mistyped_security_fields() -> None:
    policy = _policy()
    policy["downstreams"]["mail"]["tools"]["search"]["reviewed_readonly"] = True
    with pytest.raises(PolicyError, match="unknown fields"):
        parse_policy(policy)

    policy = _policy()
    policy["downstreams"]["mail"]["tools"]["search"]["schema_digest"] = "A" * 64
    with pytest.raises(PolicyError, match="lowercase SHA-256"):
        parse_policy(policy)

    policy = _policy()
    policy["downstreams"]["mail"]["tools"]["send"]["adapter"] = {"name": "mail.send"}
    with pytest.raises(PolicyError, match="non-empty"):
        parse_policy(policy)

    policy = _policy()
    policy["downstreams"]["mail"]["url"] = "http://provider.example.test/mcp"
    with pytest.raises(PolicyError, match="HTTPS"):
        parse_policy(policy)

    policy = _policy()
    policy["downstreams"]["mail"]["credential_ref"] = "plaintext-secret"
    with pytest.raises(PolicyError, match="keychain"):
        parse_policy(policy)

    policy = _policy()
    policy["downstreams"]["mail"]["tools"]["search"]["limits"] = {"queue": 10}
    with pytest.raises(PolicyError, match="unsupported keys"):
        parse_policy(policy)

    policy = _policy()
    policy["downstreams"]["mail"]["tools"]["search"]["limits"] = {
        "payload_bytes": 16 * 1024 * 1024 + 1
    }
    with pytest.raises(PolicyError, match="safe maximum"):
        parse_policy(policy)


def test_policy_retains_only_supported_enforceable_tool_limits() -> None:
    policy = _policy()
    policy["downstreams"]["mail"]["tools"]["send"]["limits"] = {
        "payload_bytes": 1_024,
        "pending_requests": 3,
        "requests_per_minute": 5,
    }
    parsed = parse_policy(policy)
    assert parsed.downstreams["mail"].tools["send"].limits == {
        "payload_bytes": 1_024,
        "pending_requests": 3,
        "requests_per_minute": 5,
    }


@pytest.mark.parametrize(
    "document",
    [
        "version: 1\nversion: 2\ndefault_mode: deny\ndownstreams: {}\n",
        (
            "version: 1\ndefault_mode: deny\ndownstreams:\n"
            "  mail:\n"
            "    transport: http\n"
            "    url: https://provider.example.test/mcp\n"
            "    tools:\n"
            "      search:\n"
            "        mode: deny\n"
            "        mode: passthrough\n"
            "        reviewed_read_only: true\n"
        ),
    ],
)
def test_policy_yaml_rejects_duplicate_mapping_keys(tmp_path: Path, document: str) -> None:
    path = tmp_path / "duplicate-policy.yaml"
    path.write_text(document, encoding="utf-8")

    with pytest.raises(PolicyError, match="invalid YAML"):
        load_policy(path)


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
    store = staging_store(
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
    envelope = record.path.read_bytes()
    assert b"private body" not in envelope
    assert hashlib.sha256(envelope).hexdigest() == record.envelope_sha256
    with store.database.read() as connection:
        catalog = connection.execute(
            "SELECT * FROM staged_objects WHERE attachment_id = ?",
            (record.opaque_id,),
        ).fetchone()
    assert catalog["storage_path"] == str(record.path)
    assert catalog["encryption_key_ref"] == record.encryption_key_ref
    assert "note.txt" not in repr(record)
    assert record.encryption_key_ref not in repr(record)
    with store.plaintext_descriptor(
        record.opaque_id,
        adapter="fastmail",
        account="primary",
        expected_size=record.size,
        expected_sha256=record.sha256,
    ) as (_, descriptor):
        assert os.fstat(descriptor).st_nlink == 0
        assert os.read(descriptor, record.size) == b"private body"
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
    store = staging_store(
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


def test_staged_catalog_and_verified_bytes_survive_store_restart(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "durable.bin"
    source.write_bytes(b"durable before enqueue")
    staging_root = tmp_path / "staging"
    first = staging_store(
        staging_root,
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    record = first.stage_path(
        source,
        adapter="fastmail",
        account="primary",
        filename="durable.bin",
        declared_mime="application/octet-stream",
    )

    restarted = staging_store(
        staging_root,
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    resolved, content = restarted.read_verified(
        record.opaque_id,
        adapter="fastmail",
        account="primary",
    )

    assert resolved == record
    assert content == b"durable before enqueue"


def test_staging_capacity_comes_from_durable_files_not_process_memory(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    first_source = source_root / "first.bin"
    second_source = source_root / "second.bin"
    first_source.write_bytes(b"1234")
    second_source.write_bytes(b"5678")
    staging_root = tmp_path / "staging"
    one_envelope_plus_headroom = attachment_cipher().envelope_size(4) + 3
    first = staging_store(
        staging_root,
        allowed_source_roots=(source_root,),
        max_total_bytes=one_envelope_plus_headroom,
        minimum_free_bytes=0,
    )
    first.stage_path(
        first_source,
        adapter="a",
        account="b",
        filename="first.bin",
        declared_mime="application/octet-stream",
    )

    restarted = staging_store(
        staging_root,
        allowed_source_roots=(source_root,),
        max_total_bytes=one_envelope_plus_headroom,
        minimum_free_bytes=0,
    )
    with pytest.raises(StagingError, match="total"):
        restarted.stage_path(
            second_source,
            adapter="a",
            account="b",
            filename="second.bin",
            declared_mime="application/octet-stream",
        )


def test_metadata_publish_failure_leaves_no_visible_staged_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "fixture.bin"
    source.write_bytes(b"fixture")
    staging_root = tmp_path / "staging"
    store = staging_store(
        staging_root,
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )

    def fail_publish(record: object) -> None:
        del record
        raise OSError("injected metadata fsync failure")

    monkeypatch.setattr(store, "_write_metadata", fail_publish)
    with pytest.raises(OSError, match="injected"):
        store.stage_path(
            source,
            adapter="a",
            account="b",
            filename="fixture.bin",
            declared_mime="application/octet-stream",
        )

    assert not [path for path in staging_root.iterdir() if path.name.startswith("stg_")]
    assert not list((staging_root / ".metadata").iterdir())


def test_orphan_sweep_preserves_catalogued_and_explicitly_protected_objects(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "kept.bin"
    source.write_bytes(b"kept")
    staging_root = tmp_path / "staging"
    store = staging_store(
        staging_root,
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    kept = store.stage_path(
        source,
        adapter="a",
        account="b",
        filename="kept.bin",
        declared_mime="application/octet-stream",
    )
    orphan_id = "stg_" + "o" * 20
    protected_id = "stg_" + "p" * 20
    temporary_id = "stg_" + "t" * 20
    orphan = staging_root / orphan_id
    protected = staging_root / protected_id
    temporary = staging_root / f".{temporary_id}.tmp"
    for path in (orphan, protected, temporary):
        path.write_bytes(b"unpublished")
        os.utime(path, (100, 100))

    removed = store.sweep_orphans(
        protected_ids={protected_id},
        minimum_age_seconds=10,
        now=1_000,
    )

    assert removed == 2
    assert not orphan.exists()
    assert not temporary.exists()
    assert protected.exists()
    assert kept.path.exists()
    assert store.resolve(kept.opaque_id, adapter="a", account="b") == kept


def test_unconsumed_purge_serializes_against_attachment_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "race.bin"
    source.write_bytes(b"purge versus enqueue")
    store = staging_store(
        tmp_path / "staging",
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )
    record = store.stage_path(
        source,
        adapter="fastmail",
        account="primary",
        filename="race.bin",
        declared_mime="application/octet-stream",
    )
    payload_hash = hashlib.sha256(b"frozen request").hexdigest()
    request = EnqueueRequest(
        request_id="purge-enqueue-race",
        downstream_alias="fastmail",
        tool_name="send_email",
        policy_mode="approval",
        origin_namespace="profile:test",
        encrypted_payload=b"encrypted:frozen request",
        payload_hash=payload_hash,
        payload_fingerprint=payload_hash,
        pending_result=b'{"status":"pending_approval"}',
        created_at=record.created_at,
        expires_at=record.created_at + 600,
        policy_version="1",
        adapter_version="1",
        schema_version="1",
        editor_actor="caller:test",
        canonical_size=len(b"frozen request"),
        encryption_key_ref="keychain://Signet/fake-payload",
        attachments=(
            AttachmentReference(
                attachment_id=record.opaque_id,
                filename=record.filename,
                mime_type=record.declared_mime,
                size_bytes=record.size,
                sha256=record.sha256,
                storage_path=str(record.path),
            ),
        ),
    )
    machine = ApprovalStateMachine(store.database)
    attempting = Event()
    outcomes: list[BaseException | None] = []

    def enqueue() -> None:
        attempting.set()
        try:
            machine.enqueue(request)
        except BaseException as exc:
            outcomes.append(exc)
        else:
            outcomes.append(None)

    original_unlink = os.unlink
    contender: Thread | None = None

    def racing_unlink(path: str, *args: Any, **kwargs: Any) -> None:
        nonlocal contender
        if path == record.opaque_id and contender is None:
            contender = Thread(target=enqueue, daemon=True)
            contender.start()
            assert attempting.wait(timeout=1)
            time.sleep(0.05)
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", racing_unlink)
    store.purge(record.opaque_id, adapter="fastmail", account="primary")
    assert contender is not None
    contender.join(timeout=2)

    assert not contender.is_alive()
    assert len(outcomes) == 1 and isinstance(outcomes[0], InvalidTransition)
    with store.database.read() as connection:
        catalog = connection.execute(
            """
            SELECT consumed_request_id, storage_path, purged_at
            FROM staged_objects WHERE attachment_id = ?
            """,
            (record.opaque_id,),
        ).fetchone()
        request_count = connection.execute(
            "SELECT count(*) FROM approval_requests WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()[0]
    assert tuple(catalog) == (None, None, catalog["purged_at"])
    assert catalog["purged_at"] is not None
    assert request_count == 0


def test_source_open_rejects_intermediate_symlinks_and_hardlinks(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "value.bin").write_bytes(b"outside")
    (source_root / "linked").symlink_to(outside, target_is_directory=True)
    original = source_root / "original.bin"
    original.write_bytes(b"hard linked")
    hardlink = source_root / "hardlink.bin"
    os.link(original, hardlink)
    store = staging_store(
        tmp_path / "staging",
        allowed_source_roots=(source_root,),
        minimum_free_bytes=0,
    )

    for unsafe in (source_root / "linked" / "value.bin", hardlink):
        with pytest.raises(StagingError, match="safely"):
            store.stage_path(
                unsafe,
                adapter="a",
                account="b",
                filename="value.bin",
                declared_mime="application/octet-stream",
            )
