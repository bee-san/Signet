from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from signet.extension_worker import ExtensionWorker, StaticWorkerCommandResolver
from signet.mcp_mirror import validate_lossless_tool
from signet.plugin_manifest import (
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    MAX_MANIFEST_BYTES,
    REFERENCE_PLUGIN_IDS,
    MutationEffect,
    PluginManifestError,
    load_plugin_manifest,
    load_reference_discovery_fixture,
    load_reference_plugin,
    parse_plugin_manifest,
)


def manifest_document(name: str = "fastmail") -> dict[str, Any]:
    loaded = load_reference_plugin(name)
    return json.loads(loaded.canonical_bytes)


def encoded(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def test_canonical_manifest_digest_is_stable_and_file_pin_is_required(tmp_path: Path) -> None:
    raw = manifest_document()
    reordered = dict(reversed(tuple(raw.items())))
    first = parse_plugin_manifest(json.dumps(raw, indent=2).encode())
    second = parse_plugin_manifest(json.dumps(reordered, separators=(",", ":")).encode())

    assert first.canonical_bytes == second.canonical_bytes
    assert first.sha256 == second.sha256
    assert first.canonical_bytes == encoded(json.loads(first.canonical_bytes, parse_int=int))

    path = tmp_path / "manifest.json"
    path.write_bytes(json.dumps(reordered, indent=4).encode())
    assert load_plugin_manifest(path, expected_sha256=first.sha256) == first
    with pytest.raises(PluginManifestError, match="does not match"):
        load_plugin_manifest(path, expected_sha256="0" * 64)
    with pytest.raises(PluginManifestError, match="lowercase SHA-256"):
        load_plugin_manifest(path, expected_sha256="A" * 64)


def test_models_are_strict_frozen_and_preserve_independent_effect_axes() -> None:
    loaded = load_reference_plugin("fastmail")
    sending = next(
        mapping for mapping in loaded.manifest.tool_mappings if mapping.tool_name == "send_email"
    )
    assert sending.proposed_effects.mutation is MutationEffect.ADDITIVE
    assert sending.proposed_effects.external_communication is True
    assert sending.proposed_effects.code_execution is False
    assert sending.proposed_effects.privilege_change is False
    assert sending.proposed_effects.open_world is True
    assert sending.proposed_effects.idempotent == "unknown"
    with pytest.raises(ValidationError):
        loaded.manifest.plugin_id = "replacement"  # type: ignore[misc]

    raw = manifest_document()
    raw["connectors"][0]["requires_mcp_shim"] = 0
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))
    raw = manifest_document()
    raw["tool_mappings"][0]["proposed_effects"]["idempotent"] = "true"
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))


@pytest.mark.parametrize(
    "document",
    [
        b'{"plugin_manifest_version":1,"plugin_id":"one","plugin_id":"two"}',
        (b'{"plugin_manifest_version":1,"plugin_id":"one","nested":{"value":1,"value":2}}'),
    ],
)
def test_duplicate_json_keys_are_rejected_at_every_depth(document: bytes) -> None:
    with pytest.raises(PluginManifestError, match="duplicate JSON key"):
        parse_plugin_manifest(document)


def test_unknown_fields_unsupported_versions_and_non_json_numbers_are_rejected() -> None:
    raw = manifest_document()
    raw["unexpected"] = "not allowed"
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))

    raw = manifest_document()
    raw["plugin_manifest_version"] = 2
    with pytest.raises(PluginManifestError, match="unsupported"):
        parse_plugin_manifest(encoded(raw))
    raw["plugin_manifest_version"] = True
    with pytest.raises(PluginManifestError, match="unsupported"):
        parse_plugin_manifest(encoded(raw))

    with pytest.raises(PluginManifestError, match="strict UTF-8 JSON"):
        parse_plugin_manifest(b'{"plugin_manifest_version":1,"value":NaN}')
    raw = manifest_document()
    raw["plugin_version"] = 1.0
    with pytest.raises(PluginManifestError, match="unsupported number"):
        parse_plugin_manifest(encoded(raw))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tool_name", "send_*"),
        ("tool_name", "../send"),
        ("action_id", "fastmail.*"),
        ("connector_id", "Fastmail"),
    ],
)
def test_mapping_identifiers_are_exact_without_wildcards(field: str, value: str) -> None:
    raw = manifest_document()
    raw["tool_mappings"][0][field] = value
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/payload/*",
        "/payload/../secret",
        "/payload[$.secret]",
        "/payload/~2escape",
        "/payload//empty",
        "$.payload.secret",
    ],
)
def test_json_paths_reject_wildcards_traversal_and_ambiguous_syntax(path: str) -> None:
    raw = manifest_document()
    raw["tool_mappings"][0]["sensitive_json_paths"] = [path]
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))


def test_json_pointer_escapes_are_exact_and_safe_results_cannot_name_credentials() -> None:
    raw = manifest_document()
    raw["tool_mappings"][0]["sensitive_json_paths"] = ["/headers/x~1account", "/value/~0tag"]
    loaded = parse_plugin_manifest(encoded(raw))
    assert loaded.manifest.tool_mappings[0].sensitive_json_paths == (
        "/headers/x~1account",
        "/value/~0tag",
    )

    raw["tool_mappings"][0]["safe_result_fields"] = ["/access_token"]
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))


@pytest.mark.parametrize(
    "description",
    [
        "authorization: Bearer abcdefghijklmnop",
        "api_key=abcdefghijklmnop",
        "https://operator:credential@example.test/mcp",
        "-----BEGIN PRIVATE KEY-----",
        "token=ghp-abcdefghijklmnop",
    ],
)
def test_embedded_credential_like_values_are_rejected(description: str) -> None:
    raw = manifest_document()
    raw["description"] = description
    with pytest.raises(PluginManifestError, match="credential-like"):
        parse_plugin_manifest(encoded(raw))


def test_duplicate_and_unresolved_manifest_identities_are_rejected() -> None:
    raw = manifest_document()
    raw["connectors"].append(dict(raw["connectors"][0]))
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))

    raw = manifest_document()
    raw["tool_mappings"].append(dict(raw["tool_mappings"][0]))
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))

    raw = manifest_document()
    raw["tool_mappings"][1]["action_id"] = raw["tool_mappings"][0]["action_id"]
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))

    raw = manifest_document()
    raw["tool_mappings"][0]["sensitive_json_paths"] = ["/query", "/query"]
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))

    raw = manifest_document()
    raw["tool_mappings"][0]["connector_id"] = "missing"
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))


def test_worker_metadata_allows_only_pinned_opaque_protocol_fields() -> None:
    raw = manifest_document()
    raw["worker"] = {
        "command_ref": "reviewed-fastmail-worker",
        "executable_sha256": "a" * 64,
        "protocol_version": 1,
        "operations": ["identity", "redact", "review_summary"],
    }
    worker = parse_plugin_manifest(encoded(raw)).manifest.worker
    assert worker is not None
    assert worker.command_ref == "reviewed-fastmail-worker"
    assert worker.operations == (
        "identity",
        "redact",
        "review_summary",
    )
    runtime = ExtensionWorker(worker, StaticWorkerCommandResolver(()))
    assert "operations=3" in repr(runtime)

    raw["worker"]["executable_path"] = "/tmp/unreviewed.py"
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))
    del raw["worker"]["executable_path"]
    raw["worker"]["command_ref"] = "/tmp/unreviewed.py"
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))
    raw["worker"]["command_ref"] = "reviewed-fastmail-worker"
    raw["worker"]["operations"] = ["redact", "redact"]
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))
    raw["worker"]["operations"] = ["tools_call"]
    with pytest.raises(PluginManifestError, match="schema"):
        parse_plugin_manifest(encoded(raw))


def test_manifest_reader_rejects_symlinks_hardlinks_directories_and_oversize(
    tmp_path: Path,
) -> None:
    validated = load_reference_plugin("fastmail")
    original = tmp_path / "manifest.json"
    original.write_bytes(validated.canonical_bytes)
    symlink = tmp_path / "linked.json"
    symlink.symlink_to(original)
    with pytest.raises(PluginManifestError, match="safe local file"):
        load_plugin_manifest(symlink, expected_sha256=validated.sha256)

    hardlink = tmp_path / "hardlinked.json"
    os.link(original, hardlink)
    with pytest.raises(PluginManifestError, match="bounded regular"):
        load_plugin_manifest(original, expected_sha256=validated.sha256)
    hardlink.unlink()

    with pytest.raises(PluginManifestError, match="bounded regular"):
        load_plugin_manifest(tmp_path, expected_sha256=validated.sha256)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_MANIFEST_BYTES + 1))
    with pytest.raises(PluginManifestError, match="bounded regular"):
        load_plugin_manifest(oversized, expected_sha256=validated.sha256)


def test_manifest_parser_enforces_depth_node_and_byte_limits() -> None:
    deep = b"[" * (MAX_JSON_DEPTH + 2) + b"0" + b"]" * (MAX_JSON_DEPTH + 2)
    with pytest.raises(PluginManifestError, match="structural"):
        parse_plugin_manifest(deep)

    many_nodes = {
        "plugin_manifest_version": 1,
        "nodes": [0] * (MAX_JSON_NODES + 1),
    }
    with pytest.raises(PluginManifestError, match="structural"):
        parse_plugin_manifest(encoded(many_nodes))

    with pytest.raises(PluginManifestError, match="byte limit"):
        parse_plugin_manifest(b" " * (MAX_MANIFEST_BYTES + 1))


def test_reference_plugins_and_fake_discovery_fixtures_are_exact_and_inert() -> None:
    for name in REFERENCE_PLUGIN_IDS:
        loaded = load_reference_plugin(name)
        fixture = load_reference_discovery_fixture(name)
        assert set(fixture) == {"tools"}
        tools = fixture["tools"]
        assert isinstance(tools, list) and tools
        exact = [validate_lossless_tool(tool) for tool in tools]
        discovered_names = {tool["name"] for tool in exact}
        mapped_names = {mapping.tool_name for mapping in loaded.manifest.tool_mappings}
        assert discovered_names == mapped_names
        assert b"credential" not in loaded.canonical_bytes.lower()

    fastmail = load_reference_plugin("fastmail").manifest
    deletion = next(item for item in fastmail.tool_mappings if item.tool_name == "delete_email")
    assert deletion.proposed_effects.mutation is MutationEffect.DESTRUCTIVE
    assert deletion.adapter_requirement == "provider_specific"

    telegram = load_reference_plugin("telegram").manifest
    privileged = {"invite_member", "remove_member", "promote_member"}
    assert all(
        item.proposed_effects.privilege_change is True
        for item in telegram.tool_mappings
        if item.tool_name in privileged
    )

    whatsapp = load_reference_plugin("whatsapp").manifest
    assert whatsapp.connectors[0].requires_mcp_shim is True
    assert whatsapp.connectors[0].transports == ("stdio",)
    assert all(
        item.proposed_effects.external_communication is True
        and item.proposed_effects.mutation is MutationEffect.ADDITIVE
        for item in whatsapp.tool_mappings
    )


def test_unknown_reference_plugin_fails_without_path_traversal() -> None:
    for value in ("../fastmail", "Fastmail", "missing", "fastmail/manifest.json"):
        with pytest.raises(PluginManifestError, match="unknown reference"):
            load_reference_plugin(value)
