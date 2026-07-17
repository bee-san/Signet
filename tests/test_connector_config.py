from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from signet.connector_config import (
    MAX_CONFIG_JSON_DEPTH,
    MAX_CONFIG_JSON_NODES,
    MAX_CONNECTOR_CONFIG_BYTES,
    ConnectorConfigError,
    ReviewedCommandResolver,
    detached_connector_document,
    load_connector_config,
    load_reviewed_command_document,
    parse_connector_config,
    parse_reviewed_command_document,
    validate_connector_template,
)
from signet.plugin_manifest import ConnectorTemplate, load_reference_plugin


def encoded(value: Any, *, pretty: bool = False) -> bytes:
    if pretty:
        return json.dumps(value, ensure_ascii=False, indent=2).encode()
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def http_config(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "connector_config_version": 1,
        "transport": "streamable_http",
        "credential_ref": "keychain://Signet/fastmail",
        "credential_identity_digest": "c" * 64,
        "url": "https://api.example.test/mcp",
        "timeout_seconds": 30,
        "output_limit_bytes": 1_048_576,
    }
    value.update(changes)
    return value


def stdio_config(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "connector_config_version": 1,
        "transport": "stdio",
        "credential_ref": "keychain://Signet/telegram",
        "credential_identity_digest": "d" * 64,
        "command_ref": "reviewed-telegram-mcp",
        "executable_sha256": "e" * 64,
        "timeout_seconds": 15,
        "output_limit_bytes": 2_000_000,
    }
    value.update(changes)
    return value


def template(name: str) -> ConnectorTemplate:
    return load_reference_plugin(name).manifest.connectors[0]


def command_document(root: Path, **changes: Any) -> dict[str, Any]:
    command: dict[str, Any] = {
        "command_ref": "reviewed-telegram-mcp",
        "executable": str(root / "bin" / "telegram-mcp"),
        "executable_sha256": "e" * 64,
        "cwd": str(root / "working"),
        "snapshot_root": str(root / "snapshots"),
        "args": ["--stdio", "--bounded-output"],
    }
    command.update(changes)
    return {
        "reviewed_command_document_version": 1,
        "commands": [command],
    }


def test_http_config_is_canonical_pinned_and_template_bound(tmp_path: Path) -> None:
    raw = http_config()
    reordered = dict(reversed(tuple(raw.items())))
    first = parse_connector_config(encoded(raw, pretty=True), template=template("fastmail"))
    second = parse_connector_config(encoded(reordered), template=template("fastmail"))
    assert first == second
    assert first.config.timeout_seconds == 30.0
    assert first.sha256 == "cc48f5d434337752c1f839813ed2c2d22ff3354da34556385abb681970bd432b"
    assert detached_connector_document(first) == json.loads(first.canonical_bytes)

    path = tmp_path / "connector.json"
    path.write_bytes(encoded(reordered, pretty=True))
    assert (
        load_connector_config(
            path,
            template=template("fastmail"),
            expected_sha256=first.sha256,
        )
        == first
    )
    with pytest.raises(ConnectorConfigError, match="does not match"):
        load_connector_config(path, expected_sha256="0" * 64)


def test_connector_model_is_strict_and_frozen() -> None:
    loaded = parse_connector_config(encoded(http_config()))
    with pytest.raises(ValidationError):
        loaded.config.transport = "stdio"  # type: ignore[misc]

    raw = http_config(output_limit_bytes=True)
    with pytest.raises(ConnectorConfigError, match="schema"):
        parse_connector_config(encoded(raw))
    raw = http_config(timeout_seconds="30")
    with pytest.raises(ConnectorConfigError, match="schema"):
        parse_connector_config(encoded(raw))


def test_template_allows_only_declared_transport() -> None:
    http = parse_connector_config(encoded(http_config()))
    assert validate_connector_template(http, template("fastmail")) is http.config
    with pytest.raises(ConnectorConfigError, match="not allowed"):
        validate_connector_template(http, template("whatsapp"))
    with pytest.raises(ConnectorConfigError, match="not allowed"):
        parse_connector_config(encoded(stdio_config()), template=template("fastmail"))


def test_stdio_requires_opaque_reference_and_exact_executable_digest() -> None:
    loaded = parse_connector_config(encoded(stdio_config()), template=template("telegram"))
    assert loaded.config.command_ref == "reviewed-telegram-mcp"
    assert loaded.config.executable_sha256 == "e" * 64
    for invalid in ("/usr/local/bin/server", "../server", "server *", "Server"):
        with pytest.raises(ConnectorConfigError, match="schema"):
            parse_connector_config(encoded(stdio_config(command_ref=invalid)))
    for invalid in ("E" * 64, "e" * 63, "not-a-digest"):
        with pytest.raises(ConnectorConfigError, match="schema"):
            parse_connector_config(encoded(stdio_config(executable_sha256=invalid)))
    with pytest.raises(ConnectorConfigError, match="schema"):
        parse_connector_config(encoded(stdio_config(url="https://example.test/mcp")))


@pytest.mark.parametrize(
    "changes",
    [
        {"url": None},
        {"command_ref": "reviewed-command"},
        {"executable_sha256": "a" * 64},
    ],
)
def test_http_and_stdio_fields_never_mix(changes: dict[str, Any]) -> None:
    with pytest.raises(ConnectorConfigError, match="schema"):
        parse_connector_config(encoded(http_config(**changes)))

    if changes.get("url") is not None:
        changes = {**changes, "url": "https://example.test/mcp"}
        with pytest.raises(ConnectorConfigError, match="schema"):
            parse_connector_config(encoded(stdio_config(**changes)))


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.test/mcp",
        "ftp://api.example.test/mcp",
        "https://user:password@api.example.test/mcp",
        "https://api.example.test/mcp?token=value",
        "https://api.example.test/mcp#fragment",
        "https://api.example.test/mcp?",
        "https://api.example.test/mcp#",
        "https://api.example.test\\mcp",
        "https://api.example.test:70000/mcp",
    ],
)
def test_endpoint_rejects_cleartext_remote_and_credential_bearing_components(url: str) -> None:
    with pytest.raises(ConnectorConfigError):
        parse_connector_config(encoded(http_config(url=url)))


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8789/mcp",
        "http://[::1]:8789/mcp",
        "http://localhost:8789/mcp",
        "https://api.example.test/mcp",
    ],
)
def test_endpoint_accepts_https_or_exact_loopback_http(url: str) -> None:
    assert parse_connector_config(encoded(http_config(url=url))).config.url == url


@pytest.mark.parametrize(
    "reference",
    [
        "plaintext-value",
        "https://secrets.example.test/value",
        "KEYCHAIN://Signet/account",
        "keychain://Signet/",
        "keychain://Signet/nested/account",
        "keychain://user:password@Signet/account",
        "keychain://Signet/account?generation=1",
        "keychain://Signet/account#fragment",
    ],
)
def test_credential_configuration_contains_references_not_values(reference: str) -> None:
    with pytest.raises(ConnectorConfigError):
        parse_connector_config(encoded(http_config(credential_ref=reference)))


@pytest.mark.parametrize(
    "material",
    [
        "authorization=Bearer abcdefghijklmnop",
        "api_key=abcdefghijklmnop",
        "sk_live_abcdefghijklmnop",
        "-----BEGIN PRIVATE KEY-----",
    ],
)
def test_embedded_credentials_are_rejected_without_echoing(material: str) -> None:
    raw = http_config()
    raw["url"] = f"https://api.example.test/{material}"
    with pytest.raises(ConnectorConfigError, match="credential-like") as caught:
        parse_connector_config(encoded(raw))
    assert material not in str(caught.value)


def test_unknown_duplicate_and_unsupported_config_fields_are_rejected() -> None:
    raw = http_config(environment={"TOKEN": "value"})
    with pytest.raises(ConnectorConfigError, match="schema"):
        parse_connector_config(encoded(raw))

    duplicate = encoded(http_config()).replace(
        b'"transport":"streamable_http"',
        b'"transport":"streamable_http","transport":"stdio"',
    )
    with pytest.raises(ConnectorConfigError, match="duplicate JSON key"):
        parse_connector_config(duplicate)

    raw = http_config(connector_config_version=2)
    with pytest.raises(ConnectorConfigError, match="unsupported"):
        parse_connector_config(encoded(raw))
    raw = http_config(connector_config_version=True)
    with pytest.raises(ConnectorConfigError, match="unsupported"):
        parse_connector_config(encoded(raw))


@pytest.mark.parametrize(
    "changes",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": 120.1},
        {"timeout_seconds": float("inf")},
        {"output_limit_bytes": 0},
        {"output_limit_bytes": 16_777_217},
    ],
)
def test_timeout_and_output_bounds_fail_closed(changes: dict[str, Any]) -> None:
    with pytest.raises(ConnectorConfigError):
        parse_connector_config(encoded(http_config(**changes)))


def test_connector_reader_rejects_symlinks_hardlinks_directories_and_oversize(
    tmp_path: Path,
) -> None:
    validated = parse_connector_config(encoded(http_config()))
    original = tmp_path / "connector.json"
    original.write_bytes(validated.canonical_bytes)
    symlink = tmp_path / "linked.json"
    symlink.symlink_to(original)
    with pytest.raises(ConnectorConfigError, match="local file"):
        load_connector_config(symlink)

    hardlink = tmp_path / "hardlink.json"
    os.link(original, hardlink)
    with pytest.raises(ConnectorConfigError, match="bounded regular"):
        load_connector_config(original)
    hardlink.unlink()

    with pytest.raises(ConnectorConfigError, match="bounded regular"):
        load_connector_config(tmp_path)

    fifo = tmp_path / "connector.fifo"
    os.mkfifo(fifo)
    with pytest.raises(ConnectorConfigError, match="bounded regular"):
        load_connector_config(fifo)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_CONNECTOR_CONFIG_BYTES + 1))
    with pytest.raises(ConnectorConfigError, match="bounded regular"):
        load_connector_config(oversized)


def test_connector_parser_rejects_excessive_depth_nodes_bytes_and_constants() -> None:
    deep = b"[" * (MAX_CONFIG_JSON_DEPTH + 2) + b"0" + b"]" * (MAX_CONFIG_JSON_DEPTH + 2)
    with pytest.raises(ConnectorConfigError, match="structural"):
        parse_connector_config(deep)

    nodes = {"connector_config_version": 1, "nodes": [0] * (MAX_CONFIG_JSON_NODES + 1)}
    with pytest.raises(ConnectorConfigError, match="structural"):
        parse_connector_config(encoded(nodes))
    with pytest.raises(ConnectorConfigError, match="byte limit"):
        parse_connector_config(b" " * (MAX_CONNECTOR_CONFIG_BYTES + 1))
    with pytest.raises(ConnectorConfigError, match="strict UTF-8 JSON"):
        parse_connector_config(b'{"connector_config_version":1,"value":NaN}')


def test_reviewed_command_document_is_canonical_and_resolves_exact_stdio_config(
    tmp_path: Path,
) -> None:
    raw = command_document(tmp_path)
    validated = parse_reviewed_command_document(encoded(raw, pretty=True))
    assert (
        validated.sha256
        == parse_reviewed_command_document(encoded(dict(reversed(tuple(raw.items()))))).sha256
    )
    command = validated.document.commands[0]
    assert command.executable == tmp_path / "bin" / "telegram-mcp"
    assert command.args == ("--stdio", "--bounded-output")

    connector = parse_connector_config(encoded(stdio_config()))
    resolver = ReviewedCommandResolver(validated)
    assert resolver.resolve_connector(connector) is command

    path = tmp_path / "commands.json"
    path.write_bytes(encoded(raw))
    assert load_reviewed_command_document(path, expected_sha256=validated.sha256) == validated
    with pytest.raises(ConnectorConfigError, match="does not match"):
        load_reviewed_command_document(path, expected_sha256="0" * 64)


def test_reviewed_command_resolver_rejects_unknown_digest_and_http_scope(tmp_path: Path) -> None:
    validated = parse_reviewed_command_document(encoded(command_document(tmp_path)))
    resolver = ReviewedCommandResolver(validated)
    with pytest.raises(ConnectorConfigError, match="unavailable"):
        resolver.resolve("missing-command", executable_sha256="e" * 64)
    with pytest.raises(ConnectorConfigError, match="does not match"):
        resolver.resolve("reviewed-telegram-mcp", executable_sha256="f" * 64)
    with pytest.raises(ConnectorConfigError, match="stdio"):
        resolver.resolve_connector(parse_connector_config(encoded(http_config())))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("executable", "relative/server"),
        ("executable", "/opt/server/./replacement"),
        ("executable", "/opt/server/../replacement"),
        ("cwd", "relative/working"),
        ("snapshot_root", "/tmp/../snapshots"),
        ("executable", "/bin/sh"),
        ("executable", "/usr/bin/env"),
        ("executable", "/usr/bin/python3"),
        ("executable", "/opt/runtime/node"),
    ],
)
def test_reviewed_commands_reject_relative_traversing_and_shell_paths(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    raw = command_document(tmp_path, **{field: value})
    with pytest.raises(ConnectorConfigError, match="schema"):
        parse_reviewed_command_document(encoded(raw))


def test_reviewed_command_document_rejects_env_secrets_duplicate_refs_and_unknowns(
    tmp_path: Path,
) -> None:
    raw = command_document(tmp_path)
    raw["commands"][0]["env"] = {"TOKEN": "value"}
    with pytest.raises(ConnectorConfigError, match="schema"):
        parse_reviewed_command_document(encoded(raw))

    raw = command_document(tmp_path, args=["--api-key", "value"])
    with pytest.raises(ConnectorConfigError, match="schema"):
        parse_reviewed_command_document(encoded(raw))

    raw = command_document(tmp_path)
    raw["commands"].append(dict(raw["commands"][0]))
    with pytest.raises(ConnectorConfigError, match="schema"):
        parse_reviewed_command_document(encoded(raw))

    raw = command_document(tmp_path)
    raw["commands"][0]["shell"] = True
    with pytest.raises(ConnectorConfigError, match="schema"):
        parse_reviewed_command_document(encoded(raw))

    raw = command_document(tmp_path)
    raw["reviewed_command_document_version"] = 2
    with pytest.raises(ConnectorConfigError, match="unsupported"):
        parse_reviewed_command_document(encoded(raw))


def test_reviewed_command_document_uses_the_same_bounded_safe_file_reader(
    tmp_path: Path,
) -> None:
    validated = parse_reviewed_command_document(encoded(command_document(tmp_path)))
    original = tmp_path / "commands.json"
    original.write_bytes(validated.canonical_bytes)
    link = tmp_path / "commands-link.json"
    link.symlink_to(original)
    with pytest.raises(ConnectorConfigError, match="local file"):
        load_reviewed_command_document(link)

    oversized = tmp_path / "oversized-commands.json"
    oversized.write_bytes(b" " * (MAX_CONNECTOR_CONFIG_BYTES + 1))
    with pytest.raises(ConnectorConfigError, match="bounded regular"):
        load_reviewed_command_document(oversized)
