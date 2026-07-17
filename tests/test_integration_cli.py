from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from signet.app import _parser, main
from signet.config import DownstreamConfig
from signet.connector_config import parse_reviewed_command_document
from signet.credential_broker import MemorySecretStore, SecretStore
from signet.integration_cli import DATABASE_PATH_ENV, run_integration_command
from signet.plugin_manifest import (
    load_reference_discovery_fixture,
    load_reference_plugin,
)

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_ROOT = ROOT / "src" / "signet" / "reference_plugins"
NOW = 2_100_000_000


def _invoke(argv: list[str], capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    main(argv)
    captured = capsys.readouterr()
    assert captured.err == ""
    value = json.loads(captured.out)
    assert value["live_dispatch_enabled"] is False
    assert "keychain://" not in captured.out
    return value


def _connector_document(
    reference: str,
    *,
    transport: str,
    command_ref: str | None = None,
    executable_sha256: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "connector_config_version": 1,
        "transport": transport,
        "credential_ref": f"keychain://Signet/{reference}",
        "credential_identity_digest": "c" * 64,
        "timeout_seconds": 2.0,
        "output_limit_bytes": 1_048_576,
    }
    if transport == "streamable_http":
        value["url"] = f"https://{reference}.invalid/mcp"
    else:
        value["command_ref"] = command_ref or f"{reference}-reviewed"
        value["executable_sha256"] = executable_sha256 or "d" * 64
    return value


@pytest.mark.parametrize(
    ("reference", "plugin_id", "connector_id", "transport", "tool_count"),
    (
        ("fastmail", "signet.fastmail", "fastmail", "streamable_http", 5),
        ("telegram", "signet.telegram", "telegram", "streamable_http", 6),
        ("whatsapp", "signet.whatsapp", "whatsapp_cli_shim", "stdio", 2),
    ),
)
def test_reference_fixture_onboarding_is_inert_and_dispatch_disabled(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    reference: str,
    plugin_id: str,
    connector_id: str,
    transport: str,
    tool_count: int,
) -> None:
    database = tmp_path / f"{reference}.sqlite3"
    manifest = REFERENCE_ROOT / reference / "manifest.json"
    fixture = REFERENCE_ROOT / reference / "tools-list.json"
    config = tmp_path / f"{reference}-connector.json"
    config.write_text(
        json.dumps(_connector_document(reference, transport=transport)),
        encoding="utf-8",
    )
    digest = load_reference_plugin(reference).sha256

    installed = _invoke(
        [
            "plugin",
            "install",
            str(manifest),
            "--sha256",
            digest,
            "--database",
            str(database),
        ],
        capsys,
    )
    assert installed["plugin"]["plugin_id"] == plugin_id

    configured = _invoke(
        [
            "connector",
            "configure",
            "--plugin",
            plugin_id,
            "--connector",
            connector_id,
            "--alias",
            f"{reference}-staged",
            "--config",
            str(config),
            "--database",
            str(database),
        ],
        capsys,
    )
    assert configured["connector"]["active"] is True

    discovered = _invoke(
        [
            "connector",
            "discover",
            f"{reference}-staged",
            "--fixture",
            str(fixture),
            "--database",
            str(database),
        ],
        capsys,
    )
    assert discovered["discovery"]["source"] == "fixture"
    assert discovered["discovery"]["tool_count"] == tool_count
    assert discovered["transport_started"] is False
    assert discovered["tools_call_requests"] == 0
    assert discovered["provider_effect_count"] == 0


def test_database_environment_precedence_and_plugin_management_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "environment.sqlite3"
    monkeypatch.setenv(DATABASE_PATH_ENV, str(database))
    manifest = REFERENCE_ROOT / "fastmail" / "manifest.json"
    digest = load_reference_plugin("fastmail").sha256

    validated = _invoke(
        ["plugin", "validate", str(manifest), "--sha256", digest],
        capsys,
    )
    assert validated["valid"] is True
    assert not database.exists()

    _invoke(["plugin", "install", str(manifest), "--sha256", digest], capsys)
    listing = _invoke(["plugin", "list"], capsys)
    assert [item["plugin_id"] for item in listing["plugins"]] == ["signet.fastmail"]

    shown = _invoke(["plugin", "show", "signet.fastmail"], capsys)
    assert shown["manifest"]["plugin_id"] == "signet.fastmail"

    disabled = _invoke(["plugin", "disable", "signet.fastmail"], capsys)
    assert disabled["disabled"] is True
    assert _invoke(["plugin", "list"], capsys)["plugins"][0]["active"] is False


class _FakeDiscoveryDownstream:
    def __init__(
        self,
        tools: list[dict[str, Any]],
        *,
        server_name: str,
    ) -> None:
        self._tools = tools
        self._identity = {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": server_name, "version": "1.0.0"},
        }
        self.events: list[str] = []

    @property
    def initialization_identity(self) -> dict[str, Any] | None:
        return self._identity

    async def start(self) -> _FakeDiscoveryDownstream:
        self.events.append("initialize")
        return self

    async def discover_all_tools(self) -> list[dict[str, Any]]:
        self.events.append("tools/list")
        return self._tools

    async def close(self) -> None:
        self.events.append("close")


def _prepare_connector(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    *,
    reference: str,
    plugin_id: str,
    connector_id: str,
    config_document: dict[str, Any],
) -> tuple[Path, str]:
    database = tmp_path / f"{reference}-live.sqlite3"
    manifest = REFERENCE_ROOT / reference / "manifest.json"
    config = tmp_path / f"{reference}-live-connector.json"
    config.write_text(json.dumps(config_document), encoding="utf-8")
    _invoke(
        [
            "plugin",
            "install",
            str(manifest),
            "--sha256",
            load_reference_plugin(reference).sha256,
            "--database",
            str(database),
        ],
        capsys,
    )
    alias = f"{reference}-live"
    _invoke(
        [
            "connector",
            "configure",
            "--plugin",
            plugin_id,
            "--connector",
            connector_id,
            "--alias",
            alias,
            "--config",
            str(config),
            "--database",
            str(database),
        ],
        capsys,
    )
    return database, alias


def _run_fake_live(
    argv: list[str],
    *,
    account: str,
    tools: list[dict[str, Any]],
) -> tuple[dict[str, Any], _FakeDiscoveryDownstream, DownstreamConfig]:
    clients: list[_FakeDiscoveryDownstream] = []
    configs: list[DownstreamConfig] = []

    def factory(
        alias: str,
        config: DownstreamConfig,
        secret_store: SecretStore,
    ) -> _FakeDiscoveryDownstream:
        del secret_store
        configs.append(config)
        client = _FakeDiscoveryDownstream(tools, server_name=f"fake:{alias}")
        clients.append(client)
        return client

    output = io.StringIO()
    args = _parser().parse_args(argv)
    run_integration_command(
        args,
        clock=lambda: NOW,
        secret_store=MemorySecretStore({("Signet", account): "fixture-credential"}),
        downstream_factory=factory,
        stdout=output,
    )
    return json.loads(output.getvalue()), clients[0], configs[0]


def test_explicit_http_live_discovery_has_only_initialize_and_tools_list(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database, alias = _prepare_connector(
        tmp_path,
        capsys,
        reference="fastmail",
        plugin_id="signet.fastmail",
        connector_id="fastmail",
        config_document=_connector_document("fastmail", transport="streamable_http"),
    )
    fixture = load_reference_discovery_fixture("fastmail")
    result, client, config = _run_fake_live(
        [
            "connector",
            "discover",
            alias,
            "--live-discovery",
            "--database",
            str(database),
        ],
        account="fastmail",
        tools=fixture["tools"],
    )

    assert config.transport == "http"
    assert client.events == ["initialize", "tools/list", "close"]
    assert not hasattr(client, "call_tool")
    assert result["discovery"]["source"] == "live"
    assert result["tools_call_requests"] == 0
    assert result["provider_effect_count"] == 0
    assert result["live_dispatch_enabled"] is False


def test_stdio_live_discovery_requires_and_resolves_hash_pinned_command_reference(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    executable_digest = "e" * 64
    database, alias = _prepare_connector(
        tmp_path,
        capsys,
        reference="whatsapp",
        plugin_id="signet.whatsapp",
        connector_id="whatsapp_cli_shim",
        config_document=_connector_document(
            "whatsapp",
            transport="stdio",
            command_ref="whatsapp-reviewed",
            executable_sha256=executable_digest,
        ),
    )
    command_document = {
        "reviewed_command_document_version": 1,
        "commands": [
            {
                "command_ref": "whatsapp-reviewed",
                "executable": "/opt/signet/bin/whatsapp-mcp-shim",
                "executable_sha256": executable_digest,
                "cwd": str(tmp_path),
                "snapshot_root": "/var/empty/signet-exec",
                "args": ["--mcp"],
            }
        ],
    }
    command_bytes = json.dumps(command_document).encode()
    command_path = tmp_path / "reviewed-commands.json"
    command_path.write_bytes(command_bytes)
    command_digest = parse_reviewed_command_document(command_bytes).sha256
    fixture = load_reference_discovery_fixture("whatsapp")

    result, client, config = _run_fake_live(
        [
            "connector",
            "discover",
            alias,
            "--live-discovery",
            "--command-references",
            str(command_path),
            "--command-references-sha256",
            command_digest,
            "--database",
            str(database),
        ],
        account="whatsapp",
        tools=fixture["tools"],
    )

    assert config.transport == "stdio"
    assert config.command == ("/opt/signet/bin/whatsapp-mcp-shim", "--mcp")
    assert config.executable_sha256 == executable_digest
    assert client.events == ["initialize", "tools/list", "close"]
    assert result["provider_effect_count"] == 0
    assert result["live_dispatch_enabled"] is False
