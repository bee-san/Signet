"""Operator CLI for staged, dispatch-disabled plugin integrations.

The commands in this module install only local hash-pinned manifests, persist
non-secret connector references, and discover schemas.  Fixture discovery is
the ordinary path.  Explicit live discovery owns a narrowly assembled
``DownstreamClient`` for MCP initialization and ``tools/list`` only; no command
in this module has a ``tools/call`` operation.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import math
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol, TextIO, cast

from signet.canonical import canonical_json
from signet.config import DownstreamConfig
from signet.connector_config import (
    ConnectorConfigError,
    ReviewedCommandResolver,
    ValidatedConnectorConfig,
    detached_connector_document,
    load_connector_config,
    load_reviewed_command_document,
    parse_connector_config,
)
from signet.connector_discovery import (
    ConnectorDiscoveryError,
    ConnectorDiscoveryService,
    DiscoveryOutcome,
    LiveToolsPage,
    strict_fixture_json,
)
from signet.credential_broker import (
    CredentialError,
    KeychainSecretStore,
    SecretStore,
)
from signet.db import Database, DatabaseError
from signet.downstream import DownstreamClient, DownstreamError
from signet.integration_store import (
    ConnectorRecord,
    IntegrationStoreError,
    PluginDetail,
    PluginIdentity,
    PluginRecord,
    SQLiteIntegrationStore,
    connector_generation_digest,
)
from signet.plugin_manifest import (
    ConnectorTemplate,
    PluginManifestError,
    load_plugin_manifest,
    parse_plugin_manifest,
)

DATABASE_PATH_ENV = "SIGNET_DATABASE_PATH"
_DATABASE_NAME = "signet.sqlite3"
_MAX_FIXTURE_BYTES = 8 * 1024 * 1024
_MAX_FIXTURE_NODES = 50_000
_MAX_FIXTURE_DEPTH = 32
_MAX_FIXTURE_STRING_BYTES = 64 * 1024
_SECRET_LIKE_TEXT = re.compile(
    r"(?ix)(?:"
    r"authorization\s*[:=]\s*bearer\s+\S+|"
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)"
    r"\s*[:=]\s*\S+|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"-----BEGIN\s+[A-Z ]*PRIVATE\s+KEY-----|"
    r"\b(?:sk|sk_live|xox[baprs]|gh[pousr])[-_][A-Za-z0-9_-]{12,}|"
    r"[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@"
    r")"
)


class IntegrationCLIError(RuntimeError):
    """A staged integration command failed without exposing credential material."""


class DiscoveryDownstream(Protocol):
    """The subset of ``DownstreamClient`` available to CLI live discovery."""

    @property
    def initialization_identity(self) -> dict[str, Any] | None: ...

    async def start(self) -> DiscoveryDownstream: ...

    async def close(self) -> None: ...

    async def discover_all_tools(self) -> list[dict[str, Any]]: ...


DownstreamFactory = Callable[[str, DownstreamConfig, SecretStore], DiscoveryDownstream]
Clock = Callable[[], float]


def add_integration_parsers(subcommands: Any) -> None:
    """Register the exact staged plugin and connector command hierarchy."""

    plugin = subcommands.add_parser(
        "plugin",
        help="validate and manage local hash-pinned staged plugins",
    )
    plugin_commands = plugin.add_subparsers(dest="plugin_command", required=True)

    validate = plugin_commands.add_parser(
        "validate",
        help="validate a local manifest against its trusted canonical digest",
    )
    validate.add_argument("manifest", type=Path)
    validate.add_argument("--sha256", required=True)

    install = plugin_commands.add_parser(
        "install",
        help="install a validated local manifest into staged state",
    )
    install.add_argument("manifest", type=Path)
    install.add_argument("--sha256", required=True)
    _database_argument(install)

    listing = plugin_commands.add_parser("list", help="list selected plugin generations")
    _database_argument(listing)

    show = plugin_commands.add_parser("show", help="show one selected plugin generation")
    show.add_argument("plugin_id")
    _database_argument(show)

    disable = plugin_commands.add_parser(
        "disable",
        help="disable one selected plugin and its active connectors",
    )
    disable.add_argument("plugin_id")
    _database_argument(disable)

    connector = subcommands.add_parser(
        "connector",
        help="configure and discover staged MCP connectors",
    )
    connector_commands = connector.add_subparsers(dest="connector_command", required=True)

    configure = connector_commands.add_parser(
        "configure",
        help="bind a strict non-secret connector configuration to a plugin",
    )
    configure.add_argument("--plugin", required=True, dest="plugin_id")
    configure.add_argument("--connector", required=True, dest="connector_id")
    configure.add_argument("--alias", required=True)
    configure.add_argument("--config", required=True, type=Path)
    _database_argument(configure)

    discover = connector_commands.add_parser(
        "discover",
        help="stage exact tool schemas from a fixture or explicit live tools/list",
    )
    discover.add_argument("alias")
    mode = discover.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fixture", type=Path)
    mode.add_argument(
        "--live-discovery",
        action="store_true",
        help="explicitly allow initialization and bounded tools/list",
    )
    discover.add_argument("--command-references", type=Path)
    discover.add_argument("--command-references-sha256")
    _database_argument(discover)


def run_integration_command(
    args: argparse.Namespace,
    *,
    clock: Clock = time.time,
    secret_store: SecretStore | None = None,
    downstream_factory: DownstreamFactory = DownstreamClient,
    stdout: TextIO | None = None,
) -> None:
    """Execute one parsed staged integration command and print bounded JSON."""

    try:
        result = _run_integration_command(
            args,
            now=_timestamp(clock),
            secret_store=secret_store,
            downstream_factory=downstream_factory,
        )
        _print_json(result, stdout=stdout)
    except IntegrationCLIError:
        raise
    except (
        ConnectorConfigError,
        ConnectorDiscoveryError,
        CredentialError,
        DatabaseError,
        DownstreamError,
        IntegrationStoreError,
        PluginManifestError,
        OSError,
        ValueError,
    ) as exc:
        raise IntegrationCLIError(str(exc)) from None
    except Exception:
        # CLI failures are deliberately terse: transport and parser exceptions may
        # retain request headers or process environment in their representations.
        raise IntegrationCLIError("staged integration command failed safely") from None


def _run_integration_command(
    args: argparse.Namespace,
    *,
    now: int,
    secret_store: SecretStore | None,
    downstream_factory: DownstreamFactory,
) -> dict[str, Any]:
    if args.command == "plugin":
        return _run_plugin_command(args, now=now)
    if args.command == "connector":
        return _run_connector_command(
            args,
            now=now,
            secret_store=secret_store,
            downstream_factory=downstream_factory,
        )
    raise IntegrationCLIError("unknown staged integration command")


def _run_plugin_command(args: argparse.Namespace, *, now: int) -> dict[str, Any]:
    command = cast(str, args.plugin_command)
    if command == "validate":
        validated = load_plugin_manifest(args.manifest, expected_sha256=args.sha256)
        return _with_dispatch_flag(
            {
                "command": "plugin.validate",
                "valid": True,
                "plugin": _plugin_identity_json(
                    PluginIdentity(
                        validated.manifest.plugin_id,
                        validated.manifest.plugin_version,
                        validated.sha256,
                    )
                ),
                "connector_count": len(validated.manifest.connectors),
                "tool_mapping_count": len(validated.manifest.tool_mappings),
                "worker_declared": validated.manifest.worker is not None,
            }
        )

    store = _store_for_args(args)
    if command == "install":
        validated = load_plugin_manifest(args.manifest, expected_sha256=args.sha256)
        identity = store.install_plugin(validated, installed_at=now)
        return _with_dispatch_flag(
            {
                "command": "plugin.install",
                "installed": True,
                "plugin": _plugin_identity_json(identity),
            }
        )
    if command == "list":
        return _with_dispatch_flag(
            {
                "command": "plugin.list",
                "plugins": [_plugin_record_json(record) for record in store.list_plugins()],
            }
        )
    if command == "show":
        detail = store.get_plugin(args.plugin_id)
        if detail is None:
            raise IntegrationCLIError("plugin is not installed")
        return _with_dispatch_flag(
            {
                "command": "plugin.show",
                "plugin": _plugin_record_json(detail.record),
                "manifest": detail.manifest,
                "tool_mapping_count": len(detail.mappings),
            }
        )
    if command == "disable":
        if not store.disable_plugin(args.plugin_id, disabled_at=now):
            raise IntegrationCLIError("plugin is not installed and active")
        return _with_dispatch_flag(
            {
                "command": "plugin.disable",
                "disabled": True,
                "plugin_id": args.plugin_id,
            }
        )
    raise IntegrationCLIError("unknown plugin command")


def _run_connector_command(
    args: argparse.Namespace,
    *,
    now: int,
    secret_store: SecretStore | None,
    downstream_factory: DownstreamFactory,
) -> dict[str, Any]:
    command = cast(str, args.connector_command)
    store = _store_for_args(args)
    if command == "configure":
        detail, template = _active_plugin_connector(
            store,
            plugin_id=args.plugin_id,
            connector_id=args.connector_id,
        )
        validated = load_connector_config(args.config, template=template)
        document = detached_connector_document(validated)
        credential_ref = cast(str, document.pop("credential_ref"))
        credential_identity_digest = cast(str, document.pop("credential_identity_digest"))
        connector = store.configure_connector(
            plugin_id=detail.record.plugin.plugin_id,
            connector_id=template.connector_id,
            alias=args.alias,
            config=document,
            credential_ref=credential_ref,
            credential_identity_digest=credential_identity_digest,
            canonical_config_bytes=validated.canonical_bytes,
            canonical_config_sha256=validated.sha256,
            configured_at=now,
        )
        return _with_dispatch_flag(
            {
                "command": "connector.configure",
                "configured": True,
                "connector": _connector_json(connector),
            }
        )

    if command != "discover":
        raise IntegrationCLIError("unknown connector command")
    service = ConnectorDiscoveryService.staged(store)
    if args.fixture is not None:
        if args.command_references is not None or args.command_references_sha256 is not None:
            raise IntegrationCLIError(
                "command references are accepted only for explicit live discovery"
            )
        fixture = strict_fixture_json(_read_fixture(args.fixture))
        _validate_fixture_bounds(fixture)
        outcome = asyncio.run(service.discover_fixture(args.alias, fixture, discovered_at=now))
        return _discovery_json(outcome, transport_started=False)

    if args.live_discovery is not True:
        raise IntegrationCLIError("live discovery requires an explicit opt-in")
    outcome = asyncio.run(
        _discover_live(
            store,
            service,
            alias=args.alias,
            command_references=args.command_references,
            command_references_sha256=args.command_references_sha256,
            discovered_at=now,
            secret_store=secret_store or KeychainSecretStore(),
            downstream_factory=downstream_factory,
        )
    )
    return _discovery_json(outcome, transport_started=True)


async def _discover_live(
    store: SQLiteIntegrationStore,
    service: ConnectorDiscoveryService,
    *,
    alias: str,
    command_references: Path | None,
    command_references_sha256: str | None,
    discovered_at: int,
    secret_store: SecretStore,
    downstream_factory: DownstreamFactory,
) -> DiscoveryOutcome:
    connector = store.active_connector(alias)
    validated = _validated_stored_config(store, connector)
    config = _downstream_config(
        validated,
        command_references=command_references,
        command_references_sha256=command_references_sha256,
    )
    client = downstream_factory(alias, config, secret_store)
    adapter = _DownstreamDiscoveryAdapter(client)
    try:
        return await service.discover_live(
            alias,
            adapter,
            live_discovery=True,
            discovered_at=discovered_at,
            expected_config_digest=connector.config_digest,
        )
    finally:
        await client.close()


class _DownstreamDiscoveryAdapter:
    """Collapse a supervised client's bounded pagination into one list-only page."""

    def __init__(self, client: DiscoveryDownstream) -> None:
        self._client = client
        self._listed = False

    async def initialize(self) -> Mapping[str, Any]:
        await self._client.start()
        identity = self._client.initialization_identity
        if identity is None:
            raise ConnectorDiscoveryError("live initialization identity is unavailable")
        _validate_fixture_bounds(identity)
        return identity

    async def list_tools(self, cursor: str | None) -> LiveToolsPage:
        if cursor is not None or self._listed:
            raise ConnectorDiscoveryError("live discovery pagination boundary was reused")
        self._listed = True
        tools = await self._client.discover_all_tools()
        _validate_fixture_bounds({"tools": tools})
        return LiveToolsPage(tools=tuple(tools), next_cursor=None)


def _validated_stored_config(
    store: SQLiteIntegrationStore,
    connector: ConnectorRecord,
) -> ValidatedConnectorConfig:
    detail, template = _active_plugin_connector(
        store,
        plugin_id=connector.plugin.plugin_id,
        connector_id=connector.connector_id,
    )
    if detail.record.plugin != connector.plugin:
        raise IntegrationStoreError("connector plugin generation is no longer current")
    document = store.connector_configuration(connector.alias)
    validated = parse_connector_config(canonical_json(document), template=template)
    expected_digest = connector_generation_digest(
        alias=connector.alias,
        plugin=connector.plugin,
        connector_id=connector.connector_id,
        canonical_config_sha256=validated.sha256,
    )
    if not hmac.compare_digest(expected_digest, connector.config_digest):
        raise IntegrationStoreError("connector generation digest no longer matches")
    return validated


def _downstream_config(
    validated: ValidatedConnectorConfig,
    *,
    command_references: Path | None,
    command_references_sha256: str | None,
) -> DownstreamConfig:
    config = validated.config
    if config.transport == "streamable_http":
        if command_references is not None or command_references_sha256 is not None:
            raise IntegrationCLIError("HTTP live discovery does not accept command references")
        if config.url is None:  # defended by the strict connector model
            raise ConnectorConfigError("HTTP connector endpoint is unavailable")
        return DownstreamConfig(
            transport="http",
            credential_ref=config.credential_ref,
            credential_identity_digest=config.credential_identity_digest,
            url=config.url,
            timeout_seconds=config.timeout_seconds,
            output_limit_bytes=config.output_limit_bytes,
        )

    if command_references is None or command_references_sha256 is None:
        raise IntegrationCLIError(
            "stdio live discovery requires a hash-pinned command-reference document"
        )
    reviewed = load_reviewed_command_document(
        command_references,
        expected_sha256=command_references_sha256,
    )
    command = ReviewedCommandResolver(reviewed).resolve_connector(validated)
    return DownstreamConfig(
        transport="stdio",
        credential_ref=config.credential_ref,
        credential_identity_digest=config.credential_identity_digest,
        command=(str(command.executable), *command.args),
        working_directory=command.cwd,
        executable_sha256=command.executable_sha256,
        execution_snapshot_root=command.snapshot_root,
        timeout_seconds=config.timeout_seconds,
        output_limit_bytes=config.output_limit_bytes,
    )


def _active_plugin_connector(
    store: SQLiteIntegrationStore,
    *,
    plugin_id: str,
    connector_id: str,
) -> tuple[PluginDetail, ConnectorTemplate]:
    detail = store.get_plugin(plugin_id)
    if detail is None or detail.record.disabled_at is not None:
        raise IntegrationCLIError("plugin is not installed and active")
    validated = parse_plugin_manifest(canonical_json(detail.manifest))
    if not hmac.compare_digest(
        validated.sha256,
        detail.record.plugin.manifest_sha256,
    ):
        raise IntegrationStoreError("stored plugin manifest digest no longer matches")
    template = next(
        (
            candidate
            for candidate in validated.manifest.connectors
            if candidate.connector_id == connector_id
        ),
        None,
    )
    if template is None:
        raise IntegrationCLIError("connector is not declared by the active plugin")
    return detail, template


def _store_for_args(args: argparse.Namespace) -> SQLiteIntegrationStore:
    database = Database(_database_path(getattr(args, "database", None)))
    database.initialize()
    return SQLiteIntegrationStore(database)


def _database_path(argument: Path | None) -> Path:
    selected: Path
    if argument is not None:
        selected = argument
    else:
        environment = os.environ.get(DATABASE_PATH_ENV)
        if environment == "":
            raise IntegrationCLIError("database path is invalid")
        selected = (
            Path(environment)
            if environment is not None
            else Path.home() / ".hermes" / "services" / "signet" / "data" / _DATABASE_NAME
        )
    try:
        expanded = selected.expanduser()
        encoded = os.fsencode(expanded)
    except (OSError, RuntimeError, ValueError) as exc:
        raise IntegrationCLIError("database path is invalid") from exc
    if (
        not encoded
        or len(encoded) > 4096
        or not expanded.is_absolute()
        or "\x00" in str(expanded)
        or ".." in expanded.parts
    ):
        raise IntegrationCLIError("database path is invalid")
    return expanded


def _database_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--database",
        type=Path,
        help=f"state database (default: ${DATABASE_PATH_ENV}, then standard data database)",
    )


def _timestamp(clock: Clock) -> int:
    value = clock()
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise IntegrationCLIError("system clock is unavailable")
    timestamp = int(value)
    if timestamp < 0:
        raise IntegrationCLIError("system clock is unavailable")
    return timestamp


def _read_fixture(path: Path) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > _MAX_FIXTURE_BYTES
        ):
            raise ConnectorDiscoveryError("fixture must be a bounded regular local file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size < 1
            or opened.st_size > _MAX_FIXTURE_BYTES
        ):
            raise ConnectorDiscoveryError("fixture must be a bounded regular local file")
        chunks: list[bytes] = []
        remaining = _MAX_FIXTURE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        document = b"".join(chunks)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            len(document) > _MAX_FIXTURE_BYTES
            or _file_identity(opened) != _file_identity(after)
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ConnectorDiscoveryError("fixture changed while it was read")
        return document
    except ConnectorDiscoveryError:
        raise
    except (OSError, ValueError) as exc:
        raise ConnectorDiscoveryError("fixture is unavailable or unsafe") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_fixture_bounds(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_FIXTURE_NODES or depth > _MAX_FIXTURE_DEPTH:
            raise ConnectorDiscoveryError("fixture exceeds its structural limits")
        if isinstance(item, dict):
            for key, child in item.items():
                if (
                    not isinstance(key, str)
                    or len(key.encode("utf-8")) > 256
                    or _SECRET_LIKE_TEXT.search(key)
                ):
                    raise ConnectorDiscoveryError("fixture contains an invalid object key")
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > _MAX_FIXTURE_STRING_BYTES or _SECRET_LIKE_TEXT.search(
                item
            ):
                raise ConnectorDiscoveryError(
                    "fixture contains an oversized string or credential-like material"
                )
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ConnectorDiscoveryError("fixture contains a non-finite number")
        elif item is not None and not isinstance(item, (bool, int)):
            raise ConnectorDiscoveryError("fixture contains a non-JSON value")


def _plugin_identity_json(identity: PluginIdentity) -> dict[str, Any]:
    return {
        "plugin_id": identity.plugin_id,
        "plugin_version": identity.plugin_version,
        "manifest_sha256": identity.manifest_sha256,
    }


def _plugin_record_json(record: PluginRecord) -> dict[str, Any]:
    return {
        **_plugin_identity_json(record.plugin),
        "installed_at": record.installed_at,
        "disabled_at": record.disabled_at,
        "active": record.disabled_at is None,
    }


def _connector_json(connector: ConnectorRecord) -> dict[str, Any]:
    return {
        "alias": connector.alias,
        "config_digest": connector.config_digest,
        "plugin": _plugin_identity_json(connector.plugin),
        "connector_id": connector.connector_id,
        "configured_at": connector.configured_at,
        "active": connector.is_active,
    }


def _discovery_json(
    outcome: DiscoveryOutcome,
    *,
    transport_started: bool,
) -> dict[str, Any]:
    discovery = outcome.discovery
    refresh = outcome.schema_refresh
    return _with_dispatch_flag(
        {
            "command": "connector.discover",
            "discovery": {
                "run_id": discovery.run_id,
                "alias": discovery.alias,
                "config_digest": discovery.config_digest,
                "source": discovery.source,
                "server_identity_digest": discovery.server_identity_digest,
                "status": discovery.status,
                "tool_count": discovery.tool_count,
                "discovered_at": discovery.discovered_at,
            },
            "schema_refresh": {
                "changed_tools": list(refresh.changed_tools),
                "list_changed": refresh.list_changed,
                "notifications_sent": refresh.notifications_sent,
            },
            "transport_started": transport_started,
            "tools_call_requests": 0,
            "provider_effect_count": 0,
        }
    )


def _with_dispatch_flag(value: dict[str, Any]) -> dict[str, Any]:
    return {**value, "live_dispatch_enabled": False}


def _print_json(value: Mapping[str, Any], *, stdout: TextIO | None) -> None:
    selected = stdout or sys.stdout
    try:
        encoded = json.dumps(
            dict(value),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(encoded.encode("utf-8")) > _MAX_FIXTURE_BYTES:
            raise IntegrationCLIError("staged integration output exceeds its byte limit")
        selected.write(encoded + "\n")
        selected.flush()
    except IntegrationCLIError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise IntegrationCLIError("staged integration output failed safely") from exc
