"""Runnable downstream-disabled deployment assembly and operator commands.

This module deliberately has no downstream transport, provider client, credential
resolver, worker, or dispatch path.  It is a durable staging target for a reviewed
deployment: MCP caller authentication can be provisioned and exercised while every
gateway tool fails closed and every downstream alias remains absent.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import stat
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

import mcp.types as types
from mcp.shared.exceptions import McpError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from signet.auth import InvalidCredentials, canonical_user_id
from signet.credential_broker import SQLiteTokenRegistry, StoredTokenMetadata
from signet.db import Database, DatabaseError, MigrationBackupReceipt
from signet.gateway_tools import GATEWAY_TOOL_DEFINITIONS, GatewayPrincipal, GatewayToolSurface
from signet.mcp_mirror import domain_error_result
from signet.private_paths import PrivatePathError, ensure_private_directory
from signet.runtime import (
    APPROVALS_ALIAS,
    LoopbackHostMiddleware,
    MCPRuntime,
    _allowed_host_values,
    _loopback_address,
    assemble_mcp_runtime,
    gateway_principal_provider,
)

DISABLED_CONFIG_ENV = "SIGNET_DISABLED_CONFIG"
_CONFIG_MAX_BYTES = 64 * 1024
_DATABASE_NAME = "signet.sqlite3"
_DISABLED_ERROR = (
    "This Signet deployment is downstream-disabled. No request or external action was performed."
)
_KNOWN_GATEWAY_TOOLS = frozenset(definition["name"] for definition in GATEWAY_TOOL_DEFINITIONS)
Runner = Callable[..., None]


class DeploymentError(RuntimeError):
    """Raised when disabled deployment state is missing, unsafe, or inconsistent."""


class _CreatedFileError(DeploymentError):
    def __init__(self, message: str, *, path: Path, identity: tuple[int, int]) -> None:
        super().__init__(message)
        self.path = path
        self.identity = identity


class ListenerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    port: int = Field(ge=1024, le=65535)
    limit_concurrency: int = Field(default=64, ge=1, le=256)

    @field_validator("host")
    @classmethod
    def host_is_numeric_loopback(cls, value: str) -> str:
        try:
            return _loopback_address(value).compressed
        except ValueError as exc:
            raise ValueError("listeners must use a numeric loopback address") from exc


class PrincipalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    namespace: str
    allowed_aliases: tuple[Literal["approvals"], ...] = cast(
        tuple[Literal["approvals"], ...], (APPROVALS_ALIAS,)
    )

    @field_validator("namespace")
    @classmethod
    def namespace_is_exact(cls, value: str) -> str:
        if not _valid_namespace(value):
            raise ValueError("invalid caller namespace")
        return value

    @field_validator("allowed_aliases")
    @classmethod
    def disabled_aliases_are_exact(
        cls, value: tuple[Literal["approvals"], ...]
    ) -> tuple[Literal["approvals"], ...]:
        if value != (APPROVALS_ALIAS,):
            raise ValueError("disabled deployments expose only the approvals alias")
        return value


class HumanAuthContext(BaseModel):
    """Non-secret context to validate before a later human-only ceremony."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: str
    public_origin: str
    rp_id: str

    @model_validator(mode="after")
    def validate_exact_origin(self) -> HumanAuthContext:
        try:
            canonical_user_id(self.user_id)
        except InvalidCredentials as exc:
            raise ValueError("invalid human user ID") from exc
        parsed = urlsplit(self.public_origin)
        try:
            port = parsed.port
        except ValueError:
            raise ValueError("invalid human-auth public origin") from None
        hostname = parsed.hostname
        if (
            parsed.scheme != "https"
            or hostname is None
            or not hostname.isascii()
            or hostname != hostname.lower()
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or (port is not None and not 1 <= port <= 65535)
            or self.public_origin != self.public_origin.lower()
            or not _valid_host(hostname)
            or self.rp_id != hostname
        ):
            raise ValueError(
                "human-auth context requires an exact lowercase HTTPS host and matching RP ID"
            )
        return self


class DisabledDeploymentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    mode: Literal["disabled"] = "disabled"
    data_dir: Path
    mcp: ListenerConfig = ListenerConfig(host="127.0.0.1", port=8789)
    web: ListenerConfig = ListenerConfig(host="127.0.0.1", port=8790)
    principals: tuple[PrincipalConfig, ...]
    human_auth: HumanAuthContext | None = None

    @field_validator("data_dir")
    @classmethod
    def data_directory_is_absolute(cls, value: Path) -> Path:
        if not value.is_absolute() or "~" in value.parts:
            raise ValueError("data_dir must be an absolute path without shell expansion")
        return value

    @model_validator(mode="after")
    def principals_are_unique(self) -> DisabledDeploymentConfig:
        namespaces = tuple(principal.namespace for principal in self.principals)
        if not namespaces or len(namespaces) != len(set(namespaces)):
            raise ValueError("at least one unique caller namespace is required")
        if self.mcp.host == self.web.host and self.mcp.port == self.web.port:
            raise ValueError("MCP and web listeners must use different ports")
        return self

    @property
    def database_path(self) -> Path:
        return self.data_dir / _DATABASE_NAME

    @property
    def allowed_principals(self) -> Mapping[str, tuple[str, ...]]:
        return {
            principal.namespace: tuple(principal.allowed_aliases) for principal in self.principals
        }


class DisabledGatewayTools:
    """Publish the normative tool schemas while refusing every operation."""

    def list_tools(self) -> list[dict[str, Any]]:
        return copy.deepcopy(GATEWAY_TOOL_DEFINITIONS)

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        principal: GatewayPrincipal,
    ) -> dict[str, Any]:
        del arguments, principal
        if name not in _KNOWN_GATEWAY_TOOLS:
            raise McpError(
                types.ErrorData(code=types.INVALID_PARAMS, message=f"Unknown tool: {name}")
            )
        return domain_error_result("deployment_disabled", _DISABLED_ERROR)


class DisabledSecurityHeaders:
    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_headers(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"cache-control", b"no-store"),
                        (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                    ]
                )
                message["headers"] = headers
            await send(message)

        await self._app(scope, receive, send_headers)


class LoopbackClientMiddleware:
    """Keep a mis-bound disabled factory inaccessible to non-loopback peers."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            client = scope.get("client")
            try:
                address = ipaddress.ip_address(client[0] if client is not None else "")
            except (TypeError, ValueError):
                address = None
            if address is None or not address.is_loopback:
                response = PlainTextResponse(
                    "Forbidden",
                    status_code=403,
                    headers={"Cache-Control": "no-store"},
                )
                await response(scope, receive, send)
                return
        await self._app(scope, receive, send)


def load_disabled_config(path: str | os.PathLike[str]) -> DisabledDeploymentConfig:
    selected = Path(path)
    if not selected.is_absolute():
        raise DeploymentError("the disabled deployment config path must be absolute")
    encoded = _read_private_config(selected)
    try:
        raw = json.loads(encoded, object_pairs_hook=_unique_object)
        config = DisabledDeploymentConfig.model_validate(raw)
    except (UnicodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise DeploymentError("the disabled deployment config is invalid") from exc
    if not config.data_dir.exists() or config.data_dir.is_symlink():
        raise DeploymentError("the deployment data directory must already exist")
    try:
        resolved_data = ensure_private_directory(config.data_dir)
    except PrivatePathError as exc:
        raise DeploymentError("the deployment data directory must be owned mode 0700") from exc
    if resolved_data != config.data_dir:
        raise DeploymentError("the deployment data directory must not use symbolic links")
    return config


def create_mcp_runtime(config: DisabledDeploymentConfig) -> MCPRuntime:
    database = _current_database(config)
    tokens = SQLiteTokenRegistry(
        database,
        allowed_principals=config.allowed_principals,
    )
    approvals = GatewayToolSurface(
        tools=cast(Any, DisabledGatewayTools()),
        principal_provider=gateway_principal_provider("disabled:no-human-auth"),
    )
    runtime = assemble_mcp_runtime(
        aliases={},
        approvals=approvals,
        tokens=tokens,
        bind_host=config.mcp.host,
        bind_port=config.mcp.port,
        request_concurrency_limit=config.mcp.limit_concurrency,
    )
    runtime.app.add_middleware(LoopbackClientMiddleware)
    return runtime


def create_mcp_app() -> Starlette:
    """Uvicorn factory using a non-secret absolute config path from the environment."""

    return create_mcp_runtime(_config_from_environment()).app


def create_web_app_from_config(config: DisabledDeploymentConfig) -> Starlette:
    _current_database(config)
    address = _loopback_address(config.web.host)
    allowed_hosts = _allowed_host_values(address, config.web.port)
    app = Starlette(
        debug=False,
        routes=[
            Route("/", _disabled_status, methods=["GET"], include_in_schema=False),
            Route("/healthz", _web_health, methods=["GET"], include_in_schema=False),
        ],
        middleware=[
            Middleware(LoopbackClientMiddleware),
            Middleware(DisabledSecurityHeaders),
            Middleware(LoopbackHostMiddleware, allowed_hosts=allowed_hosts),
        ],
    )
    app.router.redirect_slashes = False
    return app


def create_web_app() -> Starlette:
    """Uvicorn factory using a non-secret absolute config path from the environment."""

    return create_web_app_from_config(_config_from_environment())


def add_deployment_parser(subcommands: Any) -> None:
    deployment = subcommands.add_parser(
        "deployment",
        help="initialize and run a persistent downstream-disabled deployment",
    )
    commands = deployment.add_subparsers(dest="deployment_command", required=True)

    initialize = commands.add_parser("init", help="create strict disabled config and state")
    initialize.add_argument("--config", type=Path, required=True)
    initialize.add_argument("--data-dir", type=Path, required=True)
    initialize.add_argument("--namespace", required=True)
    initialize.add_argument("--mcp-host", default="127.0.0.1")
    initialize.add_argument("--mcp-port", type=int, default=8789)
    initialize.add_argument("--web-host", default="127.0.0.1")
    initialize.add_argument("--web-port", type=int, default=8790)
    initialize.add_argument("--human-user-id")
    initialize.add_argument("--public-origin")
    initialize.add_argument("--rp-id")

    for name, help_text in (
        ("validate", "validate private config, schema, and disabled invariants"),
        ("auth-status", "report non-secret enrollment counts without reading secrets"),
        ("serve-mcp", "serve the loopback disabled MCP application"),
        ("serve-web", "serve the loopback disabled status application"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--config", type=Path, required=True)

    migrate = commands.add_parser(
        "migrate", help="migrate with an explicit private pre-migration snapshot"
    )
    migrate.add_argument("--config", type=Path, required=True)
    migrate.add_argument("--backup-snapshot", type=Path, required=True)

    token = commands.add_parser("token", help="manage persistent MCP caller tokens")
    token_commands = token.add_subparsers(dest="token_command", required=True)
    issue = token_commands.add_parser("issue", help="issue a token and print it once")
    issue.add_argument("--config", type=Path, required=True)
    issue.add_argument("--namespace", required=True)
    listing = token_commands.add_parser("list", help="list non-secret token metadata")
    listing.add_argument("--config", type=Path, required=True)
    for name in ("revoke", "rotate"):
        command = token_commands.add_parser(name, help=f"{name} a caller token")
        command.add_argument("--config", type=Path, required=True)
        command.add_argument("--token-id", required=True)


def run_deployment_command(args: argparse.Namespace, *, runner: Runner) -> None:
    command = cast(str, args.deployment_command)
    if command == "init":
        _initialize_command(args)
        return
    config = load_disabled_config(args.config)
    if command == "migrate":
        _migrate_command(config, args.backup_snapshot)
        return
    if command == "validate":
        _print_json(_validation_report(config))
        return
    if command == "auth-status":
        _print_json(_auth_status(config))
        return
    if command in {"serve-mcp", "serve-web"}:
        listener = config.mcp if command == "serve-mcp" else config.web
        app = (
            create_mcp_runtime(config).app
            if command == "serve-mcp"
            else create_web_app_from_config(config)
        )
        runner(
            app,
            host=listener.host,
            port=listener.port,
            server_header=False,
            limit_concurrency=listener.limit_concurrency,
        )
        return
    if command == "token":
        _token_command(config, args)
        return
    raise DeploymentError("unknown deployment command")


async def _disabled_status(request: Any) -> PlainTextResponse:
    del request
    return PlainTextResponse(
        "Signet is downstream-disabled. No agent request or external action is available.\n",
        status_code=503,
    )


async def _web_health(request: Any) -> JSONResponse:
    del request
    return JSONResponse({"status": "ok", "service": "signet", "mode": "disabled"})


def _config_from_environment() -> DisabledDeploymentConfig:
    path = os.environ.get(DISABLED_CONFIG_ENV)
    if not path:
        raise DeploymentError(f"{DISABLED_CONFIG_ENV} must name an absolute private config file")
    return load_disabled_config(path)


def _current_database(config: DisabledDeploymentConfig) -> Database:
    if not config.database_path.exists() or config.database_path.is_symlink():
        raise DeploymentError("the disabled deployment database is not initialized")
    database = Database(config.database_path)
    try:
        database.initialize()
    except DatabaseError:
        raise
    except Exception as exc:
        raise DeploymentError("the disabled deployment database is unavailable") from exc
    return database


def _initialize_command(args: argparse.Namespace) -> None:
    config_path = cast(Path, args.config)
    data_dir = cast(Path, args.data_dir)
    if not config_path.is_absolute() or not data_dir.is_absolute():
        raise DeploymentError("config and data paths must be absolute")
    canonical_config = Path(os.path.abspath(config_path))
    canonical_data = Path(os.path.abspath(data_dir))
    if canonical_config != config_path or canonical_data != data_dir:
        raise DeploymentError("config and data paths must be absolute canonical paths")
    config_path = canonical_config
    data_dir = canonical_data
    human_values = (args.human_user_id, args.public_origin, args.rp_id)
    if any(value is not None for value in human_values) and not all(
        value is not None for value in human_values
    ):
        raise DeploymentError(
            "human auth context requires --human-user-id, --public-origin, and --rp-id together"
        )
    human = (
        None
        if human_values == (None, None, None)
        else HumanAuthContext(
            user_id=args.human_user_id,
            public_origin=args.public_origin,
            rp_id=args.rp_id,
        )
    )
    try:
        config = DisabledDeploymentConfig(
            data_dir=data_dir,
            mcp=ListenerConfig(host=args.mcp_host, port=args.mcp_port),
            web=ListenerConfig(host=args.web_host, port=args.web_port),
            principals=(PrincipalConfig(namespace=args.namespace),),
            human_auth=human,
        )
    except ValidationError as exc:
        raise DeploymentError("disabled deployment settings are invalid") from exc
    if config_path == config.data_dir or config_path in _reserved_database_paths(config):
        raise DeploymentError("the config path collides with reserved database state")
    if config_path.exists() or config_path.is_symlink():
        raise DeploymentError("the config destination must be a new nonsymlink path")
    if any(path.exists() or path.is_symlink() for path in _reserved_database_paths(config)):
        raise DeploymentError("deployment init requires new database state paths")
    created_directories = {
        path
        for path in (config.data_dir, config_path.parent)
        if not path.exists() and not path.is_symlink()
    }
    config_identity: tuple[int, int] | None = None
    database_identity: tuple[int, int] | None = None
    try:
        resolved_data = ensure_private_directory(config.data_dir)
        if resolved_data != config.data_dir:
            raise DeploymentError("the deployment data directory must not use symbolic links")
        config_identity = _write_private_config(config_path, config)
        database_identity = _create_private_database(config.database_path)
        Database(config.database_path).initialize()
    except _CreatedFileError as exc:
        if exc.path == config_path:
            config_identity = exc.identity
        elif exc.path == config.database_path:
            database_identity = exc.identity
        else:  # pragma: no cover - creation helpers receive only these exact paths
            raise DeploymentError("initialization failed at an unexpected state path") from exc
        _require_safe_init_rollback(
            config_path=config_path,
            config_identity=config_identity,
            config=config,
            database_identity=database_identity,
            cause=exc,
        )
        _remove_empty_directories(created_directories)
        raise
    except PrivatePathError as exc:
        _require_safe_init_rollback(
            config_path=config_path,
            config_identity=config_identity,
            config=config,
            database_identity=database_identity,
            cause=exc,
        )
        _remove_empty_directories(created_directories)
        raise DeploymentError("the deployment data directory must be owned mode 0700") from exc
    except (DatabaseError, DeploymentError) as exc:
        _require_safe_init_rollback(
            config_path=config_path,
            config_identity=config_identity,
            config=config,
            database_identity=database_identity,
            cause=exc,
        )
        _remove_empty_directories(created_directories)
        raise
    except Exception as exc:
        _require_safe_init_rollback(
            config_path=config_path,
            config_identity=config_identity,
            config=config,
            database_identity=database_identity,
            cause=exc,
        )
        _remove_empty_directories(created_directories)
        raise DeploymentError("the disabled deployment database could not be initialized") from exc
    _print_json(
        {
            "mode": "disabled",
            "config_created": True,
            "database_initialized": True,
            "downstream_aliases": [],
            "mcp_aliases": [APPROVALS_ALIAS],
            "human_credentials_enrolled": False,
        }
    )


def _migrate_command(config: DisabledDeploymentConfig, destination: Path) -> None:
    if not destination.is_absolute():
        raise DeploymentError("the backup snapshot path must be absolute")
    try:
        backup_parent = ensure_private_directory(destination.parent)
    except PrivatePathError as exc:
        raise DeploymentError("the backup snapshot parent must be owned mode 0700") from exc
    if backup_parent != destination.parent:
        raise DeploymentError("the backup snapshot path must not use symbolic links")
    database = Database(config.database_path)

    def backup(selected: Database, prior_version: int) -> MigrationBackupReceipt:
        snapshot = selected.create_snapshot(destination)
        Database.verify_snapshot(snapshot)
        return MigrationBackupReceipt(
            database_path=selected.path,
            source_schema_version=prior_version,
            artifact_path=snapshot.absolute(),
            artifact_sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),
            verified_restore_schema_version=prior_version,
        )

    try:
        database.initialize(pre_migration_backup=backup)
    except DatabaseError:
        raise
    except Exception as exc:
        raise DeploymentError("the disabled deployment database could not be migrated") from exc
    _print_json({"migrated": True, "backup_snapshot_created": destination.exists()})


def _token_command(config: DisabledDeploymentConfig, args: argparse.Namespace) -> None:
    registry = SQLiteTokenRegistry(
        _current_database(config),
        allowed_principals=config.allowed_principals,
    )
    command = cast(str, args.token_command)
    if command == "issue":
        aliases = config.allowed_principals.get(args.namespace)
        if aliases is None:
            raise DeploymentError("namespace is not present in the deployment config")
        issued = registry.issue(args.namespace, aliases)
        _print_raw_token(issued.token, rotation=False)
        return
    if command == "list":
        _print_json([_metadata_json(item) for item in registry.list_metadata()])
        return
    existing = registry.metadata(args.token_id)
    if existing is None:
        raise DeploymentError("caller token ID does not exist")
    if command == "revoke":
        registry.revoke(args.token_id)
        _print_json(_metadata_json(cast(StoredTokenMetadata, registry.metadata(args.token_id))))
        return
    if command == "rotate":
        issued = registry.rotate(args.token_id)
        _print_raw_token(issued.token, rotation=True)
        return
    raise DeploymentError("unknown token command")


def _validation_report(config: DisabledDeploymentConfig) -> dict[str, Any]:
    database = _current_database(config)
    integrity, foreign_keys = database.integrity_check()
    return {
        "mode": "disabled",
        "database_integrity": integrity,
        "foreign_key_violations": len(foreign_keys),
        "downstream_aliases": [],
        "mcp_aliases": [APPROVALS_ALIAS],
        "principals": [principal.namespace for principal in config.principals],
        "all_gateway_tools_deny": True,
        "human_auth_context_configured": config.human_auth is not None,
        "authorizes_live_actions": False,
    }


def _auth_status(config: DisabledDeploymentConfig) -> dict[str, Any]:
    database = _current_database(config)
    with database.read() as connection:
        rows = connection.execute(
            """
            SELECT kind, count(*) AS count
            FROM auth_credentials
            WHERE disabled_at IS NULL
            GROUP BY kind
            """
        ).fetchall()
    counts = {"password": 0, "totp": 0, "webauthn": 0}
    for row in rows:
        kind = str(row["kind"])
        if kind in counts:
            counts[kind] = int(row["count"])
    return {
        "context_configured": config.human_auth is not None,
        "active_credentials": counts,
        "passkey_browser_ceremony_required": True,
        "secrets_read": False,
        "enrollment_performed": False,
        "authenticated_web_enabled": False,
        "authorizes_live_actions": False,
    }


def _metadata_json(item: StoredTokenMetadata) -> dict[str, Any]:
    return {
        "token_id": item.token_id,
        "namespace": item.namespace,
        "allowed_aliases": list(item.allowed_aliases),
        "created_at": item.created_at,
        "revoked_at": item.revoked_at,
        "rotation_of_token_id": item.rotation_of_token_id,
    }


def _print_raw_token(token: str, *, rotation: bool) -> None:
    try:
        print(token, flush=True)
    except OSError as exc:
        if rotation:
            message = (
                "the replacement token was created but stdout delivery failed; "
                "the old token remains active, so inspect token list and revoke "
                "the linked replacement before retrying"
            )
        else:
            message = (
                "the caller token was created but stdout delivery failed; "
                "inspect token list and revoke the new token before retrying"
            )
        raise DeploymentError(message) from exc


def _read_private_config(path: Path) -> str:
    try:
        parent = ensure_private_directory(path.parent)
    except PrivatePathError as exc:
        raise DeploymentError("the config parent must be owned mode 0700") from exc
    if parent != path.parent:
        raise DeploymentError("the config path must not use symbolic links")
    descriptor: int | None = None
    try:
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_uid != current_uid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size <= 0
            or opened.st_size > _CONFIG_MAX_BYTES
        ):
            raise DeploymentError("the deployment config must be an owned mode-0600 file")
        data = bytearray()
        while len(data) <= _CONFIG_MAX_BYTES:
            chunk = os.read(descriptor, min(8192, _CONFIG_MAX_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        if len(data) > _CONFIG_MAX_BYTES or (opened.st_dev, opened.st_ino, opened.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise DeploymentError("the deployment config changed while it was read")
        return bytes(data).decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise DeploymentError("the deployment config could not be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_private_config(path: Path, config: DisabledDeploymentConfig) -> tuple[int, int]:
    try:
        parent = ensure_private_directory(path.parent)
    except PrivatePathError as exc:
        raise DeploymentError("the config parent must be owned mode 0700") from exc
    if parent != path.parent or path.exists() or path.is_symlink():
        raise DeploymentError("the config destination must be a new nonsymlink path")
    encoded = (json.dumps(config.model_dump(mode="json"), indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if not _private_regular_file(metadata):
            raise OSError("unsafe config file")
        identity = (metadata.st_dev, metadata.st_ino)
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short config write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        _fsync_directory(parent)
    except OSError as exc:
        if identity is not None:
            raise _CreatedFileError(
                "the deployment config could not be created safely",
                path=path,
                identity=identity,
            ) from exc
        raise DeploymentError("the deployment config could not be created safely") from exc
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
    if identity is None:  # pragma: no cover - a successful descriptor always has metadata
        raise DeploymentError("the deployment config identity could not be verified")
    return identity


def _create_private_database(path: Path) -> tuple[int, int]:
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if not _private_regular_file(metadata):
            raise OSError("unsafe database placeholder")
        identity = (metadata.st_dev, metadata.st_ino)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        _fsync_directory(path.parent)
    except OSError as exc:
        if identity is not None:
            raise _CreatedFileError(
                "the deployment database could not be created safely",
                path=path,
                identity=identity,
            ) from exc
        raise DeploymentError("the deployment database could not be created safely") from exc
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
    if identity is None:  # pragma: no cover - a successful descriptor always has metadata
        raise DeploymentError("the deployment database identity could not be verified")
    return identity


def _require_safe_init_rollback(
    *,
    config_path: Path,
    config_identity: tuple[int, int] | None,
    config: DisabledDeploymentConfig,
    database_identity: tuple[int, int] | None,
    cause: Exception,
) -> None:
    database_removed = database_identity is None or _remove_created_database_state(
        config, database_identity
    )
    config_removed = config_identity is None
    if database_removed and config_identity is not None:
        config_removed = _unlink_verified_private_file(config_path, config_identity)
    if not database_removed or not config_removed:
        raise DeploymentError(
            "initialization failed and created state changed before verified cleanup; "
            "preserved it for manual review"
        ) from cause


def _remove_created_database_state(
    config: DisabledDeploymentConfig, database_identity: tuple[int, int]
) -> bool:
    database = config.database_path
    if not _private_file_has_identity(database, database_identity):
        return False
    paths = sorted(
        _reserved_database_paths(config),
        key=lambda path: (path == database, path.name),
    )
    for path in paths:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if path == database:
                return False
            continue
        except OSError:
            return False
        identity = (metadata.st_dev, metadata.st_ino)
        if path == database and identity != database_identity:
            return False
        if not _unlink_verified_private_file(path, identity):
            return False
    try:
        _fsync_directory(config.data_dir)
    except OSError:
        return False
    return True


def _unlink_verified_private_file(path: Path, expected_identity: tuple[int, int]) -> bool:
    descriptor: int | None = None
    try:
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino)
        if (
            identity != expected_identity
            or (before.st_dev, before.st_ino) != identity
            or not _private_regular_file(opened)
        ):
            return False
        current = path.lstat()
        if (current.st_dev, current.st_ino) != identity:
            return False
        path.unlink()
        return True
    except OSError:
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _private_file_has_identity(path: Path, expected_identity: tuple[int, int]) -> bool:
    descriptor: int | None = None
    try:
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        return (
            (before.st_dev, before.st_ino) == expected_identity
            and (opened.st_dev, opened.st_ino) == expected_identity
            and _private_regular_file(opened)
        )
    except OSError:
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _private_regular_file(metadata: os.stat_result) -> bool:
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == current_uid
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == 0o600
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _unique_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _valid_namespace(value: str) -> bool:
    if len(value) < 3 or len(value) > 160 or value.count(":") != 1:
        return False
    prefix, name = value.split(":", 1)
    return (
        bool(prefix)
        and prefix[0].islower()
        and prefix[0].isascii()
        and all(
            character.isascii()
            and (character.islower() or character.isdigit() or character in "_-")
            for character in prefix
        )
        and len(prefix) <= 32
        and bool(name)
        and name[0].isascii()
        and name[0].isalnum()
        and all(
            character.isascii() and (character.isalnum() or character in "._-")
            for character in name
        )
        and len(name) <= 128
    )


def _valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        labels = host.split(".")
        return bool(labels) and all(
            label
            and len(label) <= 63
            and label[0].isalnum()
            and label[-1].isalnum()
            and label.isascii()
            and all(character.isalnum() or character == "-" for character in label)
            for label in labels
        )


def _reserved_database_paths(config: DisabledDeploymentConfig) -> frozenset[Path]:
    database = config.database_path
    return frozenset(
        {
            database,
            database.with_name(f"{database.name}-wal"),
            database.with_name(f"{database.name}-shm"),
            database.with_name(f"{database.name}-journal"),
            database.with_name(f".{database.name}.maintenance.lock"),
        }
    )


def _remove_empty_directories(paths: set[Path]) -> None:
    for path in sorted(paths, key=lambda item: len(item.parts), reverse=True):
        with suppress(OSError):
            path.rmdir()


def _print_json(value: Any) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)
