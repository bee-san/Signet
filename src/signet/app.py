"""Fail-closed command-line entry point for explicit Signet app factories."""

from __future__ import annotations

import argparse
import re
import sys
import time
from collections.abc import Callable, Sequence
from typing import Literal

import uvicorn

from signet.credential_broker import CredentialError
from signet.db import Database, DatabaseError
from signet.demo import DemoError, add_demo_parser, run_demo_command
from signet.deployment import DeploymentError, add_deployment_parser, run_deployment_command
from signet.integration_cli import (
    IntegrationCLIError,
    add_integration_parsers,
    run_integration_command,
)
from signet.runtime import RuntimeAssemblyError, _loopback_address
from signet.setup_cli import add_setup_parsers, is_setup_command, run_setup_command
from signet.setup_state import SetupError

_FACTORY_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*$"
)
_PRODUCTION_FACTORIES: dict[tuple[str, str], Literal["mcp", "web"]] = {
    (
        "serve-mcp",
        "signet.production:create_production_mcp_app_from_environment",
    ): "mcp",
    (
        "serve-web",
        "signet.production:create_production_web_app_from_environment",
    ): "web",
}
Runner = Callable[..., None]


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: Runner | None = None,
) -> None:
    """Run an explicitly assembled MCP or web ASGI factory."""

    parser = _parser()
    if not _supported_platform(sys.platform):
        parser.error("Signet supports Linux and macOS only")
    args = parser.parse_args(argv)
    if args.command == "demo":
        try:
            run_demo_command(args)
        except (DemoError, RuntimeAssemblyError, ValueError) as exc:
            parser.error(str(exc))
        return
    if args.command == "deployment":
        try:
            run_deployment_command(args, runner=runner or uvicorn.run)
        except (
            CredentialError,
            DatabaseError,
            DeploymentError,
            RuntimeAssemblyError,
            ValueError,
        ) as exc:
            parser.error(str(exc))
        return
    if args.command in {"plugin", "connector"}:
        try:
            run_integration_command(args)
        except IntegrationCLIError as exc:
            parser.error(str(exc))
        return
    if is_setup_command(args.command):
        try:
            run_setup_command(args, runner=runner or uvicorn.run)
        except (CredentialError, DatabaseError, SetupError, ValueError) as exc:
            parser.error(str(exc))
        return
    if args.command == "bootstrap":
        from signet.authenticator_management import KeychainTotpSecretProvisioner
        from signet.browser_auth import BootstrapError, BootstrapService
        from signet.credential_broker import KeychainSecretStore
        from signet.production import load_production_config
        from signet.totp_enrollment import TotpEnrollmentCleanupError, TotpEnrollmentService

        try:
            config = load_production_config(args.config)
            database = Database(config.storage.database_path)
            database.initialize()
            totp_enrollments = TotpEnrollmentService(
                database,
                provisioner=KeychainTotpSecretProvisioner(),
                secret_store=KeychainSecretStore(),
            )
            capability = BootstrapService(
                database,
                owner_user_id=config.owner_user_id,
                totp_enrollments=totp_enrollments,
            ).issue_capability(now=int(time.time()), lifetime=args.lifetime)
        except (
            BootstrapError,
            CredentialError,
            DatabaseError,
            TotpEnrollmentCleanupError,
            ValueError,
        ) as exc:
            parser.error(str(exc))
        print(capability)
        return
    if _FACTORY_PATTERN.fullmatch(args.factory) is None:
        parser.error("--factory must be an explicit module.path:callable reference")
    if args.command in {"serve-mcp", "serve-web"}:
        try:
            _loopback_address(args.host)
        except RuntimeAssemblyError as exc:
            parser.error(str(exc))
    production_service = _PRODUCTION_FACTORIES.get((args.command, args.factory))
    if production_service is not None:
        from signet.production import (
            ProductionAssemblyError,
            production_listener_from_environment,
        )

        try:
            expected_host, expected_port = production_listener_from_environment(production_service)
        except (ProductionAssemblyError, ValueError) as exc:
            parser.error(str(exc))
        if (args.host, args.port) != (expected_host, expected_port):
            parser.error("listener host and port must match the production configuration")

    selected_runner = runner or uvicorn.run
    selected_runner(
        args.factory,
        factory=True,
        host=args.host,
        port=args.port,
        server_header=False,
        limit_concurrency=args.limit_concurrency,
        proxy_headers=False,
    )


def _supported_platform(value: str) -> bool:
    return value == "darwin" or value.startswith("linux")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="signet")
    subcommands = parser.add_subparsers(dest="command", required=True)

    mcp = subcommands.add_parser("serve-mcp", help="serve an assembled local MCP app")
    _factory_arguments(mcp, default_host="127.0.0.1", default_port=8789)

    web = subcommands.add_parser("serve-web", help="serve an assembled authenticated web app")
    _factory_arguments(web, default_host="127.0.0.1", default_port=8790)
    bootstrap = subcommands.add_parser(
        "bootstrap",
        help="perform an attended local owner-bootstrap ceremony",
    )
    bootstrap_commands = bootstrap.add_subparsers(dest="bootstrap_command", required=True)
    issue = bootstrap_commands.add_parser("issue", help="issue one short-lived setup capability")
    issue.add_argument("--config", required=True, help="private production JSON configuration")
    issue.add_argument("--lifetime", type=int, choices=range(60, 3601), default=600)
    add_demo_parser(subcommands)
    add_deployment_parser(subcommands)
    add_integration_parsers(subcommands)
    add_setup_parsers(subcommands)
    return parser


def _factory_arguments(
    parser: argparse.ArgumentParser,
    *,
    default_host: str,
    default_port: int,
) -> None:
    parser.add_argument(
        "--factory",
        required=True,
        help="explicit ASGI application factory as module.path:callable",
    )
    parser.add_argument("--host", default=default_host)
    parser.add_argument("--port", type=int, choices=range(1024, 65536), default=default_port)
    parser.add_argument(
        "--limit-concurrency",
        type=int,
        choices=range(1, 257),
        default=64,
        help="maximum concurrent server tasks before admission is refused",
    )
