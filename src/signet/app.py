"""Fail-closed command-line entry point for explicit Signet app factories."""

from __future__ import annotations

import argparse
import re
from collections.abc import Callable, Sequence

import uvicorn

from signet.demo import DemoError, add_demo_parser, run_demo_command
from signet.runtime import RuntimeAssemblyError, _loopback_address

_FACTORY_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*$"
)
Runner = Callable[..., None]


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: Runner | None = None,
) -> None:
    """Run an explicitly assembled MCP or web ASGI factory."""

    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "demo":
        try:
            run_demo_command(args)
        except (DemoError, RuntimeAssemblyError, ValueError) as exc:
            parser.error(str(exc))
        return
    if _FACTORY_PATTERN.fullmatch(args.factory) is None:
        parser.error("--factory must be an explicit module.path:callable reference")
    if args.command == "serve-mcp":
        try:
            _loopback_address(args.host)
        except RuntimeAssemblyError as exc:
            parser.error(str(exc))

    selected_runner = runner or uvicorn.run
    selected_runner(
        args.factory,
        factory=True,
        host=args.host,
        port=args.port,
        server_header=False,
        limit_concurrency=args.limit_concurrency,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="signet")
    subcommands = parser.add_subparsers(dest="command", required=True)

    mcp = subcommands.add_parser("serve-mcp", help="serve an assembled local MCP app")
    _factory_arguments(mcp, default_host="127.0.0.1", default_port=8789)

    web = subcommands.add_parser("serve-web", help="serve an assembled authenticated web app")
    _factory_arguments(web, default_host="127.0.0.1", default_port=8790)
    add_demo_parser(subcommands)
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
