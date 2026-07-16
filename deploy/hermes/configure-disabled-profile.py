#!/usr/bin/env python3
"""Safely configure Signet's persistent downstream-disabled Hermes profile."""

from __future__ import annotations

import argparse
import os
import re
import runpy
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

PROFILE_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,63}")
TOKEN_NAME = "SIGNET_DISABLED_MCP_CALLER_TOKEN"  # nosec B105
TOKEN_PATTERN = re.compile(r"sgt_[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}")
TOKEN_ASSIGNMENT = re.compile(
    rb"(?m)^[ \t]*(?:export[ \t]+)?SIGNET_DISABLED_MCP_CALLER_TOKEN[ \t]*="
)
SERVER_NAME = "signet_disabled_approvals"
MAX_TOKEN_INPUT_BYTES = 65

# The fake and persistent configurators share the same descriptor-verified file
# transaction. Loading the sibling avoids two security-critical implementations.
_SUPPORT = runpy.run_path(str(Path(__file__).with_name("configure-demo-profile.py")))
ConfigurationError = _SUPPORT["ConfigurationError"]
MAX_CONFIG_BYTES = _SUPPORT["MAX_CONFIG_BYTES"]
MAX_ENV_BYTES = _SUPPORT["MAX_ENV_BYTES"]
MAX_FRAGMENT_BYTES = _SUPPORT["MAX_FRAGMENT_BYTES"]
_commit_profile_files = _SUPPORT["_commit_profile_files"]
_read_private_file = _SUPPORT["_read_private_file"]
_yaml_mapping = _SUPPORT["_yaml_mapping"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Configure one dedicated Hermes profile for Signet's "
            "persistent downstream-disabled approvals route."
        )
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--fragment", type=Path, required=True)
    parser.add_argument("--mcp-port", type=_port, default=8789)
    args = parser.parse_args(argv)

    try:
        _validate_argument_path(args.config, label="profile config")
        _validate_argument_path(args.env_file, label="profile environment")
        _validate_argument_path(args.fragment, label="reviewed fragment")
        config_file = _read_private_file(
            args.config, label="profile config", maximum=MAX_CONFIG_BYTES
        )
        env_file = _read_private_file(
            args.env_file, label="profile environment", maximum=MAX_ENV_BYTES
        )
        fragment_file = _read_private_file(
            args.fragment, label="reviewed fragment", maximum=MAX_FRAGMENT_BYTES
        )
        _validate_profile_paths(config_file.path, env_file.path, args.profile)
        config = _yaml_mapping(config_file.value, label="profile config")
        fragment = _yaml_mapping(fragment_file.value, label="reviewed fragment")
        server = _validated_fragment(fragment, mcp_port=args.mcp_port)
        merged = _merge_dedicated_profile(config, server)
        token = _read_token()
        updated_env = _install_token(env_file.value, token)
        rendered = yaml.safe_dump(
            merged,
            allow_unicode=False,
            default_flow_style=False,
            sort_keys=False,
        ).encode("utf-8")
        if len(rendered) > MAX_CONFIG_BYTES:
            raise ConfigurationError("merged profile config exceeds its size limit")
        _commit_profile_files(
            config_file=config_file,
            config_content=rendered,
            env_file=env_file,
            env_content=updated_env,
        )
    except ConfigurationError as exc:
        parser.exit(1, f"error: {exc}\n")

    print("Configured one downstream-disabled Signet MCP route in the dedicated profile.")
    return 0


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("MCP port must be an integer") from None
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("MCP port must be between 1024 and 65535")
    return port


def _validate_argument_path(path: Path, *, label: str) -> None:
    if not path.is_absolute():
        raise ConfigurationError(f"{label} path must be absolute")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ConfigurationError(f"{label} must be an existing file") from exc
    if path != resolved:
        raise ConfigurationError(f"{label} path must be canonical and contain no symlinks")


def _validate_profile_paths(config: Path, env_file: Path, profile: str) -> None:
    if PROFILE_PATTERN.fullmatch(profile) is None:
        raise ConfigurationError("Hermes profile name is invalid")
    if config.parent != env_file.parent or config.parent.name != profile:
        raise ConfigurationError("paths do not belong to the selected Hermes profile")
    if config.name != "config.yaml" or env_file.name != ".env":
        raise ConfigurationError("Hermes profile files must be config.yaml and .env")
    parent = config.parent
    try:
        metadata = parent.stat()
    except OSError:
        raise ConfigurationError("Hermes profile parent is unavailable") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise ConfigurationError("Hermes profile parent must be a directory")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ConfigurationError("Hermes profile parent must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ConfigurationError("Hermes profile parent must not be group/world writable")


def _validated_fragment(fragment: Mapping[str, Any], *, mcp_port: int) -> dict[str, Any]:
    if set(fragment) != {"mcp_servers"} or not isinstance(fragment["mcp_servers"], dict):
        raise ConfigurationError("reviewed fragment must contain only mcp_servers")
    raw_servers = fragment["mcp_servers"]
    if set(raw_servers) != {SERVER_NAME}:
        raise ConfigurationError("reviewed fragment has an unexpected server set")
    server = raw_servers[SERVER_NAME]
    if not isinstance(server, dict):
        raise ConfigurationError("reviewed fragment contains an invalid server")
    expected = {
        "headers": {"Authorization": f"Bearer ${{{TOKEN_NAME}}}"},
        "enabled": True,
        "connect_timeout": 10,
        "timeout": 120,
        "supports_parallel_tool_calls": False,
        "tools": {"resources": False, "prompts": False},
        "sampling": {"enabled": False},
    }
    if {key: value for key, value in server.items() if key != "url"} != expected:
        raise ConfigurationError("reviewed fragment weakens the required MCP controls")
    url = server.get("url")
    if not isinstance(url, str) or not _exact_disabled_url(url, mcp_port=mcp_port):
        raise ConfigurationError("reviewed fragment contains an unexpected MCP URL")
    return dict(server)


def _exact_disabled_url(value: str, *, mcp_port: int) -> bool:
    return value == f"http://127.0.0.1:{mcp_port}/mcp/approvals"


def _merge_dedicated_profile(config: dict[str, Any], server: dict[str, Any]) -> dict[str, Any]:
    expected = {SERVER_NAME: server}
    existing = config.get("mcp_servers")
    if config == {"mcp_servers": expected}:
        return config
    if existing not in (None, {}):
        raise ConfigurationError("dedicated profile already contains MCP servers")
    if config:
        raise ConfigurationError("dedicated profile config is not blank")
    return {"mcp_servers": expected}


def _read_token() -> str:
    if sys.stdin.isatty():
        raise ConfigurationError("token input must be piped on stdin")
    try:
        raw = sys.stdin.buffer.read(MAX_TOKEN_INPUT_BYTES + 1)
    except OSError as exc:
        raise ConfigurationError("token input could not be read") from exc
    if len(raw) > MAX_TOKEN_INPUT_BYTES:
        raise ConfigurationError("token input exceeds its size limit")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if b"\n" in raw or b"\r" in raw or b"\x00" in raw:
        raise ConfigurationError("token input must contain exactly one LF-terminated line")
    try:
        token = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ConfigurationError("token input must be ASCII") from None
    if TOKEN_PATTERN.fullmatch(token) is None:
        raise ConfigurationError("token input is not an exact Signet caller token")
    return token


def _install_token(env_bytes: bytes, token: str) -> bytes:
    if b"\x00" in env_bytes:
        raise ConfigurationError("profile environment contains invalid bytes")
    try:
        text = env_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigurationError("profile environment is not valid UTF-8") from None
    assignments = [
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    exact_assignment = f"{TOKEN_NAME}={token}"
    if assignments == [exact_assignment]:
        return env_bytes
    if TOKEN_ASSIGNMENT.search(env_bytes):
        raise ConfigurationError("disabled token already exists with a different value or form")
    if assignments:
        raise ConfigurationError("dedicated profile environment is not blank")
    prefix = env_bytes
    if prefix and not prefix.endswith(b"\n"):
        prefix += b"\n"
    updated = prefix + f"{TOKEN_NAME}={token}\n".encode("ascii")
    if len(updated) > MAX_ENV_BYTES:
        raise ConfigurationError("profile environment exceeds its size limit")
    return updated


if __name__ == "__main__":
    raise SystemExit(main())
