#!/usr/bin/env python3
"""Safely add Signet's fake-only MCP routes to a blank Hermes profile."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import yaml

PROFILE_NAME = "signet-demo"
TOKEN_NAME = "SIGNET_DEMO_MCP_CALLER_TOKEN"  # nosec B105
SERVER_ALIASES = {
    "signet_demo_fastmail": "fastmail",
    "signet_demo_whatsapp": "whatsapp",
    "signet_demo_approvals": "approvals",
}
MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_ENV_BYTES = 1024 * 1024
MAX_FRAGMENT_BYTES = 256 * 1024
TOKEN_PATTERN = re.compile(r"fake:sgt_[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}")
TOKEN_ASSIGNMENT = re.compile(
    rb"(?m)^[ \t]*(?:export[ \t]+)?SIGNET_DEMO_MCP_CALLER_TOKEN[ \t]*="
)


class ConfigurationError(RuntimeError):
    """The selected profile cannot be changed without weakening isolation."""


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that also rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found a duplicate key",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Configure only a new, blank signet-demo Hermes profile."
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--fragment", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        config_path, config_bytes = _read_private_file(
            args.config, label="profile config", maximum=MAX_CONFIG_BYTES
        )
        env_path, env_bytes = _read_private_file(
            args.env_file, label="profile environment", maximum=MAX_ENV_BYTES
        )
        _, fragment_bytes = _read_private_file(
            args.fragment, label="generated fragment", maximum=MAX_FRAGMENT_BYTES
        )
        _validate_profile_paths(config_path, env_path)
        config = _yaml_mapping(config_bytes, label="profile config")
        fragment = _yaml_mapping(fragment_bytes, label="generated fragment")
        servers = _validated_fragment(fragment)
        merged = _merge_blank_profile(config, servers)
        token = _read_fake_token()
        updated_env = _append_token(env_bytes, token)
        rendered = yaml.safe_dump(
            merged,
            allow_unicode=False,
            default_flow_style=False,
            sort_keys=False,
        ).encode("utf-8")
        if len(rendered) > MAX_CONFIG_BYTES:
            raise ConfigurationError("merged profile config exceeds its size limit")
        _atomic_replace(env_path, updated_env)
        _atomic_replace(config_path, rendered)
    except ConfigurationError as exc:
        parser.exit(1, f"error: {exc}\n")

    print("Configured 3 fake-only Signet MCP routes in profile signet-demo.")
    return 0


def _read_private_file(path: Path, *, label: str, maximum: int) -> tuple[Path, bytes]:
    selected = path.expanduser().absolute()
    try:
        if selected.is_symlink():
            raise ConfigurationError(f"{label} must not be a symlink")
        descriptor = os.open(
            selected,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except ConfigurationError:
        raise
    except OSError as exc:
        raise ConfigurationError(f"{label} must be an existing private file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ConfigurationError(f"{label} must be a regular file")
        if metadata.st_nlink != 1:
            raise ConfigurationError(f"{label} must have exactly one filesystem link")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ConfigurationError(f"{label} must be owned by the current user")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ConfigurationError(f"{label} must have mode 0600")
        if metadata.st_size > maximum:
            raise ConfigurationError(f"{label} exceeds its size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            value = stream.read(maximum + 1)
        if len(value) > maximum:
            raise ConfigurationError(f"{label} exceeds its size limit")
    finally:
        os.close(descriptor)
    return selected.resolve(strict=True), value


def _validate_profile_paths(config: Path, env_file: Path) -> None:
    if config.parent != env_file.parent or config.parent.name != PROFILE_NAME:
        raise ConfigurationError("paths must belong to the disposable signet-demo profile")
    if config.name != "config.yaml" or env_file.name != ".env":
        raise ConfigurationError("Hermes profile files must be config.yaml and .env")
    parent = config.parent
    metadata = parent.stat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ConfigurationError("Hermes profile parent must be a directory")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ConfigurationError("Hermes profile parent must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ConfigurationError("Hermes profile parent must not be group/world writable")


def _yaml_mapping(raw: bytes, *, label: str) -> dict[str, Any]:
    loader: UniqueKeyLoader | None = None
    try:
        loader = UniqueKeyLoader(raw)
        value = loader.get_single_data()
    except (UnicodeDecodeError, yaml.YAMLError):
        raise ConfigurationError(f"{label} is not valid unique-key YAML") from None
    finally:
        if loader is not None:
            cast(Any, loader).dispose()
    if value is None:
        return {}
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ConfigurationError(f"{label} must contain one string-keyed mapping")
    return value


def _validated_fragment(fragment: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if set(fragment) != {"mcp_servers"} or not isinstance(fragment["mcp_servers"], dict):
        raise ConfigurationError("generated fragment must contain only mcp_servers")
    raw_servers = fragment["mcp_servers"]
    if set(raw_servers) != set(SERVER_ALIASES):
        raise ConfigurationError("generated fragment has an unexpected server set")
    servers: dict[str, dict[str, Any]] = {}
    for name, alias in SERVER_ALIASES.items():
        server = raw_servers[name]
        if not isinstance(server, dict):
            raise ConfigurationError("generated fragment contains an invalid server")
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
            raise ConfigurationError("generated fragment weakens the required MCP controls")
        url = server.get("url")
        if not isinstance(url, str) or not _exact_demo_url(url, alias):
            raise ConfigurationError("generated fragment contains a non-loopback MCP URL")
        servers[name] = dict(server)
    return servers


def _exact_demo_url(value: str, alias: str) -> bool:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and port is not None
        and 1024 <= port <= 65535
        and parsed.path == f"/mcp/{alias}"
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
    )


def _merge_blank_profile(
    config: dict[str, Any],
    servers: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    existing = config.get("mcp_servers")
    if existing not in (None, {}):
        raise ConfigurationError("disposable profile already contains MCP servers")
    merged = dict(config)
    merged["mcp_servers"] = servers
    return merged


def _read_fake_token() -> str:
    raw = sys.stdin.buffer.read(513)
    if len(raw) > 512:
        raise ConfigurationError("fake token input exceeds its size limit")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if b"\n" in raw or b"\r" in raw:
        raise ConfigurationError("fake token input must contain exactly one line")
    try:
        token = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ConfigurationError("fake token input must be ASCII") from None
    if TOKEN_PATTERN.fullmatch(token) is None:
        raise ConfigurationError("token input is not an explicit fake-only token")
    return token


def _append_token(env_bytes: bytes, token: str) -> bytes:
    if b"\x00" in env_bytes:
        raise ConfigurationError("profile environment contains invalid bytes")
    if TOKEN_ASSIGNMENT.search(env_bytes):
        raise ConfigurationError("demo token already exists in the profile environment")
    try:
        text = env_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigurationError("profile environment is not valid UTF-8") from None
    assignments = [
        line
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if assignments:
        raise ConfigurationError("disposable profile environment is not blank")
    prefix = env_bytes
    if prefix and not prefix.endswith(b"\n"):
        prefix += b"\n"
    return prefix + f"{TOKEN_NAME}={token}\n".encode("ascii")


def _atomic_replace(path: Path, content: bytes) -> None:
    parent = path.parent
    temporary = parent / f".{path.name}.signet-demo-{os.getpid()}"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise ConfigurationError("profile files could not be replaced atomically") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
