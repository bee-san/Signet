#!/usr/bin/env python3
"""Safely add Signet's fake-only MCP routes to a blank Hermes profile."""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import secrets
import stat
import sys
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import yaml
from yaml.composer import ComposerError
from yaml.events import AliasEvent, ScalarEvent
from yaml.nodes import MappingNode, Node

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
MAX_YAML_NODES = 50_000
MAX_YAML_DEPTH = 32
MAX_YAML_SCALAR_LENGTH = 16 * 1024
MAX_YAML_ANCHOR_LENGTH = 256
TOKEN_PATTERN = re.compile(r"fake:sgt_[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}")
TOKEN_ASSIGNMENT = re.compile(rb"(?m)^[ \t]*(?:export[ \t]+)?SIGNET_DEMO_MCP_CALLER_TOKEN[ \t]*=")


class ConfigurationError(RuntimeError):
    """The selected profile cannot be changed without weakening isolation."""


@dataclass(frozen=True)
class PrivateFile:
    """A reviewed file snapshot used for compare-before-replace commits."""

    path: Path
    value: bytes
    maximum: int
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


class UniqueKeyLoader(yaml.SafeLoader):
    """Bounded SafeLoader that rejects aliases, merges, and duplicate keys."""

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        self._node_count = 0
        self._compose_depth = 0

    def compose_node(self, parent: Node | None, index: Any) -> Node:
        peek_event = cast(Any, self.peek_event)
        check_event = cast(Any, self.check_event)
        event = peek_event()
        if check_event(AliasEvent):
            raise _yaml_composer_error("YAML aliases are forbidden", event)
        self._compose_depth += 1
        try:
            if self._compose_depth > MAX_YAML_DEPTH:
                raise _yaml_composer_error("YAML exceeds its nesting-depth limit", event)
            anchor = getattr(event, "anchor", None)
            if isinstance(anchor, str) and len(anchor) > MAX_YAML_ANCHOR_LENGTH:
                raise _yaml_composer_error("YAML exceeds its anchor-name limit", event)
            self._node_count += 1
            if self._node_count > MAX_YAML_NODES:
                raise _yaml_composer_error("YAML exceeds its node limit", event)
            if isinstance(event, ScalarEvent) and len(event.value) > MAX_YAML_SCALAR_LENGTH:
                raise _yaml_composer_error("YAML exceeds its scalar-length limit", event)
            return cast(Node, super().compose_node(parent, index))
        finally:
            self._compose_depth -= 1


def _yaml_composer_error(problem: str, event: Any) -> ComposerError:
    mark = getattr(event, "start_mark", None)
    return ComposerError("while composing profile YAML", mark, problem, mark)


def _construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    if any(key.tag == "tag:yaml.org,2002:merge" for key, _ in node.value):
        raise yaml.constructor.ConstructorError(
            "while constructing a mapping",
            node.start_mark,
            "YAML merge keys are forbidden",
            node.start_mark,
        )
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
        config_file = _read_private_file(
            args.config, label="profile config", maximum=MAX_CONFIG_BYTES
        )
        env_file = _read_private_file(
            args.env_file, label="profile environment", maximum=MAX_ENV_BYTES
        )
        fragment_file = _read_private_file(
            args.fragment, label="generated fragment", maximum=MAX_FRAGMENT_BYTES
        )
        _validate_profile_paths(config_file.path, env_file.path)
        config = _yaml_mapping(config_file.value, label="profile config")
        fragment = _yaml_mapping(fragment_file.value, label="generated fragment")
        servers = _validated_fragment(fragment)
        merged = _merge_blank_profile(config, servers)
        token = _read_fake_token()
        updated_env = _append_token(env_file.value, token)
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

    print("Configured 3 fake-only Signet MCP routes in profile signet-demo.")
    return 0


def _read_private_file(path: Path, *, label: str, maximum: int) -> PrivateFile:
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
    return PrivateFile(
        path=selected.resolve(strict=True),
        value=value,
        maximum=maximum,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


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
    except (RecursionError, UnicodeDecodeError, yaml.YAMLError):
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
    if existing == servers:
        return config
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
        raise ConfigurationError("demo token already exists with a different value or form")
    if assignments:
        raise ConfigurationError("disposable profile environment is not blank")
    prefix = env_bytes
    if prefix and not prefix.endswith(b"\n"):
        prefix += b"\n"
    return prefix + f"{TOKEN_NAME}={token}\n".encode("ascii")


def _commit_profile_files(
    *,
    config_file: PrivateFile,
    config_content: bytes,
    env_file: PrivateFile,
    env_content: bytes,
) -> None:
    parent = config_file.path.parent
    directory: int | None = None
    lock: int | None = None
    temporaries: dict[str, str] = {}
    try:
        directory = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        _validate_open_parent(directory, parent)
        lock = _open_profile_lock(directory)
        fcntl.flock(lock, fcntl.LOCK_EX)

        _assert_snapshot(directory, config_file, label="profile config")
        _assert_snapshot(directory, env_file, label="profile environment")

        if env_content != env_file.value:
            temporaries[env_file.path.name] = _prepare_private_temp(
                directory, env_file.path.name, env_content
            )
        if config_content != config_file.value:
            temporaries[config_file.path.name] = _prepare_private_temp(
                directory, config_file.path.name, config_content
            )
        os.fsync(directory)

        env_temporary = temporaries.get(env_file.path.name)
        if env_temporary is not None:
            _assert_snapshot(directory, env_file, label="profile environment")
            os.replace(
                env_temporary,
                env_file.path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            temporaries.pop(env_file.path.name)
            os.fsync(directory)

        config_temporary = temporaries.get(config_file.path.name)
        if config_temporary is not None:
            _assert_expected_content(
                directory,
                env_file.path.name,
                env_content,
                env_file.maximum,
                label="profile environment",
            )
            _assert_snapshot(directory, config_file, label="profile config")
            os.replace(
                config_temporary,
                config_file.path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            temporaries.pop(config_file.path.name)
            os.fsync(directory)
    except OSError as exc:
        raise ConfigurationError("profile files could not be replaced atomically") from exc
    finally:
        if directory is not None:
            for temporary in temporaries.values():
                with suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=directory)
            if lock is not None:
                os.close(lock)
            os.close(directory)


def _validate_open_parent(descriptor: int, path: Path) -> None:
    metadata = os.fstat(descriptor)
    current = path.stat()
    if not stat.S_ISDIR(metadata.st_mode) or (
        metadata.st_dev,
        metadata.st_ino,
    ) != (current.st_dev, current.st_ino):
        raise ConfigurationError("Hermes profile parent changed during configuration")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ConfigurationError("Hermes profile parent must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ConfigurationError("Hermes profile parent must not be group/world writable")


def _open_profile_lock(directory: int) -> int:
    try:
        descriptor = os.open(
            ".signet-configure.lock",
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory,
        )
    except OSError as exc:
        raise ConfigurationError("profile configuration lock is unsafe") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        os.close(descriptor)
        raise ConfigurationError("profile configuration lock is unsafe")
    return descriptor


def _assert_snapshot(directory: int, snapshot: PrivateFile, *, label: str) -> None:
    descriptor = _open_private_target(directory, snapshot.path.name, label=label)
    try:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) != (
            snapshot.device,
            snapshot.inode,
            snapshot.size,
            snapshot.modified_ns,
            snapshot.changed_ns,
        ):
            raise ConfigurationError(f"{label} changed during configuration")
        value = _read_bounded_descriptor(descriptor, snapshot.maximum, label=label)
        if not secrets.compare_digest(value, snapshot.value):
            raise ConfigurationError(f"{label} changed during configuration")
    finally:
        os.close(descriptor)


def _assert_expected_content(
    directory: int,
    name: str,
    expected: bytes,
    maximum: int,
    *,
    label: str,
) -> None:
    descriptor = _open_private_target(directory, name, label=label)
    try:
        value = _read_bounded_descriptor(descriptor, maximum, label=label)
        if not secrets.compare_digest(value, expected):
            raise ConfigurationError(f"{label} changed during configuration")
    finally:
        os.close(descriptor)


def _open_private_target(directory: int, name: str, *, label: str) -> int:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory,
        )
    except OSError as exc:
        raise ConfigurationError(f"{label} changed during configuration") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        os.close(descriptor)
        raise ConfigurationError(f"{label} changed during configuration")
    return descriptor


def _read_bounded_descriptor(descriptor: int, maximum: int, *, label: str) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    value = b"".join(chunks)
    if len(value) > maximum:
        raise ConfigurationError(f"{label} exceeds its size limit")
    return value


def _prepare_private_temp(directory: int, name: str, content: bytes) -> str:
    descriptor: int | None = None
    temporary = ""
    try:
        for _ in range(8):
            temporary = f".{name}.signet-demo-{secrets.token_hex(12)}"
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=directory,
                )
                break
            except FileExistsError:
                continue
        if descriptor is None:
            raise OSError("could not allocate a private temporary file")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        return temporary
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if temporary:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=directory)
        raise ConfigurationError("profile files could not be prepared atomically") from exc


if __name__ == "__main__":
    raise SystemExit(main())
