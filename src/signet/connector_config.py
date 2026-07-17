"""Strict, non-secret configuration for staged MCP connector discovery.

This module validates local configuration and reviewed command references only.
It never resolves credentials, opens a network connection, or launches a process.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Never, Self, cast
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from signet.canonical import canonical_json, sha256_hex
from signet.plugin_manifest import ConnectorTemplate, ConnectorTransport

MAX_CONNECTOR_CONFIG_BYTES = 256 * 1024
MAX_CONFIG_JSON_DEPTH = 24
MAX_CONFIG_JSON_NODES = 10_000
MAX_CONFIG_STRING_BYTES = 64 * 1024

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_REFERENCE_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_KEYCHAIN_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
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
_SECRET_ARGUMENT_RE = re.compile(
    r"(?i)^--?(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)"
    r"(?:=|$)"
)
_SHELL_NAMES = frozenset(
    {
        "bash",
        "cmd",
        "cmd.exe",
        "csh",
        "dash",
        "env",
        "fish",
        "ksh",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "sh",
        "tcsh",
        "zsh",
    }
)
_INTERPRETER_NAME_RE = re.compile(
    r"^(?:node(?:js)?|perl|php|python(?:3(?:\.\d+)?)?|ruby)(?:\.exe)?$",
    re.IGNORECASE,
)


class ConnectorConfigError(ValueError):
    """A connector or reviewed command document is unsafe or malformed."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ConnectorConfig(_StrictModel):
    connector_config_version: Literal[1]
    transport: ConnectorTransport
    credential_ref: str
    credential_identity_digest: str
    url: str | None = None
    command_ref: str | None = None
    executable_sha256: str | None = None
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    output_limit_bytes: int = Field(default=1_048_576, ge=1, le=16_777_216)

    @field_validator("credential_ref")
    @classmethod
    def credential_is_reference_only(cls, value: str) -> str:
        return _keychain_reference(value)

    @field_validator("credential_identity_digest")
    @classmethod
    def credential_generation_is_exact(cls, value: str) -> str:
        return _sha256(value, label="credential identity digest")

    @field_validator("url")
    @classmethod
    def endpoint_is_bounded(cls, value: str | None) -> str | None:
        return None if value is None else _connector_url(value)

    @field_validator("command_ref")
    @classmethod
    def command_reference_is_opaque(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _reference(value, label="command reference")

    @field_validator("executable_sha256")
    @classmethod
    def executable_digest_is_exact(cls, value: str | None) -> str | None:
        return None if value is None else _sha256(value, label="executable digest")

    @model_validator(mode="after")
    def transport_fields_are_disjoint(self) -> Self:
        if self.transport == "streamable_http":
            if (
                self.url is None
                or self.command_ref is not None
                or self.executable_sha256 is not None
            ):
                raise ValueError("HTTP connector fields are incomplete or mixed with stdio")
        elif self.url is not None or self.command_ref is None or self.executable_sha256 is None:
            raise ValueError("stdio connector fields are incomplete or mixed with HTTP")
        return self


@dataclass(frozen=True, slots=True)
class ValidatedConnectorConfig:
    config: ConnectorConfig
    canonical_bytes: bytes
    sha256: str


class ReviewedCommandReference(_StrictModel):
    """An operator-reviewed argv boundary; it contains no environment values."""

    command_ref: str
    executable: Path
    executable_sha256: str
    cwd: Path
    snapshot_root: Path
    args: tuple[str, ...] = Field(default=(), max_length=64)

    @field_validator("command_ref")
    @classmethod
    def reviewed_reference_is_opaque(cls, value: str) -> str:
        return _reference(value, label="reviewed command reference")

    @field_validator("executable_sha256")
    @classmethod
    def reviewed_executable_digest_is_exact(cls, value: str) -> str:
        return _sha256(value, label="reviewed executable digest")

    @field_validator("executable", "cwd", "snapshot_root", mode="before")
    @classmethod
    def reviewed_path_text_is_lexical(cls, value: Any) -> Any:
        if isinstance(value, str):
            components = value.split("/")[1:] if value.startswith("/") else []
            if (
                not components
                or any(component in {"", ".", ".."} for component in components)
                or "\x00" in value
            ):
                raise ValueError("reviewed command paths must be absolute lexical paths")
        return value

    @field_validator("executable", "cwd", "snapshot_root")
    @classmethod
    def reviewed_paths_are_absolute(cls, value: Path) -> Path:
        return _absolute_lexical_path(value)

    @field_validator("args")
    @classmethod
    def reviewed_arguments_are_bounded(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        total = 0
        for argument in value:
            encoded = argument.encode("utf-8")
            total += len(encoded)
            if (
                not argument
                or len(encoded) > 4096
                or any(character in argument for character in "\x00\r\n")
                or _SECRET_LIKE_TEXT.search(argument)
                or _SECRET_ARGUMENT_RE.match(argument)
            ):
                raise ValueError("reviewed command argument is invalid")
        if total > 32 * 1024:
            raise ValueError("reviewed command arguments exceed their byte limit")
        return value

    @model_validator(mode="after")
    def executable_is_not_a_shell(self) -> Self:
        executable_name = self.executable.name.lower()
        if executable_name in _SHELL_NAMES or _INTERPRETER_NAME_RE.fullmatch(executable_name):
            raise ValueError("reviewed command executable cannot be a shell or interpreter")
        return self


class ReviewedCommandDocument(_StrictModel):
    reviewed_command_document_version: Literal[1]
    commands: tuple[ReviewedCommandReference, ...] = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def references_are_unique(self) -> Self:
        references = tuple(command.command_ref for command in self.commands)
        if len(references) != len(set(references)):
            raise ValueError("reviewed command references must be unique")
        return self


@dataclass(frozen=True, slots=True)
class ValidatedReviewedCommandDocument:
    document: ReviewedCommandDocument
    canonical_bytes: bytes
    sha256: str


class ReviewedCommandResolver:
    """Resolve an opaque stdio reference without opening or executing its path."""

    def __init__(
        self, document: ReviewedCommandDocument | ValidatedReviewedCommandDocument
    ) -> None:
        selected = (
            document.document
            if isinstance(document, ValidatedReviewedCommandDocument)
            else document
        )
        self._commands = {command.command_ref: command for command in selected.commands}

    def resolve(
        self,
        command_ref: str,
        *,
        executable_sha256: str,
    ) -> ReviewedCommandReference:
        selected_ref = _reference(command_ref, label="command reference")
        selected_digest = _sha256(executable_sha256, label="executable digest")
        command = self._commands.get(selected_ref)
        if command is None:
            raise ConnectorConfigError("reviewed command reference is unavailable")
        if not hmac.compare_digest(command.executable_sha256, selected_digest):
            raise ConnectorConfigError("reviewed command executable digest does not match")
        return command

    def resolve_connector(
        self,
        config: ConnectorConfig | ValidatedConnectorConfig,
    ) -> ReviewedCommandReference:
        selected = config.config if isinstance(config, ValidatedConnectorConfig) else config
        if (
            selected.transport != "stdio"
            or selected.command_ref is None
            or selected.executable_sha256 is None
        ):
            raise ConnectorConfigError("only a complete stdio connector has a command reference")
        return self.resolve(
            selected.command_ref,
            executable_sha256=selected.executable_sha256,
        )


def parse_connector_config(
    document: bytes,
    *,
    template: ConnectorTemplate | None = None,
) -> ValidatedConnectorConfig:
    """Validate connector JSON and optionally bind it to one plugin template."""

    raw = _parse_json(document, label="connector configuration")
    if not isinstance(raw, dict):
        raise ConnectorConfigError("connector configuration root must be an object")
    version = raw.get("connector_config_version")
    if version != 1 or isinstance(version, bool):
        raise ConnectorConfigError("unsupported connector configuration version")
    _reject_secret_like_values(raw)
    try:
        model = ConnectorConfig.model_validate_json(canonical_json(raw), strict=True)
    except ValidationError as exc:
        raise ConnectorConfigError("connector configuration schema is invalid") from exc
    except (TypeError, ValueError) as exc:
        raise ConnectorConfigError("connector configuration is not canonicalizable JSON") from exc
    if template is not None:
        validate_connector_template(model, template)
    canonical = canonical_json(model.model_dump(mode="json", exclude_none=True))
    return ValidatedConnectorConfig(
        config=model,
        canonical_bytes=canonical,
        sha256=sha256_hex(canonical),
    )


def load_connector_config(
    path: str | os.PathLike[str],
    *,
    template: ConnectorTemplate | None = None,
    expected_sha256: str | None = None,
) -> ValidatedConnectorConfig:
    """Read one bounded local connector configuration and validate its identity."""

    validated = parse_connector_config(
        _read_bounded_regular(Path(path), label="connector configuration"),
        template=template,
    )
    if expected_sha256 is not None:
        expected = _sha256(expected_sha256, label="expected connector configuration digest")
        if not hmac.compare_digest(validated.sha256, expected):
            raise ConnectorConfigError("connector configuration canonical digest does not match")
    return validated


def validate_connector_template(
    config: ConnectorConfig | ValidatedConnectorConfig,
    template: ConnectorTemplate,
) -> ConnectorConfig:
    """Require the connector transport to be allowed by the exact plugin template."""

    selected = config.config if isinstance(config, ValidatedConnectorConfig) else config
    if selected.transport not in template.transports:
        raise ConnectorConfigError("connector transport is not allowed by the plugin template")
    return selected


def parse_reviewed_command_document(document: bytes) -> ValidatedReviewedCommandDocument:
    """Validate a non-secret reviewed command-reference document."""

    raw = _parse_json(document, label="reviewed command document")
    if not isinstance(raw, dict):
        raise ConnectorConfigError("reviewed command document root must be an object")
    version = raw.get("reviewed_command_document_version")
    if version != 1 or isinstance(version, bool):
        raise ConnectorConfigError("unsupported reviewed command document version")
    _reject_secret_like_values(raw)
    try:
        model = ReviewedCommandDocument.model_validate_json(canonical_json(raw), strict=True)
    except ValidationError as exc:
        raise ConnectorConfigError("reviewed command document schema is invalid") from exc
    except (TypeError, ValueError) as exc:
        raise ConnectorConfigError("reviewed command document is not canonicalizable JSON") from exc
    canonical = canonical_json(model.model_dump(mode="json"))
    return ValidatedReviewedCommandDocument(
        document=model,
        canonical_bytes=canonical,
        sha256=sha256_hex(canonical),
    )


def load_reviewed_command_document(
    path: str | os.PathLike[str],
    *,
    expected_sha256: str | None = None,
) -> ValidatedReviewedCommandDocument:
    """Read a bounded local reviewed command-reference document."""

    validated = parse_reviewed_command_document(
        _read_bounded_regular(Path(path), label="reviewed command document")
    )
    if expected_sha256 is not None:
        expected = _sha256(expected_sha256, label="expected command document digest")
        if not hmac.compare_digest(validated.sha256, expected):
            raise ConnectorConfigError("reviewed command document digest does not match")
    return validated


def _connector_url(value: str) -> str:
    _bounded_text(value, maximum=8192, label="connector URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("connector URL is invalid") from None
    hostname = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or hostname is None
        or not hostname.isascii()
        or parsed.username is not None
        or parsed.password is not None
        or "?" in value
        or "#" in value
        or (port is not None and not 1 <= port <= 65535)
        or "\\" in value
    ):
        raise ValueError("connector URL contains unsupported components")
    if parsed.scheme == "http" and not _loopback_host(hostname):
        raise ValueError("cleartext connector URLs are limited to loopback")
    return value


def _loopback_host(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _keychain_reference(value: str) -> str:
    _bounded_text(value, maximum=512, label="credential reference")
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ValueError("credential reference is invalid") from None
    account = parsed.path.removeprefix("/")
    if (
        not value.startswith("keychain://")
        or parsed.scheme != "keychain"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != f"/{account}"
        or not account
        or "/" in account
        or "?" in value
        or "#" in value
        or _KEYCHAIN_COMPONENT_RE.fullmatch(parsed.netloc) is None
        or _KEYCHAIN_COMPONENT_RE.fullmatch(account) is None
    ):
        raise ValueError("credential reference must be an exact keychain reference")
    return value


def _reference(value: str, *, label: str) -> str:
    if len(value.encode("utf-8")) > 128 or _REFERENCE_RE.fullmatch(value) is None:
        raise ConnectorConfigError(f"{label} must be an opaque bounded identifier")
    return value


def _sha256(value: str, *, label: str) -> str:
    if _SHA256_RE.fullmatch(value) is None:
        raise ConnectorConfigError(f"{label} must be lowercase SHA-256")
    return value


def _absolute_lexical_path(value: Path) -> Path:
    text = str(value)
    if (
        not value.is_absolute()
        or not text
        or "\x00" in text
        or "~" in value.parts
        or any(part in {"", ".", ".."} for part in value.parts)
        or len(os.fsencode(value)) > 4096
    ):
        raise ValueError("reviewed command paths must be absolute lexical paths")
    return value


def _bounded_text(value: str, *, maximum: int, label: str) -> str:
    if (
        not value
        or value.strip() != value
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or _SECRET_LIKE_TEXT.search(value)
    ):
        raise ValueError(f"{label} is invalid or unbounded")
    return value


def _parse_json(document: bytes, *, label: str) -> Any:
    if (
        not isinstance(document, bytes)
        or not document
        or len(document) > MAX_CONNECTOR_CONFIG_BYTES
    ):
        raise ConnectorConfigError(f"{label} exceeds its byte limit or is empty")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ConnectorConfigError(f"{label} contains a duplicate JSON key")
            value[key] = item
        return value

    try:
        value = json.loads(
            document.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_constant=_reject_json_constant,
        )
    except ConnectorConfigError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ConnectorConfigError(f"{label} is not strict UTF-8 JSON") from exc
    _validate_json_bounds(value, label=label)
    return value


def _validate_json_bounds(value: Any, *, label: str) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_CONFIG_JSON_NODES or depth > MAX_CONFIG_JSON_DEPTH:
            raise ConnectorConfigError(f"{label} exceeds its structural limits")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 256:
                    raise ConnectorConfigError(f"{label} contains an invalid object key")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > MAX_CONFIG_STRING_BYTES:
                raise ConnectorConfigError(f"{label} contains an oversized string")
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ConnectorConfigError(f"{label} contains a non-finite number")
        elif item is not None and not isinstance(item, (bool, int)):
            raise ConnectorConfigError(f"{label} contains a non-JSON value")

    visit(value, 0)


def _reject_secret_like_values(value: Any) -> None:
    def visit(item: Any) -> None:
        if isinstance(item, str):
            if _SECRET_LIKE_TEXT.search(item):
                raise ConnectorConfigError("configuration contains credential-like material")
        elif isinstance(item, dict):
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)


def _read_bounded_regular(path: Path, *, label: str) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAX_CONNECTOR_CONFIG_BYTES
        ):
            raise ConnectorConfigError(f"{label} must be a bounded regular local file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size < 1
            or opened.st_size > MAX_CONNECTOR_CONFIG_BYTES
        ):
            raise ConnectorConfigError(f"{label} must be a bounded regular local file")
        chunks: list[bytes] = []
        remaining = MAX_CONNECTOR_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        document = b"".join(chunks)
        after = os.fstat(descriptor)
        try:
            current = path.lstat()
        except OSError as exc:
            raise ConnectorConfigError(f"{label} changed while it was read") from exc
        if (
            len(document) > MAX_CONNECTOR_CONFIG_BYTES
            or _file_identity(opened) != _file_identity(after)
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ConnectorConfigError(f"{label} changed while it was read")
        return document
    except ConnectorConfigError:
        raise
    except (OSError, ValueError) as exc:
        raise ConnectorConfigError(f"{label} is unavailable or not a safe local file") from exc
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


def detached_connector_document(value: ValidatedConnectorConfig) -> dict[str, Any]:
    """Return a detached copy of the complete canonical v1 document."""

    return cast(dict[str, Any], json.loads(value.canonical_bytes))


def _reject_json_constant(value: str) -> Never:
    raise ValueError(f"unsupported JSON constant: {value}")
