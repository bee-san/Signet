"""Bounded, synthetic-only protocol for optional plugin extension workers.

Workers are never imported into the Signet process.  A reviewed command
reference resolves to one executable, whose SHA-256 is checked immediately
before every launch.  The child receives one canonical JSON line and must
return one canonical JSON line matching the operation-specific response
schema.

The v1 boundary is deliberately limited to fake onboarding material.  It has
no credential resolver, database handle, attachment catalogue, or downstream
MCP client.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import signal
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Never, Protocol, cast

from signet.canonical import CanonicalizationError, canonical_json

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_REFERENCE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SECRET_TEXT_RE = re.compile(
    r"(?i)(?:authorization\s*[:=]\s*bearer\s+\S+|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*\S+)"
)
_FORBIDDEN_PAYLOAD_KEYS = frozenset(
    {
        "attachment_path",
        "credential_value",
        "database_path",
        "downstream_client",
        "encryption_key",
        "private_key",
        "secret_value",
    }
)
_SHELL_NAMES = frozenset(
    {
        "bash",
        "csh",
        "dash",
        "fish",
        "ksh",
        "powershell",
        "pwsh",
        "sh",
        "tcsh",
        "zsh",
    }
)


class WorkerOperation(StrEnum):
    IDENTITY = "identity"
    VALIDATE_SCHEMA = "validate_schema"
    CANONICALIZE = "canonicalize"
    REVIEW_SUMMARY = "review_summary"
    REDACT = "redact"
    CLASSIFY_FAKE_OUTCOME = "classify_fake_outcome"


class ExtensionWorkerError(RuntimeError):
    """A secret-free worker failure safe to expose to an operator."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ExtensionWorkerTimeout(ExtensionWorkerError):
    pass


class ExtensionWorkerProtocolError(ExtensionWorkerError):
    pass


@dataclass(frozen=True, slots=True)
class WorkerLimits:
    timeout_seconds: float = 5.0
    input_limit_bytes: int = 512 * 1024
    output_limit_bytes: int = 512 * 1024
    stderr_limit_bytes: int = 16 * 1024
    max_nodes: int = 16_384
    max_depth: int = 32
    max_scalar_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        if not 0.05 <= self.timeout_seconds <= 30:
            raise ValueError("worker timeout must be between 0.05 and 30 seconds")
        if not 1 <= self.input_limit_bytes <= 4 * 1024 * 1024:
            raise ValueError("worker input limit is invalid")
        if not 1 <= self.output_limit_bytes <= 4 * 1024 * 1024:
            raise ValueError("worker output limit is invalid")
        if not 1 <= self.stderr_limit_bytes <= 256 * 1024:
            raise ValueError("worker stderr limit is invalid")
        if not 1 <= self.max_nodes <= 100_000 or not 1 <= self.max_depth <= 64:
            raise ValueError("worker structural limits are invalid")
        if not 1 <= self.max_scalar_bytes <= 256 * 1024:
            raise ValueError("worker scalar limit is invalid")


@dataclass(frozen=True, slots=True)
class ReviewedWorkerCommand:
    """Operator-reviewed resolution of an opaque manifest command reference."""

    command_ref: str
    executable: Path
    executable_sha256: str
    arguments: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        path = Path(self.executable)
        if _REFERENCE_RE.fullmatch(self.command_ref) is None:
            raise ValueError("worker command reference is invalid")
        if not path.is_absolute() or "\x00" in str(path):
            raise ValueError("worker executable path must be absolute")
        if _SHA256_RE.fullmatch(self.executable_sha256) is None:
            raise ValueError("worker executable digest must be a lowercase SHA-256")
        if len(self.arguments) > 32:
            raise ValueError("worker command has too many arguments")
        total = 0
        for argument in self.arguments:
            if (
                not isinstance(argument, str)
                or not argument
                or any(character in argument for character in "\x00\r\n")
            ):
                raise ValueError("worker command argument is invalid")
            total += len(argument.encode("utf-8"))
        if total > 32 * 1024:
            raise ValueError("worker command arguments are oversized")
        if path.name.lower() in _SHELL_NAMES:
            raise ValueError("worker command may not resolve to a shell")
        object.__setattr__(self, "executable", path)


class WorkerCommandResolver(Protocol):
    def resolve(self, command_ref: str) -> ReviewedWorkerCommand: ...


class StaticWorkerCommandResolver:
    """Small explicit resolver suitable for assembled runtimes and tests."""

    def __init__(self, commands: Sequence[ReviewedWorkerCommand]) -> None:
        selected: dict[str, ReviewedWorkerCommand] = {}
        for command in commands:
            if command.command_ref in selected:
                raise ValueError("worker command references must be unique")
            selected[command.command_ref] = command
        self._commands = selected

    def resolve(self, command_ref: str) -> ReviewedWorkerCommand:
        try:
            return self._commands[command_ref]
        except KeyError:
            raise ExtensionWorkerError("worker_command_reference_unavailable") from None


class WorkerMetadata(Protocol):
    """Structural view implemented by the strict manifest worker model."""

    command_ref: str
    executable_sha256: str
    protocol_version: int
    operations: Sequence[str | WorkerOperation]


@dataclass(frozen=True, slots=True)
class WorkerResult:
    operation: WorkerOperation
    result: Any


class ExtensionWorker:
    """Launch a hash-pinned worker for one synthetic, deterministic operation."""

    def __init__(
        self,
        metadata: WorkerMetadata,
        resolver: WorkerCommandResolver,
        *,
        limits: WorkerLimits | None = None,
    ) -> None:
        if metadata.protocol_version != 1:
            raise ValueError("worker protocol version is unsupported")
        if _REFERENCE_RE.fullmatch(metadata.command_ref) is None:
            raise ValueError("worker command reference is invalid")
        if _SHA256_RE.fullmatch(metadata.executable_sha256) is None:
            raise ValueError("worker executable digest is invalid")
        try:
            operations = frozenset(WorkerOperation(value) for value in metadata.operations)
        except ValueError:
            raise ValueError("worker operation is unsupported") from None
        if not operations:
            raise ValueError("worker must declare at least one operation")
        self._command_ref = metadata.command_ref
        self._expected_sha256 = metadata.executable_sha256
        self._operations = operations
        self._resolver = resolver
        self._limits = limits or WorkerLimits()

    def __repr__(self) -> str:
        return (
            "ExtensionWorker(command_ref="
            f"{self._command_ref!r}, operations={len(self._operations)}, executable=<reviewed>)"
        )

    async def run(
        self,
        operation: WorkerOperation | str,
        payload: Mapping[str, Any],
        *,
        request_id: str,
        verify_determinism: bool | None = None,
    ) -> WorkerResult:
        """Run one operation; canonicalization is double-run by default."""

        try:
            selected_operation = WorkerOperation(operation)
        except ValueError:
            raise ExtensionWorkerError("worker_operation_unsupported") from None
        if selected_operation not in self._operations:
            raise ExtensionWorkerError("worker_operation_not_declared")
        if _REQUEST_ID_RE.fullmatch(request_id) is None:
            raise ValueError("worker request ID is invalid")
        detached = dict(payload)
        _require_synthetic_payload(detached)
        _validate_json_bounds(detached, self._limits)
        first = await self._run_once(selected_operation, detached, request_id=request_id)
        check = selected_operation is WorkerOperation.CANONICALIZE
        if verify_determinism is not None:
            check = verify_determinism
        if check:
            second_id = _determinism_request_id(request_id)
            second = await self._run_once(selected_operation, detached, request_id=second_id)
            try:
                same = canonical_json(first) == canonical_json(second)
            except CanonicalizationError:
                same = False
            if not same:
                raise ExtensionWorkerProtocolError("worker_nondeterministic_response")
        return WorkerResult(operation=selected_operation, result=first)

    async def _run_once(
        self,
        operation: WorkerOperation,
        payload: Mapping[str, Any],
        *,
        request_id: str,
    ) -> Any:
        envelope = {
            "operation": operation.value,
            "payload": dict(payload),
            "protocol_version": 1,
            "request_id": request_id,
        }
        encoded = canonical_json(envelope) + b"\n"
        if len(encoded) > self._limits.input_limit_bytes:
            raise ExtensionWorkerError("worker_input_oversized")

        command = self._resolver.resolve(self._command_ref)
        if (
            command.command_ref != self._command_ref
            or command.executable_sha256 != self._expected_sha256
        ):
            raise ExtensionWorkerError("worker_command_reference_mismatch")

        descriptor, identity = _open_verified_worker(command)
        process: asyncio.subprocess.Process | None = None
        try:
            executable, pinned_arguments, pass_fds = _execution_target(
                command.executable,
                descriptor,
            )
            with tempfile.TemporaryDirectory(prefix="signet-worker-") as directory:
                os.chmod(directory, 0o700)
                process = await asyncio.create_subprocess_exec(
                    executable,
                    *pinned_arguments,
                    *command.arguments,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=directory,
                    env={
                        "LANG": "C",
                        "LC_ALL": "C",
                        "PATH": "/usr/bin:/bin",
                        "PYTHONHASHSEED": "0",
                    },
                    pass_fds=pass_fds,
                    start_new_session=True,
                )
                _reverify_after_spawn(command.executable, descriptor, identity)
                stdout = await _bounded_communicate(
                    process,
                    encoded,
                    timeout=self._limits.timeout_seconds,
                    stdout_limit=self._limits.output_limit_bytes,
                    stderr_limit=self._limits.stderr_limit_bytes,
                )
        except asyncio.CancelledError:
            if process is not None:
                await asyncio.shield(_terminate(process))
            raise
        except TimeoutError:
            if process is not None:
                await _terminate(process)
            raise ExtensionWorkerTimeout("worker_timeout") from None
        except ExtensionWorkerError:
            if process is not None:
                await _terminate(process)
            raise
        except (OSError, ValueError):
            if process is not None:
                await _terminate(process)
            raise ExtensionWorkerError("worker_launch_failed") from None
        finally:
            os.close(descriptor)

        response = _strict_response(stdout, operation=operation, request_id=request_id)
        _validate_json_bounds(response, self._limits)
        if response["ok"] is not True:
            error = cast(dict[str, Any], response["error"])
            raise ExtensionWorkerError(cast(str, error["code"]))
        result = response["result"]
        _validate_operation_result(operation, result)
        return result


def _require_synthetic_payload(payload: Mapping[str, Any]) -> None:
    fixture_identity = payload.get("fixture_identity")
    if payload.get("synthetic") is not True and not (
        isinstance(fixture_identity, str) and fixture_identity.startswith("fake:")
    ):
        raise ExtensionWorkerError("worker_requires_synthetic_fixture")

    def visit(value: Any) -> None:
        if isinstance(value, str):
            if _SECRET_TEXT_RE.search(value):
                raise ExtensionWorkerError("worker_payload_contains_secret_like_material")
        elif isinstance(value, Mapping):
            for key, child in value.items():
                if key.lower() in _FORBIDDEN_PAYLOAD_KEYS:
                    raise ExtensionWorkerError("worker_payload_contains_forbidden_material")
                visit(child)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for child in value:
                visit(child)

    visit(payload)


def _validate_json_bounds(value: Any, limits: WorkerLimits) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > limits.max_nodes or depth > limits.max_depth:
            raise ExtensionWorkerProtocolError("worker_json_structure_oversized")
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, float):
            if not (-sys.float_info.max <= item <= sys.float_info.max):
                raise ExtensionWorkerProtocolError("worker_json_non_finite")
            return
        if isinstance(item, str):
            if len(item.encode("utf-8")) > limits.max_scalar_bytes:
                raise ExtensionWorkerProtocolError("worker_json_scalar_oversized")
            return
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 1024:
                    raise ExtensionWorkerProtocolError("worker_json_key_invalid")
                visit(child, depth + 1)
            return
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for child in item:
                visit(child, depth + 1)
            return
        raise ExtensionWorkerProtocolError("worker_json_value_invalid")

    visit(value, 0)


def _open_verified_worker(
    command: ReviewedWorkerCommand,
) -> tuple[int, tuple[int, int, int, int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        before_path = command.executable.lstat()
        if command.executable.resolve(strict=True) != command.executable:
            raise ExtensionWorkerError("worker_executable_unsafe")
        descriptor = os.open(command.executable, flags)
        before = os.fstat(descriptor)
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, current_uid}
            or before.st_mode & 0o111 == 0
            or before.st_mode & 0o022
            or before.st_size <= 0
            or before.st_size > 256 * 1024 * 1024
            or _file_identity(before_path) != _file_identity(before)
        ):
            raise ExtensionWorkerError("worker_executable_unsafe")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
        after = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(after):
            raise ExtensionWorkerError("worker_executable_changed")
        if digest.hexdigest() != command.executable_sha256:
            raise ExtensionWorkerError("worker_executable_digest_mismatch")
        return descriptor, _file_identity(after)
    except ExtensionWorkerError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except (OSError, RuntimeError):
        if descriptor >= 0:
            os.close(descriptor)
        raise ExtensionWorkerError("worker_executable_unavailable") from None


def _execution_target(
    path: Path,
    descriptor: int,
) -> tuple[str, tuple[str, ...], tuple[int, ...]]:
    del path
    descriptor_roots = (
        (Path("/proc/self/fd"), sys.platform.startswith("linux")),
        (Path("/dev/fd"), sys.platform == "darwin"),
    )
    for descriptor_root, supported_platform in descriptor_roots:
        if supported_platform and descriptor_root.is_dir():
            pinned_path = str(descriptor_root / str(descriptor))
            interpreter = _python_script_interpreter(descriptor)
            if interpreter is not None:
                return str(interpreter), ("-I", "-B", pinned_path), (descriptor,)
            if sys.platform.startswith("linux"):
                return pinned_path, (), (descriptor,)
            raise ExtensionWorkerError("worker_executable_format_unsupported")
    raise ExtensionWorkerError("worker_process_boundary_unsupported")


def _python_script_interpreter(descriptor: int) -> Path | None:
    try:
        prefix = os.pread(descriptor, 4096, 0)
    except OSError:
        raise ExtensionWorkerError("worker_executable_changed") from None
    if not prefix.startswith(b"#!"):
        return None
    first_line = prefix.split(b"\n", 1)[0]
    try:
        declaration = first_line[2:].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ExtensionWorkerError("worker_executable_format_unsupported") from None
    if (
        not declaration
        or declaration.strip() != declaration
        or any(character.isspace() for character in declaration)
    ):
        raise ExtensionWorkerError("worker_executable_format_unsupported")
    interpreter = Path(declaration)
    if not interpreter.is_absolute() or not re.fullmatch(
        r"python(?:3(?:\.\d+)?)?", interpreter.name
    ):
        raise ExtensionWorkerError("worker_executable_format_unsupported")
    try:
        resolved = interpreter.resolve(strict=True)
        metadata = resolved.stat()
    except (OSError, RuntimeError):
        raise ExtensionWorkerError("worker_interpreter_unavailable") from None
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, current_uid}
        or metadata.st_mode & 0o111 == 0
        or metadata.st_mode & 0o022
    ):
        raise ExtensionWorkerError("worker_interpreter_unsafe")
    return resolved


def _reverify_after_spawn(
    path: Path,
    descriptor: int,
    expected: tuple[int, int, int, int, int],
) -> None:
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ExtensionWorkerError("worker_executable_changed") from None
    if (
        _file_identity(opened) != expected
        or _file_identity(current) != expected
        or resolved != path
    ):
        raise ExtensionWorkerError("worker_executable_changed")


async def _bounded_communicate(
    process: asyncio.subprocess.Process,
    data: bytes,
    *,
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
) -> bytes:
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise ExtensionWorkerError("worker_pipe_unavailable")

    async def write_input() -> None:
        if process.stdin is None:  # pragma: no cover - narrowed above
            return
        process.stdin.write(data)
        await process.stdin.drain()
        process.stdin.close()
        await process.stdin.wait_closed()

    async def read_bounded(
        stream: asyncio.StreamReader,
        limit: int,
        *,
        code: str,
    ) -> bytes:
        result = bytearray()
        while True:
            chunk = await stream.read(min(64 * 1024, limit + 1 - len(result)))
            if not chunk:
                return bytes(result)
            result.extend(chunk)
            if len(result) > limit:
                raise ExtensionWorkerProtocolError(code)

    tasks = (
        asyncio.create_task(write_input()),
        asyncio.create_task(
            read_bounded(process.stdout, stdout_limit, code="worker_output_oversized")
        ),
        asyncio.create_task(
            read_bounded(process.stderr, stderr_limit, code="worker_stderr_oversized")
        ),
        asyncio.create_task(process.wait()),
    )
    try:
        _, stdout, _stderr, returncode = await asyncio.wait_for(
            asyncio.gather(*tasks),
            timeout=timeout,
        )
    except BaseException:
        await _terminate(process)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    if returncode != 0:
        raise ExtensionWorkerError("worker_process_failed")
    return stdout


async def _terminate(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=0.5)
        return
    except (ProcessLookupError, TimeoutError):
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    with suppress(ProcessLookupError):
        await process.wait()


def _strict_response(
    raw: bytes,
    *,
    operation: WorkerOperation,
    request_id: str,
) -> dict[str, Any]:
    if not raw or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise ExtensionWorkerProtocolError("worker_response_not_single_json_line")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        selected: dict[str, Any] = {}
        for key, value in pairs:
            if key in selected:
                raise ExtensionWorkerProtocolError("worker_response_duplicate_key")
            selected[key] = value
        return selected

    try:
        value = json.loads(
            raw[:-1].decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=_reject_constant,
        )
    except ExtensionWorkerProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ExtensionWorkerProtocolError("worker_response_invalid_json") from None
    if not isinstance(value, dict):
        raise ExtensionWorkerProtocolError("worker_response_invalid_shape")
    try:
        if canonical_json(value) + b"\n" != raw:
            raise ExtensionWorkerProtocolError("worker_response_not_canonical")
    except CanonicalizationError:
        raise ExtensionWorkerProtocolError("worker_response_invalid_json") from None
    if set(value) != {
        "error",
        "ok",
        "operation",
        "protocol_version",
        "request_id",
        "result",
    }:
        raise ExtensionWorkerProtocolError("worker_response_invalid_shape")
    if (
        value.get("protocol_version") != 1
        or value.get("request_id") != request_id
        or value.get("operation") != operation.value
        or type(value.get("ok")) is not bool
    ):
        raise ExtensionWorkerProtocolError("worker_response_binding_mismatch")
    if value["ok"] is True:
        if value["error"] is not None:
            raise ExtensionWorkerProtocolError("worker_response_invalid_shape")
    else:
        error = value["error"]
        if (
            value["result"] is not None
            or not isinstance(error, dict)
            or set(error) != {"code"}
            or not isinstance(error.get("code"), str)
            or _SAFE_IDENTIFIER_RE.fullmatch(error["code"]) is None
        ):
            raise ExtensionWorkerProtocolError("worker_response_invalid_shape")
    return value


def _validate_operation_result(operation: WorkerOperation, result: Any) -> None:
    if not isinstance(result, dict):
        raise ExtensionWorkerProtocolError("worker_result_invalid_shape")
    if operation is WorkerOperation.IDENTITY:
        if set(result) != {"operations", "protocol_version", "worker_id", "worker_version"}:
            raise ExtensionWorkerProtocolError("worker_result_invalid_shape")
        operations = result.get("operations")
        if (
            result.get("protocol_version") != 1
            or not _safe_text(result.get("worker_id"), maximum=128)
            or not _safe_text(result.get("worker_version"), maximum=64)
            or not isinstance(operations, list)
            or not operations
            or len(operations) > len(WorkerOperation)
        ):
            raise ExtensionWorkerProtocolError("worker_result_invalid_shape")
        try:
            if len(set(operations)) != len(operations):
                raise ValueError
            for item in operations:
                WorkerOperation(item)
        except (TypeError, ValueError):
            raise ExtensionWorkerProtocolError("worker_result_invalid_shape") from None
        return
    if operation is WorkerOperation.VALIDATE_SCHEMA:
        if set(result) != {"issues", "valid"}:
            raise ExtensionWorkerProtocolError("worker_result_invalid_shape")
        issues = result.get("issues")
        if (
            type(result.get("valid")) is not bool
            or not isinstance(issues, list)
            or len(issues) > 64
            or any(not _safe_text(item, maximum=512) for item in issues)
        ):
            raise ExtensionWorkerProtocolError("worker_result_invalid_shape")
        return
    if operation in {WorkerOperation.CANONICALIZE, WorkerOperation.REDACT}:
        if set(result) != {"value"}:
            raise ExtensionWorkerProtocolError("worker_result_invalid_shape")
        return
    if operation is WorkerOperation.REVIEW_SUMMARY:
        if set(result) != {"summary", "title", "warnings"}:
            raise ExtensionWorkerProtocolError("worker_result_invalid_shape")
        warnings = result.get("warnings")
        if (
            not _safe_text(result.get("title"), maximum=256)
            or not _safe_text(result.get("summary"), maximum=4096)
            or not isinstance(warnings, list)
            or len(warnings) > 32
            or any(not _safe_text(item, maximum=512) for item in warnings)
        ):
            raise ExtensionWorkerProtocolError("worker_result_invalid_shape")
        return
    if operation is WorkerOperation.CLASSIFY_FAKE_OUTCOME:
        if set(result) != {"classification", "safe_result"} or result.get("classification") not in {
            "failed_before_effect",
            "outcome_unknown",
            "succeeded",
        }:
            raise ExtensionWorkerProtocolError("worker_result_invalid_shape")
        if not isinstance(result.get("safe_result"), dict):
            raise ExtensionWorkerProtocolError("worker_result_invalid_shape")
        return
    raise AssertionError("unreachable worker operation")


def _safe_text(value: Any, *, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value.encode("utf-8")) <= maximum
        and "\x00" not in value
        and "\r" not in value
        and "\n" not in value
        and _SECRET_TEXT_RE.search(value) is None
    )


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _determinism_request_id(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]
    return f"determinism:{digest}"


def _reject_constant(value: str) -> Never:
    del value
    raise ExtensionWorkerProtocolError("worker_response_non_finite")
