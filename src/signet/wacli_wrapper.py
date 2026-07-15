"""Bounded, no-shell process wrapper for the reviewed ``wacli`` executable.

The wrapper owns the JSON contract presented to the WhatsApp adapter.  It never
uses a shell, never inherits the agent environment, closes stdin, selects an
explicit account, requires a pinned CLI version, and bounds both runtime and
captured output.  The default binary/version pair reflects the reviewed July
2026 Homebrew installation; any upgrade fails closed until the version is
explicitly reviewed and changed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import signal
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from signet.adapters.base import DispatchError, copy_json_object

DEFAULT_WACLI_EXECUTABLE = Path("/opt/homebrew/bin/wacli")
REVIEWED_WACLI_VERSION = "0.12.0"
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
_DESTINATION_RE = re.compile(
    r"(?:\+[1-9][0-9]{7,14}|[1-9][0-9]{6,31}@(s\.whatsapp\.net|g\.us|newsletter))"
)


class WacliError(DispatchError):
    """A redacted ``wacli`` boundary failure."""

    def __init__(
        self,
        code: str,
        *,
        dispatch_may_have_occurred: bool,
    ) -> None:
        super().__init__(code, dispatch_may_have_occurred=dispatch_may_have_occurred)
        self.code = code


@dataclass(frozen=True, slots=True)
class WacliConfig:
    """Reviewed executable and resource limits for one WhatsApp account."""

    account: str
    executable: Path = DEFAULT_WACLI_EXECUTABLE
    expected_version: str = REVIEWED_WACLI_VERSION
    expected_sha256: str | None = None
    staging_root: Path | None = None
    home: Path = Path.home()
    timeout_seconds: float = 20.0
    cli_timeout: str = "15s"
    max_output_bytes: int = 256 * 1024
    reviewed_dispatch_enabled: bool = False

    def __post_init__(self) -> None:
        executable = Path(self.executable)
        if not executable.is_absolute():
            raise ValueError("wacli executable must be an absolute pinned path")
        if not _ACCOUNT_RE.fullmatch(self.account):
            raise ValueError("wacli account name is invalid")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.expected_version):
            raise ValueError("wacli expected version must be an exact semantic version")
        if self.expected_sha256 is not None and not _HASH_RE.fullmatch(self.expected_sha256):
            raise ValueError("wacli executable digest must be a lowercase SHA-256")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 120:
            raise ValueError("wacli timeout must be between zero and 120 seconds")
        if not re.fullmatch(r"[1-9][0-9]{0,2}s", self.cli_timeout):
            raise ValueError("wacli CLI timeout must be a bounded whole-second duration")
        if self.max_output_bytes < 1024 or self.max_output_bytes > 4 * 1024 * 1024:
            raise ValueError("wacli output bound must be between 1 KiB and 4 MiB")
        object.__setattr__(self, "executable", executable)
        object.__setattr__(self, "home", Path(self.home))
        if self.staging_root is not None:
            object.__setattr__(self, "staging_root", Path(self.staging_root).resolve())


def normalize_destination(value: str) -> str:
    """Accept only deterministic phone/JID targets, never ambiguous contact names."""
    if value != value.strip() or not _DESTINATION_RE.fullmatch(value):
        raise WacliError("invalid_destination", dispatch_may_have_occurred=False)
    return value


def validate_message(value: str) -> str:
    if not value or len(value) > 65_536 or "\x00" in value:
        raise WacliError("invalid_message", dispatch_may_have_occurred=False)
    return value


async def _read_bounded(stream: asyncio.StreamReader, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await stream.read(min(8192, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise WacliError("output_limit_exceeded", dispatch_may_have_occurred=True)


class WacliWrapper:
    """An injected downstream client for the owned WhatsApp adapter contract."""

    def __init__(self, config: WacliConfig) -> None:
        self.config = config
        self._version_lock = asyncio.Lock()
        self._verified_signature: tuple[int, int, int, int] | None = None

    def _binary_signature(self) -> tuple[int, int, int, int]:
        try:
            metadata = self.config.executable.stat()
        except OSError as exc:
            raise WacliError("executable_unavailable", dispatch_may_have_occurred=False) from exc
        if not stat.S_ISREG(metadata.st_mode) or not os.access(self.config.executable, os.X_OK):
            raise WacliError("executable_not_runnable", dispatch_may_have_occurred=False)
        if self.config.expected_sha256 is not None:
            digest = hashlib.sha256()
            try:
                with self.config.executable.open("rb") as executable_file:
                    while chunk := executable_file.read(1024 * 1024):
                        digest.update(chunk)
            except OSError as exc:
                raise WacliError(
                    "executable_digest_unavailable", dispatch_may_have_occurred=False
                ) from exc
            if digest.hexdigest() != self.config.expected_sha256:
                raise WacliError("executable_digest_mismatch", dispatch_may_have_occurred=False)
        return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)

    def _environment(self) -> dict[str, str]:
        return {
            "HOME": str(self.config.home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/opt/homebrew/bin:/usr/bin:/bin",
        }

    async def _terminate(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            with suppress(ProcessLookupError):
                process.kill()
        await process.wait()

    async def _run_json(
        self,
        command_arguments: tuple[str, ...],
        *,
        dispatch_may_have_occurred: bool,
        required_signature: tuple[int, int, int, int] | None = None,
        pass_fds: tuple[int, ...] = (),
    ) -> dict[str, Any]:
        if any("\x00" in argument for argument in command_arguments):
            raise WacliError("invalid_argument", dispatch_may_have_occurred=False)
        signature = self._binary_signature()
        if required_signature is not None and signature != required_signature:
            raise WacliError("executable_changed", dispatch_may_have_occurred=False)
        argv = (
            str(self.config.executable),
            "--account",
            self.config.account,
            "--json",
            "--timeout",
            self.config.cli_timeout,
            *command_arguments,
        )
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._environment(),
                start_new_session=True,
                pass_fds=pass_fds,
            )
        except OSError as exc:
            raise WacliError("process_start_failed", dispatch_may_have_occurred=False) from exc
        assert process.stdout is not None
        assert process.stderr is not None
        try:
            async with asyncio.timeout(self.config.timeout_seconds):
                stdout, stderr, return_code = await asyncio.gather(
                    _read_bounded(process.stdout, self.config.max_output_bytes),
                    _read_bounded(process.stderr, self.config.max_output_bytes),
                    process.wait(),
                )
        except TimeoutError as exc:
            await self._terminate(process)
            raise WacliError(
                "process_timeout",
                dispatch_may_have_occurred=dispatch_may_have_occurred,
            ) from exc
        except WacliError as exc:
            await self._terminate(process)
            raise WacliError(
                exc.code,
                dispatch_may_have_occurred=dispatch_may_have_occurred,
            ) from exc
        except asyncio.CancelledError:
            await asyncio.shield(self._terminate(process))
            raise
        if len(stdout) + len(stderr) > self.config.max_output_bytes:
            raise WacliError(
                "output_limit_exceeded",
                dispatch_may_have_occurred=dispatch_may_have_occurred,
            )
        try:
            decoded = stdout.decode("utf-8", errors="strict")
            value = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WacliError(
                "invalid_json_output",
                dispatch_may_have_occurred=dispatch_may_have_occurred,
            ) from exc
        if not isinstance(value, dict):
            raise WacliError(
                "invalid_json_output",
                dispatch_may_have_occurred=dispatch_may_have_occurred,
            )
        if return_code != 0:
            raise WacliError(
                "command_failed",
                dispatch_may_have_occurred=dispatch_may_have_occurred,
            )
        return cast(dict[str, Any], value)

    @staticmethod
    def _reported_version(result: Mapping[str, Any]) -> str | None:
        for key in ("version", "Version"):
            value = result.get(key)
            if isinstance(value, str):
                return value.removeprefix("v")
        data = result.get("data")
        if isinstance(data, Mapping):
            return WacliWrapper._reported_version(data)
        return None

    async def verify_version(self) -> None:
        """Preflight the exact binary version, caching only an unchanged inode."""
        async with self._version_lock:
            signature = self._binary_signature()
            if signature == self._verified_signature:
                return
            result = await self._run_json(("version",), dispatch_may_have_occurred=False)
            if self._reported_version(result) != self.config.expected_version:
                raise WacliError("version_mismatch", dispatch_may_have_occurred=False)
            self._verified_signature = signature

    def _open_confined_media(
        self,
        value: object,
        *,
        expected_size: object,
        expected_sha256: object,
    ) -> int:
        if not isinstance(value, str) or self.config.staging_root is None:
            raise WacliError("invalid_media_path", dispatch_may_have_occurred=False)
        if (
            not isinstance(expected_size, int)
            or expected_size < 0
            or not isinstance(expected_sha256, str)
            or not _HASH_RE.fullmatch(expected_sha256)
        ):
            raise WacliError("invalid_media_integrity", dispatch_may_have_occurred=False)
        try:
            path = Path(value).resolve(strict=True)
            path.relative_to(self.config.staging_root)
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except (OSError, ValueError) as exc:
            raise WacliError("invalid_media_path", dispatch_may_have_occurred=False) from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise WacliError("invalid_media_path", dispatch_may_have_occurred=False)
            if metadata.st_size > 100 * 1024 * 1024 or metadata.st_size != expected_size:
                raise WacliError("media_integrity_mismatch", dispatch_may_have_occurred=False)
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 1024 * 1024):
                digest.update(chunk)
            if digest.hexdigest() != expected_sha256:
                raise WacliError("media_integrity_mismatch", dispatch_may_have_occurred=False)
            os.lseek(descriptor, 0, os.SEEK_SET)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    async def call_tool(
        self, tool_name: str, arguments: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        detached = copy_json_object(arguments)
        if tool_name == "send_text":
            return await self.send_text(detached)
        if tool_name == "send_file":
            return await self.send_file(detached)
        raise WacliError("unknown_owned_tool", dispatch_may_have_occurred=False)

    async def send_text(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if not self.config.reviewed_dispatch_enabled:
            raise WacliError("provider_contract_inactive", dispatch_may_have_occurred=False)
        allowed = {"to", "message", "reply_to", "reply_to_sender"}
        if set(arguments) - allowed or set(arguments) < {"to", "message"}:
            raise WacliError("invalid_send_text_arguments", dispatch_may_have_occurred=False)
        to = arguments.get("to")
        message = arguments.get("message")
        if not isinstance(to, str) or not isinstance(message, str):
            raise WacliError("invalid_send_text_arguments", dispatch_may_have_occurred=False)
        command = [
            "send",
            "text",
            "--to",
            normalize_destination(to),
            "--message",
            validate_message(message),
            "--no-preview",
        ]
        reply_to = arguments.get("reply_to")
        reply_sender = arguments.get("reply_to_sender")
        if reply_to is not None:
            if not isinstance(reply_to, str) or not reply_to or "\x00" in reply_to:
                raise WacliError("invalid_reply", dispatch_may_have_occurred=False)
            command.extend(("--reply-to", reply_to))
        if reply_sender is not None:
            if not isinstance(reply_sender, str):
                raise WacliError("invalid_reply", dispatch_may_have_occurred=False)
            command.extend(("--reply-to-sender", normalize_destination(reply_sender)))
        await self.verify_version()
        assert self._verified_signature is not None
        return await self._run_json(
            tuple(command),
            dispatch_may_have_occurred=True,
            required_signature=self._verified_signature,
        )

    async def send_file(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        allowed = {
            "to",
            "file_path",
            "filename",
            "mime_type",
            "caption",
            "reply_to",
            "reply_to_sender",
            "expected_size",
            "expected_sha256",
        }
        required = {
            "to",
            "file_path",
            "filename",
            "mime_type",
            "expected_size",
            "expected_sha256",
        }
        if set(arguments) - allowed or set(arguments) < required:
            raise WacliError("invalid_send_file_arguments", dispatch_may_have_occurred=False)
        to = arguments.get("to")
        filename = arguments.get("filename")
        mime_type = arguments.get("mime_type")
        if (
            not isinstance(to, str)
            or not to
            or not isinstance(filename, str)
            or not filename
            or not isinstance(mime_type, str)
            or not mime_type
        ):
            raise WacliError("invalid_send_file_arguments", dispatch_may_have_occurred=False)
        if not self.config.reviewed_dispatch_enabled:
            raise WacliError("provider_contract_inactive", dispatch_may_have_occurred=False)
        caption = arguments.get("caption")
        if caption is not None and (
            not isinstance(caption, str) or len(caption) > 65_536 or "\x00" in caption
        ):
            raise WacliError("invalid_caption", dispatch_may_have_occurred=False)
        reply_to = arguments.get("reply_to")
        reply_sender = arguments.get("reply_to_sender")
        if reply_to is not None and (
            not isinstance(reply_to, str) or not reply_to or "\x00" in reply_to
        ):
            raise WacliError("invalid_reply", dispatch_may_have_occurred=False)
        if reply_sender is not None and not isinstance(reply_sender, str):
            raise WacliError("invalid_reply", dispatch_may_have_occurred=False)
        descriptor = self._open_confined_media(
            arguments.get("file_path"),
            expected_size=arguments.get("expected_size"),
            expected_sha256=arguments.get("expected_sha256"),
        )
        try:
            await self.verify_version()
            assert self._verified_signature is not None
            command = [
                "send",
                "file",
                "--to",
                normalize_destination(to),
                "--file",
                f"/dev/fd/{descriptor}",
                "--filename",
                filename,
                "--mime",
                mime_type,
            ]
            if caption is not None:
                command.extend(("--caption", caption))
            if reply_to is not None:
                command.extend(("--reply-to", reply_to))
            if reply_sender is not None:
                command.extend(
                    ("--reply-to-sender", normalize_destination(reply_sender))
                )
            return await self._run_json(
                tuple(command),
                dispatch_may_have_occurred=True,
                required_signature=self._verified_signature,
                pass_fds=(descriptor,),
            )
        finally:
            os.close(descriptor)
