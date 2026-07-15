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
import secrets
import signal
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from signet.adapters.base import DispatchError, copy_json_object
from signet.staging import StagingError, StagingStore

DEFAULT_WACLI_EXECUTABLE = Path("/opt/homebrew/bin/wacli")
REVIEWED_WACLI_VERSION = "0.12.0"
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_NATIVE_EXECUTABLE_MAGICS = frozenset(
    {
        b"\x7fELF",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
    }
)
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
    execution_snapshot_root: Path | None = None
    test_only_allow_script: bool = False

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
        if self.execution_snapshot_root is not None:
            snapshot_root = Path(self.execution_snapshot_root)
            if not snapshot_root.is_absolute():
                raise ValueError("wacli execution snapshot root must be absolute")
            object.__setattr__(self, "execution_snapshot_root", snapshot_root)
        if self.reviewed_dispatch_enabled and self.execution_snapshot_root is None:
            raise ValueError("active wacli dispatch requires a private execution snapshot root")
        if not isinstance(self.test_only_allow_script, bool):
            raise TypeError("wacli test script flag must be a boolean")


def normalize_destination(value: str) -> str:
    """Accept only deterministic phone/JID targets, never ambiguous contact names."""
    if value != value.strip() or not _DESTINATION_RE.fullmatch(value):
        raise WacliError("invalid_destination", dispatch_may_have_occurred=False)
    return value


def validate_message(value: str) -> str:
    if not value or len(value) > 65_536 or "\x00" in value:
        raise WacliError("invalid_message", dispatch_may_have_occurred=False)
    return value


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("executable snapshot write made no progress")
        view = view[written:]


def _hash_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


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

    def __init__(
        self,
        config: WacliConfig,
        *,
        staging_store: StagingStore | None = None,
    ) -> None:
        self.config = config
        if staging_store is not None and not isinstance(staging_store, StagingStore):
            raise TypeError("wacli staging store is invalid")
        if staging_store is not None and (
            config.staging_root is None or staging_store.root != config.staging_root
        ):
            raise ValueError("wacli staging store does not match its reviewed root")
        self._staging_store = staging_store
        self._version_lock = asyncio.Lock()
        self._verified_signature: tuple[int, int, int, int, str] | None = None

    def _open_verified_executable(self) -> tuple[int, tuple[int, int, int, int, str]]:
        snapshot_root = self.config.execution_snapshot_root
        if snapshot_root is None:
            raise WacliError("snapshot_root_unavailable", dispatch_may_have_occurred=False)
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            source_descriptor = os.open(self.config.executable, flags)
            source_before = os.fstat(source_descriptor)
        except OSError as exc:
            raise WacliError("executable_unavailable", dispatch_may_have_occurred=False) from exc

        root_descriptor = -1
        writer = -1
        snapshot_descriptor = -1
        snapshot_name: str | None = None
        try:
            if not stat.S_ISREG(source_before.st_mode) or source_before.st_mode & 0o111 == 0:
                raise WacliError("executable_not_runnable", dispatch_may_have_occurred=False)
            self._prepare_snapshot_root(snapshot_root)
            root_flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_DIRECTORY"):
                root_flags |= os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                root_flags |= os.O_NOFOLLOW
            root_descriptor = os.open(snapshot_root, root_flags)

            for _ in range(4):
                candidate = f".wacli-exec-{secrets.token_hex(18)}"
                try:
                    writer = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                        0o600,
                        dir_fd=root_descriptor,
                    )
                except FileExistsError:
                    continue
                snapshot_name = candidate
                break
            if writer < 0 or snapshot_name is None:
                raise WacliError("snapshot_create_failed", dispatch_may_have_occurred=False)

            digest = hashlib.sha256()
            copied = 0
            leading = b""
            try:
                while chunk := os.read(source_descriptor, 1024 * 1024):
                    copied += len(chunk)
                    if copied > _MAX_EXECUTABLE_BYTES:
                        raise WacliError(
                            "executable_too_large", dispatch_may_have_occurred=False
                        )
                    if len(leading) < 4:
                        leading = (leading + chunk)[:4]
                    digest.update(chunk)
                    _write_all(writer, chunk)
            except OSError as exc:
                raise WacliError(
                    "executable_digest_unavailable", dispatch_may_have_occurred=False
                ) from exc
            source_after = os.fstat(source_descriptor)
            if (
                _file_identity(source_before) != _file_identity(source_after)
                or copied != source_before.st_size
            ):
                raise WacliError("executable_changed", dispatch_may_have_occurred=False)
            if not self._native_or_test_executable(leading):
                raise WacliError("executable_format_unreviewed", dispatch_may_have_occurred=False)
            executable_digest = digest.hexdigest()
            if (
                self.config.expected_sha256 is not None
                and executable_digest != self.config.expected_sha256
            ):
                raise WacliError("executable_digest_mismatch", dispatch_may_have_occurred=False)

            os.fsync(writer)
            os.fchmod(writer, 0o500)
            os.close(writer)
            writer = -1
            snapshot_descriptor = os.open(
                snapshot_name,
                flags,
                dir_fd=root_descriptor,
            )
            snapshot_metadata = os.fstat(snapshot_descriptor)
            if (
                not stat.S_ISREG(snapshot_metadata.st_mode)
                or snapshot_metadata.st_size != copied
                or snapshot_metadata.st_nlink != 1
                or _hash_descriptor(snapshot_descriptor) != executable_digest
            ):
                raise WacliError("snapshot_integrity_failed", dispatch_may_have_occurred=False)
            os.unlink(snapshot_name, dir_fd=root_descriptor)
            snapshot_name = None
            os.fsync(root_descriptor)
            if os.fstat(snapshot_descriptor).st_nlink != 0:
                raise WacliError("snapshot_unlink_failed", dispatch_may_have_occurred=False)
            os.lseek(snapshot_descriptor, 0, os.SEEK_SET)
            signature = (
                source_before.st_dev,
                source_before.st_ino,
                source_before.st_size,
                source_before.st_mtime_ns,
                executable_digest,
            )
            result = snapshot_descriptor
            snapshot_descriptor = -1
            return result, signature
        except BaseException:
            raise
        finally:
            if writer >= 0:
                os.close(writer)
            if snapshot_descriptor >= 0:
                os.close(snapshot_descriptor)
            if snapshot_name is not None and root_descriptor >= 0:
                with suppress(OSError):
                    os.unlink(snapshot_name, dir_fd=root_descriptor)
            if root_descriptor >= 0:
                os.close(root_descriptor)
            os.close(source_descriptor)

    @staticmethod
    def _prepare_snapshot_root(root: Path) -> None:
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            metadata = root.lstat()
            resolved = root.resolve(strict=True)
        except OSError as exc:
            raise WacliError("snapshot_root_unavailable", dispatch_may_have_occurred=False) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or resolved != root
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise WacliError("snapshot_root_unsafe", dispatch_may_have_occurred=False)

    def _native_or_test_executable(self, leading: bytes) -> bool:
        if leading in _NATIVE_EXECUTABLE_MAGICS:
            return True
        return self.config.test_only_allow_script and leading.startswith(b"#!")

    @staticmethod
    def _descriptor_path(descriptor: int) -> str:
        proc_path = f"/proc/self/fd/{descriptor}"
        return proc_path if Path("/proc/self/fd").is_dir() else f"/dev/fd/{descriptor}"

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
        required_signature: tuple[int, int, int, int, str] | None = None,
        pass_fds: tuple[int, ...] = (),
    ) -> tuple[dict[str, Any], tuple[int, int, int, int, str]]:
        if any("\x00" in argument for argument in command_arguments):
            raise WacliError("invalid_argument", dispatch_may_have_occurred=False)
        executable_fd, signature = self._open_verified_executable()
        if required_signature is not None and signature != required_signature:
            os.close(executable_fd)
            raise WacliError("executable_changed", dispatch_may_have_occurred=False)
        argv = (
            self._descriptor_path(executable_fd),
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
                pass_fds=tuple(dict.fromkeys((*pass_fds, executable_fd))),
            )
        except OSError as exc:
            raise WacliError("process_start_failed", dispatch_may_have_occurred=False) from exc
        finally:
            os.close(executable_fd)
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
        return cast(dict[str, Any], value), signature

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
            result, signature = await self._run_json(
                ("version",), dispatch_may_have_occurred=False
            )
            if self._reported_version(result) != self.config.expected_version:
                raise WacliError("version_mismatch", dispatch_may_have_occurred=False)
            self._verified_signature = signature

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
        result, _ = await self._run_json(
            tuple(command),
            dispatch_may_have_occurred=True,
            required_signature=self._verified_signature,
        )
        return result

    async def send_file(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        allowed = {
            "to",
            "staged_id",
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
            "staged_id",
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
        staged_id = arguments.get("staged_id")
        expected_size = arguments.get("expected_size")
        expected_sha256 = arguments.get("expected_sha256")
        if (
            not isinstance(staged_id, str)
            or not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
            or not isinstance(expected_sha256, str)
            or not _HASH_RE.fullmatch(expected_sha256)
            or self._staging_store is None
        ):
            raise WacliError("invalid_media_integrity", dispatch_may_have_occurred=False)
        try:
            plaintext = self._staging_store.plaintext_descriptor(
                staged_id,
                adapter="whatsapp",
                account=self.config.account,
                expected_size=expected_size,
                expected_sha256=expected_sha256,
            )
            with plaintext as (_, descriptor):
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
                result, _ = await self._run_json(
                    tuple(command),
                    dispatch_may_have_occurred=True,
                    required_signature=self._verified_signature,
                    pass_fds=(descriptor,),
                )
                return result
        except StagingError as exc:
            raise WacliError(
                "media_integrity_mismatch", dispatch_may_have_occurred=False
            ) from exc
