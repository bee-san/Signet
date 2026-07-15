"""Supervised, role-separated MCP clients for reviewed downstream servers."""

from __future__ import annotations

import asyncio
import copy
import json
import os
import re
import signal
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import (
    AbstractAsyncContextManager,
    AsyncExitStack,
    asynccontextmanager,
    suppress,
)
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

import anyio
import httpx
import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.message import SessionMessage

from signet.adapters.base import AdapterProtocolError, copy_json_object
from signet.config import DownstreamConfig
from signet.credential_broker import Secret, SecretReference, SecretStore
from signet.mcp_mirror import (
    MirrorError,
    raw_model,
)
from signet.mcp_mirror import (
    discover_all_tools as _discover_all_tools,
)
from signet.reviewed_process import descriptor_path, open_verified_executable

_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_MAX_TOOL_NAME_LENGTH = 256
_MAX_EXECUTABLE_LENGTH = 4096
_MAX_ARGUMENT_COUNT = 64
_MAX_ARGUMENT_LENGTH = 4096
_MAX_ARGUMENT_BYTES = 32_768
_SHELL_EXECUTABLES = frozenset(
    {
        "bash",
        "cmd",
        "cmd.exe",
        "csh",
        "dash",
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
_RELATED_TASK_META = "io.modelcontextprotocol/related-task"


class DownstreamError(RuntimeError):
    """Base class for secret-free downstream client failures."""


class DownstreamConfigurationError(DownstreamError, ValueError):
    """A downstream endpoint or process definition is not safely constrained."""


class DownstreamLifecycleError(DownstreamError):
    """An operation was attempted outside an initialized client lifecycle."""


class DownstreamConnectionError(DownstreamError):
    """A transport or initialization operation failed."""


class DownstreamCallError(DownstreamError):
    """A downstream tools/call request failed before a valid result was captured."""


class DownstreamProtocolError(AdapterProtocolError, DownstreamError):
    """The downstream returned an unsupported or malformed MCP value."""


class RedactedStdioServerParameters(StdioServerParameters):
    """Official SDK process parameters whose display never renders the environment."""

    def __repr__(self) -> str:
        return (
            "RedactedStdioServerParameters("
            f"command={self.command!r}, args_count={len(self.args)}, env=<redacted>)"
        )

    def __str__(self) -> str:
        return repr(self)


class ReviewedStdioServerParameters(RedactedStdioServerParameters):
    """Pinned local process inputs consumed only by Signet's exact-env launcher."""

    expected_sha256: str
    execution_snapshot_root: Path
    output_limit_bytes: int
    test_only_allow_script: bool = False


class _Lifecycle(StrEnum):
    NEW = "new"
    STARTING = "starting"
    RUNNING = "running"
    CLOSING = "closing"
    CLOSED = "closed"
    FAILED = "failed"


TransportStreams = tuple[Any, Any] | tuple[Any, Any, Callable[[], str | None]]
HTTPConnector = Callable[
    [str, Mapping[str, str], float, int], AbstractAsyncContextManager[TransportStreams]
]
StdioConnector = Callable[
    [ReviewedStdioServerParameters], AbstractAsyncContextManager[TransportStreams]
]


class DownstreamSession(Protocol):
    async def initialize(self) -> Any: ...

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any: ...


SessionFactory = Callable[[Any, Any, timedelta], AbstractAsyncContextManager[DownstreamSession]]


class _BoundedHTTPResponseStream(httpx.AsyncByteStream):
    """Reject oversized JSON bodies or individual SSE events before parsing."""

    def __init__(
        self,
        stream: httpx.AsyncByteStream,
        *,
        limit_bytes: int,
        event_stream: bool,
    ) -> None:
        self._stream = stream
        self._limit_bytes = limit_bytes
        self._event_stream = event_stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        consumed = 0
        line_has_content = False
        previous_was_cr = False
        async for chunk in self._stream:
            if not self._event_stream:
                consumed += len(chunk)
                if consumed > self._limit_bytes:
                    raise DownstreamProtocolError(
                        "downstream HTTP response exceeds its configured limit"
                    )
            else:
                for byte in chunk:
                    consumed += 1
                    if consumed > self._limit_bytes:
                        raise DownstreamProtocolError(
                            "downstream SSE event exceeds its configured limit"
                        )
                    if byte == 13:
                        if not line_has_content:
                            consumed = 0
                        line_has_content = False
                        previous_was_cr = True
                    elif byte == 10:
                        if previous_was_cr:
                            previous_was_cr = False
                            continue
                        if not line_has_content:
                            consumed = 0
                        line_has_content = False
                    else:
                        previous_was_cr = False
                        line_has_content = True
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


def _bounded_response_hook(
    limit_bytes: int,
) -> Callable[[httpx.Response], Any]:
    async def bound(response: httpx.Response) -> None:
        if not isinstance(response.stream, httpx.AsyncByteStream):
            raise DownstreamProtocolError("downstream HTTP response stream is invalid")
        content_encoding = response.headers.get("content-encoding", "identity").lower()
        if content_encoding != "identity":
            await response.aclose()
            raise DownstreamProtocolError(
                "compressed downstream HTTP responses are not accepted"
            )
        media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        response.stream = _BoundedHTTPResponseStream(
            response.stream,
            limit_bytes=limit_bytes,
            event_stream=media_type == "text/event-stream",
        )

    return bound


@asynccontextmanager
async def _official_http_connector(
    url: str,
    headers: Mapping[str, str],
    timeout_seconds: float,
    output_limit_bytes: int,
) -> AsyncIterator[TransportStreams]:
    timeout = httpx.Timeout(timeout_seconds)
    async with (
        httpx.AsyncClient(
            headers={**dict(headers), "Accept-Encoding": "identity"},
            timeout=timeout,
            trust_env=False,
            event_hooks={"response": [_bounded_response_hook(output_limit_bytes)]},
        ) as http_client,
        streamable_http_client(
            url,
            http_client=http_client,
            terminate_on_close=True,
        ) as streams,
    ):
        yield cast(TransportStreams, streams)


@asynccontextmanager
async def _official_stdio_connector(
    parameters: ReviewedStdioServerParameters,
) -> AsyncIterator[TransportStreams]:
    executable_descriptor = open_verified_executable(
        Path(parameters.command),
        expected_sha256=parameters.expected_sha256,
        snapshot_root=parameters.execution_snapshot_root,
        test_only_allow_script=parameters.test_only_allow_script,
    )
    try:
        executable = descriptor_path(executable_descriptor)
        with Path(os.devnull).open("w", encoding="utf-8") as error_sink:
            process = await anyio.open_process(
                [executable, *parameters.args],
                env=dict(parameters.env or {}),
                stderr=error_sink,
                cwd=parameters.cwd,
                start_new_session=True,
                pass_fds=(executable_descriptor,),
                umask=0o077,
            )
    finally:
        os.close(executable_descriptor)

    read_sender, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    write_stream, write_receiver = anyio.create_memory_object_stream[SessionMessage](0)

    async def stdout_reader() -> None:
        assert process.stdout is not None
        buffer = bytearray()
        try:
            async with read_sender:
                while True:
                    remaining = parameters.output_limit_bytes + 1 - len(buffer)
                    try:
                        chunk = await process.stdout.receive(min(65_536, remaining))
                    except anyio.EndOfStream:
                        return
                    buffer.extend(chunk)
                    while (newline := buffer.find(b"\n")) >= 0:
                        line = bytes(buffer[:newline])
                        del buffer[: newline + 1]
                        if len(line) > parameters.output_limit_bytes:
                            await _reject_oversized_stdio_frame(process, read_sender)
                            return
                        try:
                            decoded = line.decode(
                                encoding=parameters.encoding,
                                errors=parameters.encoding_error_handler,
                            )
                            message = types.JSONRPCMessage.model_validate_json(decoded)
                        except (UnicodeDecodeError, ValueError):
                            await read_sender.send(
                                DownstreamProtocolError("downstream emitted invalid JSON-RPC")
                            )
                            continue
                        await read_sender.send(SessionMessage(message))
                    if len(buffer) > parameters.output_limit_bytes:
                        await _reject_oversized_stdio_frame(process, read_sender)
                        return
        except anyio.ClosedResourceError:
            await anyio.lowlevel.checkpoint()

    async def stdin_writer() -> None:
        assert process.stdin is not None
        try:
            async with write_receiver:
                async for session_message in write_receiver:
                    encoded = session_message.message.model_dump_json(
                        by_alias=True, exclude_none=True
                    )
                    await process.stdin.send(
                        (encoded + "\n").encode(
                            encoding=parameters.encoding,
                            errors=parameters.encoding_error_handler,
                        )
                    )
        except anyio.ClosedResourceError:
            await anyio.lowlevel.checkpoint()

    async with anyio.create_task_group() as task_group, process:
        task_group.start_soon(stdout_reader)
        task_group.start_soon(stdin_writer)
        try:
            yield cast(TransportStreams, (read_stream, write_stream))
        finally:
            if process.stdin is not None:
                with suppress(Exception):
                    await process.stdin.aclose()
            try:
                with anyio.fail_after(2):
                    await process.wait()
            except TimeoutError:
                await _terminate_stdio_process(process)
            except ProcessLookupError:
                pass
            await read_stream.aclose()
            await write_stream.aclose()
            await read_sender.aclose()
            await write_receiver.aclose()


async def _terminate_stdio_process(process: Any) -> None:
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    with anyio.move_on_after(2) as termination_scope:
        await process.wait()
    if not termination_scope.cancel_called:
        return
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    with suppress(ProcessLookupError):
        await process.wait()


async def _reject_oversized_stdio_frame(process: Any, sender: Any) -> None:
    await _terminate_stdio_process(process)
    with suppress(anyio.BrokenResourceError, anyio.ClosedResourceError):
        await sender.send(DownstreamProtocolError("downstream JSON-RPC frame exceeds its limit"))


def _official_session_factory(
    read_stream: Any, write_stream: Any, timeout: timedelta
) -> AbstractAsyncContextManager[DownstreamSession]:
    session = ClientSession(
        read_stream,
        write_stream,
        read_timeout_seconds=timeout,
        client_info=types.Implementation(name="signet-downstream", version="0.1.0"),
    )
    return cast(AbstractAsyncContextManager[DownstreamSession], session)


def _credential_environment_name(alias: str) -> str:
    normalized = alias.upper().replace("-", "_")
    return f"SIGNET_DOWNSTREAM_{normalized}_CREDENTIAL"


def _validate_json_object(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return copy_json_object(value)
    except (TypeError, ValueError):
        pass
    raise DownstreamProtocolError("downstream value must be a JSON object")


def _is_task_result(raw: Mapping[str, Any]) -> bool:
    if "task" in raw:
        return True
    meta = raw.get("_meta")
    return isinstance(meta, Mapping) and _RELATED_TASK_META in meta


def validate_call_tool_result(value: Any) -> dict[str, Any]:
    """Validate and detach a complete non-task ``CallToolResult`` losslessly."""

    if isinstance(value, types.CreateTaskResult):
        raise DownstreamProtocolError("downstream task results are not supported")
    if isinstance(value, types.CallToolResult):
        captured = raw_model(value)
    elif isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise DownstreamProtocolError("downstream CallToolResult must be a JSON object")
        captured = copy.deepcopy(dict(value))
    else:
        raise DownstreamProtocolError("downstream CallToolResult must be a JSON object")

    try:
        json.dumps(captured, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError):
        invalid_json = True
    else:
        invalid_json = False
    if invalid_json:
        raise DownstreamProtocolError("downstream CallToolResult is not valid JSON")
    if _is_task_result(captured):
        raise DownstreamProtocolError("downstream task results are not supported")
    if "isError" in captured and type(captured["isError"]) is not bool:
        raise DownstreamProtocolError("downstream CallToolResult has an invalid error marker")

    try:
        validated = types.CallToolResult.model_validate(captured, strict=True)
        normalized = raw_model(validated)
    except Exception:
        invalid_result = True
        normalized = {}
    else:
        invalid_result = False
    if invalid_result:
        raise DownstreamProtocolError("downstream returned an invalid CallToolResult")
    if normalized != captured:
        raise DownstreamProtocolError("the pinned MCP SDK changed a downstream CallToolResult")
    return copy.deepcopy(captured)


def structured_adapter_result(raw_result: Mapping[str, Any]) -> dict[str, Any]:
    """Extract a detached object result and add the envelope error bit without ambiguity."""

    raw = validate_call_tool_result(raw_result)
    structured = raw.get("structuredContent")
    if not isinstance(structured, Mapping):
        raise DownstreamProtocolError("downstream structuredContent must be a JSON object")
    detached = _validate_json_object(structured)
    envelope_error = raw.get("isError", False)
    if type(envelope_error) is not bool:  # also documents the invariant after validation
        raise DownstreamProtocolError("downstream CallToolResult has an invalid error marker")
    for marker in ("isError", "is_error"):
        if marker not in detached:
            continue
        structured_error = detached[marker]
        if type(structured_error) is not bool or structured_error is not envelope_error:
            raise DownstreamProtocolError("downstream result contains contradictory error markers")
    detached.setdefault("isError", envelope_error)
    return detached


class DownstreamClient:
    """One independently initialized and supervised downstream MCP client role.

    ``start`` is idempotent only while the client is running. A failed or closed
    instance is terminal and must be replaced, which prevents accidental replay
    through an implicitly re-established mutation session.
    """

    def __init__(
        self,
        alias: str,
        config: DownstreamConfig,
        secret_store: SecretStore,
        *,
        http_connector: HTTPConnector = _official_http_connector,
        stdio_connector: StdioConnector = _official_stdio_connector,
        session_factory: SessionFactory = _official_session_factory,
    ) -> None:
        self._validate_config(alias, config)
        self._alias = alias
        self._config = config
        self._credential_reference = SecretReference.parse(config.credential_ref)
        self._secret_store = secret_store
        self._http_connector = http_connector
        self._stdio_connector = stdio_connector
        self._session_factory = session_factory
        self._state = _Lifecycle.NEW
        self._session: DownstreamSession | None = None
        self._lifecycle_lock = asyncio.Lock()
        self._ready: asyncio.Future[None] | None = None
        self._stop_event: asyncio.Event | None = None
        self._supervisor_task: asyncio.Task[None] | None = None
        self._active_operations: set[asyncio.Task[Any]] = set()
        self._close_failure: DownstreamConnectionError | None = None

    def __repr__(self) -> str:
        return (
            f"DownstreamClient(alias={self._alias!r}, transport={self._config.transport!r}, "
            f"state={self._state.value!r}, credential=<redacted>)"
        )

    @property
    def alias(self) -> str:
        return self._alias

    @property
    def state(self) -> str:
        return self._state.value

    @property
    def is_running(self) -> bool:
        return self._state is _Lifecycle.RUNNING

    async def __aenter__(self) -> DownstreamClient:
        return await self.start()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: Any,
    ) -> None:
        del exc_type, exc_value, traceback
        await self.close()

    async def start(self) -> DownstreamClient:
        """Initialize this downstream role, or return it unchanged when already running."""

        async with self._lifecycle_lock:
            if self._state is _Lifecycle.RUNNING:
                return self
            if self._state is not _Lifecycle.NEW:
                raise DownstreamLifecycleError(
                    "downstream client cannot be started from its current lifecycle state"
                )

            loop = asyncio.get_running_loop()
            self._state = _Lifecycle.STARTING
            self._ready = loop.create_future()
            self._stop_event = asyncio.Event()
            self._supervisor_task = asyncio.create_task(
                self._supervise(self._ready, self._stop_event),
                name=f"signet-downstream-{self._alias}",
            )
            try:
                await self._ready
            except asyncio.CancelledError:
                if not self._ready.done():
                    self._ready.cancel()
                self._stop_event.set()
                self._supervisor_task.cancel()
                with suppress(asyncio.CancelledError):
                    await asyncio.shield(self._supervisor_task)
                self._state = _Lifecycle.FAILED
                raise
            except DownstreamConnectionError:
                await self._supervisor_task
                self._state = _Lifecycle.FAILED
                raise
            return self

    async def close(self) -> None:
        """Cancel in-flight operations and close the owned session and transport once."""

        async with self._lifecycle_lock:
            if self._state is _Lifecycle.CLOSED:
                return
            if self._state is _Lifecycle.NEW:
                self._state = _Lifecycle.CLOSED
                return

            self._state = _Lifecycle.CLOSING
            current = asyncio.current_task()
            active = [task for task in self._active_operations if task is not current]
            for task in active:
                task.cancel()
            cancellation: asyncio.CancelledError | None = None
            try:
                if active:
                    await asyncio.gather(*active, return_exceptions=True)
            except asyncio.CancelledError as exc:
                cancellation = exc
            finally:
                if self._stop_event is not None:
                    self._stop_event.set()

            if self._supervisor_task is not None:
                while not self._supervisor_task.done():
                    try:
                        await asyncio.shield(self._supervisor_task)
                    except asyncio.CancelledError as exc:
                        cancellation = cancellation or exc
            self._session = None
            self._state = _Lifecycle.CLOSED
            if cancellation is not None:
                raise cancellation
            if self._close_failure is not None:
                raise self._close_failure

    async def discover_all_tools(self) -> list[dict[str, Any]]:
        """Exhaust the official tools/list pagination for this initialized role."""

        session, operation = await self._begin_operation()
        connection_failed = False
        protocol_failed = False
        try:
            try:
                tools = await _discover_all_tools(
                    session,
                    max_aggregate_bytes=self._config.output_limit_bytes,
                    timeout_seconds=self._config.timeout_seconds,
                )
            except asyncio.CancelledError:
                raise
            except MirrorError:
                protocol_failed = True
                tools = []
            except Exception:
                connection_failed = True
                tools = []
            if protocol_failed:
                raise DownstreamProtocolError("downstream tool discovery was malformed")
            if connection_failed:
                raise DownstreamConnectionError("downstream tool discovery failed")
            self._enforce_output_limit(tools)
            return copy.deepcopy(tools)
        finally:
            self._active_operations.discard(operation)

    async def discover_tools(self) -> list[dict[str, Any]]:
        """Compatibility spelling for ``discover_all_tools``."""

        return await self.discover_all_tools()

    async def call_tool_raw(self, tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Return an exact detached MCP result for passthrough mirroring."""

        self._validate_tool_name(tool_name)
        try:
            detached_arguments = copy_json_object(arguments)
        except (TypeError, ValueError):
            invalid_arguments = True
            detached_arguments = {}
        else:
            invalid_arguments = False
        if invalid_arguments:
            raise DownstreamProtocolError("downstream tool arguments must be a JSON object")

        session, operation = await self._begin_operation()
        failed = False
        raw_value: Any = None
        try:
            try:
                raw_value = await session.call_tool(tool_name, detached_arguments)
            except asyncio.CancelledError:
                raise
            except Exception:
                failed = True
            if failed:
                raise DownstreamCallError("downstream tool call failed")
            captured = validate_call_tool_result(raw_value)
            self._enforce_output_limit(captured)
            return captured
        finally:
            self._active_operations.discard(operation)

    async def call_tool(self, tool_name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return only the detached structured object consumed by provider adapters."""

        raw = await self.call_tool_raw(tool_name, arguments)
        return structured_adapter_result(raw)

    async def _begin_operation(self) -> tuple[DownstreamSession, asyncio.Task[Any]]:
        async with self._lifecycle_lock:
            if self._state is not _Lifecycle.RUNNING or self._session is None:
                raise DownstreamLifecycleError("downstream client is not initialized")
            operation = asyncio.current_task()
            if operation is None:  # pragma: no cover - asyncio always supplies one here
                raise DownstreamLifecycleError("downstream operation has no owning task")
            self._active_operations.add(operation)
            return self._session, operation

    async def _supervise(self, ready: asyncio.Future[None], stop_event: asyncio.Event) -> None:
        stack = AsyncExitStack()
        failure: DownstreamConnectionError | None = None
        cancelled = False
        try:
            try:
                async with asyncio.timeout(self._config.timeout_seconds):
                    credential = self._secret_store.get(self._credential_reference)
                    if (
                        not isinstance(credential, Secret)
                        or not credential.reveal()
                        or any(character in credential.reveal() for character in "\x00\r\n")
                    ):
                        raise DownstreamConfigurationError(
                            "downstream credential material is unavailable"
                        )
                    streams = await self._enter_transport(stack, credential)
                    if len(streams) not in (2, 3):
                        raise DownstreamProtocolError(
                            "downstream connector returned invalid transport streams"
                        )
                    session_context = self._session_factory(
                        streams[0],
                        streams[1],
                        timedelta(seconds=self._config.timeout_seconds),
                    )
                    session = await stack.enter_async_context(session_context)
                    await session.initialize()
            except asyncio.CancelledError:
                cancelled = True
            except BaseException:
                failure = DownstreamConnectionError("downstream transport initialization failed")

            if not cancelled and failure is None:
                self._session = session
                self._state = _Lifecycle.RUNNING
                ready.set_result(None)
                try:
                    await stop_event.wait()
                except asyncio.CancelledError:
                    cancelled = True
        finally:
            if cancelled:
                task = asyncio.current_task()
                if task is not None:
                    while task.cancelling():
                        task.uncancel()
            try:
                await stack.aclose()
            except BaseException:
                self._close_failure = DownstreamConnectionError(
                    "downstream transport cleanup failed"
                )
                if failure is None and not ready.done():
                    failure = self._close_failure
            self._session = None
            if not ready.done():
                ready.set_exception(
                    failure
                    or DownstreamConnectionError("downstream transport initialization failed")
                )
            if self._state not in {_Lifecycle.CLOSING, _Lifecycle.CLOSED}:
                self._state = _Lifecycle.FAILED

    async def _enter_transport(self, stack: AsyncExitStack, credential: Secret) -> TransportStreams:
        revealed = credential.reveal()
        if self._config.transport == "http":
            assert self._config.url is not None
            context = self._http_connector(
                self._config.url,
                {"Authorization": f"Bearer {revealed}"},
                self._config.timeout_seconds,
                self._config.output_limit_bytes,
            )
            return await stack.enter_async_context(context)

        executable, *arguments = self._config.command
        if any(revealed in argument for argument in arguments):
            raise DownstreamConfigurationError(
                "downstream credentials may not appear in process arguments"
            )
        assert self._config.executable_sha256 is not None
        assert self._config.execution_snapshot_root is not None
        parameters = ReviewedStdioServerParameters(
            command=executable,
            args=list(arguments),
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                _credential_environment_name(self._alias): revealed,
            },
            cwd=self._config.working_directory,
            expected_sha256=self._config.executable_sha256,
            execution_snapshot_root=self._config.execution_snapshot_root,
            output_limit_bytes=self._config.output_limit_bytes,
            test_only_allow_script=self._config.test_only_allow_script,
        )
        return await stack.enter_async_context(self._stdio_connector(parameters))

    def _enforce_output_limit(self, value: Any) -> None:
        try:
            encoded = json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError):
            invalid_json = True
            encoded = b""
        else:
            invalid_json = False
        if invalid_json:
            raise DownstreamProtocolError("downstream response is not valid JSON")
        if len(encoded) > self._config.output_limit_bytes:
            raise DownstreamProtocolError("downstream response exceeds its configured limit")

    @staticmethod
    def _validate_tool_name(tool_name: str) -> None:
        if (
            not isinstance(tool_name, str)
            or not tool_name
            or len(tool_name) > _MAX_TOOL_NAME_LENGTH
            or "\x00" in tool_name
        ):
            raise DownstreamConfigurationError("downstream tool name is invalid")

    @staticmethod
    def _validate_config(alias: str, config: DownstreamConfig) -> None:
        if not isinstance(alias, str) or not _ALIAS_RE.fullmatch(alias):
            raise DownstreamConfigurationError("downstream alias is invalid")
        if not isinstance(config, DownstreamConfig):
            raise DownstreamConfigurationError("downstream configuration is invalid")

        if config.transport == "http":
            if (
                config.url is None
                or config.command
                or config.working_directory is not None
                or config.executable_sha256 is not None
                or config.execution_snapshot_root is not None
                or config.test_only_allow_script
            ):
                raise DownstreamConfigurationError("HTTP downstream configuration is invalid")
            parsed = urlsplit(config.url)
            try:
                port = parsed.port
            except ValueError:
                raise DownstreamConfigurationError(
                    "HTTP downstream endpoint is invalid"
                ) from None
            if (
                len(config.url) > _MAX_EXECUTABLE_LENGTH
                or parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or port is not None
                and not 1 <= port <= 65535
            ):
                raise DownstreamConfigurationError("HTTP downstream endpoint is invalid")
            if parsed.scheme == "http" and parsed.hostname not in {
                "127.0.0.1",
                "::1",
                "localhost",
            }:
                raise DownstreamConfigurationError(
                    "cleartext HTTP downstream endpoints must be loopback"
                )
            return

        if (
            config.url is not None
            or not config.command
            or config.executable_sha256 is None
            or config.execution_snapshot_root is None
            or not config.execution_snapshot_root.is_absolute()
        ):
            raise DownstreamConfigurationError("stdio downstream configuration is invalid")
        executable, *arguments = config.command
        executable_path = Path(executable)
        if (
            not executable_path.is_absolute()
            or not executable
            or len(executable) > _MAX_EXECUTABLE_LENGTH
            or "\x00" in executable
            or executable_path.name.casefold() in _SHELL_EXECUTABLES
        ):
            raise DownstreamConfigurationError("stdio executable must be a pinned non-shell path")
        if (
            len(arguments) > _MAX_ARGUMENT_COUNT
            or any(
                not isinstance(argument, str)
                or len(argument) > _MAX_ARGUMENT_LENGTH
                or "\x00" in argument
                for argument in arguments
            )
            or sum(len(argument.encode("utf-8")) for argument in arguments) > _MAX_ARGUMENT_BYTES
        ):
            raise DownstreamConfigurationError("stdio process arguments exceed safe bounds")
        if config.working_directory is not None and not config.working_directory.is_absolute():
            raise DownstreamConfigurationError("stdio working directory must be absolute")
