"""Small pure-ASGI guards shared by the web and MCP listeners."""

from __future__ import annotations

from collections.abc import Mapping

import anyio
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class _BodyTooLarge(Exception):
    pass


class RequestConcurrencyLimitMiddleware:
    """Reject excess in-flight requests before their bodies are consumed."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        maximum: int,
        exempt_paths: frozenset[str] = frozenset(),
    ) -> None:
        if maximum < 1 or maximum > 256:
            raise ValueError("request concurrency limit is invalid")
        if any(not path.startswith("/") for path in exempt_paths):
            raise ValueError("request concurrency exemptions are invalid")
        self._app = app
        self._semaphore = anyio.Semaphore(maximum)
        self._exempt_paths = exempt_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") in self._exempt_paths:
            await self._app(scope, receive, send)
            return
        try:
            self._semaphore.acquire_nowait()
        except anyio.WouldBlock:
            response = Response(
                "Too Many Requests",
                status_code=429,
                headers={"Cache-Control": "no-store", "Retry-After": "1"},
            )
            await response(scope, receive, send)
            return
        try:
            await self._app(scope, receive, send)
        finally:
            self._semaphore.release()


class RequestBodyLimitMiddleware:
    """Reject oversized streamed bodies before a framework buffers or parses them."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        default_limit: int,
        route_limits: Mapping[tuple[str, str], int] | None = None,
    ) -> None:
        if default_limit <= 0 or default_limit > 64 * 1024 * 1024:
            raise ValueError("default request body limit is invalid")
        selected = dict(route_limits or {})
        if any(
            not method or not path.startswith("/") or limit <= 0 or limit > 64 * 1024 * 1024
            for (method, path), limit in selected.items()
        ):
            raise ValueError("route request body limits are invalid")
        self._app = app
        self._default_limit = default_limit
        self._route_limits = {
            (method.upper(), path): limit for (method, path), limit in selected.items()
        }

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        method = str(scope.get("method", "")).upper()
        path = str(scope.get("path", ""))
        limit = self._route_limits.get((method, path), self._default_limit)
        content_length = _content_length(scope)
        if content_length is not None and content_length > limit:
            await _too_large_response(scope, receive, send)
            return

        received = 0
        response_started = False

        async def bounded_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self._app(scope, bounded_receive, tracked_send)
        except _BodyTooLarge:
            if response_started:
                raise
            await _too_large_response(scope, receive, send)


def _content_length(scope: Scope) -> int | None:
    values = [
        value
        for name, value in scope.get("headers", [])
        if bytes(name).lower() == b"content-length"
    ]
    if not values:
        return None
    if len(values) != 1:
        return 2**63 - 1
    try:
        decoded = bytes(values[0]).decode("ascii")
        if not decoded or not decoded.isdigit():
            raise ValueError
        return int(decoded)
    except (UnicodeError, ValueError):
        return 2**63 - 1


async def _too_large_response(scope: Scope, receive: Receive, send: Send) -> None:
    response = Response(
        "Request Entity Too Large",
        status_code=413,
        headers={"Cache-Control": "no-store", "Connection": "close"},
    )
    await response(scope, receive, send)
