from __future__ import annotations

from typing import Any

import anyio
import pytest

from signet.http_security import (
    RequestBodyLimitMiddleware,
    RequestConcurrencyLimitMiddleware,
)


@pytest.mark.asyncio
async def test_streaming_body_limit_rejects_chunked_overflow_before_buffering() -> None:
    app_reached_end = False

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        nonlocal app_reached_end
        del scope
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        app_reached_end = True
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    chunks = iter(
        (
            {"type": "http.request", "body": b"123456", "more_body": True},
            {"type": "http.request", "body": b"789012", "more_body": False},
        )
    )
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return next(chunks)

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    middleware = RequestBodyLimitMiddleware(app, default_limit=10)  # type: ignore[arg-type]
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/upload",
            "headers": [],
        },  # type: ignore[arg-type]
        receive,  # type: ignore[arg-type]
        send,  # type: ignore[arg-type]
    )

    assert app_reached_end is False
    assert sent[0]["status"] == 413
    assert b"Request Entity Too Large" in sent[1]["body"]


@pytest.mark.asyncio
async def test_concurrency_limit_rejects_before_reading_the_request_body() -> None:
    entered = anyio.Event()
    release = anyio.Event()

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        del scope, receive
        entered.set()
        await release.wait()
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = RequestConcurrencyLimitMiddleware(  # type: ignore[arg-type]
        app,
        maximum=1,
    )
    scope = {"type": "http", "method": "POST", "path": "/mcp/test", "headers": []}
    first_sent: list[dict[str, Any]] = []
    second_sent: list[dict[str, Any]] = []
    second_reads = 0

    async def receive() -> dict[str, Any]:
        nonlocal second_reads
        second_reads += 1
        return {"type": "http.request", "body": b"x" * 1024, "more_body": False}

    async def send_first(message: dict[str, Any]) -> None:
        first_sent.append(message)

    async def send_second(message: dict[str, Any]) -> None:
        second_sent.append(message)

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(
            middleware,
            scope,  # type: ignore[arg-type]
            receive,  # type: ignore[arg-type]
            send_first,  # type: ignore[arg-type]
        )
        await entered.wait()
        await middleware(
            scope,  # type: ignore[arg-type]
            receive,  # type: ignore[arg-type]
            send_second,  # type: ignore[arg-type]
        )
        release.set()

    assert first_sent[0]["status"] == 204
    assert second_sent[0]["status"] == 429
    assert (b"retry-after", b"1") in second_sent[0]["headers"]
    assert second_reads == 0

    after_release: list[dict[str, Any]] = []

    async def send_after_release(message: dict[str, Any]) -> None:
        after_release.append(message)

    await middleware(
        scope,  # type: ignore[arg-type]
        receive,  # type: ignore[arg-type]
        send_after_release,  # type: ignore[arg-type]
    )
    assert after_release[0]["status"] == 204


@pytest.mark.asyncio
async def test_concurrency_slot_is_released_when_request_is_cancelled() -> None:
    entered = anyio.Event()
    calls = 0

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        nonlocal calls
        del scope, receive
        calls += 1
        if calls == 1:
            entered.set()
            await anyio.sleep_forever()
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = RequestConcurrencyLimitMiddleware(  # type: ignore[arg-type]
        app,
        maximum=1,
    )
    scope = {"type": "http", "method": "POST", "path": "/mcp/test", "headers": []}

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def discard(message: dict[str, Any]) -> None:
        del message

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(
            middleware,
            scope,  # type: ignore[arg-type]
            receive,  # type: ignore[arg-type]
            discard,  # type: ignore[arg-type]
        )
        await entered.wait()
        tasks.cancel_scope.cancel()

    sent: list[dict[str, Any]] = []

    async def capture(message: dict[str, Any]) -> None:
        sent.append(message)

    await middleware(
        scope,  # type: ignore[arg-type]
        receive,  # type: ignore[arg-type]
        capture,  # type: ignore[arg-type]
    )
    assert sent[0]["status"] == 204
