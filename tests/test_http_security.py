from __future__ import annotations

from typing import Any

import pytest

from signet.http_security import RequestBodyLimitMiddleware


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
