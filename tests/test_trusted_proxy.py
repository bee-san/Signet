from __future__ import annotations

import socket
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request

from signet.runtime import TrustedProxySourceMiddleware


def source_app() -> FastAPI:
    app = FastAPI()

    @app.get("/source")
    async def source(request: Request) -> dict[str, str]:
        return {
            "raw_peer": request.client.host if request.client is not None else "unknown",
            "source": str(request.scope.get("state", {}).get("signet_source", "missing")),
        }

    app.add_middleware(TrustedProxySourceMiddleware)
    return app


async def request_from(
    raw_peer: str,
    *,
    headers: list[tuple[str, str]] | None = None,
) -> httpx.Response:
    transport = httpx.ASGITransport(app=source_app(), client=(raw_peer, 43123))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        return await client.get("/source", headers=headers)


@pytest.mark.asyncio
async def test_trusted_proxy_preserves_raw_peer_and_uses_one_valid_forwarded_source() -> None:
    response = await request_from(
        "127.0.0.1",
        headers=[
            ("X-Forwarded-For", "100.101.102.103"),
            ("Tailscale-User-Login", "attacker@example.test"),
        ],
    )

    assert response.status_code == 200
    assert response.json() == {"raw_peer": "127.0.0.1", "source": "100.101.102.103"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        [("X-Forwarded-For", "100.64.0.1, 127.0.0.1")],
        [("X-Forwarded-For", "not-an-ip")],
        [("X-Forwarded-For", "100.64.0.1"), ("X-Forwarded-For", "100.64.0.2")],
    ],
)
async def test_trusted_proxy_rejects_ambiguous_or_malformed_forwarding(
    headers: list[tuple[str, str]],
) -> None:
    response = await request_from("127.0.0.1", headers=headers)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_forged_forwarded_headers_cannot_bypass_raw_loopback_boundary() -> None:
    response = await request_from(
        "100.101.102.103",
        headers=[("X-Forwarded-For", "127.0.0.1")],
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_direct_loopback_request_uses_raw_peer_as_source() -> None:
    response = await request_from("::1")
    assert response.status_code == 200
    assert response.json() == {"raw_peer": "::1", "source": "::1"}


def test_real_uvicorn_keeps_raw_peer_while_trusted_middleware_attributes_source() -> None:
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = int(reservation.getsockname()[1])

    server = uvicorn.Server(
        uvicorn.Config(
            source_app(),
            host="127.0.0.1",
            port=port,
            log_level="warning",
            proxy_headers=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False) as client:
            while time.monotonic() < deadline:
                try:
                    response = client.get(
                        "/source",
                        headers={"X-Forwarded-For": "100.96.0.12"},
                    )
                    break
                except httpx.TransportError:
                    time.sleep(0.02)
            else:
                raise AssertionError("Uvicorn did not start")
        assert response.status_code == 200
        assert response.json() == {"raw_peer": "127.0.0.1", "source": "100.96.0.12"}
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        assert not thread.is_alive()
