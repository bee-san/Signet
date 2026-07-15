"""Local-only MCP HTTP runtime assembly.

Assembly is intentionally dependency-injected: callers must construct reviewed
alias and approval surfaces before this module is invoked.  Creating the ASGI
application performs no discovery, secret lookup, or downstream connection.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

import anyio
from mcp.server.auth.middleware.bearer_auth import (
    AuthenticatedUser,
    BearerAuthBackend,
    RequireAuthMiddleware,
)
from mcp.server.auth.provider import AccessToken
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from signet.credential_broker import (
    CallerPrincipal,
    CredentialError,
    TokenRegistry,
)
from signet.gateway_tools import GatewayPrincipal, GatewayToolSurface
from signet.http_security import (
    RequestBodyLimitMiddleware,
    RequestConcurrencyLimitMiddleware,
)
from signet.mcp_mirror import AliasToolSurface

APPROVALS_ALIAS = "approvals"
_ALIAS_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_MCP_SCOPE_PREFIX = "signet:mcp:"
_current_caller: ContextVar[CallerPrincipal | None] = ContextVar(
    "signet_current_mcp_caller", default=None
)


class RuntimeAssemblyError(ValueError):
    """Raised when an MCP runtime would expose an unsafe or ambiguous surface."""


@dataclass(frozen=True, slots=True)
class MCPRuntime:
    """One-run ASGI application and its path-specific official session managers."""

    app: Starlette
    managers: Mapping[str, StreamableHTTPSessionManager]
    allowed_hosts: frozenset[str]


class RegistryTokenVerifier:
    """Adapt Signet's profile token registry to the MCP SDK bearer contract."""

    def __init__(self, registry: TokenRegistry, *, alias: str) -> None:
        self._registry = registry
        self._alias = alias

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            principal = self._registry.authenticate(f"Bearer {token}", alias=self._alias)
        except CredentialError:
            return None
        return AccessToken(
            token="<redacted>",
            client_id=principal.token_id,
            subject=principal.namespace,
            scopes=[_alias_scope(self._alias)],
            claims={
                "iss": "signet:local",
                "namespace": principal.namespace,
                "allowed_aliases": sorted(principal.allowed_aliases),
                "token_id": principal.token_id,
            },
        )


class LoopbackHostMiddleware:
    """Reject untrusted Host headers on every route, including health checks."""

    def __init__(self, app: ASGIApp, *, allowed_hosts: frozenset[str]) -> None:
        if not allowed_hosts:
            raise RuntimeAssemblyError("at least one loopback Host value is required")
        self._app = app
        self._allowed_hosts = frozenset(value.lower() for value in allowed_hosts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            host = _header(scope, b"host")
            if host is None or host.lower() not in self._allowed_hosts:
                response = Response(
                    "Misdirected Request",
                    status_code=421,
                    headers={"Cache-Control": "no-store"},
                )
                await response(scope, receive, send)
                return
        await self._app(scope, receive, send)


class CallerContextMiddleware:
    """Expose the authenticated profile to gateway-owned tool providers."""

    def __init__(self, app: ASGIApp, *, alias: str) -> None:
        self._app = app
        self._alias = alias

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        user = scope.get("user")
        if not isinstance(user, AuthenticatedUser):
            await self._app(scope, receive, send)
            return
        claims = user.access_token.claims or {}
        namespace = claims.get("namespace")
        token_id = claims.get("token_id")
        raw_aliases = claims.get("allowed_aliases")
        if (
            not isinstance(namespace, str)
            or not isinstance(token_id, str)
            or not isinstance(raw_aliases, list)
            or any(not isinstance(alias, str) for alias in raw_aliases)
            or self._alias not in raw_aliases
        ):
            response = JSONResponse(
                {"error": "invalid_token", "error_description": "Authentication required"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return
        caller = CallerPrincipal(
            namespace=namespace,
            allowed_aliases=frozenset(raw_aliases),
            token_id=token_id,
        )
        context_token: Token[CallerPrincipal | None] = _current_caller.set(caller)
        try:
            await self._app(scope, receive, send)
        finally:
            _current_caller.reset(context_token)


class PrincipalConcurrencyLimiter:
    """Bound concurrent parsed MCP work for each authenticated token."""

    def __init__(self, maximum: int) -> None:
        if maximum < 1 or maximum > 64:
            raise RuntimeAssemblyError("per-token concurrency limit must be 1 to 64")
        self._maximum = maximum
        self._semaphores: dict[str, anyio.Semaphore] = {}

    async def run(
        self,
        app: ASGIApp,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        user = scope.get("user")
        token_id = (
            (user.access_token.claims or {}).get("token_id")
            if isinstance(user, AuthenticatedUser)
            else None
        )
        if not isinstance(token_id, str):
            await app(scope, receive, send)
            return
        semaphore = self._semaphores.setdefault(token_id, anyio.Semaphore(self._maximum))
        try:
            semaphore.acquire_nowait()
        except anyio.WouldBlock:
            response = JSONResponse(
                {
                    "error": "rate_limited",
                    "error_description": "Too many concurrent requests for this token",
                },
                status_code=429,
                headers={"Cache-Control": "no-store", "Retry-After": "1"},
            )
            await response(scope, receive, send)
            return
        try:
            await app(scope, receive, send)
        finally:
            semaphore.release()


class PrincipalConcurrencyLimitMiddleware:
    def __init__(self, app: ASGIApp, *, limiter: PrincipalConcurrencyLimiter) -> None:
        self._app = app
        self._limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        await self._limiter.run(self._app, scope, receive, send)


class _ManagerEndpoint:
    """Call the SDK manager and retire explicitly terminated stateful sessions."""

    def __init__(
        self,
        manager: StreamableHTTPSessionManager,
        *,
        on_session_closed: Callable[[str], object] | None = None,
        session_limit: int | None = None,
    ) -> None:
        self._manager = manager
        self._on_session_closed = on_session_closed
        self._session_limit = session_limit
        self._session_admission_lock = anyio.Lock()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        session_id = _header(scope, b"mcp-session-id")
        if session_id is None and self._session_limit is not None:
            async with self._session_admission_lock:
                if len(self._manager._server_instances) >= self._session_limit:
                    response = JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "id": "server-error",
                            "error": {
                                "code": -32600,
                                "message": "The Signet MCP session limit is reached.",
                            },
                        },
                        status_code=429,
                        headers={"Cache-Control": "no-store"},
                    )
                    await response(scope, receive, send)
                    return
                await self._manager.handle_request(scope, receive, send)
        else:
            await self._manager.handle_request(scope, receive, send)
        if scope.get("method") == "DELETE" and session_id is not None:
            transport = self._manager._server_instances.get(session_id)
            if transport is not None and transport.is_terminated:
                self._manager._server_instances.pop(session_id, None)
                self._manager._session_owners.pop(session_id, None)
                if self._on_session_closed is not None:
                    self._on_session_closed(session_id)


def current_caller() -> CallerPrincipal:
    """Return the profile bound to the active MCP request or session task."""

    principal = _current_caller.get()
    if principal is None:
        raise RuntimeError("no authenticated MCP caller is active")
    return principal


def gateway_principal_provider(user_id: str) -> Callable[[], GatewayPrincipal]:
    """Bind an injected human TOTP owner to the active caller namespace."""

    if not user_id:
        raise RuntimeAssemblyError("the approvals surface requires a human user ID")

    def provide() -> GatewayPrincipal:
        return GatewayPrincipal(namespace=current_caller().namespace, user_id=user_id)

    return provide


def assemble_mcp_runtime(
    *,
    aliases: Mapping[str, AliasToolSurface],
    approvals: GatewayToolSurface,
    tokens: TokenRegistry,
    bind_host: str = "127.0.0.1",
    bind_port: int = 8789,
    session_idle_timeout: float = 30 * 60,
    json_response: bool = False,
    request_concurrency_limit: int = 32,
    per_token_concurrency_limit: int = 8,
) -> MCPRuntime:
    """Assemble a local MCP ASGI app without contacting downstream providers."""

    address = _loopback_address(bind_host)
    if bind_port < 1024 or bind_port > 65535:
        raise RuntimeAssemblyError("the MCP port must be between 1024 and 65535")
    if session_idle_timeout < 60 or session_idle_timeout > 30 * 60:
        raise RuntimeAssemblyError("the MCP session idle timeout must be 60 to 1800 seconds")
    if request_concurrency_limit < 1 or request_concurrency_limit > 256:
        raise RuntimeAssemblyError("request concurrency limit must be 1 to 256")
    if APPROVALS_ALIAS in aliases:
        raise RuntimeAssemblyError("the approvals alias is reserved for gateway-owned tools")

    server_ids = {id(approvals.server)}
    for alias, surface in aliases.items():
        if _ALIAS_PATTERN.fullmatch(alias) is None or alias != surface.alias:
            raise RuntimeAssemblyError("alias mappings must use exact safe surface aliases")
        if id(surface.server) in server_ids:
            raise RuntimeAssemblyError("each MCP path requires a distinct server instance")
        if surface.session_tracking_ttl_seconds <= session_idle_timeout:
            raise RuntimeAssemblyError(
                "surface session tracking must outlive the transport idle timeout"
            )
        server_ids.add(id(surface.server))

    allowed_hosts = _allowed_host_values(address, bind_port)
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=sorted(allowed_hosts),
        allowed_origins=sorted(_allowed_origin_values(address, bind_port)),
    )

    managers: dict[str, StreamableHTTPSessionManager] = {}
    for alias, surface in aliases.items():
        managers[alias] = StreamableHTTPSessionManager(
            surface.server,
            json_response=json_response,
            stateless=False,
            security_settings=security,
            session_idle_timeout=session_idle_timeout,
        )
    managers[APPROVALS_ALIAS] = StreamableHTTPSessionManager(
        approvals.server,
        json_response=json_response,
        stateless=True,
        security_settings=security,
    )

    routes: list[Route] = []
    principal_limiter = PrincipalConcurrencyLimiter(per_token_concurrency_limit)
    for alias, manager in managers.items():
        bound_surface = aliases.get(alias)
        endpoint: ASGIApp = _ManagerEndpoint(
            manager,
            on_session_closed=(bound_surface.retire_session if bound_surface is not None else None),
            session_limit=(
                bound_surface.tracked_session_limit if bound_surface is not None else None
            ),
        )
        endpoint = RequireAuthMiddleware(endpoint, required_scopes=[_alias_scope(alias)])
        endpoint = PrincipalConcurrencyLimitMiddleware(
            endpoint,
            limiter=principal_limiter,
        )
        endpoint = CallerContextMiddleware(endpoint, alias=alias)
        endpoint = AuthenticationMiddleware(
            endpoint,
            backend=BearerAuthBackend(RegistryTokenVerifier(tokens, alias=alias)),
        )
        routes.append(
            Route(
                f"/mcp/{alias}",
                endpoint=endpoint,
                methods=["GET", "POST", "DELETE"],
                name=f"mcp-{alias}",
                include_in_schema=False,
            )
        )
    routes.append(
        Route(
            "/healthz",
            endpoint=_healthz,
            methods=["GET"],
            name="healthz",
            include_in_schema=False,
        )
    )

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        del app
        async with AsyncExitStack() as stack:
            for manager in managers.values():
                await stack.enter_async_context(manager.run())
            yield

    app = Starlette(
        debug=False,
        routes=routes,
        middleware=[
            Middleware(
                RequestConcurrencyLimitMiddleware,
                maximum=request_concurrency_limit,
                exempt_paths=frozenset({"/healthz"}),
            ),
            Middleware(RequestBodyLimitMiddleware, default_limit=16 * 1024 * 1024),
            Middleware(LoopbackHostMiddleware, allowed_hosts=allowed_hosts),
        ],
        lifespan=lifespan,
    )
    app.router.redirect_slashes = False
    return MCPRuntime(
        app=app,
        managers=MappingProxyType(managers),
        allowed_hosts=allowed_hosts,
    )


async def _healthz(request: Any) -> JSONResponse:
    del request
    return JSONResponse(
        {"status": "ok"},
        headers={"Cache-Control": "no-store"},
    )


def _alias_scope(alias: str) -> str:
    return f"{_MCP_SCOPE_PREFIX}{alias}"


def _loopback_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise RuntimeAssemblyError("the MCP listener must use a numeric loopback address") from exc
    if not address.is_loopback:
        raise RuntimeAssemblyError("the MCP listener must use a loopback address")
    return address


def _host_label(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    return f"[{address.compressed}]" if address.version == 6 else address.compressed


def _allowed_host_values(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int
) -> frozenset[str]:
    host = _host_label(address)
    return frozenset((host, f"{host}:{port}", "localhost", f"localhost:{port}"))


def _allowed_origin_values(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int
) -> frozenset[str]:
    host = _host_label(address)
    return frozenset((f"http://{host}:{port}", f"http://localhost:{port}"))


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return bytes(value).decode("latin-1")
    return None
