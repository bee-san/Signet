"""Normally authenticated human web application for Signet."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, cast
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware

from signet.auth import InvalidSession, SessionPrincipal
from signet.http_security import RequestBodyLimitMiddleware

type HumanAction = Literal[
    "approve",
    "deny",
    "cancel",
    "edit",
    "promote_approval",
    "promote_passthrough",
]

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_LOGIN_CSRF_COOKIE = "__Host-signet_login_csrf"
_SESSION_COOKIE = "__Host-signet_session"
_COOKIE_NAME_CHARACTERS = frozenset(
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)


class WebError(RuntimeError):
    status_code = status.HTTP_400_BAD_REQUEST
    code = "invalid_request"


class WebUnauthorized(WebError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "authentication_required"


class WebForbidden(WebError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "forbidden"


class WebConflict(WebError):
    status_code = status.HTTP_409_CONFLICT
    code = "stale_request"


class WebRateLimited(WebError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "rate_limited"


@dataclass(frozen=True, slots=True)
class QueueItem:
    request_id: str
    service: str
    action: str
    destination_summary: str
    state: str
    created_at: int
    expires_at: int
    version: int
    payload_hash: str


@dataclass(frozen=True, slots=True)
class DetailBlock:
    label: str
    kind: str
    value: Any


@dataclass(frozen=True, slots=True)
class RequestAttachment:
    attachment_id: str
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    purged: bool


@dataclass(frozen=True, slots=True)
class RequestDetail:
    request_id: str
    service: str
    action: str
    title: str
    destination_summary: str
    state: str
    created_at: int
    expires_at: int
    version: int
    payload_hash: str
    detail_blocks: tuple[DetailBlock, ...]
    events: tuple[Mapping[str, Any], ...] = ()
    editable_arguments_json: str | None = None
    gateway_internal: bool = False
    warnings: tuple[str, ...] = ()
    reviewed_arguments_json: str = "{}"
    attachments: tuple[RequestAttachment, ...] = ()
    staged_file_hashes: tuple[str, ...] = ()
    downstream_alias: str = ""
    tool_name: str = ""
    account_context: str | None = None
    policy_mode: str = ""
    policy_version: str = ""
    adapter_version: str = ""
    schema_version: str = ""
    origin_namespace: str = ""
    retry_of_request_id: str | None = None
    approved_at: int | None = None
    execution_started_at: int | None = None
    completed_at: int | None = None
    safe_outcome_json: str | None = None
    failure_reason: str | None = None
    manual_retry_allowed: bool = False
    duplicate_warning_required: bool = False


@dataclass(frozen=True, slots=True)
class AuditEntry:
    occurred_at: int
    actor: str
    action: str
    request_id: str | None
    payload_hash_prefix: str | None


class LoginOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str
    public_key: dict[str, Any]


class ActionOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str
    public_key: dict[str, Any]
    action: HumanAction
    request_id: str
    version: int
    payload_hash: str


class PushSubscriptionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoint: str = Field(min_length=1, max_length=4096)
    p256dh: str = Field(min_length=1, max_length=512)
    auth: str = Field(min_length=1, max_length=512)
    device_label: str = Field(min_length=1, max_length=80)
    categories: tuple[str, ...] = ()


class WebBackend(Protocol):
    """Transaction-aware application boundary used by the HTTP routes."""

    def authenticate(self, token: str | None, *, now: int) -> SessionPrincipal: ...

    def password_totp_login(
        self,
        user_id: str,
        password: str,
        totp_proof: str,
        *,
        source: str,
        previous_token: str | None,
        now: int,
    ) -> str: ...

    def begin_passkey_login(
        self,
        user_id: str,
        *,
        source: str,
        http_method: str,
        now: int,
    ) -> LoginOptions: ...

    def complete_passkey_login(
        self,
        challenge_id: str,
        assertion: Mapping[str, Any],
        *,
        source: str,
        http_method: str,
        previous_token: str | None,
        now: int,
    ) -> str: ...

    def logout(self, token: str | None, *, now: int) -> None: ...

    def list_queue(self, principal: SessionPrincipal, *, now: int) -> tuple[QueueItem, ...]: ...

    def get_detail(self, principal: SessionPrincipal, request_id: str) -> RequestDetail: ...

    def list_audit(self, principal: SessionPrincipal) -> tuple[AuditEntry, ...]: ...

    def begin_passkey_action(
        self,
        principal: SessionPrincipal,
        request_id: str,
        action: HumanAction,
        *,
        expected_version: int,
        expected_payload_hash: str,
        prospective_arguments_json: str | None,
        http_method: str,
        now: int,
    ) -> ActionOptions: ...

    def complete_passkey_action(
        self,
        principal: SessionPrincipal,
        request_id: str,
        challenge_id: str,
        assertion: Mapping[str, Any],
        *,
        http_method: str,
        now: int,
    ) -> str: ...

    def complete_totp_action(
        self,
        principal: SessionPrincipal,
        request_id: str,
        action: HumanAction,
        totp_proof: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        prospective_arguments_json: str | None,
        now: int,
    ) -> str: ...

    def subscribe_push(
        self,
        principal: SessionPrincipal,
        subscription: PushSubscriptionInput,
        *,
        now: int,
    ) -> None: ...

    def unsubscribe_push(
        self,
        principal: SessionPrincipal,
        endpoint: str,
        *,
        now: int,
    ) -> None: ...


class CsrfManager:
    """Issue bounded HMAC tokens tied to one session and route purpose."""

    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < 32:
            raise ValueError("CSRF signing key must contain at least 32 bytes")
        self._key = bytes(signing_key)

    def login_token(self) -> str:
        nonce = secrets.token_urlsafe(32)
        return f"c1.{nonce}.{self._signature('login', nonce)}"

    def session_token(self, session_id: str, purpose: str) -> str:
        if not session_id or not purpose or len(purpose) > 512:
            raise ValueError("invalid CSRF binding")
        return f"c1.{self._signature(session_id, purpose)}"

    def verify_login(self, cookie: str | None, supplied: str | None) -> bool:
        if cookie is None or supplied is None or not hmac.compare_digest(cookie, supplied):
            return False
        try:
            version, nonce, signature = supplied.split(".")
        except ValueError:
            return False
        return version == "c1" and hmac.compare_digest(signature, self._signature("login", nonce))

    def verify_session(
        self,
        session_id: str,
        purpose: str,
        supplied: str | None,
    ) -> bool:
        if supplied is None:
            return False
        expected = self.session_token(session_id, purpose)
        return hmac.compare_digest(expected, supplied)

    def _signature(self, subject: str, purpose: str) -> str:
        return hmac.new(
            self._key,
            f"{subject}\x00{purpose}".encode(),
            hashlib.sha256,
        ).hexdigest()

    def __repr__(self) -> str:
        return "CsrfManager(signing_key=<redacted>)"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Any, *, public_origin: str) -> None:
        super().__init__(app)
        self.public_origin = public_origin

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method == "OPTIONS":
            response: Response = Response(status_code=status.HTTP_403_FORBIDDEN)
        elif (
            request.method in _UNSAFE_METHODS
            and request.headers.get("origin") != self.public_origin
        ):
            response = Response(status_code=status.HTTP_403_FORBIDDEN)
        else:
            response = await call_next(request)
        response.headers.update(
            {
                "Cache-Control": "no-store, max-age=0",
                "Content-Security-Policy": (
                    "default-src 'self'; base-uri 'none'; object-src 'none'; frame-src 'none'; "
                    "frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; "
                    "style-src 'self'; script-src 'self'; connect-src 'self'; "
                    "manifest-src 'self'; worker-src 'self'"
                ),
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Resource-Policy": "same-origin",
                "Permissions-Policy": (
                    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
                    "publickey-credentials-get=(self)"
                ),
                "Referrer-Policy": "no-referrer",
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            }
        )
        return response


@dataclass(frozen=True, slots=True)
class WebSettings:
    public_origin: str
    allowed_hosts: tuple[str, ...]
    vapid_public_key: str = ""
    session_cookie: str = _SESSION_COOKIE
    login_csrf_cookie: str = _LOGIN_CSRF_COOKIE
    secure_cookies: bool = True
    fake_only_ui: bool = False

    def __post_init__(self) -> None:
        parsed = urlsplit(self.public_origin)
        try:
            port = parsed.port
        except ValueError:
            raise ValueError("web public origin is invalid") from None
        hostname = parsed.hostname
        if (
            hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or port is not None
            and not 1 <= port <= 65535
        ):
            raise ValueError("web public origin is invalid")
        loopback = hostname == "localhost"
        with suppress(ValueError):
            loopback = loopback or ipaddress.ip_address(hostname).is_loopback
        if self.secure_cookies:
            if parsed.scheme != "https":
                raise ValueError("secure web cookies require an HTTPS public origin")
            if not self.session_cookie.startswith(
                "__Host-"
            ) or not self.login_csrf_cookie.startswith("__Host-"):
                raise ValueError("secure web cookies require __Host- cookie names")
        elif (
            parsed.scheme != "http"
            or not loopback
            or self.session_cookie.startswith("__Host-")
            or self.login_csrf_cookie.startswith("__Host-")
        ):
            raise ValueError("insecure web cookies are restricted to named loopback cookies")
        if self.fake_only_ui and self.secure_cookies:
            raise ValueError("fake-only web UI requires explicit loopback demo mode")
        cookie_names = (self.session_cookie, self.login_csrf_cookie)
        if (
            not self.allowed_hosts
            or hostname not in self.allowed_hosts
            or len(set(cookie_names)) != len(cookie_names)
            or any(not _valid_allowed_host(host) for host in self.allowed_hosts)
            or any(
                not name
                or len(name) > 128
                or any(character not in _COOKIE_NAME_CHARACTERS for character in name)
                for name in cookie_names
            )
        ):
            raise ValueError("web host or cookie configuration is invalid")


def _valid_allowed_host(host: str) -> bool:
    if not host or len(host) > 253 or host.endswith("."):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        return all(
            label
            and len(label) <= 63
            and label[0].isalnum()
            and label[-1].isalnum()
            and all(character.isalnum() or character == "-" for character in label)
            and label.isascii()
            for label in labels
        )
    return True


def create_agent_health_app() -> FastAPI:
    """Agent listener surface: deliberately no browser routes."""

    app = FastAPI(title="Signet MCP", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "signet"}

    return app


def create_web_app(
    backend: WebBackend,
    *,
    settings: WebSettings,
    csrf: CsrfManager,
    clock: Callable[[], int] | None = None,
) -> FastAPI:
    """Create the private human app without exposing any agent bearer authority."""

    now_fn = clock or (lambda: int(time.time()))
    package_root = Path(__file__).resolve().parent
    templates = Jinja2Templates(directory=package_root / "templates")
    app = FastAPI(title="Signet", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityHeadersMiddleware, public_origin=settings.public_origin)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    app.add_middleware(
        RequestBodyLimitMiddleware,
        default_limit=4_100_000,
        route_limits={
            ("POST", "/login/password"): 16 * 1024,
            ("POST", "/login/passkey/options"): 8 * 1024,
            ("POST", "/login/passkey/complete"): 128 * 1024,
            ("POST", "/push/subscriptions"): 16 * 1024,
            ("DELETE", "/push/subscriptions"): 8 * 1024,
        },
    )
    app.mount("/static", StaticFiles(directory=package_root / "static"), name="static")

    def source(request: Request) -> str:
        client = request.client.host if request.client is not None else "unknown"
        return hashlib.sha256(client.encode()).hexdigest()

    def principal(request: Request) -> SessionPrincipal:
        try:
            return backend.authenticate(
                request.cookies.get(settings.session_cookie),
                now=now_fn(),
            )
        except (InvalidSession, WebUnauthorized):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED) from None

    def require_csrf(
        request: Request,
        selected: SessionPrincipal,
        purpose: str,
        supplied: str | None,
    ) -> None:
        header = request.headers.get("x-csrf-token")
        if not csrf.verify_session(selected.session_id, purpose, header or supplied):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid CSRF token")

    def context(request: Request, selected: SessionPrincipal | None = None) -> dict[str, Any]:
        return {
            "request": request,
            "principal": selected,
            "vapid_public_key": settings.vapid_public_key,
            "fake_only_ui": settings.fake_only_ui,
        }

    @app.exception_handler(WebError)
    async def web_error_handler(request: Request, exc: WebError) -> Response:
        if request.headers.get("accept", "").startswith("application/json"):
            return JSONResponse(
                {"error": {"code": exc.code, "message": str(exc)}},
                status_code=exc.status_code,
            )
        return cast(
            Response,
            templates.TemplateResponse(
                request,
                "error.html",
                {**context(request), "status_code": exc.status_code, "message": str(exc)},
                status_code=exc.status_code,
            ),
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "signet-web"}

    @app.get("/manifest.webmanifest", include_in_schema=False)
    async def manifest() -> Response:
        path = package_root / "static" / "manifest.webmanifest"
        return Response(path.read_bytes(), media_type="application/manifest+json")

    @app.get("/service-worker.js", include_in_schema=False)
    async def service_worker() -> Response:
        path = package_root / "static" / "service-worker.js"
        return Response(
            path.read_bytes(),
            media_type="application/javascript",
            headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"},
        )

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Response:
        token = csrf.login_token()
        response = cast(
            Response,
            templates.TemplateResponse(
                request,
                "login.html",
                {**context(request), "login_csrf": token},
            ),
        )
        response.set_cookie(
            settings.login_csrf_cookie,
            token,
            secure=settings.secure_cookies,
            httponly=True,
            samesite="strict",
            path="/",
            max_age=600,
        )
        return response

    @app.post("/login/password")
    async def password_login(
        request: Request,
        user_id: Annotated[str, Form(min_length=1, max_length=256)],
        password: Annotated[str, Form(min_length=1, max_length=1024)],
        totp_proof: Annotated[str, Form(min_length=1, max_length=128)],
        csrf_token: Annotated[str, Form()],
    ) -> Response:
        if not csrf.verify_login(request.cookies.get(settings.login_csrf_cookie), csrf_token):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        token = backend.password_totp_login(
            user_id,
            password,
            totp_proof,
            source=source(request),
            previous_token=request.cookies.get(settings.session_cookie),
            now=now_fn(),
        )
        response = Response(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/"})
        _set_session_cookie(
            response,
            settings.session_cookie,
            token,
            secure=settings.secure_cookies,
        )
        response.delete_cookie(
            settings.login_csrf_cookie,
            path="/",
            secure=settings.secure_cookies,
            httponly=True,
        )
        return response

    @app.post("/login/passkey/options")
    async def passkey_login_options(request: Request) -> LoginOptions:
        if not csrf.verify_login(
            request.cookies.get(settings.login_csrf_cookie),
            request.headers.get("x-csrf-token"),
        ):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        body = await _json_object(request)
        user_id = body.get("user_id")
        if not isinstance(user_id, str) or not user_id or len(user_id) > 256:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
        return backend.begin_passkey_login(
            user_id,
            source=source(request),
            http_method=request.method,
            now=now_fn(),
        )

    @app.post("/login/passkey/complete")
    async def passkey_login_complete(request: Request) -> Response:
        if not csrf.verify_login(
            request.cookies.get(settings.login_csrf_cookie),
            request.headers.get("x-csrf-token"),
        ):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        body = await _json_object(request)
        challenge_id = body.get("challenge_id")
        assertion = body.get("assertion")
        if not isinstance(challenge_id, str) or not isinstance(assertion, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
        token = backend.complete_passkey_login(
            challenge_id,
            assertion,
            source=source(request),
            http_method=request.method,
            previous_token=request.cookies.get(settings.session_cookie),
            now=now_fn(),
        )
        response = JSONResponse({"status": "authenticated"})
        _set_session_cookie(
            response,
            settings.session_cookie,
            token,
            secure=settings.secure_cookies,
        )
        response.delete_cookie(
            settings.login_csrf_cookie,
            path="/",
            secure=settings.secure_cookies,
            httponly=True,
        )
        return response

    @app.post("/logout")
    async def logout(request: Request, csrf_token: Annotated[str, Form()]) -> Response:
        selected = principal(request)
        require_csrf(request, selected, "logout", csrf_token)
        backend.logout(request.cookies.get(settings.session_cookie), now=now_fn())
        response = Response(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
        response.delete_cookie(
            settings.session_cookie,
            path="/",
            secure=settings.secure_cookies,
            httponly=True,
        )
        return response

    @app.get("/", response_class=HTMLResponse)
    async def queue(request: Request) -> Response:
        selected = principal(request)
        items = backend.list_queue(selected, now=now_fn())
        return cast(
            Response,
            templates.TemplateResponse(
                request,
                "queue.html",
                {
                    **context(request, selected),
                    "items": items,
                    "now": now_fn(),
                    "logout_csrf": csrf.session_token(selected.session_id, "logout"),
                    "push_csrf": csrf.session_token(selected.session_id, "push"),
                },
            ),
        )

    @app.get("/requests/{request_id}", response_class=HTMLResponse)
    async def detail(request: Request, request_id: str) -> Response:
        selected = principal(request)
        value = backend.get_detail(selected, request_id)
        purpose = f"request:{request_id}"
        return cast(
            Response,
            templates.TemplateResponse(
                request,
                "detail.html",
                {
                    **context(request, selected),
                    "item": value,
                    "csrf_token": csrf.session_token(selected.session_id, purpose),
                    "logout_csrf": csrf.session_token(selected.session_id, "logout"),
                },
            ),
        )

    @app.get("/requests/{request_id}/review", response_class=HTMLResponse)
    async def review_fragment(request: Request, request_id: str) -> Response:
        selected = principal(request)
        value = backend.get_detail(selected, request_id)
        return cast(
            Response,
            templates.TemplateResponse(
                request,
                "review_fragment.html",
                {
                    **context(request, selected),
                    "item": value,
                    "id_suffix": hashlib.sha256(request_id.encode()).hexdigest()[:12],
                    "csrf_token": csrf.session_token(
                        selected.session_id,
                        f"request:{request_id}",
                    ),
                },
            ),
        )

    @app.get("/audit", response_class=HTMLResponse)
    async def audit(request: Request) -> Response:
        selected = principal(request)
        return cast(
            Response,
            templates.TemplateResponse(
                request,
                "audit.html",
                {
                    **context(request, selected),
                    "entries": backend.list_audit(selected),
                    "logout_csrf": csrf.session_token(selected.session_id, "logout"),
                },
            ),
        )

    @app.post("/requests/{request_id}/actions/totp")
    async def totp_action(
        request: Request,
        request_id: str,
        action: Annotated[HumanAction, Form()],
        expected_version: Annotated[int, Form(ge=1)],
        expected_payload_hash: Annotated[str, Form(min_length=64, max_length=64)],
        totp_proof: Annotated[str, Form(min_length=1, max_length=128)],
        csrf_token: Annotated[str, Form()],
        prospective_arguments_json: Annotated[
            str | None,
            Form(max_length=4_000_000),
        ] = None,
    ) -> Response:
        selected = principal(request)
        require_csrf(request, selected, f"request:{request_id}", csrf_token)
        backend.complete_totp_action(
            selected,
            request_id,
            action,
            totp_proof,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            prospective_arguments_json=prospective_arguments_json,
            now=now_fn(),
        )
        return Response(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": f"/requests/{request_id}"},
        )

    @app.post("/requests/{request_id}/actions/passkey/options")
    async def passkey_action_options(request: Request, request_id: str) -> ActionOptions:
        selected = principal(request)
        require_csrf(request, selected, f"request:{request_id}", None)
        body = await _json_object(request)
        action = body.get("action")
        if action not in _HUMAN_ACTIONS:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
        expected_version = body.get("expected_version")
        payload_hash = body.get("expected_payload_hash")
        prospective = body.get("prospective_arguments_json")
        if (
            not isinstance(expected_version, int)
            or expected_version < 1
            or not isinstance(payload_hash, str)
            or len(payload_hash) != 64
            or (prospective is not None and not isinstance(prospective, str))
        ):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
        return backend.begin_passkey_action(
            selected,
            request_id,
            action,
            expected_version=expected_version,
            expected_payload_hash=payload_hash,
            prospective_arguments_json=prospective,
            http_method=request.method,
            now=now_fn(),
        )

    @app.post("/requests/{request_id}/actions/passkey/complete")
    async def passkey_action_complete(request: Request, request_id: str) -> dict[str, str]:
        selected = principal(request)
        require_csrf(request, selected, f"request:{request_id}", None)
        body = await _json_object(request)
        challenge_id = body.get("challenge_id")
        assertion = body.get("assertion")
        if not isinstance(challenge_id, str) or not isinstance(assertion, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
        final_state = backend.complete_passkey_action(
            selected,
            request_id,
            challenge_id,
            assertion,
            http_method=request.method,
            now=now_fn(),
        )
        return {"status": final_state, "request_id": request_id}

    @app.post("/push/subscriptions", status_code=status.HTTP_204_NO_CONTENT)
    async def subscribe_push(request: Request, payload: PushSubscriptionInput) -> Response:
        selected = principal(request)
        require_csrf(request, selected, "push", None)
        backend.subscribe_push(selected, payload, now=now_fn())
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.delete("/push/subscriptions", status_code=status.HTTP_204_NO_CONTENT)
    async def unsubscribe_push(request: Request) -> Response:
        selected = principal(request)
        require_csrf(request, selected, "push", None)
        body = await _json_object(request)
        endpoint = body.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint or len(endpoint) > 4096:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
        backend.unsubscribe_push(selected, endpoint, now=now_fn())
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return app


_HUMAN_ACTIONS: frozenset[str] = frozenset(
    {
        "approve",
        "deny",
        "cancel",
        "edit",
        "promote_approval",
        "promote_passthrough",
    }
)


async def _json_object(request: Request) -> dict[str, Any]:
    try:
        value = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST) from None
    if not isinstance(value, dict):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
    return value


def _set_session_cookie(
    response: Response,
    name: str,
    token: str,
    *,
    secure: bool = True,
) -> None:
    response.set_cookie(
        name,
        token,
        secure=secure,
        httponly=True,
        samesite="strict",
        path="/",
    )
