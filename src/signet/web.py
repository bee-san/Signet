"""Normally authenticated human web application for Signet."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, cast
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, HTTPException, Query, Request, Response, status
from fastapi import Path as ApiPath
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware

from signet.auth import InvalidSession, SessionPrincipal
from signet.authenticator_management import (
    AuthenticatorManagementError,
    LastAuthenticatorRemovalDenied,
)
from signet.browser_auth import (
    BootstrapAlreadyComplete,
    BootstrapError,
    BrowserAuthController,
    ManagementIntent,
)
from signet.config import is_valid_allowed_host
from signet.decision_notes import (
    APPROVAL_REASON_LABELS,
    DENIAL_REASON_LABELS,
    MAX_DECISION_NOTE_CHARS,
    decision_reason_label,
    normalize_decision_note,
    reason_for_action,
)
from signet.effects import (
    EffectEvidence,
    EffectProfile,
    MutationEffect,
    RecommendedMode,
    TriState,
)
from signet.http_security import RequestBodyLimitMiddleware
from signet.totp import TotpError
from signet.totp_enrollment import IssuedTotpEnrollment, TotpEnrollmentError
from signet.webauthn import WebAuthnError
from signet.webauthn_registration import IssuedRegistration, PasskeyRegistrationError

type HumanAction = Literal[
    "approve",
    "deny",
    "cancel",
    "edit",
    "promote_approval",
    "promote_passthrough",
]
type EffectMutationInput = Literal["none", "additive", "mutating", "destructive", "unknown"]
type EffectTriStateInput = Literal["true", "false", "unknown"]

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_LOGIN_CSRF_COOKIE = "__Host-signet_login_csrf"
_SESSION_COOKIE = "__Host-signet_session"
_BOOTSTRAP_COOKIE = "__Host-signet_bootstrap_claim"
_COOKIE_NAME_CHARACTERS = frozenset(
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_OPAQUE_INTEGRATION_ID_PATTERN = r"^[A-Za-z0-9_-]{16,128}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"


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
    downstream_alias: str
    tool_name: str
    state: str
    created_at: int
    expires_at: int
    version: int
    payload_hash_prefix: str


@dataclass(frozen=True, slots=True)
class QueuePage:
    items: tuple[QueueItem, ...]
    has_more: bool
    next_cursor: str | None = None


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
    detected_mime: str | None = None
    detection_source: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyPromotionPreview:
    target_alias: str
    target_tool: str
    current_mode: str
    proposed_mode: str
    reviewed_read_only: bool
    communication_send: bool
    reviewed_classification: str | None
    current_policy_version: int
    proposed_policy_version: int
    active_policy_version: int
    can_approve: bool
    stale: bool


@dataclass(frozen=True, slots=True, repr=False)
class AttachmentDownload:
    content: bytes
    size_bytes: int
    sha256: str

    def __repr__(self) -> str:
        return "AttachmentDownload(content=<redacted>)"


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
    reviewed_arguments_json: str | None = "{}"
    attachments: tuple[RequestAttachment, ...] = ()
    staged_file_hashes: tuple[str, ...] = ()
    downstream_alias: str = ""
    tool_name: str = ""
    account_context: str | None = None
    policy_promotion_preview: PolicyPromotionPreview | None = None
    policy_promotion_preview_unavailable: str | None = None
    decision_window_expired: bool = False
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
    review_available: bool = True
    content_purged: bool = False
    content_purged_at: int | None = None
    content_purge_reason: str | None = None
    canonical_size: int | None = None
    editor_actor: str | None = None
    historical_event_id: int | None = None
    historical_event_action: str | None = None
    historical_event_actor: str | None = None
    historical_event_occurred_at: int | None = None


@dataclass(frozen=True, slots=True)
class AuditEntry:
    occurred_at: int
    actor: str
    action: str
    request_id: str | None
    payload_hash_prefix: str | None


@dataclass(frozen=True, slots=True)
class DecisionEntry:
    event_id: int
    occurred_at: int
    actor: str
    decision: Literal["approved", "denied", "policy_change"]
    decision_label: str
    confirmation_path: str | None
    confirmation_kind: str | None
    request_id: str
    current_state: str
    downstream_alias: str
    tool_name: str
    version: int
    payload_hash_prefix: str
    confirmation_attribution_ambiguous: bool = False
    confirmation_match_count: int = 0


@dataclass(frozen=True, slots=True)
class DecisionPage:
    items: tuple[DecisionEntry, ...]
    has_more: bool
    next_event_id: int | None = None


@dataclass(frozen=True, slots=True)
class UtcTime:
    iso: str
    display: str


@dataclass(frozen=True, slots=True)
class IntegrationToolSummary:
    opaque_id: str
    tool_name: str
    display_label: str
    schema_digest: str
    present: bool
    review_state: str
    recommended_mode: RecommendedMode | None = None

    def __post_init__(self) -> None:
        _validate_opaque_integration_id(self.opaque_id)
        _validate_bounded_text(self.tool_name, name="tool name", maximum=256)
        _validate_bounded_text(self.display_label, name="display label", maximum=256)
        _validate_sha256(self.schema_digest, name="tool schema digest")
        _validate_bounded_text(self.review_state, name="review state", maximum=64)
        if not isinstance(self.present, bool):
            raise ValueError("tool presence must be boolean")


@dataclass(frozen=True, slots=True)
class IntegrationConnectorSummary:
    alias: str
    connector_id: str
    display_name: str
    config_digest: str
    enabled: bool
    discovery_status: str
    discovery_source: str | None
    discovered_at: int | None
    server_identity_digest: str | None
    tools: tuple[IntegrationToolSummary, ...] = ()

    def __post_init__(self) -> None:
        _validate_bounded_text(self.alias, name="connector alias", maximum=64)
        _validate_bounded_text(self.connector_id, name="connector ID", maximum=128)
        _validate_bounded_text(self.display_name, name="connector display name", maximum=256)
        _validate_sha256(self.config_digest, name="connector configuration digest")
        _validate_bounded_text(self.discovery_status, name="discovery status", maximum=64)
        if self.discovery_source is not None:
            _validate_bounded_text(self.discovery_source, name="discovery source", maximum=32)
        if self.discovered_at is not None:
            _validate_timestamp(self.discovered_at, name="discovery time")
        if self.server_identity_digest is not None:
            _validate_sha256(self.server_identity_digest, name="server identity digest")
        if not isinstance(self.enabled, bool) or len(self.tools) > 512:
            raise ValueError("connector summary exceeds its bounds")


@dataclass(frozen=True, slots=True)
class IntegrationPluginSummary:
    plugin_id: str
    plugin_version: str
    manifest_sha256: str
    display_name: str
    enabled: bool
    connectors: tuple[IntegrationConnectorSummary, ...] = ()

    def __post_init__(self) -> None:
        _validate_bounded_text(self.plugin_id, name="plugin ID", maximum=128)
        _validate_bounded_text(self.plugin_version, name="plugin version", maximum=64)
        _validate_sha256(self.manifest_sha256, name="manifest digest")
        _validate_bounded_text(self.display_name, name="plugin display name", maximum=256)
        if not isinstance(self.enabled, bool) or len(self.connectors) > 128:
            raise ValueError("plugin summary exceeds its bounds")


@dataclass(frozen=True, slots=True)
class IntegrationsPage:
    plugins: tuple[IntegrationPluginSummary, ...]

    def __post_init__(self) -> None:
        if len(self.plugins) > 256:
            raise ValueError("integration workspace exceeds its plugin limit")


@dataclass(frozen=True, slots=True)
class EffectReviewView:
    review_id: int
    profile: EffectProfile
    recommended_mode: RecommendedMode
    actor: str
    auth_kind: Literal["totp", "webauthn"]
    reviewed_at: int
    current: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.review_id, int)
            or isinstance(self.review_id, bool)
            or self.review_id < 1
        ):
            raise ValueError("effect review ID is invalid")
        _validate_bounded_text(self.actor, name="effect review actor", maximum=256)
        _validate_timestamp(self.reviewed_at, name="effect review time")
        if self.auth_kind not in {"totp", "webauthn"} or not isinstance(self.current, bool):
            raise ValueError("effect review provenance is invalid")


@dataclass(frozen=True, slots=True)
class IntegrationToolDetail:
    opaque_id: str
    plugin_id: str
    plugin_version: str
    plugin_display_name: str
    manifest_sha256: str
    connector_id: str
    connector_alias: str
    connector_display_name: str
    connector_config_digest: str
    discovery_status: str
    discovery_source: str
    discovered_at: int
    server_identity_digest: str
    tool_name: str
    display_label: str
    action_id: str
    schema_digest: str
    target_snapshot_digest: str
    evidence_bundle_digest: str
    canonical_tool_json: str
    sensitive_json_paths: tuple[str, ...]
    safe_result_fields: tuple[str, ...]
    evidence: tuple[EffectEvidence, ...]
    disagreements: tuple[str, ...]
    reviews: tuple[EffectReviewView, ...] = ()
    reviewable: bool = True
    unavailable_reason: str | None = None

    def __post_init__(self) -> None:
        _validate_opaque_integration_id(self.opaque_id)
        for value, name, maximum in (
            (self.plugin_id, "plugin ID", 128),
            (self.plugin_version, "plugin version", 64),
            (self.plugin_display_name, "plugin display name", 256),
            (self.connector_id, "connector ID", 128),
            (self.connector_alias, "connector alias", 64),
            (self.connector_display_name, "connector display name", 256),
            (self.discovery_status, "discovery status", 64),
            (self.discovery_source, "discovery source", 32),
            (self.tool_name, "tool name", 256),
            (self.display_label, "display label", 256),
            (self.action_id, "action ID", 128),
        ):
            _validate_bounded_text(value, name=name, maximum=maximum)
        for value, name in (
            (self.manifest_sha256, "manifest digest"),
            (self.connector_config_digest, "connector configuration digest"),
            (self.server_identity_digest, "server identity digest"),
            (self.schema_digest, "tool schema digest"),
            (self.target_snapshot_digest, "target snapshot digest"),
            (self.evidence_bundle_digest, "evidence bundle digest"),
        ):
            _validate_sha256(value, name=name)
        _validate_timestamp(self.discovered_at, name="discovery time")
        if (
            not isinstance(self.canonical_tool_json, str)
            or not 2 <= len(self.canonical_tool_json.encode("utf-8")) <= 1_048_576
        ):
            raise ValueError("canonical tool JSON exceeds its bounds")
        if (
            len(self.sensitive_json_paths) > 128
            or len(self.safe_result_fields) > 128
            or len(self.evidence) > 8
            or len(self.disagreements) > 6
            or len(self.reviews) > 100
        ):
            raise ValueError("integration tool detail exceeds its collection bounds")
        for value in (*self.sensitive_json_paths, *self.safe_result_fields):
            _validate_bounded_text(value, name="JSON path", maximum=512)
        effect_axes = frozenset(EffectProfile.__dataclass_fields__)
        if any(value not in effect_axes for value in self.disagreements):
            raise ValueError("effect disagreement names an unknown axis")
        if not isinstance(self.reviewable, bool):
            raise ValueError("effect review availability must be boolean")
        if self.unavailable_reason is not None:
            _validate_bounded_text(
                self.unavailable_reason,
                name="effect review unavailable reason",
                maximum=1_000,
            )
        if self.reviewable == (self.unavailable_reason is not None):
            raise ValueError("effect review availability is inconsistent")


@dataclass(frozen=True, slots=True)
class EffectReviewResult:
    opaque_id: str
    review_id: int
    recommended_mode: RecommendedMode

    def __post_init__(self) -> None:
        _validate_opaque_integration_id(self.opaque_id)
        if (
            not isinstance(self.review_id, int)
            or isinstance(self.review_id, bool)
            or self.review_id < 1
        ):
            raise ValueError("effect review result ID is invalid")


class EffectProfileInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mutation: EffectMutationInput
    external_communication: EffectTriStateInput
    code_execution: EffectTriStateInput
    privilege_change: EffectTriStateInput
    open_world: EffectTriStateInput
    idempotent: EffectTriStateInput

    def effect_profile(self) -> EffectProfile:
        return EffectProfile(
            mutation=MutationEffect(self.mutation),
            external_communication=TriState(self.external_communication),
            code_execution=TriState(self.code_execution),
            privilege_change=TriState(self.privilege_change),
            open_world=TriState(self.open_world),
            idempotent=TriState(self.idempotent),
        )


class IntegrationPasskeyReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    opaque_id: str = Field(min_length=16, max_length=128, pattern=_OPAQUE_INTEGRATION_ID_PATTERN)
    expected_snapshot_digest: str = Field(
        min_length=64,
        max_length=64,
        pattern=_SHA256_PATTERN,
    )
    profile: EffectProfileInput


class IntegrationPasskeyCompleteInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    opaque_id: str = Field(min_length=16, max_length=128, pattern=_OPAQUE_INTEGRATION_ID_PATTERN)
    expected_snapshot_digest: str = Field(
        min_length=64,
        max_length=64,
        pattern=_SHA256_PATTERN,
    )
    challenge_id: str = Field(min_length=16, max_length=128)
    assertion: dict[str, Any]


class IntegrationPasskeyOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=16, max_length=128)
    public_key: dict[str, Any]
    opaque_id: str = Field(min_length=16, max_length=128, pattern=_OPAQUE_INTEGRATION_ID_PATTERN)
    target_snapshot_digest: str = Field(
        min_length=64,
        max_length=64,
        pattern=_SHA256_PATTERN,
    )
    recommended_mode: RecommendedMode


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

    def list_queue(
        self,
        principal: SessionPrincipal,
        *,
        now: int,
        cursor: str | None = None,
    ) -> QueuePage: ...

    def get_detail(self, principal: SessionPrincipal, request_id: str) -> RequestDetail: ...

    def get_historical_detail(
        self,
        principal: SessionPrincipal,
        event_id: int,
    ) -> RequestDetail: ...

    def get_attachment(
        self,
        principal: SessionPrincipal,
        request_id: str,
        attachment_id: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
    ) -> AttachmentDownload: ...

    def list_audit(self, principal: SessionPrincipal) -> tuple[AuditEntry, ...]: ...

    def list_decisions(
        self,
        principal: SessionPrincipal,
        *,
        before_event_id: int | None = None,
    ) -> DecisionPage: ...

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
        decision_note: str | None = None,
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
        decision_note: str | None = None,
        credential_id: str | None = None,
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


class IntegrationWebBackend(Protocol):
    """Authenticated staged-integration reads and exact effect-review mutations."""

    def list_integrations(
        self,
        principal: SessionPrincipal,
        *,
        now: int,
    ) -> IntegrationsPage: ...

    def get_integration_tool(
        self,
        principal: SessionPrincipal,
        opaque_id: str,
        *,
        now: int,
    ) -> IntegrationToolDetail: ...

    def complete_totp_effect_review(
        self,
        principal: SessionPrincipal,
        opaque_id: str,
        profile: EffectProfile,
        totp_proof: str,
        *,
        expected_snapshot_digest: str,
        now: int,
        credential_id: str | None = None,
    ) -> EffectReviewResult: ...

    def begin_passkey_effect_review(
        self,
        principal: SessionPrincipal,
        opaque_id: str,
        profile: EffectProfile,
        *,
        expected_snapshot_digest: str,
        http_method: str,
        now: int,
    ) -> IntegrationPasskeyOptions: ...

    def complete_passkey_effect_review(
        self,
        principal: SessionPrincipal,
        opaque_id: str,
        challenge_id: str,
        assertion: Mapping[str, Any],
        *,
        expected_snapshot_digest: str,
        http_method: str,
        now: int,
    ) -> EffectReviewResult: ...


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

    def cursor_token(self, session_id: str, purpose: str, position: int) -> str:
        if (
            not session_id
            or not purpose
            or len(purpose) > 128
            or not isinstance(position, int)
            or isinstance(position, bool)
            or position < 1
            or position > (2**63 - 1)
        ):
            raise ValueError("invalid cursor binding")
        value = str(position)
        signature = self._signature(session_id, f"cursor:{purpose}:{value}")
        return f"p1.{value}.{signature}"

    def cursor_position(self, session_id: str, purpose: str, supplied: str) -> int:
        if not session_id or not purpose or len(purpose) > 128 or len(supplied) > 96:
            raise ValueError("invalid cursor")
        try:
            version, value, signature = supplied.split(".")
            position = int(value)
        except (TypeError, ValueError):
            raise ValueError("invalid cursor") from None
        if (
            version != "p1"
            or value != str(position)
            or position < 1
            or position > (2**63 - 1)
            or not hmac.compare_digest(
                signature,
                self._signature(session_id, f"cursor:{purpose}:{value}"),
            )
        ):
            raise ValueError("invalid cursor")
        return position

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
                # Chromium serializes same-origin form POSTs with Origin: null
                # under no-referrer, which correctly fails our strict Origin
                # check. same-origin keeps cross-origin referrers suppressed
                # while preserving an exact Origin on authenticated actions.
                "Referrer-Policy": "same-origin",
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
    bootstrap_cookie: str = _BOOTSTRAP_COOKIE
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
            if (
                not self.session_cookie.startswith("__Host-")
                or not self.login_csrf_cookie.startswith("__Host-")
                or not self.bootstrap_cookie.startswith("__Host-")
            ):
                raise ValueError("secure web cookies require __Host- cookie names")
        elif (
            parsed.scheme != "http"
            or not loopback
            or self.session_cookie.startswith("__Host-")
            or self.login_csrf_cookie.startswith("__Host-")
            or self.bootstrap_cookie.startswith("__Host-")
        ):
            raise ValueError("insecure web cookies are restricted to named loopback cookies")
        if self.fake_only_ui == self.secure_cookies:
            raise ValueError("insecure loopback cookies and fake-only UI must be enabled together")
        cookie_names = (self.session_cookie, self.login_csrf_cookie, self.bootstrap_cookie)
        if (
            not self.allowed_hosts
            or hostname not in self.allowed_hosts
            or len({host.lower() for host in self.allowed_hosts}) != len(self.allowed_hosts)
            or len(set(cookie_names)) != len(cookie_names)
            or any(not is_valid_allowed_host(host) for host in self.allowed_hosts)
            or any(
                not name
                or len(name) > 128
                or any(character not in _COOKIE_NAME_CHARACTERS for character in name)
                for name in cookie_names
            )
        ):
            raise ValueError("web host or cookie configuration is invalid")


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
    integrations: IntegrationWebBackend | None = None,
    browser_auth: BrowserAuthController | None = None,
    clock: Callable[[], int] | None = None,
) -> FastAPI:
    """Create the private human app without exposing any agent bearer authority."""

    now_fn = clock or (lambda: int(time.time()))
    package_root = Path(__file__).resolve().parent
    templates = Jinja2Templates(directory=package_root / "templates")
    templates.env.filters["utc_time"] = _utc_time
    templates.env.filters["decision_reason_label"] = decision_reason_label
    templates.env.globals["approval_reason_labels"] = APPROVAL_REASON_LABELS
    templates.env.globals["denial_reason_labels"] = DENIAL_REASON_LABELS
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
            ("POST", "/setup/password"): 16 * 1024,
            ("POST", "/setup/passkeys/options"): 8 * 1024,
            ("POST", "/setup/passkeys/complete"): 128 * 1024,
            ("POST", "/setup/passkeys/resume"): 8 * 1024,
            ("POST", "/setup/totp/start"): 8 * 1024,
            ("POST", "/setup/totp/verify"): 8 * 1024,
            ("POST", "/setup/totp/resume"): 8 * 1024,
            ("POST", "/setup/complete"): 8 * 1024,
            ("POST", "/authenticators/passkeys/options"): 8 * 1024,
            ("POST", "/authenticators/passkeys/complete"): 128 * 1024,
            ("POST", "/authenticators/totp/start"): 8 * 1024,
            ("POST", "/authenticators/totp/verify"): 8 * 1024,
            ("POST", "/authenticators/confirm/passkey/options"): 16 * 1024,
            ("POST", "/authenticators/confirm/passkey/complete"): 128 * 1024,
            ("POST", "/authenticators/confirm/totp"): 16 * 1024,
            ("POST", "/authenticators/enroll/status"): 8 * 1024,
            ("POST", "/authenticators/enroll/resume"): 8 * 1024,
            ("POST", "/integrations/effect-reviews/totp"): 16 * 1024,
            ("POST", "/integrations/effect-reviews/passkey/options"): 32 * 1024,
            ("POST", "/integrations/effect-reviews/passkey/complete"): 128 * 1024,
            ("POST", "/push/subscriptions"): 16 * 1024,
            ("DELETE", "/push/subscriptions"): 8 * 1024,
        },
    )
    app.mount("/static", StaticFiles(directory=package_root / "static"), name="static")

    def source(request: Request) -> str:
        attributed = request.scope.get("state", {}).get("signet_source")
        client = (
            attributed
            if isinstance(attributed, str)
            else request.client.host
            if request.client is not None
            else "unknown"
        )
        return hashlib.sha256(client.encode()).hexdigest()

    def principal(request: Request) -> SessionPrincipal:
        try:
            return backend.authenticate(
                request.cookies.get(settings.session_cookie),
                now=now_fn(),
            )
        except (InvalidSession, WebUnauthorized):
            raise WebUnauthorized(
                "Your session expired or is no longer valid. Sign in again to continue."
            ) from None

    async def async_principal(request: Request) -> SessionPrincipal:
        return await run_in_threadpool(principal, request)

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
            "integrations_available": integrations is not None,
            "authenticator_management_available": browser_auth is not None,
        }

    def active_totp_factors(selected: SessionPrincipal) -> tuple[Any, ...]:
        if browser_auth is None:
            return ()
        return tuple(
            factor
            for factor in browser_auth.list_factors(selected.user_id)
            if factor.kind == "totp"
        )

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

    async def browser_auth_error_handler(request: Request, exc: Exception) -> Response:
        if isinstance(exc, BootstrapAlreadyComplete):
            status_code = status.HTTP_409_CONFLICT
            message = "Setup was already completed. Reload before continuing."
        elif isinstance(exc, LastAuthenticatorRemovalDenied):
            status_code = status.HTTP_400_BAD_REQUEST
            message = (
                "Signet kept this authenticator active because it is the final active "
                "authenticator—the last active sign-in method for this account. Add another "
                "authenticator before revoking it."
            )
        else:
            status_code = status.HTTP_400_BAD_REQUEST
            message = "The authenticator request was invalid, stale, or already used."
        if request.headers.get("accept", "").startswith("application/json"):
            return JSONResponse(
                {"error": {"code": "authenticator_request_failed", "message": message}},
                status_code=status_code,
            )
        return cast(
            Response,
            templates.TemplateResponse(
                request,
                "error.html",
                {**context(request), "status_code": status_code, "message": message},
                status_code=status_code,
            ),
        )

    for browser_error in (
        BootstrapError,
        PasskeyRegistrationError,
        TotpEnrollmentError,
        AuthenticatorManagementError,
        TotpError,
        WebAuthnError,
    ):
        app.add_exception_handler(browser_error, browser_auth_error_handler)

    @app.get("/healthz")
    async def healthz() -> Response:
        probe = getattr(app.state, "signet_health_probe", None)
        try:
            healthy = probe is None or (callable(probe) and probe() is True)
        except Exception:
            healthy = False
        if not healthy:
            return JSONResponse(
                {"status": "unavailable", "service": "signet-web"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return JSONResponse({"status": "ok", "service": "signet-web"})

    @app.get("/manifest.webmanifest", include_in_schema=False)
    def manifest() -> Response:
        path = package_root / "static" / "manifest.webmanifest"
        return Response(path.read_bytes(), media_type="application/manifest+json")

    @app.get("/service-worker.js", include_in_schema=False)
    def service_worker() -> Response:
        path = package_root / "static" / "service-worker.js"
        return Response(
            path.read_bytes(),
            media_type="application/javascript",
            headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"},
        )

    def required_browser_auth() -> BrowserAuthController:
        if browser_auth is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        return browser_auth

    def require_bootstrap_complete() -> None:
        if browser_auth is not None and not browser_auth.bootstrap.status(now=now_fn()).complete:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="setup incomplete")

    def require_setup_csrf(request: Request, supplied: str | None) -> None:
        if not csrf.verify_login(
            request.cookies.get(settings.login_csrf_cookie),
            request.headers.get("x-csrf-token") or supplied,
        ):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    def management_intent(body: Mapping[str, Any]) -> ManagementIntent:
        action = body.get("action")
        operation_id = body.get("operation_id")
        if action not in {"add_passkey", "add_totp", "rename", "revoke"} or not isinstance(
            operation_id, str
        ):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        factor_id = body.get("factor_id")
        label = body.get("label")
        registration_id = body.get("registration_id")
        authorization_id = body.get("authorization_id")
        compromised = body.get("compromised", False)
        if (
            (factor_id is not None and not isinstance(factor_id, str))
            or (label is not None and not isinstance(label, str))
            or (registration_id is not None and not isinstance(registration_id, str))
            or (authorization_id is not None and not isinstance(authorization_id, str))
            or not isinstance(compromised, bool)
        ):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        return ManagementIntent(
            action=action,
            operation_id=operation_id,
            factor_id=factor_id,
            label=label,
            registration_id=registration_id,
            authorization_id=authorization_id,
            compromised=compromised,
        )

    @app.get("/setup", response_class=HTMLResponse)
    def setup_page(request: Request) -> Response:
        selected_auth = required_browser_auth()
        setup_status = selected_auth.bootstrap.status(
            now=now_fn(),
            claimant_token=request.cookies.get(settings.bootstrap_cookie),
        )
        if setup_status.complete:
            return Response(
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Location": "/login"},
            )
        token = csrf.login_token()
        response = cast(
            Response,
            templates.TemplateResponse(
                request,
                "setup.html",
                {
                    **context(request),
                    "setup": setup_status,
                    "login_csrf": token,
                },
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

    @app.post("/setup/claim")
    async def setup_claim(
        request: Request,
        capability: Annotated[str, Form(min_length=32, max_length=384)],
        csrf_token: Annotated[str, Form()],
    ) -> Response:
        require_setup_csrf(request, csrf_token)
        claimant_token = secrets.token_urlsafe(32)
        selected_auth = required_browser_auth()
        await run_in_threadpool(
            selected_auth.bootstrap.claim,
            capability,
            claimant_token,
            now=now_fn(),
        )
        response = Response(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/setup"},
        )
        response.set_cookie(
            settings.bootstrap_cookie,
            claimant_token,
            secure=settings.secure_cookies,
            httponly=True,
            samesite="strict",
            path="/",
            max_age=60 * 60,
        )
        return response

    @app.post("/setup/password")
    async def setup_password(
        request: Request,
        password: Annotated[str, Form(min_length=12, max_length=1024)],
        password_confirmation: Annotated[str, Form(min_length=12, max_length=1024)],
        csrf_token: Annotated[str, Form()],
    ) -> Response:
        require_setup_csrf(request, csrf_token)
        if not hmac.compare_digest(password, password_confirmation):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="password confirmation does not match",
            )
        selected_auth = required_browser_auth()
        await run_in_threadpool(
            selected_auth.bootstrap.enroll_password,
            password,
            claimant_token=request.cookies.get(settings.bootstrap_cookie),
            now=now_fn(),
        )
        return Response(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/setup#passkey"},
        )

    @app.post("/setup/passkeys/options")
    async def setup_passkey_options(request: Request) -> dict[str, Any]:
        require_setup_csrf(request, None)
        body = await _json_object(request)
        label = body.get("label")
        if not isinstance(label, str):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        selected_auth = required_browser_auth()
        issued = await run_in_threadpool(
            selected_auth.begin_registration,
            selected_auth.bootstrap.owner_user_id,
            label,
            flow="bootstrap",
            session_id=None,
            claimant_token=request.cookies.get(settings.bootstrap_cookie),
            now=now_fn(),
        )
        return {
            "challenge_id": issued.challenge_id,
            "publicKey": json.loads(issued.options_json),
        }

    @app.post("/setup/passkeys/resume")
    async def setup_passkey_resume(request: Request) -> dict[str, Any]:
        require_setup_csrf(request, None)
        body = await _json_object(request)
        challenge_id = body.get("challenge_id")
        if not isinstance(challenge_id, str):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        selected_auth = required_browser_auth()
        try:
            issued = await run_in_threadpool(
                selected_auth.resume_registration,
                challenge_id,
                user_id=selected_auth.bootstrap.owner_user_id,
                session_id=None,
                claimant_token=request.cookies.get(settings.bootstrap_cookie),
                now=now_fn(),
            )
        except PasskeyRegistrationError:
            await run_in_threadpool(
                selected_auth.pending_registration,
                challenge_id,
                user_id=selected_auth.bootstrap.owner_user_id,
                session_id=None,
                claimant_token=request.cookies.get(settings.bootstrap_cookie),
                now=now_fn(),
            )
            return {"kind": "passkey", "status": "registered"}
        return {
            "kind": "passkey",
            "challenge_id": issued.challenge_id,
            "publicKey": json.loads(issued.options_json),
        }

    @app.post("/setup/passkeys/complete")
    async def setup_passkey_complete(request: Request) -> dict[str, Any]:
        require_setup_csrf(request, None)
        body = await _json_object(request)
        challenge_id = body.get("challenge_id")
        credential = body.get("credential")
        if not isinstance(challenge_id, str) or not isinstance(credential, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        selected_auth = required_browser_auth()
        await run_in_threadpool(
            selected_auth.complete_registration,
            challenge_id,
            credential,
            user_id=selected_auth.bootstrap.owner_user_id,
            session_id=None,
            claimant_token=request.cookies.get(settings.bootstrap_cookie),
            now=now_fn(),
        )
        setup_status = await run_in_threadpool(
            selected_auth.commit_bootstrap_passkey,
            challenge_id,
            claimant_token=request.cookies.get(settings.bootstrap_cookie),
            now=now_fn(),
        )
        return {
            "status": "registered",
            "authenticator_count": len(setup_status.factor_labels),
        }

    @app.post("/setup/totp/start")
    async def setup_totp_start(request: Request) -> dict[str, str]:
        require_setup_csrf(request, None)
        body = await _json_object(request)
        label = body.get("label")
        if not isinstance(label, str):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        selected_auth = required_browser_auth()
        issued = await run_in_threadpool(
            selected_auth.begin_totp_enrollment,
            selected_auth.bootstrap.owner_user_id,
            label,
            flow="bootstrap",
            session_id=None,
            claimant_token=request.cookies.get(settings.bootstrap_cookie),
            now=now_fn(),
        )
        return {
            "enrollment_id": issued.enrollment.enrollment_id,
            "provisioning_uri": issued.provisioning_uri,
            "qr_code_data_uri": issued.qr_code_data_uri,
            "manual_key": issued.manual_key,
        }

    @app.post("/setup/totp/verify")
    async def setup_totp_verify(request: Request) -> dict[str, Any]:
        require_setup_csrf(request, None)
        body = await _json_object(request)
        enrollment_id = body.get("enrollment_id")
        proof = body.get("proof")
        if not isinstance(enrollment_id, str) or not isinstance(proof, str):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        selected_auth = required_browser_auth()
        await run_in_threadpool(
            selected_auth.verify_totp_enrollment,
            enrollment_id,
            proof,
            user_id=selected_auth.bootstrap.owner_user_id,
            session_id=None,
            claimant_token=request.cookies.get(settings.bootstrap_cookie),
            now=now_fn(),
        )
        setup_status = await run_in_threadpool(
            selected_auth.commit_bootstrap_totp,
            enrollment_id,
            claimant_token=request.cookies.get(settings.bootstrap_cookie),
            now=now_fn(),
        )
        return {
            "status": "registered",
            "authenticator_count": len(setup_status.factor_labels),
        }

    @app.post("/setup/totp/resume")
    async def setup_totp_resume(request: Request) -> dict[str, Any]:
        require_setup_csrf(request, None)
        body = await _json_object(request)
        enrollment_id = body.get("enrollment_id")
        if not isinstance(enrollment_id, str):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        selected_auth = required_browser_auth()
        try:
            issued = await run_in_threadpool(
                selected_auth.resume_totp_enrollment,
                enrollment_id,
                user_id=selected_auth.bootstrap.owner_user_id,
                session_id=None,
                claimant_token=request.cookies.get(settings.bootstrap_cookie),
                now=now_fn(),
            )
        except TotpEnrollmentError:
            await run_in_threadpool(
                selected_auth.pending_totp_enrollment,
                enrollment_id,
                user_id=selected_auth.bootstrap.owner_user_id,
                session_id=None,
                claimant_token=request.cookies.get(settings.bootstrap_cookie),
                now=now_fn(),
            )
            return {"kind": "totp", "status": "registered"}
        return enrollment_response(issued)

    @app.post("/setup/complete")
    async def setup_complete(
        request: Request,
        csrf_token: Annotated[str, Form()],
    ) -> Response:
        require_setup_csrf(request, csrf_token)
        selected_auth = required_browser_auth()
        await run_in_threadpool(
            selected_auth.bootstrap.complete,
            claimant_token=request.cookies.get(settings.bootstrap_cookie),
            now=now_fn(),
        )
        response = Response(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login?setup=complete"},
        )
        response.delete_cookie(
            settings.login_csrf_cookie,
            path="/",
            secure=settings.secure_cookies,
            httponly=True,
        )
        response.delete_cookie(
            settings.bootstrap_cookie,
            path="/",
            secure=settings.secure_cookies,
            httponly=True,
        )
        return response

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request) -> Response:
        if browser_auth is not None and not browser_auth.bootstrap.status(now=now_fn()).complete:
            return Response(
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Location": "/setup"},
            )
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
    def password_login(
        request: Request,
        user_id: Annotated[str, Form(min_length=1, max_length=256)],
        password: Annotated[str, Form(min_length=1, max_length=1024)],
        totp_proof: Annotated[str, Form(min_length=1, max_length=128)],
        csrf_token: Annotated[str, Form()],
    ) -> Response:
        require_bootstrap_complete()
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
        require_bootstrap_complete()
        if not csrf.verify_login(
            request.cookies.get(settings.login_csrf_cookie),
            request.headers.get("x-csrf-token"),
        ):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        body = await _json_object(request)
        user_id = body.get("user_id")
        if not isinstance(user_id, str) or not user_id or len(user_id) > 256:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        return await run_in_threadpool(
            backend.begin_passkey_login,
            user_id,
            source=source(request),
            http_method=request.method,
            now=now_fn(),
        )

    @app.post("/login/passkey/complete")
    async def passkey_login_complete(request: Request) -> Response:
        require_bootstrap_complete()
        if not csrf.verify_login(
            request.cookies.get(settings.login_csrf_cookie),
            request.headers.get("x-csrf-token"),
        ):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        body = await _json_object(request)
        challenge_id = body.get("challenge_id")
        assertion = body.get("assertion")
        if not isinstance(challenge_id, str) or not isinstance(assertion, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        token = await run_in_threadpool(
            backend.complete_passkey_login,
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
    def logout(request: Request, csrf_token: Annotated[str, Form()]) -> Response:
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

    def authenticator_mutation_response() -> Response:
        response = Response(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login?authenticators=updated"},
        )
        response.delete_cookie(
            settings.session_cookie,
            path="/",
            secure=settings.secure_cookies,
            httponly=True,
        )
        return response

    def enrollment_response(
        issued: IssuedRegistration | IssuedTotpEnrollment,
    ) -> dict[str, Any]:
        if isinstance(issued, IssuedRegistration):
            return {
                "kind": "passkey",
                "challenge_id": issued.challenge_id,
                "publicKey": json.loads(issued.options_json),
                "authorization_id": issued.authorization_id,
                "operation_id": issued.operation_id,
            }
        enrollment = issued.enrollment
        return {
            "kind": "totp",
            "enrollment_id": enrollment.enrollment_id,
            "provisioning_uri": issued.provisioning_uri,
            "qr_code_data_uri": issued.qr_code_data_uri,
            "manual_key": issued.manual_key,
            "authorization_id": enrollment.authorization_id,
            "operation_id": enrollment.operation_id,
        }

    @app.get("/authenticators", response_class=HTMLResponse)
    async def authenticators_page(request: Request) -> Response:
        selected = await async_principal(request)
        selected_auth = required_browser_auth()
        factors = await run_in_threadpool(selected_auth.list_factors, selected.user_id)
        return cast(
            Response,
            templates.TemplateResponse(
                request,
                "authenticators.html",
                {
                    **context(request, selected),
                    "factors": factors,
                    "totp_factors": tuple(factor for factor in factors if factor.kind == "totp"),
                    "passkey_factors": tuple(
                        factor for factor in factors if factor.kind == "webauthn"
                    ),
                    "csrf_token": csrf.session_token(selected.session_id, "authenticators"),
                    "logout_csrf": csrf.session_token(selected.session_id, "logout"),
                    "operation_ids": {
                        factor.factor_id: {
                            "rename": secrets.token_urlsafe(24),
                            "revoke": secrets.token_urlsafe(24),
                        }
                        for factor in factors
                    },
                },
            ),
        )

    @app.post("/authenticators/enroll/status")
    async def authenticator_enrollment_status(request: Request) -> dict[str, str]:
        selected = await async_principal(request)
        require_csrf(request, selected, "authenticators", None)
        body = await _json_object(request)
        kind = body.get("kind")
        registration_id = body.get("registration_id")
        if kind not in {"passkey", "totp"} or not isinstance(registration_id, str):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        selected_auth = required_browser_auth()
        enrollment_status = await run_in_threadpool(
            selected_auth.authorized_enrollment_status,
            selected.user_id,
            kind,
            registration_id,
            now=now_fn(),
        )
        return {"status": enrollment_status}

    @app.post("/authenticators/passkeys/options")
    async def authenticator_passkey_options(request: Request) -> dict[str, Any]:
        selected = await async_principal(request)
        require_csrf(request, selected, "authenticators", None)
        body = await _json_object(request)
        label = body.get("label")
        if not isinstance(label, str):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        selected_auth = required_browser_auth()
        issued = await run_in_threadpool(
            selected_auth.begin_registration,
            selected.user_id,
            label,
            flow="management",
            session_id=selected.session_id,
            now=now_fn(),
        )
        return {
            "challenge_id": issued.challenge_id,
            "publicKey": json.loads(issued.options_json),
        }

    @app.post("/authenticators/passkeys/complete")
    async def authenticator_passkey_complete(request: Request) -> dict[str, str]:
        selected = await async_principal(request)
        require_csrf(request, selected, "authenticators", None)
        body = await _json_object(request)
        challenge_id = body.get("challenge_id")
        credential = body.get("credential")
        if not isinstance(challenge_id, str) or not isinstance(credential, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        selected_auth = required_browser_auth()
        pending = await run_in_threadpool(
            selected_auth.complete_registration,
            challenge_id,
            credential,
            user_id=selected.user_id,
            session_id=selected.session_id,
            now=now_fn(),
        )
        if pending.authorization_id is None or pending.operation_id is None:
            raise PasskeyRegistrationError("passkey enrollment authorization is missing")
        return {
            "status": "ready_to_finalize",
            "registration_id": challenge_id,
            "authorization_id": pending.authorization_id,
            "operation_id": pending.operation_id,
        }

    @app.post("/authenticators/totp/start")
    async def authenticator_totp_start(request: Request) -> dict[str, str]:
        selected = await async_principal(request)
        require_csrf(request, selected, "authenticators", None)
        body = await _json_object(request)
        label = body.get("label")
        if not isinstance(label, str):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        issued = await run_in_threadpool(
            required_browser_auth().begin_totp_enrollment,
            selected.user_id,
            label,
            flow="management",
            session_id=selected.session_id,
            now=now_fn(),
        )
        return {
            "enrollment_id": issued.enrollment.enrollment_id,
            "provisioning_uri": issued.provisioning_uri,
            "qr_code_data_uri": issued.qr_code_data_uri,
            "manual_key": issued.manual_key,
        }

    @app.post("/authenticators/totp/verify")
    async def authenticator_totp_verify(request: Request) -> dict[str, str]:
        selected = await async_principal(request)
        require_csrf(request, selected, "authenticators", None)
        body = await _json_object(request)
        enrollment_id = body.get("enrollment_id")
        proof = body.get("proof")
        if not isinstance(enrollment_id, str) or not isinstance(proof, str):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        pending = await run_in_threadpool(
            required_browser_auth().verify_totp_enrollment,
            enrollment_id,
            proof,
            user_id=selected.user_id,
            session_id=selected.session_id,
            now=now_fn(),
        )
        if pending.authorization_id is None or pending.operation_id is None:
            raise TotpEnrollmentError("TOTP enrollment authorization is missing")
        return {
            "registration_id": enrollment_id,
            "authorization_id": pending.authorization_id,
            "operation_id": pending.operation_id,
        }

    @app.post("/authenticators/enroll/resume")
    async def authenticator_enrollment_resume(request: Request) -> dict[str, Any]:
        selected = await async_principal(request)
        require_csrf(request, selected, "authenticators", None)
        body = await _json_object(request)
        kind = body.get("kind")
        if kind not in {"passkey", "totp"}:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        issued: IssuedRegistration | IssuedTotpEnrollment
        if kind == "passkey":
            challenge_id = body.get("challenge_id")
            if not isinstance(challenge_id, str):
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
            selected_auth = required_browser_auth()
            try:
                issued = await run_in_threadpool(
                    selected_auth.resume_registration,
                    challenge_id,
                    user_id=selected.user_id,
                    session_id=selected.session_id,
                    now=now_fn(),
                )
            except PasskeyRegistrationError:
                pending = await run_in_threadpool(
                    selected_auth.pending_registration,
                    challenge_id,
                    user_id=selected.user_id,
                    session_id=selected.session_id,
                    now=now_fn(),
                )
                return {
                    "kind": "passkey",
                    "status": "ready_to_finalize",
                    "registration_id": pending.challenge_id,
                    "authorization_id": pending.authorization_id,
                    "operation_id": pending.operation_id,
                }
            return enrollment_response(issued)
        enrollment_id = body.get("enrollment_id")
        if not isinstance(enrollment_id, str):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        selected_auth = required_browser_auth()
        try:
            issued = await run_in_threadpool(
                selected_auth.resume_totp_enrollment,
                enrollment_id,
                user_id=selected.user_id,
                session_id=selected.session_id,
                now=now_fn(),
            )
        except TotpEnrollmentError:
            pending_totp = await run_in_threadpool(
                selected_auth.pending_totp_enrollment,
                enrollment_id,
                user_id=selected.user_id,
                session_id=selected.session_id,
                now=now_fn(),
            )
            return {
                "kind": "totp",
                "status": "ready_to_finalize",
                "registration_id": pending_totp.enrollment_id,
                "authorization_id": pending_totp.authorization_id,
                "operation_id": pending_totp.operation_id,
            }
        return enrollment_response(issued)

    @app.post("/authenticators/enroll/totp")
    async def authenticator_enrollment_totp(request: Request) -> dict[str, Any]:
        selected = await async_principal(request)
        require_csrf(request, selected, "authenticators", None)
        body = await _json_object(request)
        proof = body.get("totp_proof")
        credential_id = body.get("totp_credential_id")
        if not isinstance(proof, str) or (
            credential_id is not None and not isinstance(credential_id, str)
        ):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        issued = await run_in_threadpool(
            required_browser_auth().authorize_enrollment_with_totp,
            selected.user_id,
            selected.session_id,
            management_intent(body),
            proof,
            source_id=source(request),
            credential_id=credential_id,
            now=now_fn(),
        )
        return enrollment_response(issued)

    @app.post("/authenticators/confirm/passkey/options")
    async def authenticator_confirmation_options(request: Request) -> dict[str, Any]:
        selected = await async_principal(request)
        require_csrf(request, selected, "authenticators", None)
        intent = management_intent(await _json_object(request))
        selected_auth = required_browser_auth()
        issued = await run_in_threadpool(
            selected_auth.begin_webauthn_confirmation,
            selected.user_id,
            selected.session_id,
            intent,
            now=now_fn(),
        )
        return {
            "challenge_id": issued.challenge_id,
            "publicKey": json.loads(issued.options_json),
        }

    @app.post("/authenticators/confirm/passkey/complete")
    async def authenticator_confirmation_complete(request: Request) -> dict[str, Any]:
        selected = await async_principal(request)
        require_csrf(request, selected, "authenticators", None)
        body = await _json_object(request)
        challenge_id = body.get("challenge_id")
        assertion = body.get("assertion")
        if not isinstance(challenge_id, str) or not isinstance(assertion, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        intent = management_intent(body)
        selected_auth = required_browser_auth()
        if intent.action in {"add_passkey", "add_totp"} and intent.registration_id is None:
            issued = await run_in_threadpool(
                selected_auth.authorize_enrollment_with_webauthn,
                selected.user_id,
                selected.session_id,
                intent,
                challenge_id=challenge_id,
                assertion=assertion,
                now=now_fn(),
            )
            return enrollment_response(issued)
        await run_in_threadpool(
            selected_auth.apply_with_webauthn,
            selected.user_id,
            selected.session_id,
            intent,
            challenge_id=challenge_id,
            assertion=assertion,
            now=now_fn(),
        )
        return {"status": "updated", "redirect_url": "/login?authenticators=updated"}

    @app.post("/authenticators/enroll/finalize")
    async def authenticator_enrollment_finalize(request: Request) -> dict[str, str]:
        selected = await async_principal(request)
        require_csrf(request, selected, "authenticators", None)
        intent = management_intent(await _json_object(request))
        await run_in_threadpool(
            required_browser_auth().complete_authorized_enrollment,
            selected.user_id,
            selected.session_id,
            intent,
            now=now_fn(),
        )
        return {"status": "updated", "redirect_url": "/login?authenticators=updated"}

    @app.post("/authenticators/confirm/totp")
    async def authenticator_confirmation_totp(
        request: Request,
        action: Annotated[Literal["add_passkey", "add_totp", "rename", "revoke"], Form()],
        operation_id: Annotated[str, Form(min_length=16, max_length=128)],
        totp_proof: Annotated[str, Form(min_length=1, max_length=128)],
        csrf_token: Annotated[str, Form()],
        factor_id: Annotated[str | None, Form(max_length=128)] = None,
        label: Annotated[str | None, Form(max_length=64)] = None,
        registration_id: Annotated[str | None, Form(max_length=128)] = None,
        totp_credential_id: Annotated[str | None, Form(max_length=256)] = None,
        compromised: Annotated[bool, Form()] = False,
    ) -> Response:
        selected = await async_principal(request)
        require_csrf(request, selected, "authenticators", csrf_token)
        intent = ManagementIntent(
            action=action,
            operation_id=operation_id,
            factor_id=factor_id,
            label=label,
            registration_id=registration_id,
            compromised=compromised,
        )
        selected_auth = required_browser_auth()
        await run_in_threadpool(
            selected_auth.apply_with_totp,
            selected.user_id,
            selected.session_id,
            intent,
            totp_proof,
            source_id=source(request),
            credential_id=totp_credential_id,
            now=now_fn(),
        )
        return authenticator_mutation_response()

    @app.get("/", response_class=HTMLResponse)
    def queue(request: Request, after: str | None = None) -> Response:
        selected = principal(request)
        page = backend.list_queue(selected, now=now_fn(), cursor=after)
        return cast(
            Response,
            templates.TemplateResponse(
                request,
                "queue.html",
                {
                    **context(request, selected),
                    "items": page.items,
                    "has_more": page.has_more,
                    "next_cursor": page.next_cursor,
                    "now": now_fn(),
                    "logout_csrf": csrf.session_token(selected.session_id, "logout"),
                    "push_csrf": csrf.session_token(selected.session_id, "push"),
                },
            ),
        )

    @app.get("/requests/{request_id}", response_class=HTMLResponse)
    def detail(request: Request, request_id: str) -> Response:
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
                    "totp_factors": active_totp_factors(selected),
                    "csrf_token": csrf.session_token(selected.session_id, purpose),
                    "logout_csrf": csrf.session_token(selected.session_id, "logout"),
                },
            ),
        )

    @app.get("/requests/{request_id}/attachments/{attachment_id}")
    def inspect_attachment(
        request: Request,
        request_id: str,
        attachment_id: str,
        version: Annotated[int, Query(ge=1)],
        payload_hash: Annotated[str, Query(min_length=64, max_length=64)],
    ) -> Response:
        selected = principal(request)
        download = backend.get_attachment(
            selected,
            request_id,
            attachment_id,
            expected_version=version,
            expected_payload_hash=payload_hash,
        )
        return Response(
            content=download.content,
            media_type="application/octet-stream",
            headers={
                "Cache-Control": "no-store, max-age=0",
                "Content-Disposition": 'attachment; filename="signet-attachment.bin"',
                "X-Content-Type-Options": "nosniff",
                "X-Signet-Content-SHA256": download.sha256,
            },
        )

    @app.get("/requests/{request_id}/review", response_class=HTMLResponse)
    def review_fragment(request: Request, request_id: str) -> Response:
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
                    "totp_factors": active_totp_factors(selected),
                    "id_suffix": hashlib.sha256(request_id.encode()).hexdigest()[:12],
                    "csrf_token": csrf.session_token(
                        selected.session_id,
                        f"request:{request_id}",
                    ),
                },
            ),
        )

    @app.get("/audit/events/{event_id}/review", response_class=HTMLResponse)
    def historical_review_fragment(request: Request, event_id: int) -> Response:
        selected = principal(request)
        value = backend.get_historical_detail(selected, event_id)
        return cast(
            Response,
            templates.TemplateResponse(
                request,
                "review_fragment.html",
                {
                    **context(request, selected),
                    "item": value,
                    "id_suffix": f"audit-event-{event_id}",
                    "csrf_token": None,
                },
            ),
        )

    @app.get("/audit/events/{event_id}", response_class=HTMLResponse)
    def historical_review_page(request: Request, event_id: int) -> Response:
        selected = principal(request)
        value = backend.get_historical_detail(selected, event_id)
        return cast(
            Response,
            templates.TemplateResponse(
                request,
                "audit_event.html",
                {
                    **context(request, selected),
                    "item": value,
                    "csrf_token": None,
                    "logout_csrf": csrf.session_token(selected.session_id, "logout"),
                },
            ),
        )

    @app.get("/audit", response_class=HTMLResponse)
    def audit(request: Request, before: str | None = None) -> Response:
        selected = principal(request)
        before_event_id = None
        if before is not None:
            try:
                before_event_id = csrf.cursor_position(
                    selected.session_id,
                    "decision-history",
                    before,
                )
            except ValueError:
                raise WebConflict("decision history cursor is invalid") from None
        decision_page = backend.list_decisions(
            selected,
            before_event_id=before_event_id,
        )
        next_decision_cursor = (
            csrf.cursor_token(
                selected.session_id,
                "decision-history",
                decision_page.next_event_id,
            )
            if decision_page.has_more and decision_page.next_event_id is not None
            else None
        )
        return cast(
            Response,
            templates.TemplateResponse(
                request,
                "audit.html",
                {
                    **context(request, selected),
                    "decisions": decision_page.items,
                    "has_more_decisions": decision_page.has_more,
                    "next_decision_cursor": next_decision_cursor,
                    "entries": backend.list_audit(selected),
                    "logout_csrf": csrf.session_token(selected.session_id, "logout"),
                },
            ),
        )

    integration_backend = integrations
    if integration_backend is not None:

        @app.get("/integrations", response_class=HTMLResponse)
        def integration_workspace(request: Request) -> Response:
            selected = principal(request)
            page = integration_backend.list_integrations(selected, now=now_fn())
            return cast(
                Response,
                templates.TemplateResponse(
                    request,
                    "integrations.html",
                    {
                        **context(request, selected),
                        "integration_page": page,
                        "logout_csrf": csrf.session_token(selected.session_id, "logout"),
                    },
                ),
            )

        @app.get("/integrations/tools/{opaque_id}", response_class=HTMLResponse)
        def integration_tool(
            request: Request,
            opaque_id: Annotated[
                str,
                ApiPath(
                    min_length=16,
                    max_length=128,
                    pattern=_OPAQUE_INTEGRATION_ID_PATTERN,
                ),
            ],
        ) -> Response:
            selected = principal(request)
            item = integration_backend.get_integration_tool(
                selected,
                opaque_id,
                now=now_fn(),
            )
            return cast(
                Response,
                templates.TemplateResponse(
                    request,
                    "integration_detail.html",
                    {
                        **context(request, selected),
                        "item": item,
                        "totp_factors": active_totp_factors(selected),
                        "review_csrf": csrf.session_token(
                            selected.session_id,
                            _effect_review_csrf_purpose(
                                item.opaque_id,
                                item.target_snapshot_digest,
                            ),
                        ),
                        "logout_csrf": csrf.session_token(selected.session_id, "logout"),
                    },
                ),
            )

        @app.post("/integrations/effect-reviews/totp")
        def integration_totp_review(
            request: Request,
            opaque_id: Annotated[
                str,
                Form(
                    min_length=16,
                    max_length=128,
                    pattern=_OPAQUE_INTEGRATION_ID_PATTERN,
                ),
            ],
            expected_snapshot_digest: Annotated[
                str,
                Form(min_length=64, max_length=64, pattern=_SHA256_PATTERN),
            ],
            mutation: Annotated[EffectMutationInput, Form()],
            external_communication: Annotated[EffectTriStateInput, Form()],
            code_execution: Annotated[EffectTriStateInput, Form()],
            privilege_change: Annotated[EffectTriStateInput, Form()],
            open_world: Annotated[EffectTriStateInput, Form()],
            idempotent: Annotated[EffectTriStateInput, Form()],
            totp_proof: Annotated[str, Form(min_length=1, max_length=128)],
            csrf_token: Annotated[str, Form()],
            totp_credential_id: Annotated[str | None, Form(max_length=256)] = None,
        ) -> Response:
            selected = principal(request)
            require_csrf(
                request,
                selected,
                _effect_review_csrf_purpose(opaque_id, expected_snapshot_digest),
                csrf_token,
            )
            profile = _effect_profile(
                mutation=mutation,
                external_communication=external_communication,
                code_execution=code_execution,
                privilege_change=privilege_change,
                open_world=open_world,
                idempotent=idempotent,
            )
            result = integration_backend.complete_totp_effect_review(
                selected,
                opaque_id,
                profile,
                totp_proof,
                expected_snapshot_digest=expected_snapshot_digest,
                now=now_fn(),
                credential_id=totp_credential_id,
            )
            _require_effect_review_result(result, opaque_id)
            return Response(
                status_code=status.HTTP_303_SEE_OTHER,
                headers={
                    "Location": f"/integrations/tools/{result.opaque_id}#effect-review-current"
                },
            )

        @app.post("/integrations/effect-reviews/passkey/options")
        async def integration_passkey_review_options(request: Request) -> IntegrationPasskeyOptions:
            selected = await async_principal(request)
            payload = await _validated_json_model(request, IntegrationPasskeyReviewInput)
            require_csrf(
                request,
                selected,
                _effect_review_csrf_purpose(
                    payload.opaque_id,
                    payload.expected_snapshot_digest,
                ),
                None,
            )
            options = await run_in_threadpool(
                integration_backend.begin_passkey_effect_review,
                selected,
                payload.opaque_id,
                payload.profile.effect_profile(),
                expected_snapshot_digest=payload.expected_snapshot_digest,
                http_method=request.method,
                now=now_fn(),
            )
            if options.opaque_id != payload.opaque_id or not hmac.compare_digest(
                options.target_snapshot_digest,
                payload.expected_snapshot_digest,
            ):
                raise WebConflict("passkey effect review binding is invalid")
            return options

        @app.post("/integrations/effect-reviews/passkey/complete")
        async def integration_passkey_review_complete(request: Request) -> dict[str, object]:
            selected = await async_principal(request)
            payload = await _validated_json_model(request, IntegrationPasskeyCompleteInput)
            require_csrf(
                request,
                selected,
                _effect_review_csrf_purpose(
                    payload.opaque_id,
                    payload.expected_snapshot_digest,
                ),
                None,
            )
            result = await run_in_threadpool(
                integration_backend.complete_passkey_effect_review,
                selected,
                payload.opaque_id,
                payload.challenge_id,
                payload.assertion,
                expected_snapshot_digest=payload.expected_snapshot_digest,
                http_method=request.method,
                now=now_fn(),
            )
            _require_effect_review_result(result, payload.opaque_id)
            return {
                "status": "reviewed",
                "review_id": result.review_id,
                "recommended_mode": result.recommended_mode.value,
                "redirect_url": (f"/integrations/tools/{result.opaque_id}#effect-review-current"),
            }

    @app.post("/requests/{request_id}/actions/totp")
    def totp_action(
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
        decision_note: Annotated[
            str | None,
            Form(max_length=MAX_DECISION_NOTE_CHARS),
        ] = None,
        approval_reason: Annotated[
            str | None,
            Form(max_length=MAX_DECISION_NOTE_CHARS),
        ] = None,
        denial_reason: Annotated[
            str | None,
            Form(max_length=MAX_DECISION_NOTE_CHARS),
        ] = None,
        totp_credential_id: Annotated[str | None, Form(max_length=256)] = None,
    ) -> Response:
        selected = principal(request)
        require_csrf(request, selected, f"request:{request_id}", csrf_token)
        selected_note = decision_note
        if selected_note is None:
            if action == "approve":
                selected_note = approval_reason or None
            elif action == "deny":
                selected_note = denial_reason or None
        policy_change = (
            action == "approve" and backend.get_detail(selected, request_id).gateway_internal
        )
        normalized_note = _decision_note_input(
            action,
            selected_note,
            policy_change=policy_change,
        )
        final_state = backend.complete_totp_action(
            selected,
            request_id,
            action,
            totp_proof,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            prospective_arguments_json=prospective_arguments_json,
            now=now_fn(),
            decision_note=normalized_note,
            credential_id=totp_credential_id,
        )
        return Response(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": _action_redirect(request_id, final_state)},
        )

    @app.post("/requests/{request_id}/actions/passkey/options")
    async def passkey_action_options(request: Request, request_id: str) -> ActionOptions:
        selected = await async_principal(request)
        require_csrf(request, selected, f"request:{request_id}", None)
        body = await _json_object(request)
        action = body.get("action")
        if action not in _HUMAN_ACTIONS:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        expected_version = body.get("expected_version")
        payload_hash = body.get("expected_payload_hash")
        prospective = body.get("prospective_arguments_json")
        decision_note = body.get("decision_note")
        if (
            not isinstance(expected_version, int)
            or expected_version < 1
            or not isinstance(payload_hash, str)
            or len(payload_hash) != 64
            or (prospective is not None and not isinstance(prospective, str))
            or (decision_note is not None and not isinstance(decision_note, str))
        ):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        detail_value = await run_in_threadpool(backend.get_detail, selected, request_id)
        policy_change = action == "approve" and detail_value.gateway_internal
        normalized_note = _decision_note_input(
            action,
            decision_note,
            policy_change=policy_change,
        )
        return await run_in_threadpool(
            backend.begin_passkey_action,
            selected,
            request_id,
            action,
            expected_version=expected_version,
            expected_payload_hash=payload_hash,
            prospective_arguments_json=prospective,
            http_method=request.method,
            now=now_fn(),
            decision_note=normalized_note,
        )

    @app.post("/requests/{request_id}/actions/passkey/complete")
    async def passkey_action_complete(request: Request, request_id: str) -> dict[str, str]:
        selected = await async_principal(request)
        require_csrf(request, selected, f"request:{request_id}", None)
        body = await _json_object(request)
        challenge_id = body.get("challenge_id")
        assertion = body.get("assertion")
        if not isinstance(challenge_id, str) or not isinstance(assertion, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        final_state = await run_in_threadpool(
            backend.complete_passkey_action,
            selected,
            request_id,
            challenge_id,
            assertion,
            http_method=request.method,
            now=now_fn(),
        )
        return {
            "status": final_state,
            "request_id": request_id,
            "redirect_url": _action_redirect(request_id, final_state),
        }

    @app.post("/push/subscriptions", status_code=status.HTTP_204_NO_CONTENT)
    def subscribe_push(request: Request, payload: PushSubscriptionInput) -> Response:
        selected = principal(request)
        require_csrf(request, selected, "push", None)
        backend.subscribe_push(selected, payload, now=now_fn())
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.delete("/push/subscriptions", status_code=status.HTTP_204_NO_CONTENT)
    async def unsubscribe_push(request: Request) -> Response:
        selected = await async_principal(request)
        require_csrf(request, selected, "push", None)
        body = await _json_object(request)
        endpoint = body.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint or len(endpoint) > 4096:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        await run_in_threadpool(backend.unsubscribe_push, selected, endpoint, now=now_fn())
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


def _effect_profile(
    *,
    mutation: EffectMutationInput,
    external_communication: EffectTriStateInput,
    code_execution: EffectTriStateInput,
    privilege_change: EffectTriStateInput,
    open_world: EffectTriStateInput,
    idempotent: EffectTriStateInput,
) -> EffectProfile:
    return EffectProfile(
        mutation=MutationEffect(mutation),
        external_communication=TriState(external_communication),
        code_execution=TriState(code_execution),
        privilege_change=TriState(privilege_change),
        open_world=TriState(open_world),
        idempotent=TriState(idempotent),
    )


def _effect_review_csrf_purpose(opaque_id: str, snapshot_digest: str) -> str:
    _validate_opaque_integration_id(opaque_id)
    _validate_sha256(snapshot_digest, name="target snapshot digest")
    return f"effect-review:{opaque_id}:{snapshot_digest}"


def _require_effect_review_result(result: EffectReviewResult, expected_opaque_id: str) -> None:
    if not hmac.compare_digest(result.opaque_id, expected_opaque_id):
        raise WebConflict("effect review result does not match its exact target")


async def _validated_json_model[ModelT: BaseModel](
    request: Request,
    model: type[ModelT],
) -> ModelT:
    value = await _json_object(request)
    try:
        return model.model_validate(value)
    except ValidationError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT) from None


def _validate_opaque_integration_id(value: str) -> None:
    if not isinstance(value, str) or re.fullmatch(_OPAQUE_INTEGRATION_ID_PATTERN, value) is None:
        raise ValueError("opaque integration ID is invalid")


def _validate_sha256(value: str, *, name: str) -> None:
    if not isinstance(value, str) or re.fullmatch(_SHA256_PATTERN, value) is None:
        raise ValueError(f"{name} is invalid")


def _validate_bounded_text(value: str, *, name: str, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or "\x00" in value
    ):
        raise ValueError(f"{name} is invalid")


def _validate_timestamp(value: int, *, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} is invalid")


def _decision_note_input(
    action: HumanAction,
    value: str | None,
    *,
    policy_change: bool = False,
) -> str | None:
    try:
        normalized = normalize_decision_note(value)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT) from None
    if policy_change:
        if action != "approve" or normalized is not None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        return None
    if normalized is not None and action not in {"approve", "deny"}:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
    if action in {"approve", "deny"}:
        if normalized is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        try:
            return reason_for_action(action, normalized)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT) from None
    return normalized


def _action_redirect(request_id: str, final_state: str) -> str:
    if final_state in {"approved", "denied"}:
        return f"/audit#decision-{request_id}"
    return f"/requests/{request_id}"


async def _json_object(request: Request) -> dict[str, Any]:
    try:
        value = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST) from None
    if not isinstance(value, dict):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
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


def _utc_time(value: int) -> UtcTime:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("invalid Unix timestamp")
    try:
        selected = datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError):
        raise ValueError("invalid Unix timestamp") from None
    return UtcTime(
        iso=selected.isoformat(timespec="seconds").replace("+00:00", "Z"),
        display=selected.strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
