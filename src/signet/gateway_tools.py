"""Gateway-owned MCP approval tools.

This module is deliberately an orchestration layer.  The approval state machine
owns durable transitions and confirmation consumption; adapters own masked
summaries; and the payload freezer owns encryption for gateway-internal access
requests.  Keeping those boundaries explicit prevents this MCP surface from
decrypting reviewed payloads or learning downstream credentials.
"""

from __future__ import annotations

import base64
import copy
import hmac
import inspect
import json
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Never, Protocol, cast

import mcp.types as types
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from mcp.shared.exceptions import McpError

from signet import __version__
from signet.async_support import run_sync_non_abandoning as _run_sync
from signet.auth import (
    ActionBinding,
    AuthenticationRateLimited,
    canonical_user_id,
    source_rate_limit_key,
    totp_rate_limit_key,
)
from signet.canonical import version_hash_prefix
from signet.mcp_mirror import LosslessToolServer, RawServerResult, domain_error_result
from signet.models import (
    ApprovalConfirmation,
    ConfirmationKind,
    ConfirmationReplay,
    EnqueueRequest,
    InvalidConfirmation,
    InvalidTransition,
    RequestExpired,
    RequestNotFound,
    StaleVersion,
)
from signet.state_machine import ApprovalStateMachine
from signet.totp import InvalidTotp, TotpNotEnrolled, TotpUnavailable, VerifiedTotp

DEFAULT_PENDING_PAGE_SIZE = 10
MAX_PENDING_PAGE_SIZE = 25
_MAX_SUMMARY_LENGTH = 2_048
_UNAVAILABLE_DESTINATION_SUMMARY = "Private summary unavailable; review in the web app."
_REQUEST_ID_RE = re.compile(r"^req_[A-Za-z0-9]+$")
_WHATSAPP_MASK_RE = re.compile(
    r"(?:\+\*{4,11}[0-9]{4}|\*{3,28}[0-9]{4}@(s\.whatsapp\.net|g\.us|newsletter))"
)

GATEWAY_TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "check_approval_status",
        "description": (
            "Return the authoritative state and safe result metadata for one caller-owned request."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["request_id"],
            "properties": {"request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"}},
        },
        "outputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "request_id",
                "status",
                "service",
                "tool",
                "destination_summary",
                "summary_available",
                "version",
                "expires_at",
            ],
            "properties": {
                "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"},
                "status": {
                    "enum": [
                        "pending_approval",
                        "approved",
                        "executing",
                        "succeeded",
                        "failed",
                        "outcome_unknown",
                        "denied",
                        "expired",
                        "cancelled",
                    ]
                },
                "service": {"type": "string", "minLength": 1},
                "tool": {"type": "string", "minLength": 1},
                "destination_summary": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": _MAX_SUMMARY_LENGTH,
                },
                "summary_available": {"type": "boolean"},
                "version": {"type": "integer", "minimum": 1},
                "expires_at": {"type": "string", "format": "date-time"},
                "safe_result_metadata": {"type": "object"},
                "failure_code": {"type": "string", "minLength": 1},
            },
        },
    },
    {
        "name": "list_pending_approvals",
        "description": "List caller-owned pending requests using masked summaries only.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "cursor": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 512,
                    "pattern": "^[A-Za-z0-9_-]+$",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_PENDING_PAGE_SIZE,
                    "default": DEFAULT_PENDING_PAGE_SIZE,
                },
            },
        },
        "outputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["requests", "next_cursor", "has_more"],
            "properties": {
                "requests": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "request_id",
                            "service",
                            "tool",
                            "destination_summary",
                            "summary_available",
                            "age_seconds",
                            "expires_at",
                            "version_hash_prefix",
                        ],
                        "properties": {
                            "request_id": {
                                "type": "string",
                                "pattern": "^req_[A-Za-z0-9]+$",
                            },
                            "service": {"type": "string", "minLength": 1},
                            "tool": {"type": "string", "minLength": 1},
                            "destination_summary": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": _MAX_SUMMARY_LENGTH,
                            },
                            "summary_available": {"type": "boolean"},
                            "age_seconds": {"type": "integer", "minimum": 0},
                            "expires_at": {"type": "string", "format": "date-time"},
                            "version_hash_prefix": {
                                "type": "string",
                                "pattern": "^[a-f0-9]{8,64}$",
                            },
                        },
                    },
                },
                "next_cursor": {
                    "type": ["string", "null"],
                    "minLength": 1,
                    "maxLength": 512,
                    "pattern": "^[A-Za-z0-9_-]+$",
                },
                "has_more": {"type": "boolean"},
            },
        },
    },
    {
        "name": "approve_request",
        "description": (
            "Approve one exact caller-owned frozen request version with a fresh "
            "single-use TOTP code."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["request_id", "totp_code", "expected_version_hash"],
            "properties": {
                "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"},
                "totp_code": {"type": "string", "pattern": "^[0-9]{6}$"},
                "expected_version_hash": {
                    "type": "string",
                    "pattern": "^[a-f0-9]{8,64}$",
                },
            },
        },
        "outputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "status",
                "request_id",
                "tool",
                "destination_summary",
                "version",
                "version_hash_prefix",
                "approval_notification_queued",
            ],
            "properties": {
                "status": {"const": "approved"},
                "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"},
                "tool": {"type": "string", "minLength": 1},
                "destination_summary": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": _MAX_SUMMARY_LENGTH,
                },
                "version": {"type": "integer", "minimum": 1},
                "version_hash_prefix": {
                    "type": "string",
                    "pattern": "^[a-f0-9]{8,64}$",
                },
                "approval_notification_queued": {"const": True},
            },
        },
    },
    {
        "name": "cancel_request",
        "description": (
            "Cancel one pending request created by the authenticated caller namespace."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["request_id"],
            "properties": {"request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"}},
        },
        "outputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["status", "request_id"],
            "properties": {
                "status": {"const": "cancelled"},
                "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"},
            },
        },
    },
    {
        "name": "request_tool_access",
        "description": "Create a web-approval-only request for a versioned policy change.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["alias", "tool", "reason"],
            "properties": {
                "alias": {
                    "type": "string",
                    "pattern": "^[a-z][a-z0-9_-]{0,63}$",
                },
                "tool": {
                    "type": "string",
                    "pattern": "^[A-Za-z][A-Za-z0-9_.-]{0,127}$",
                },
                "reason": {"type": "string", "minLength": 1, "maxLength": 1000},
            },
        },
        "outputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "status",
                "request_id",
                "expires_at",
                "message",
                "approval_channel",
            ],
            "properties": {
                "status": {"const": "pending_approval"},
                "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"},
                "expires_at": {"type": "string", "format": "date-time"},
                "message": {"type": "string", "minLength": 1},
                "approval_channel": {"const": "web_only"},
            },
        },
    },
]

_TOOL_BY_NAME = {tool["name"]: tool for tool in GATEWAY_TOOL_DEFINITIONS}
_INPUT_VALIDATORS = {
    name: Draft202012Validator(cast(dict[str, Any], tool["inputSchema"]))
    for name, tool in _TOOL_BY_NAME.items()
}
_OUTPUT_VALIDATORS = {
    name: Draft202012Validator(
        cast(dict[str, Any], tool["outputSchema"]), format_checker=FormatChecker()
    )
    for name, tool in _TOOL_BY_NAME.items()
}


@dataclass(frozen=True, slots=True)
class GatewayPrincipal:
    """Authenticated MCP identity used for both ownership and TOTP lookup."""

    namespace: str
    user_id: str

    def __post_init__(self) -> None:
        if not self.namespace or not self.user_id:
            raise ValueError("gateway principals require a namespace and user ID")
        if canonical_user_id(self.user_id) != self.user_id:
            raise ValueError("gateway principal user IDs must be canonical")
        source_rate_limit_key(self.namespace)

    @property
    def actor(self) -> str:
        return f"mcp:{self.namespace}"


@dataclass(frozen=True, slots=True)
class SafeRequestSummary:
    """Pre-masked display data; full request content is intentionally absent."""

    service: str
    tool: str
    destination_summary: str

    def __post_init__(self) -> None:
        if not self.service or not self.tool or not self.destination_summary:
            raise ValueError("safe request summaries must not contain empty fields")
        if (
            len(self.service) > 128
            or len(self.tool) > 128
            or len(self.destination_summary) > _MAX_SUMMARY_LENGTH
            or any(
                ord(character) < 32 or ord(character) == 127
                for value in (self.service, self.tool, self.destination_summary)
                for character in value
            )
        ):
            raise ValueError("safe request summary fields exceed their public bounds")


class SafeSummaryProvider(Protocol):
    def get(
        self,
        request_id: str,
        *,
        version: int,
        payload_hash: str,
    ) -> SafeRequestSummary | Awaitable[SafeRequestSummary]: ...


@dataclass(frozen=True, slots=True)
class AccessRequestDraft:
    """Gateway-internal policy proposal passed to the encrypted payload freezer."""

    origin_namespace: str
    alias: str
    tool: str
    reason: str
    actor: str
    created_at: int
    gateway_internal: bool = True


class AccessRequestFactory(Protocol):
    def freeze(self, draft: AccessRequestDraft) -> EnqueueRequest | Awaitable[EnqueueRequest]:
        """Build an encrypted, pending EnqueueRequest for the gateway queue."""

        ...


class TotpProofVerifier(Protocol):
    def verify(
        self,
        user_id: str,
        proof: str,
        *,
        binding: ActionBinding,
        now: int,
        source_id: str,
        session_id: str | None,
        http_method: str,
    ) -> VerifiedTotp: ...

    def record_consumed_success(self, proof: VerifiedTotp, *, now: int) -> None: ...


@dataclass(frozen=True, slots=True)
class _RequestSnapshot:
    request_id: str
    service: str
    tool: str
    state: str
    version: int
    payload_hash: str
    created_at: int
    expires_at: int
    gateway_internal: bool
    safe_outcome_json: str | None
    failure_reason: str | None


class GatewayTools:
    """Implement the five gateway-owned MCP tools over durable core services."""

    def __init__(
        self,
        *,
        state_machine: ApprovalStateMachine,
        totp_verifier: TotpProofVerifier,
        summaries: SafeSummaryProvider,
        access_requests: AccessRequestFactory,
        clock: Callable[[], int] | None = None,
        hash_prefix_length: int = 12,
    ) -> None:
        if hash_prefix_length < 8 or hash_prefix_length > 64:
            raise ValueError("version hash prefix length must be between 8 and 64")
        if not state_machine.notifications_enabled:
            raise ValueError("gateway approval tools require the transactional notification outbox")
        self._state_machine = state_machine
        self._totp = totp_verifier
        self._summaries = summaries
        self._access_requests = access_requests
        self._clock = clock or (lambda: int(time.time()))
        self._hash_prefix_length = hash_prefix_length

    def list_tools(self) -> list[dict[str, Any]]:
        return copy.deepcopy(GATEWAY_TOOL_DEFINITIONS)

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        principal: GatewayPrincipal,
    ) -> dict[str, Any]:
        """Call a gateway tool, reserving protocol errors for bad MCP requests."""

        values, now = await _run_sync(self._prepare_call, name, arguments)

        if name == "check_approval_status":
            result = await self._check_status(cast(str, values["request_id"]), principal)
        elif name == "list_pending_approvals":
            result = await self._list_pending(
                principal,
                now=now,
                cursor=cast(str | None, values.get("cursor")),
                limit=cast(int, values.get("limit", DEFAULT_PENDING_PAGE_SIZE)),
            )
        elif name == "approve_request":
            result = await self._approve(values, principal, now=now)
        elif name == "cancel_request":
            result = await _run_sync(
                self._cancel,
                cast(str, values["request_id"]),
                principal,
                now=now,
            )
        elif name == "request_tool_access":
            result = await self._request_access(values, principal, now=now)
        else:  # pragma: no cover - guarded by _validate_call
            raise AssertionError("unreachable gateway tool dispatch")

        return await _run_sync(_validate_tool_result, name, result)

    def _prepare_call(
        self,
        name: str,
        arguments: Mapping[str, Any],
    ) -> tuple[dict[str, Any], int]:
        values = self._validate_call(name, arguments)
        now = self._clock()
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise RuntimeError("the gateway clock returned an invalid Unix timestamp")
        return values, now

    @staticmethod
    def _validate_call(name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        validator = _INPUT_VALIDATORS.get(name)
        if validator is None:
            raise McpError(
                types.ErrorData(code=types.INVALID_PARAMS, message=f"Unknown tool: {name}")
            )
        if not isinstance(arguments, Mapping):
            raise McpError(
                types.ErrorData(
                    code=types.INVALID_PARAMS,
                    message="Tool arguments must be an object",
                )
            )
        values = dict(arguments)
        try:
            validator.validate(values)
        except ValidationError as exc:
            raise McpError(
                types.ErrorData(code=types.INVALID_PARAMS, message=f"Invalid arguments for {name}")
            ) from exc
        return values

    async def _check_status(self, request_id: str, principal: GatewayPrincipal) -> dict[str, Any]:
        try:
            request = await _run_sync(self._owned_request, request_id, principal.namespace)
        except RequestNotFound:
            return _not_found_result()

        summary, summary_available = await self._public_summary(request)
        value: dict[str, Any] = {
            "request_id": request.request_id,
            "status": request.state,
            "service": summary.service,
            "tool": request.tool,
            "destination_summary": summary.destination_summary,
            "summary_available": summary_available,
            "version": request.version,
            "expires_at": _timestamp(request.expires_at),
        }
        if request.safe_outcome_json is not None:
            metadata = json.loads(request.safe_outcome_json)
            if not isinstance(metadata, dict):
                raise RuntimeError("stored safe outcome metadata is not an object")
            value["safe_result_metadata"] = metadata
        if request.failure_reason:
            value["failure_code"] = request.failure_reason
        return _success_result(value)

    async def _list_pending(
        self,
        principal: GatewayPrincipal,
        *,
        now: int,
        cursor: str | None,
        limit: int,
    ) -> dict[str, Any]:
        after = _decode_pending_cursor(cursor) if cursor is not None else None
        requests, has_more = await _run_sync(
            self._pending_requests,
            principal.namespace,
            now=now,
            after=after,
            limit=limit,
        )
        summaries = [await self._public_summary(request) for request in requests]
        value = {
            "requests": [
                {
                    "request_id": request.request_id,
                    "service": summary.service,
                    "tool": request.tool,
                    "destination_summary": summary.destination_summary,
                    "summary_available": summary_available,
                    "age_seconds": max(0, now - request.created_at),
                    "expires_at": _timestamp(request.expires_at),
                    "version_hash_prefix": version_hash_prefix(
                        request.payload_hash, self._hash_prefix_length
                    ),
                }
                for request, (summary, summary_available) in zip(requests, summaries, strict=True)
            ],
            "next_cursor": (
                _encode_pending_cursor(requests[-1]) if has_more and requests else None
            ),
            "has_more": has_more,
        }
        return _success_result(value)

    async def _approve(
        self,
        values: Mapping[str, Any],
        principal: GatewayPrincipal,
        *,
        now: int,
    ) -> dict[str, Any]:
        request_id = cast(str, values["request_id"])
        try:
            request = await _run_sync(self._owned_request, request_id, principal.namespace)
        except RequestNotFound:
            return _not_found_result()

        if request.gateway_internal:
            return domain_error_result(
                "web_only",
                "Policy-change requests can only be approved in the authenticated web app.",
            )
        if request.state != "pending_approval":
            return domain_error_result(
                "invalid_request_state",
                "Only a pending request can be approved.",
            )
        if now >= request.expires_at:
            return domain_error_result(
                "request_expired",
                "This request has expired and cannot be approved.",
            )

        expected_prefix = cast(str, values["expected_version_hash"])
        current_prefix = request.payload_hash[: len(expected_prefix)]
        if not hmac.compare_digest(current_prefix, expected_prefix):
            return _stale_result()

        binding = ActionBinding(
            action="approve",
            request_id=request.request_id,
            version=request.version,
            payload_hash=request.payload_hash,
        )
        try:
            proof = await _run_sync(
                self._totp.verify,
                principal.user_id,
                cast(str, values["totp_code"]),
                binding=binding,
                now=now,
                source_id=principal.namespace,
                session_id=None,
                http_method="MCP",
            )
        except TotpNotEnrolled:
            return domain_error_result(
                "totp_not_enrolled",
                "TOTP is not enrolled; approve this request in the authenticated web app.",
            )
        except AuthenticationRateLimited as exc:
            return domain_error_result(
                "totp_locked",
                "TOTP verification is temporarily locked; wait before retrying or use the web app.",
                details={"retry_after": exc.retry_after},
            )
        except InvalidTotp:
            return domain_error_result(
                "totp_invalid",
                "The TOTP code is invalid or has already been consumed.",
            )
        except TotpUnavailable:
            return domain_error_result(
                "totp_unavailable",
                "TOTP verification is unavailable; use the authenticated web app.",
            )

        if (
            proof.user_id != principal.user_id
            or proof.binding != binding
            or proof.session_id is not None
            or proof.http_method != "MCP"
            or not proof.credential_id
            or not proof.use_id
            or not proof.attempt_reservation.attempt_id
            or proof.rate_limit_key != totp_rate_limit_key(principal.user_id)
            or set(proof.attempt_reservation.scope_keys)
            != {
                totp_rate_limit_key(principal.user_id),
                source_rate_limit_key(principal.namespace),
            }
        ):
            return domain_error_result(
                "totp_binding_invalid",
                "The TOTP proof was not bound to this exact request version.",
            )

        try:
            summary = await self._review_summary(request)
        except Exception:
            return domain_error_result(
                "private_summary_unavailable",
                "The private request summary is unavailable; review this request in the web app.",
            )

        confirmation = ApprovalConfirmation(
            kind=ConfirmationKind.TOTP,
            use_id=proof.use_id,
            path="mcp",
            capability=proof.capability,
            user_id=proof.user_id,
            action=proof.binding.action,
            bound_request_id=proof.binding.request_id,
            bound_version=proof.binding.version,
            bound_payload_hash=proof.binding.payload_hash,
            prospective_payload_hash=proof.binding.prospective_payload_hash,
            session_id=proof.session_id,
            http_method=proof.http_method,
            attempt_id=proof.attempt_reservation.attempt_id,
            attempt_scope_keys=proof.attempt_reservation.scope_keys,
            rate_limit_key=proof.rate_limit_key,
            credential_id=proof.credential_id,
            credential_user_id=proof.user_id,
            verified_at=proof.verified_at,
            expires_at=proof.expires_at,
        )
        try:
            await _run_sync(
                self._state_machine.approve,
                request.request_id,
                expected_version=request.version,
                expected_payload_hash=request.payload_hash,
                confirmation=confirmation,
                actor=principal.actor,
                now=now,
            )
        except RequestNotFound:
            return _not_found_result()
        except StaleVersion:
            return _stale_result()
        except RequestExpired:
            return domain_error_result(
                "request_expired",
                "This request has expired and cannot be approved.",
            )
        except ConfirmationReplay:
            return domain_error_result(
                "totp_replayed",
                "This TOTP code has already authorized another action.",
            )
        except InvalidTransition:
            return domain_error_result(
                "invalid_request_state",
                "Only a pending request can be approved.",
            )
        except InvalidConfirmation:
            return domain_error_result(
                "web_only" if request.gateway_internal else "totp_binding_invalid",
                (
                    "Policy-change requests can only be approved in the authenticated web app."
                    if request.gateway_internal
                    else "The TOTP proof was not bound to this exact request version."
                ),
            )

        await _run_sync(self._totp.record_consumed_success, proof, now=now)
        return _success_result(
            {
                "status": "approved",
                "request_id": request.request_id,
                "tool": request.tool,
                "destination_summary": summary.destination_summary,
                "version": request.version,
                "version_hash_prefix": version_hash_prefix(
                    request.payload_hash, self._hash_prefix_length
                ),
                "approval_notification_queued": True,
            }
        )

    def _cancel(
        self,
        request_id: str,
        principal: GatewayPrincipal,
        *,
        now: int,
    ) -> dict[str, Any]:
        try:
            request = self._owned_request(request_id, principal.namespace)
        except RequestNotFound:
            return _not_found_result()
        if request.state != "pending_approval":
            return domain_error_result(
                "invalid_request_state",
                "Only a pending request can be cancelled.",
            )
        try:
            self._state_machine.cancel_by_caller(
                request.request_id,
                expected_version=request.version,
                expected_payload_hash=request.payload_hash,
                actor=principal.actor,
                now=now,
                origin_namespace=principal.namespace,
            )
        except RequestNotFound:
            return _not_found_result()
        except StaleVersion:
            return _stale_result()
        except InvalidTransition:
            return domain_error_result(
                "invalid_request_state",
                "Only a pending request can be cancelled.",
            )
        return _success_result({"status": "cancelled", "request_id": request.request_id})

    async def _request_access(
        self,
        values: Mapping[str, Any],
        principal: GatewayPrincipal,
        *,
        now: int,
    ) -> dict[str, Any]:
        draft = AccessRequestDraft(
            origin_namespace=principal.namespace,
            alias=cast(str, values["alias"]),
            tool=cast(str, values["tool"]),
            reason=cast(str, values["reason"]),
            actor=principal.actor,
            created_at=now,
        )
        request = await _resolve(await _run_sync(self._access_requests.freeze, draft))
        if (
            not request.gateway_internal
            or request.origin_namespace != principal.namespace
            or request.downstream_alias != "gateway"
            or request.tool_name != "request_tool_access"
            or request.policy_mode != "approval"
            or request.created_at != now
            or request.editor_actor != principal.actor
            or re.fullmatch(r"req_[A-Za-z0-9]+", request.request_id) is None
        ):
            raise RuntimeError("access request factory violated the gateway-internal contract")
        await _run_sync(self._state_machine.enqueue, request)
        return _success_result(
            {
                "status": "pending_approval",
                "request_id": request.request_id,
                "expires_at": _timestamp(request.expires_at),
                "message": "Tool access was requested and is waiting for web approval.",
                "approval_channel": "web_only",
            }
        )

    def _owned_request(self, request_id: str, namespace: str) -> _RequestSnapshot:
        with self._state_machine.database.read() as connection:
            row = connection.execute(
                """
                SELECT request_id, downstream_alias, tool_name, state,
                       current_version, current_payload_hash, created_at, expires_at,
                       gateway_internal, safe_outcome_json, failure_reason
                FROM approval_requests
                WHERE request_id = ? AND origin_namespace = ?
                """,
                (request_id, namespace),
            ).fetchone()
        if row is None:
            raise RequestNotFound(request_id)
        return _snapshot(row)

    def _pending_requests(
        self,
        namespace: str,
        *,
        now: int,
        after: tuple[int, str] | None,
        limit: int,
    ) -> tuple[list[_RequestSnapshot], bool]:
        if limit < 1 or limit > MAX_PENDING_PAGE_SIZE:
            raise ValueError("pending approval page size is outside its hard bound")
        with self._state_machine.database.read() as connection:
            if after is None:
                rows = connection.execute(
                    """
                    SELECT request_id, downstream_alias, tool_name, state,
                           current_version, current_payload_hash, created_at, expires_at,
                           gateway_internal, safe_outcome_json, failure_reason
                    FROM approval_requests
                    WHERE origin_namespace = ? AND state = 'pending_approval'
                      AND expires_at > ?
                    ORDER BY created_at, request_id
                    LIMIT ?
                    """,
                    (namespace, now, limit + 1),
                ).fetchall()
            else:
                created_at, request_id = after
                rows = connection.execute(
                    """
                    SELECT request_id, downstream_alias, tool_name, state,
                           current_version, current_payload_hash, created_at, expires_at,
                           gateway_internal, safe_outcome_json, failure_reason
                    FROM approval_requests
                    WHERE origin_namespace = ? AND state = 'pending_approval'
                      AND expires_at > ?
                      AND (created_at > ? OR (created_at = ? AND request_id > ?))
                    ORDER BY created_at, request_id
                    LIMIT ?
                    """,
                    (namespace, now, created_at, created_at, request_id, limit + 1),
                ).fetchall()
        visible = rows[:limit]
        return [_snapshot(row) for row in visible], len(rows) > limit

    async def _review_summary(self, request: _RequestSnapshot) -> SafeRequestSummary:
        summary = await _resolve(await _run_sync(self._summary, request))
        await _run_sync(_require_safe_summary, request, summary)
        return summary

    async def _public_summary(self, request: _RequestSnapshot) -> tuple[SafeRequestSummary, bool]:
        try:
            return await self._review_summary(request), True
        except Exception:
            return (
                SafeRequestSummary(
                    service=_service_label(request.service),
                    tool=request.tool,
                    destination_summary=_UNAVAILABLE_DESTINATION_SUMMARY,
                ),
                False,
            )

    def _summary(
        self, request: _RequestSnapshot
    ) -> SafeRequestSummary | Awaitable[SafeRequestSummary]:
        return self._summaries.get(
            request.request_id,
            version=request.version,
            payload_hash=request.payload_hash,
        )


GatewayPrincipalProvider = Callable[[], GatewayPrincipal]


class GatewayToolSurface:
    """Low-level MCP server wiring for the gateway-owned tool alias."""

    def __init__(
        self,
        *,
        tools: GatewayTools,
        principal_provider: GatewayPrincipalProvider,
    ) -> None:
        self.tools = tools
        self.principal_provider = principal_provider
        self.server: LosslessToolServer = LosslessToolServer("Signet", version=__version__)
        self.server.request_handlers[types.ListToolsRequest] = self._list_tools
        self.server.request_handlers[types.CallToolRequest] = self._call_tool

    async def _list_tools(self, request: types.ListToolsRequest) -> types.ServerResult:
        del request
        self.principal_provider()
        return RawServerResult({"tools": await _run_sync(self.tools.list_tools)})

    async def _call_tool(self, request: types.CallToolRequest) -> types.ServerResult:
        principal = self.principal_provider()
        result = await self.tools.call_tool(
            request.params.name,
            request.params.arguments or {},
            principal=principal,
        )
        return RawServerResult(result)


def _snapshot(row: Mapping[str, Any]) -> _RequestSnapshot:
    return _RequestSnapshot(
        request_id=cast(str, row["request_id"]),
        service=cast(str, row["downstream_alias"]),
        tool=cast(str, row["tool_name"]),
        state=cast(str, row["state"]),
        version=cast(int, row["current_version"]),
        payload_hash=cast(str, row["current_payload_hash"]),
        created_at=cast(int, row["created_at"]),
        expires_at=cast(int, row["expires_at"]),
        gateway_internal=bool(row["gateway_internal"]),
        safe_outcome_json=cast(str | None, row["safe_outcome_json"]),
        failure_reason=cast(str | None, row["failure_reason"]),
    )


def _require_safe_summary(request: _RequestSnapshot, summary: SafeRequestSummary) -> None:
    if summary.tool != request.tool:
        raise RuntimeError("safe request summary does not match the frozen request tool")
    destination = summary.destination_summary
    if request.service == "fastmail":
        if summary.service.casefold() != "fastmail" or not _is_masked_email_summary(destination):
            raise RuntimeError("Fastmail agent summary is not safely masked")
    elif request.service == "whatsapp" and (
        summary.service.casefold() != "whatsapp"
        or "***" not in destination
        or _WHATSAPP_MASK_RE.fullmatch(destination) is None
    ):
        raise RuntimeError("WhatsApp agent summary is not safely masked")


def _is_masked_email_summary(value: str) -> bool:
    parts = value.split(", ")
    if parts and re.fullmatch(r"\(\+[1-9][0-9]{0,2} more\)", parts[-1]):
        parts.pop()
    if not parts or len(parts) > 3:
        return False
    for mailbox in parts:
        local, separator, domain = mailbox.partition(" at ")
        if (
            separator != " at "
            or re.fullmatch(r"[A-Za-z0-9]\*{3}", local) is None
            or not domain
            or len(domain) > 253
            or any(character.isspace() or ord(character) < 33 for character in domain)
            or any(character in domain for character in "@,")
            or "@" in mailbox
        ):
            return False
    return True


def _service_label(service: str) -> str:
    return {"fastmail": "Fastmail", "whatsapp": "WhatsApp"}.get(service, service)


def _encode_pending_cursor(request: _RequestSnapshot) -> str:
    return _encode_pending_cursor_values(request.created_at, request.request_id)


def _encode_pending_cursor_values(created_at: int, request_id: str) -> str:
    payload = json.dumps(
        [created_at, request_id],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _decode_pending_cursor(value: str) -> tuple[int, str]:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
        parsed = json.loads(decoded.decode("ascii"))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        _raise_invalid_cursor()
    if (
        not isinstance(parsed, list)
        or len(parsed) != 2
        or not isinstance(parsed[0], int)
        or isinstance(parsed[0], bool)
        or parsed[0] < 0
        or parsed[0] > 2**63 - 1
        or not isinstance(parsed[1], str)
        or len(parsed[1]) > 128
        or _REQUEST_ID_RE.fullmatch(parsed[1]) is None
    ):
        _raise_invalid_cursor()
    created_at, request_id = cast(tuple[int, str], tuple(parsed))
    if not hmac.compare_digest(_encode_pending_cursor_values(created_at, request_id), value):
        _raise_invalid_cursor()
    return created_at, request_id


def _raise_invalid_cursor() -> Never:
    raise McpError(
        types.ErrorData(
            code=types.INVALID_PARAMS,
            message="Invalid arguments for list_pending_approvals",
        )
    )


async def _resolve[T](value: T | Awaitable[T]) -> T:
    if inspect.isawaitable(value):
        return await value
    return value


def _validate_tool_result(name: str, result: dict[str, Any]) -> dict[str, Any]:
    if result.get("isError") is True:
        types.CallToolResult.model_validate(result)
        return result
    structured = result.get("structuredContent")
    _OUTPUT_VALIDATORS[name].validate(structured)
    types.CallToolResult.model_validate(result)
    return result


def _timestamp(value: int) -> str:
    return (
        datetime.fromtimestamp(value, tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def _success_result(value: Mapping[str, Any]) -> dict[str, Any]:
    structured = copy.deepcopy(dict(value))
    serialized = json.dumps(structured, ensure_ascii=False, separators=(",", ":"))
    return {
        "content": [{"type": "text", "text": serialized}],
        "structuredContent": structured,
        "isError": False,
    }


def _not_found_result() -> dict[str, Any]:
    return domain_error_result(
        "request_not_found",
        "No request with that ID exists in this caller namespace.",
    )


def _stale_result() -> dict[str, Any]:
    return domain_error_result(
        "stale_version",
        "The request changed after it was reviewed; list pending approvals again.",
    )
