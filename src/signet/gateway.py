"""Production call routing for reviewed alias MCP surfaces."""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

import mcp.types as types
from jsonschema.exceptions import SchemaError, ValidationError

from signet.adapters.base import ApprovalAdapter, copy_json_object
from signet.admission import ReviewedToolLimits
from signet.downstream import validate_call_tool_result
from signet.freezer import RequestFreezer
from signet.mcp_mirror import (
    DomainToolError,
    InvocationIdentity,
    SchemaMirror,
    pending_call_result,
)
from signet.models import AdmissionRejected, EnqueueRequest, EnqueueResult, IdempotencyConflict
from signet.policy import PolicyMode, ToolPolicy


class GatewayError(RuntimeError):
    """Base class for gateway wiring and stored-result failures."""


class GatewayConfigurationError(GatewayError, ValueError):
    """Reviewed gateway dependencies do not match their registry keys."""


class RawDownstreamClient(Protocol):
    async def call_tool_raw(
        self, tool_name: str, arguments: Mapping[str, Any]
    ) -> dict[str, Any]: ...


class ApprovalEnqueuer(Protocol):
    def enqueue(
        self,
        request: EnqueueRequest,
        *,
        reviewed_limits: ReviewedToolLimits,
    ) -> EnqueueResult: ...


@dataclass(frozen=True, slots=True)
class LocalInvocation:
    namespace: str
    alias: str
    tool: str
    identity: InvocationIdentity


LocalResult = Mapping[str, Any]
LocalHandler = Callable[
    [Mapping[str, Any], LocalInvocation],
    LocalResult | Awaitable[LocalResult],
]


class GatewayCallPipeline:
    """Route one validated call through its exact reviewed policy mode."""

    def __init__(
        self,
        *,
        mirror: SchemaMirror,
        downstream_clients: Mapping[str, RawDownstreamClient],
        local_handlers: Mapping[str, LocalHandler],
        adapters: Mapping[str, ApprovalAdapter],
        freezer: RequestFreezer,
        enqueuer: ApprovalEnqueuer,
    ) -> None:
        if not isinstance(mirror, SchemaMirror):
            raise GatewayConfigurationError("a schema mirror is required")
        if not isinstance(freezer, RequestFreezer):
            raise GatewayConfigurationError("a request freezer is required")
        if not callable(getattr(enqueuer, "enqueue", None)):
            raise GatewayConfigurationError("an approval enqueuer is required")
        if any(
            not _bounded_name(alias) or not callable(getattr(client, "call_tool_raw", None))
            for alias, client in downstream_clients.items()
        ):
            raise GatewayConfigurationError("downstream client registry is invalid")
        if any(
            not _bounded_name(name) or not callable(handler)
            for name, handler in local_handlers.items()
        ):
            raise GatewayConfigurationError("local handler registry is invalid")
        if any(
            not _bounded_name(adapter_id)
            or getattr(adapter, "adapter_id", None) != adapter_id
            or not _bounded_name(getattr(adapter, "downstream_alias", None))
            or not _bounded_name(getattr(adapter, "tool_name", None))
            for adapter_id, adapter in adapters.items()
        ):
            raise GatewayConfigurationError("approval adapter registry is invalid")
        self.mirror = mirror
        self._downstream_clients = dict(downstream_clients)
        self._local_handlers = dict(local_handlers)
        self._adapters = dict(adapters)
        self._freezer = freezer
        self._enqueuer = enqueuer

    def __repr__(self) -> str:
        return (
            "GatewayCallPipeline("
            f"downstreams={len(self._downstream_clients)}, "
            f"local_handlers={len(self._local_handlers)}, "
            f"adapters={len(self._adapters)})"
        )

    async def __call__(
        self,
        alias: str,
        tool: str,
        arguments: Mapping[str, Any],
        namespace: str,
        identity: InvocationIdentity,
    ) -> dict[str, Any]:
        return await self.handle_call(alias, tool, arguments, namespace, identity)

    async def handle_call(
        self,
        alias: str,
        tool: str,
        arguments: Mapping[str, Any],
        namespace: str,
        identity: InvocationIdentity,
    ) -> dict[str, Any]:
        """Validate first, then execute exactly one reviewed mode."""

        if not _bounded_name(alias) or not _bounded_name(tool) or not _bounded_namespace(namespace):
            raise DomainToolError("invalid_invocation", "The tool invocation scope is invalid.")
        if not isinstance(identity, InvocationIdentity):
            raise DomainToolError("invalid_invocation", "The tool invocation identity is invalid.")
        try:
            detached_arguments = copy_json_object(arguments)
        except (TypeError, ValueError):
            raise DomainToolError(
                "invalid_arguments",
                "Tool arguments must be a JSON object.",
            ) from None

        mode = self.mirror.require_callable(alias, tool)
        self.mirror.validate_input(alias, tool, detached_arguments)
        policy = self.mirror.policy.configured(alias, tool)
        if policy is None or policy.mode is not mode:  # pragma: no cover - mirror invariant
            raise DomainToolError("policy_unavailable", "The reviewed tool policy is unavailable.")

        if mode is PolicyMode.PASSTHROUGH:
            return await self._passthrough(policy, detached_arguments)
        if mode is PolicyMode.VIRTUALIZE_LOCAL:
            return await self._virtualize(policy, detached_arguments, namespace, identity)
        if mode is PolicyMode.APPROVAL:
            return await self._enqueue_approval(
                policy,
                detached_arguments,
                namespace,
                identity,
            )
        if mode is PolicyMode.DENY:
            raise DomainToolError(
                "policy_denied",
                "This reviewed tool is denied by Signet policy.",
            )
        raise DomainToolError("policy_unavailable", "The reviewed tool policy is unavailable.")

    async def _passthrough(
        self, policy: ToolPolicy, arguments: Mapping[str, Any]
    ) -> dict[str, Any]:
        client = self._downstream_clients.get(policy.alias)
        if client is None:
            raise DomainToolError(
                "downstream_unavailable",
                "The reviewed downstream client is unavailable.",
            )
        try:
            raw_result = await client.call_tool_raw(policy.tool, arguments)
            validated = validate_call_tool_result(raw_result)
            self.mirror.validate_downstream_result(policy.alias, policy.tool, validated)
            return validated
        except asyncio.CancelledError:
            raise
        except DomainToolError:
            raise
        except Exception:
            raise DomainToolError(
                "downstream_failed",
                "The reviewed downstream call failed or returned an invalid result.",
            ) from None

    async def _virtualize(
        self,
        policy: ToolPolicy,
        arguments: Mapping[str, Any],
        namespace: str,
        identity: InvocationIdentity,
    ) -> dict[str, Any]:
        handler_id = policy.adapter
        handler = self._local_handlers.get(handler_id or "")
        if handler is None:
            raise DomainToolError(
                "local_handler_unavailable",
                "The reviewed local tool handler is unavailable.",
            )
        invocation = LocalInvocation(
            namespace=namespace,
            alias=policy.alias,
            tool=policy.tool,
            identity=identity,
        )
        try:
            result = handler(copy.deepcopy(dict(arguments)), invocation)
            if inspect.isawaitable(result):
                result = await result
            detached = copy_json_object(result)
        except asyncio.CancelledError:
            raise
        except (TypeError, ValueError):
            raise DomainToolError(
                "invalid_local_result",
                "The local tool returned an invalid JSON object.",
            ) from None
        except DomainToolError:
            raise
        except Exception:
            raise DomainToolError(
                "local_handler_failed",
                "The reviewed local tool handler failed.",
            ) from None
        try:
            self.mirror.validate_virtual_result(policy.alias, policy.tool, detached)
        except (KeyError, SchemaError, ValidationError):
            raise DomainToolError(
                "invalid_local_result",
                "The local tool result does not match the reviewed output schema.",
            ) from None
        except Exception:
            raise DomainToolError(
                "invalid_local_result",
                "The local tool result does not match the reviewed output schema.",
            ) from None
        return _structured_success_result(detached)

    async def _enqueue_approval(
        self,
        policy: ToolPolicy,
        arguments: Mapping[str, Any],
        namespace: str,
        identity: InvocationIdentity,
    ) -> dict[str, Any]:
        adapter_id = policy.adapter
        adapter = self._adapters.get(adapter_id or "")
        if (
            adapter is None
            or adapter.adapter_id != adapter_id
            or adapter.downstream_alias != policy.alias
            or adapter.tool_name != policy.tool
            or adapter.communication_send is not policy.communication_send
        ):
            raise DomainToolError(
                "adapter_unavailable",
                "The exact reviewed approval adapter is unavailable.",
            )
        try:
            reviewed_limits = ReviewedToolLimits.from_policy(policy.limits)
        except (TypeError, ValueError):
            raise DomainToolError(
                "policy_unavailable",
                "The reviewed tool admission policy is unavailable.",
            ) from None
        try:
            adapter.validate(arguments)
            canonical = adapter.canonicalize(arguments)
            canonical_arguments = copy_json_object(canonical)
            attachment_freezer = getattr(adapter, "freeze_attachments", None)
            attachments = (
                attachment_freezer(canonical_arguments)
                if callable(attachment_freezer)
                else ()
            )
        except (TypeError, ValueError):
            raise DomainToolError(
                "invalid_arguments",
                "Tool arguments do not satisfy the reviewed approval adapter.",
            ) from None
        except Exception:
            raise DomainToolError(
                "adapter_failed",
                "The reviewed approval adapter rejected the request.",
            ) from None

        try:
            frozen = self._freezer.freeze(
                adapter,
                canonical_arguments,
                origin_namespace=namespace,
                policy_version=self.mirror.policy.version,
                schema_version=self.mirror.captured_digest(policy.alias, policy.tool),
                editor_actor=f"caller:{namespace}",
                idempotency_key=identity.invocation_key,
                attachments=attachments,
            )
        except (TypeError, ValueError):
            raise DomainToolError(
                "request_rejected",
                "The approval request could not be frozen safely.",
            ) from None

        # Cancellation may win before durable enqueue. Once this synchronous
        # transaction begins, it runs through commit before control is yielded.
        await asyncio.sleep(0)
        try:
            stored = self._enqueuer.enqueue(
                frozen.enqueue_request,
                reviewed_limits=reviewed_limits,
            )
        except IdempotencyConflict:
            raise DomainToolError(
                "invocation_conflict",
                "This invocation ID is already bound to a different payload.",
            ) from None
        except AdmissionRejected as exc:
            code, message = _admission_error(exc)
            raise DomainToolError(code, message) from None
        return _stored_pending_call_result(stored)


AliasGateway = GatewayCallPipeline


def _admission_error(error: AdmissionRejected) -> tuple[str, str]:
    if error.reason == "payload_limit":
        return "request_rejected", "The request exceeds its reviewed payload limit."
    if error.reason == "request_rate":
        return "rate_limited", "This reviewed tool has reached its request-rate limit."
    if error.reason == "queue_capacity":
        return "queue_full", "The approval queue is at capacity; no request was stored."
    return "storage_unavailable", "Durable storage has insufficient safe headroom."


def _structured_success_result(value: Mapping[str, Any]) -> dict[str, Any]:
    detached = copy_json_object(value)
    serialized = json.dumps(
        detached,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    raw = {
        "content": [{"type": "text", "text": serialized}],
        "structuredContent": detached,
        "isError": False,
    }
    types.CallToolResult.model_validate(raw, strict=True)
    return raw


def _stored_pending_call_result(stored: EnqueueResult) -> dict[str, Any]:
    if not isinstance(stored, EnqueueResult):
        raise GatewayError("approval enqueuer returned an invalid result")
    raw = stored.pending_result
    if not isinstance(raw, bytes) or not raw or len(raw) > 64 * 1024:
        raise GatewayError("stored pending result is invalid")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in items:
            if key in value:
                raise ValueError("duplicate field")
            value[key] = child
        return value

    def invalid_constant(_: str) -> None:
        raise ValueError("non-finite number")

    try:
        decoded: object = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=invalid_constant,
        )
    except (TypeError, ValueError, UnicodeError):
        raise GatewayError("stored pending result is invalid") from None
    if (
        not isinstance(decoded, dict)
        or not all(isinstance(key, str) for key in decoded)
        or decoded.get("request_id") != stored.request_id
    ):
        raise GatewayError("stored pending result is invalid")
    canonical = json.dumps(
        decoded,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if canonical != raw:
        raise GatewayError("stored pending result is invalid")
    try:
        return pending_call_result(cast(dict[str, Any], decoded))
    except (TypeError, ValueError, ValidationError):
        raise GatewayError("stored pending result is invalid") from None


def _bounded_name(value: object) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    try:
        return len(value.encode("utf-8")) <= 512
    except UnicodeError:
        return False


def _bounded_namespace(value: object) -> bool:
    return _bounded_name(value) and len(cast(str, value).encode("utf-8")) <= 480
