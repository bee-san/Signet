"""Provider-neutral approval adapter contracts.

Adapters sit on the narrow boundary between Signet's immutable request state and
provider-specific tools.  An adapter is intentionally given a small request view
instead of a database model.  Reconciliation receives :class:`ReadOnlyMCPClient`,
never the unrestricted downstream client; the wrapper rejects calls outside the
adapter's separately reviewed allowlist before they reach the wire.

New adapters should declare exact input and output schemas, validate before
canonicalization, redact audit copies without redacting the private approval
view, conservatively classify ambiguous outcomes, and either implement a bounded
read-only lookup or return ``Reconciliation.INCONCLUSIVE`` without making a call.
``build_schema_fixture`` produces a secret-free review artifact for that process.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, cast, final, runtime_checkable

from signet.models import AttachmentReference, ReadOnlyToolViolation

JSON_OBJECT_ERROR = "value must be a JSON object"
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class AdapterError(RuntimeError):
    """Base class for adapter boundary failures."""


class AdapterValidationError(AdapterError, ValueError):
    """The frozen arguments do not satisfy the reviewed adapter contract."""


class AdapterProtocolError(AdapterError):
    """A downstream result does not satisfy the reviewed result contract."""


class DispatchError(AdapterError):
    """A dispatch failed with an explicit side-effect characterization."""

    def __init__(self, message: str, *, dispatch_may_have_occurred: bool) -> None:
        super().__init__(message)
        self.dispatch_may_have_occurred = dispatch_may_have_occurred


class Outcome(StrEnum):
    """Provider outcome classification used by fenced delivery."""

    SUCCEEDED = "succeeded"
    DEFINITE_FAILURE = "definite_failure"
    OUTCOME_UNKNOWN = "outcome_unknown"


class Reconciliation(StrEnum):
    """Result of one structurally read-only ambiguity lookup."""

    CONFIRMED_EFFECT = "confirmed_effect"
    CONFIRMED_NO_EFFECT = "confirmed_no_effect"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class DetailBlock:
    """One renderable block in the private approval detail view."""

    label: str
    kind: str
    value: Any


@dataclass(frozen=True, slots=True)
class ApprovalSummary:
    """Provider-owned private review content.

    ``detail_blocks`` may contain sensitive content because it is rendered only
    in the authenticated approval application.  It must not be reused for logs,
    notifications, or agent-facing status results.
    """

    service: str
    action: str
    title: str
    destination_summary: str
    detail_blocks: tuple[DetailBlock, ...]
    warnings: tuple[str, ...] = ()


def copy_json_object(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and detach a mapping using the standard JSON data model."""

    def materialize(item: Any) -> Any:
        if isinstance(item, Mapping):
            if not all(isinstance(key, str) for key in item):
                raise AdapterValidationError(JSON_OBJECT_ERROR)
            return {key: materialize(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [materialize(child) for child in item]
        return item

    try:
        encoded = json.dumps(materialize(value), ensure_ascii=False, allow_nan=False)
        decoded = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise AdapterValidationError(JSON_OBJECT_ERROR) from exc
    if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
        raise AdapterValidationError(JSON_OBJECT_ERROR)
    return cast(dict[str, Any], decoded)


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(child) for child in value)
    return value


@dataclass(frozen=True, slots=True)
class AdapterRequest:
    """Immutable provider-facing view of one frozen request version."""

    request_id: str
    downstream_alias: str
    tool_name: str
    arguments: Mapping[str, Any]
    account: str
    payload_hash: str
    version: int = 1
    idempotency_key: str | None = None
    created_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.request_id or not self.downstream_alias or not self.tool_name:
            raise AdapterValidationError("request identity fields are required")
        if not self.account or not _SHA256_RE.fullmatch(self.payload_hash) or self.version < 1:
            raise AdapterValidationError("request scope, hash, and version are required")
        detached = copy_json_object(self.arguments)
        object.__setattr__(self, "arguments", _freeze_json(detached))


@dataclass(frozen=True, slots=True)
class ExecutionAttempt:
    """Minimal immutable context available to a reconciliation lookup."""

    attempt_id: str
    started_at: datetime
    finished_at: datetime | None = None
    downstream_result: Mapping[str, Any] | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        if not self.attempt_id:
            raise AdapterValidationError("attempt_id is required")
        if self.downstream_result is not None:
            detached = copy_json_object(self.downstream_result)
            object.__setattr__(self, "downstream_result", _freeze_json(detached))


@runtime_checkable
class MCPClient(Protocol):
    """The only unrestricted downstream operation adapters may use to execute."""

    async def call_tool(
        self, tool_name: str, arguments: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...


@final
class ReadOnlyMCPClient:
    """Exact-name allowlist around an unrestricted downstream client.

    The delegate is deliberately private and there is no general escape hatch or
    passthrough method.  Policy code constructs this object from the intersection
    of the adapter declaration and the reviewed downstream policy.
    """

    __slots__ = ("__delegate", "__reviewed_tools")

    def __init__(
        self,
        delegate: MCPClient,
        reviewed_tools: frozenset[str] | set[str] | tuple[str, ...],
    ) -> None:
        tools = frozenset(reviewed_tools)
        if any(not tool or not isinstance(tool, str) for tool in tools):
            raise ValueError("read-only tool names must be non-empty strings")
        self.__delegate = delegate
        self.__reviewed_tools = tools

    @property
    def reviewed_tools(self) -> frozenset[str]:
        return self.__reviewed_tools

    async def call_tool(self, tool_name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        if tool_name not in self.__reviewed_tools:
            raise ReadOnlyToolViolation(
                f"downstream tool {tool_name!r} is not approved for reconciliation"
            )
        detached_arguments = copy_json_object(arguments)
        result = await self.__delegate.call_tool(tool_name, detached_arguments)
        if not isinstance(result, Mapping):
            raise AdapterProtocolError("downstream tool result must be a JSON object")
        return MappingProxyType(copy_json_object(result))


@runtime_checkable
class ApprovalAdapter(Protocol):
    """Complete contract for a gated or richly rendered downstream tool."""

    adapter_id: str
    adapter_version: str
    downstream_alias: str
    tool_name: str
    communication_send: bool
    supports_idempotency: bool
    reconciliation_tools: frozenset[str]
    input_schema: Mapping[str, Any]

    def validate(self, arguments: Mapping[str, Any]) -> None: ...

    def canonicalize(self, arguments: Mapping[str, Any]) -> dict[str, Any]: ...

    def freeze_attachments(
        self, arguments: Mapping[str, Any]
    ) -> tuple[AttachmentReference, ...]: ...

    def summarize_for_web(self, arguments: Mapping[str, Any]) -> ApprovalSummary: ...

    def redact_for_audit(self, arguments: Mapping[str, Any]) -> dict[str, Any]: ...

    def prepare_for_execution(self, request: AdapterRequest) -> dict[str, Any]: ...

    async def execute(
        self, downstream: MCPClient, payload: Mapping[str, Any]
    ) -> dict[str, Any]: ...

    def classify_outcome(self, result_or_error: object) -> Outcome: ...

    async def reconcile(
        self,
        downstream: ReadOnlyMCPClient,
        request: AdapterRequest,
        attempt: ExecutionAttempt,
    ) -> Reconciliation: ...

    def safe_result_metadata(self, downstream_result: Mapping[str, Any]) -> dict[str, Any]: ...


@dataclass(slots=True)
class AdapterTestHarness:
    """Reusable contract harness for adapter fixture and fake-provider tests.

    The harness proves deterministic canonicalization, exercises the complete
    private review path, constructs a representative immutable request, and
    ensures reconciliation is always invoked through ``ReadOnlyMCPClient``.
    It never supplies an approval or contacts a provider on its own.
    """

    adapter: ApprovalAdapter
    valid_arguments: Mapping[str, Any]
    account: str = "test-account"

    def __post_init__(self) -> None:
        self.valid_arguments = MappingProxyType(copy_json_object(self.valid_arguments))

    def exercise_review_contract(self) -> ApprovalSummary:
        self.adapter.validate(self.valid_arguments)
        first = self.adapter.canonicalize(self.valid_arguments)
        second = self.adapter.canonicalize(first)
        if first != second:
            raise AssertionError("adapter canonicalization is not idempotent")
        copy_json_object(self.adapter.redact_for_audit(first))
        summary = self.adapter.summarize_for_web(first)
        try:
            json.dumps(
                [
                    {"label": block.label, "kind": block.kind, "value": block.value}
                    for block in summary.detail_blocks
                ],
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise AssertionError("adapter detail blocks must use JSON values") from exc
        return summary

    def request(self, *, request_id: str = "req_adapter_harness") -> AdapterRequest:
        canonical = self.adapter.canonicalize(self.valid_arguments)
        encoded = json.dumps(
            canonical,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return AdapterRequest(
            request_id=request_id,
            downstream_alias=self.adapter.downstream_alias,
            tool_name=self.adapter.tool_name,
            arguments=canonical,
            account=self.account,
            payload_hash=hashlib.sha256(encoded).hexdigest(),
        )

    async def execute(self, downstream: MCPClient) -> dict[str, Any]:
        request = self.request()
        payload = self.adapter.prepare_for_execution(request)
        return await self.adapter.execute(downstream, payload)

    async def reconcile(
        self,
        downstream: MCPClient,
        attempt: ExecutionAttempt,
    ) -> Reconciliation:
        restricted = ReadOnlyMCPClient(downstream, self.adapter.reconciliation_tools)
        return await self.adapter.reconcile(restricted, self.request(), attempt)


def redact_json(
    value: Mapping[str, Any],
    *,
    sensitive_keys: frozenset[str] | set[str] | tuple[str, ...],
    replacement: str = "<redacted>",
) -> dict[str, Any]:
    """Return a detached recursive audit copy with exact key redaction."""
    detached = copy_json_object(value)
    folded = {key.casefold() for key in sensitive_keys}

    def walk(item: Any) -> Any:
        if isinstance(item, dict):
            return {
                key: replacement if key.casefold() in folded else walk(child)
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [walk(child) for child in item]
        return copy.deepcopy(item)

    return cast(dict[str, Any], walk(detached))


def build_schema_fixture(
    adapter: ApprovalAdapter,
    *,
    source: str,
    schema_status: str = "review_required",
) -> dict[str, Any]:
    """Build a secret-free schema review fixture for a new adapter."""
    if not source or not _VERSION_RE.fullmatch(adapter.adapter_version):
        raise ValueError("fixture source and a simple adapter version are required")
    return {
        "fixture_kind": "signet_adapter_schema",
        "source": source,
        "schema_status": schema_status,
        "adapter": {
            "id": adapter.adapter_id,
            "version": adapter.adapter_version,
            "downstream_alias": adapter.downstream_alias,
            "tool": adapter.tool_name,
            "communication_send": adapter.communication_send,
            "supports_idempotency": adapter.supports_idempotency,
            "reconciliation_tools": sorted(adapter.reconciliation_tools),
            "input_schema": copy_json_object(adapter.input_schema),
        },
    }


def conservative_outcome(result_or_error: object) -> Outcome:
    """Classify only explicit success/no-effect failures; ambiguity stays unknown."""
    if isinstance(result_or_error, DispatchError):
        if result_or_error.dispatch_may_have_occurred:
            return Outcome.OUTCOME_UNKNOWN
        return Outcome.DEFINITE_FAILURE
    if isinstance(result_or_error, BaseException):
        return Outcome.OUTCOME_UNKNOWN
    if not isinstance(result_or_error, Mapping):
        return Outcome.OUTCOME_UNKNOWN
    status = result_or_error.get("status")
    is_error = (
        result_or_error.get("isError") is True
        or result_or_error.get("is_error") is True
        or status in {"error", "failed", "rejected"}
    )
    if is_error:
        if result_or_error.get("effect") == "none" and status in {"failed", "rejected"}:
            return Outcome.DEFINITE_FAILURE
        return Outcome.OUTCOME_UNKNOWN
    if result_or_error.get("sent") is True or result_or_error.get("success") is True:
        return Outcome.SUCCEEDED
    if status in {"sent", "submitted", "succeeded", "success", "ok"}:
        return Outcome.SUCCEEDED
    return Outcome.OUTCOME_UNKNOWN
