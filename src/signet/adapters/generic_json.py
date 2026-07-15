"""Generic structured-JSON approval adapter.

This fallback deliberately offers a plain JSON review instead of pretending to
understand provider semantics.  It is suitable only for explicitly reviewed
approval-mode tools.  It never asserts a reconciliation result because it has no
provider identity with which to prove an effect or the absence of one.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from signet.adapters.base import (
    AdapterProtocolError,
    AdapterRequest,
    AdapterValidationError,
    ApprovalSummary,
    DetailBlock,
    DispatchError,
    ExecutionAttempt,
    MCPClient,
    Outcome,
    ReadOnlyMCPClient,
    Reconciliation,
    conservative_outcome,
    copy_json_object,
    redact_json,
)
from signet.models import AttachmentReference

DEFAULT_INPUT_SCHEMA: Mapping[str, Any] = MappingProxyType(
    {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
    }
)


class GenericJSONAdapter:
    """Approval adapter with raw structured review and no provider assumptions."""

    communication_send = False
    supports_idempotency = False
    reconciliation_tools: frozenset[str] = frozenset()

    def __init__(
        self,
        *,
        downstream_alias: str,
        tool_name: str,
        input_schema: Mapping[str, Any] = DEFAULT_INPUT_SCHEMA,
        adapter_version: str = "1",
        sensitive_keys: frozenset[str] = frozenset(
            {"authorization", "credential", "password", "secret", "token"}
        ),
        safe_result_fields: tuple[str, ...] = (),
        communication_send: bool = False,
        reviewed_dispatch_enabled: bool = False,
    ) -> None:
        if not downstream_alias or not tool_name or not adapter_version:
            raise ValueError("alias, tool name, and adapter version are required")
        schema = copy_json_object(input_schema)
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            raise ValueError("input_schema must be valid JSON Schema 2020-12") from exc
        self.downstream_alias = downstream_alias
        self.tool_name = tool_name
        self.adapter_id = f"generic-json.{downstream_alias}.{tool_name}"
        self.adapter_version = adapter_version
        self.input_schema = MappingProxyType(schema)
        self.sensitive_keys = sensitive_keys
        self.safe_result_fields = safe_result_fields
        self.communication_send = communication_send
        self.reviewed_dispatch_enabled = reviewed_dispatch_enabled
        self._validator = Draft202012Validator(schema)

    def validate(self, arguments: Mapping[str, Any]) -> None:
        detached = copy_json_object(arguments)
        try:
            self._validator.validate(detached)
        except ValidationError as exc:
            path = ".".join(str(part) for part in exc.absolute_path) or "arguments"
            raise AdapterValidationError(f"invalid generic arguments at {path}") from exc

    def canonicalize(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self.validate(arguments)
        detached = copy_json_object(arguments)
        encoded = json.dumps(
            detached,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        value = json.loads(encoded)
        if not isinstance(value, dict):  # pragma: no cover - guarded by validate
            raise AdapterValidationError("arguments must be a JSON object")
        return value

    def freeze_attachments(self, arguments: Mapping[str, Any]) -> tuple[AttachmentReference, ...]:
        self.validate(arguments)
        return ()

    def summarize_for_web(self, arguments: Mapping[str, Any]) -> ApprovalSummary:
        canonical = self.canonicalize(arguments)
        return ApprovalSummary(
            service=self.downstream_alias,
            action=self.tool_name,
            title=f"Review {self.downstream_alias}.{self.tool_name}",
            destination_summary=f"{self.downstream_alias}.{self.tool_name}",
            detail_blocks=(DetailBlock("Arguments", "json", canonical),),
            warnings=("Generic adapter: provider semantics and reconciliation are unavailable.",),
        )

    def redact_for_audit(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self.validate(arguments)
        return redact_json(arguments, sensitive_keys=self.sensitive_keys)

    def prepare_for_execution(self, request: AdapterRequest) -> dict[str, Any]:
        if request.downstream_alias != self.downstream_alias or request.tool_name != self.tool_name:
            raise AdapterValidationError("request does not match this adapter")
        return self.canonicalize(request.arguments)

    async def execute(self, downstream: MCPClient, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not self.reviewed_dispatch_enabled:
            raise DispatchError(
                "generic adapter dispatch is not activated",
                dispatch_may_have_occurred=False,
            )
        self.validate(payload)
        result = await downstream.call_tool(self.tool_name, copy_json_object(payload))
        if not isinstance(result, Mapping):
            raise AdapterProtocolError("downstream tool result must be a JSON object")
        return copy_json_object(result)

    def classify_outcome(self, result_or_error: object) -> Outcome:
        return conservative_outcome(result_or_error)

    async def reconcile(
        self,
        downstream: ReadOnlyMCPClient,
        request: AdapterRequest,
        attempt: ExecutionAttempt,
    ) -> Reconciliation:
        # There is intentionally no downstream call: raw JSON has no stable
        # provider identity that could establish an effect or its absence.
        del downstream, request, attempt
        return Reconciliation.INCONCLUSIVE

    def safe_result_metadata(self, downstream_result: Mapping[str, Any]) -> dict[str, Any]:
        detached = copy_json_object(downstream_result)
        safe: dict[str, Any] = {}
        for field in self.safe_result_fields:
            if field not in detached:
                continue
            value = detached.get(field)
            if value is None or isinstance(value, (str, int, float, bool)):
                safe[field] = value
        return safe
