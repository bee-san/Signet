"""Gateway-owned adapter for encrypted policy-access proposals."""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from signet.adapters.base import (
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
    copy_json_object,
)
from signet.models import AttachmentReference

_ALIAS = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
_FIELDS = frozenset({"alias", "tool", "reason"})


class ToolAccessAdapter:
    """Review-only adapter; policy application belongs to the policy boundary."""

    adapter_id = "gateway.request-tool-access"
    adapter_version = "1"
    downstream_alias = "gateway"
    tool_name = "request_tool_access"
    communication_send = False
    supports_idempotency = False
    reconciliation_tools: frozenset[str] = frozenset()
    input_schema: Mapping[str, Any] = MappingProxyType(
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["alias", "tool", "reason"],
            "properties": {
                "alias": {"type": "string", "pattern": _ALIAS.pattern},
                "tool": {"type": "string", "pattern": _TOOL.pattern},
                "reason": {"type": "string", "minLength": 1, "maxLength": 1000},
            },
        }
    )

    def validate(self, arguments: Mapping[str, Any]) -> None:
        values = copy_json_object(arguments)
        alias = values.get("alias")
        tool = values.get("tool")
        reason = values.get("reason")
        if (
            frozenset(values) != _FIELDS
            or not isinstance(alias, str)
            or _ALIAS.fullmatch(alias) is None
            or not isinstance(tool, str)
            or _TOOL.fullmatch(tool) is None
            or not isinstance(reason, str)
            or not reason
            or reason.strip() != reason
            or len(reason.encode("utf-8")) > 1000
            or any(ord(character) < 0x20 and character not in "\t\n" for character in reason)
            or "\x7f" in reason
        ):
            raise AdapterValidationError("tool-access proposal is invalid")

    def canonicalize(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self.validate(arguments)
        return {
            "alias": arguments["alias"],
            "reason": arguments["reason"],
            "tool": arguments["tool"],
        }

    def freeze_attachments(self, arguments: Mapping[str, Any]) -> tuple[AttachmentReference, ...]:
        self.validate(arguments)
        return ()

    def summarize_for_web(self, arguments: Mapping[str, Any]) -> ApprovalSummary:
        proposal = self.canonicalize(arguments)
        target = f"{proposal['alias']}.{proposal['tool']}"
        return ApprovalSummary(
            service="Signet",
            action=self.tool_name,
            title="Tool access waiting for approval",
            destination_summary=target,
            detail_blocks=(
                DetailBlock("Requested tool", "text", target),
                DetailBlock("Reason", "text", proposal["reason"]),
            ),
            warnings=("Approval changes durable gateway policy; it does not call the tool.",),
        )

    def redact_for_audit(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        proposal = self.canonicalize(arguments)
        return {
            "alias": proposal["alias"],
            "tool": proposal["tool"],
            "reason": "<redacted>",
        }

    def prepare_for_execution(self, request: AdapterRequest) -> dict[str, Any]:
        del request
        raise AdapterValidationError("gateway policy proposals are never downstream requests")

    async def execute(self, downstream: MCPClient, payload: Mapping[str, Any]) -> dict[str, Any]:
        del downstream, payload
        raise DispatchError(
            "gateway policy proposals cannot be dispatched",
            dispatch_may_have_occurred=False,
        )

    def classify_outcome(self, result_or_error: object) -> Outcome:
        del result_or_error
        return Outcome.DEFINITE_FAILURE

    async def reconcile(
        self,
        downstream: ReadOnlyMCPClient,
        request: AdapterRequest,
        attempt: ExecutionAttempt,
    ) -> Reconciliation:
        del downstream, request, attempt
        return Reconciliation.INCONCLUSIVE

    def safe_result_metadata(self, downstream_result: Mapping[str, Any]) -> dict[str, Any]:
        del downstream_result
        return {}
