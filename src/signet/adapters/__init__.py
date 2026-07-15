"""Reviewed downstream adapter SDK and lazily loaded built-in providers."""

from __future__ import annotations

from typing import Any

from signet.adapters.base import (
    AdapterError,
    AdapterProtocolError,
    AdapterRequest,
    AdapterTestHarness,
    AdapterValidationError,
    ApprovalAdapter,
    ApprovalSummary,
    DetailBlock,
    DispatchError,
    ExecutionAttempt,
    MCPClient,
    Outcome,
    ReadOnlyMCPClient,
    Reconciliation,
    build_schema_fixture,
    redact_json,
)

__all__ = [
    "AdapterError",
    "AdapterProtocolError",
    "AdapterRequest",
    "AdapterTestHarness",
    "AdapterValidationError",
    "ApprovalAdapter",
    "ApprovalSummary",
    "DetailBlock",
    "DispatchError",
    "ExecutionAttempt",
    "FastmailAdapter",
    "GenericJSONAdapter",
    "MCPClient",
    "Outcome",
    "ReadOnlyMCPClient",
    "Reconciliation",
    "WhatsAppAdapter",
    "WhatsAppFileAdapter",
    "WhatsAppTextAdapter",
    "build_schema_fixture",
    "redact_json",
]


def __getattr__(name: str) -> Any:
    """Avoid importing the WhatsApp adapter while its wrapper imports the SDK."""

    if name == "FastmailAdapter":
        from signet.adapters.fastmail import FastmailAdapter

        return FastmailAdapter
    if name == "GenericJSONAdapter":
        from signet.adapters.generic_json import GenericJSONAdapter

        return GenericJSONAdapter
    if name in {"WhatsAppAdapter", "WhatsAppFileAdapter", "WhatsAppTextAdapter"}:
        from signet.adapters.whatsapp import (
            WhatsAppAdapter,
            WhatsAppFileAdapter,
            WhatsAppTextAdapter,
        )

        return {
            "WhatsAppAdapter": WhatsAppAdapter,
            "WhatsAppFileAdapter": WhatsAppFileAdapter,
            "WhatsAppTextAdapter": WhatsAppTextAdapter,
        }[name]
    raise AttributeError(name)
