"""Reviewed local staging handlers for production provider attachments."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from signet.adapters.base import ApprovalAdapter, staging_account_scope
from signet.adapters.fastmail import FastmailAdapter
from signet.adapters.whatsapp import WhatsAppAdapter
from signet.gateway import LocalHandler, LocalInvocation
from signet.policy import PolicyMode, PolicySnapshot
from signet.staging import StagingError, StagingStore

_MAX_UNCONSUMED_OBJECTS_PER_SCOPE = 32
_MAX_UNCONSUMED_BYTES_PER_SCOPE = 256 * 1024 * 1024


class ProductionStagingHandlerError(RuntimeError):
    """A reviewed local staging route cannot be assembled safely."""


def _staging_arguments(arguments: Mapping[str, Any]) -> tuple[Path, str, str]:
    if set(arguments) != {"source_path", "filename", "mime_type"}:
        raise ValueError("staging arguments do not match the reviewed contract")
    source_path = arguments.get("source_path")
    filename = arguments.get("filename")
    mime_type = arguments.get("mime_type")
    if not all(isinstance(value, str) and value for value in (source_path, filename, mime_type)):
        raise ValueError("staging arguments do not match the reviewed contract")
    return Path(cast(str, source_path)), cast(str, filename), cast(str, mime_type)


def _account_for(policy: PolicySnapshot, alias: str, tool_name: str) -> str:
    downstream = policy.downstreams[alias]
    account = downstream.tools[tool_name].account_ref or downstream.account_ref
    if account is None:
        raise ProductionStagingHandlerError(
            f"production staging route has no account scope: {alias}/{tool_name}"
        )
    return account


def _require_staging_capacity(
    store: StagingStore,
    *,
    adapter: str,
    account: str,
    caller_namespace: str,
) -> None:
    scoped_account = staging_account_scope(account, caller_namespace)
    object_count, total_bytes = store.unconsumed_usage(
        adapter=adapter,
        account=scoped_account,
    )
    byte_limit = min(_MAX_UNCONSUMED_BYTES_PER_SCOPE, max(1, store.max_total_bytes // 4))
    if object_count >= _MAX_UNCONSUMED_OBJECTS_PER_SCOPE or total_bytes >= byte_limit:
        raise StagingError("caller staging capacity is exhausted")


def _fastmail_handler(
    adapter: FastmailAdapter,
    *,
    alias: str,
    tool_name: str,
) -> LocalHandler:
    def stage(arguments: Mapping[str, Any], invocation: LocalInvocation) -> Mapping[str, Any]:
        if invocation.alias != alias or invocation.tool != tool_name:
            raise ValueError("staging invocation does not match its reviewed route")
        source_path, filename, mime_type = _staging_arguments(arguments)
        store = adapter.staging_store
        if store is None:
            raise ProductionStagingHandlerError("Fastmail attachment staging is unavailable")
        _require_staging_capacity(
            store,
            adapter=adapter.downstream_alias,
            account=adapter.account,
            caller_namespace=invocation.namespace,
        )
        return adapter.stage_attachment(
            source_path,
            filename=filename,
            mime_type=mime_type,
            caller_namespace=invocation.namespace,
        )

    return stage


def _whatsapp_handler(
    adapter: WhatsAppAdapter,
    *,
    alias: str,
    tool_name: str,
) -> LocalHandler:
    def stage(arguments: Mapping[str, Any], invocation: LocalInvocation) -> Mapping[str, Any]:
        if invocation.alias != alias or invocation.tool != tool_name:
            raise ValueError("staging invocation does not match its reviewed route")
        source_path, filename, mime_type = _staging_arguments(arguments)
        store = adapter.staging_store
        if store is None:
            raise ProductionStagingHandlerError("WhatsApp media staging is unavailable")
        _require_staging_capacity(
            store,
            adapter=adapter.downstream_alias,
            account=adapter.account,
            caller_namespace=invocation.namespace,
        )
        return adapter.stage_media(
            source_path,
            filename=filename,
            mime_type=mime_type,
            caller_namespace=invocation.namespace,
        )

    return stage


def build_production_staging_handlers(
    policy: PolicySnapshot,
    adapters: Mapping[tuple[str, str], ApprovalAdapter],
) -> Mapping[str, LocalHandler]:
    """Bind reviewed virtualized staging routes to account-scoped adapters."""

    handlers: dict[str, LocalHandler] = {}
    for alias, downstream in policy.downstreams.items():
        for tool_name, tool in downstream.tools.items():
            if tool.mode is not PolicyMode.VIRTUALIZE_LOCAL:
                continue
            if tool.adapter == "fastmail.stage_attachment":
                if tool.adapter in handlers:
                    raise ProductionStagingHandlerError(
                        "Fastmail staging adapter is bound to multiple routes"
                    )
                adapter = adapters.get((alias, "send_email"))
                if not isinstance(adapter, FastmailAdapter):
                    raise ProductionStagingHandlerError(
                        "Fastmail staging requires its account-scoped send adapter"
                    )
                if adapter.account != _account_for(policy, alias, tool_name):
                    raise ProductionStagingHandlerError(
                        "Fastmail staging account scope is inconsistent"
                    )
                handlers[tool.adapter] = _fastmail_handler(
                    adapter,
                    alias=alias,
                    tool_name=tool_name,
                )
            elif tool.adapter == "whatsapp.stage_media":
                if tool.adapter in handlers:
                    raise ProductionStagingHandlerError(
                        "WhatsApp staging adapter is bound to multiple routes"
                    )
                adapter = adapters.get((alias, "send_file"))
                if not isinstance(adapter, WhatsAppAdapter) or adapter.tool_name != "send_file":
                    raise ProductionStagingHandlerError(
                        "WhatsApp staging requires its account-scoped file adapter"
                    )
                if adapter.account != _account_for(policy, alias, tool_name):
                    raise ProductionStagingHandlerError(
                        "WhatsApp staging account scope is inconsistent"
                    )
                handlers[tool.adapter] = _whatsapp_handler(
                    adapter,
                    alias=alias,
                    tool_name=tool_name,
                )
    return MappingProxyType(handlers)
