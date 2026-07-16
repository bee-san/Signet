"""Immutable and current runtime scope for one downstream approval tool."""

from __future__ import annotations

import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from signet.adapters.base import ApprovalAdapter
from signet.mcp_mirror import MirrorError, SchemaMirror
from signet.policy import PolicyMode

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class ExecutionScopeError(ValueError):
    """The current runtime cannot prove an exact executable scope."""


@dataclass(frozen=True, slots=True)
class ExecutionScope:
    """Non-secret identity required to authorize one exact downstream route."""

    account_ref: str
    credential_identity_digest: str
    schema_digest: str

    def __post_init__(self) -> None:
        if not _bounded_text(self.account_ref):
            raise ExecutionScopeError("execution account reference is invalid")
        if not _is_sha256(self.credential_identity_digest):
            raise ExecutionScopeError("credential identity digest is invalid")
        if not _is_sha256(self.schema_digest):
            raise ExecutionScopeError("execution schema digest is invalid")


class ExecutionScopeResolver(Protocol):
    """Resolve the scope currently configured for an adapter route."""

    def resolve(
        self,
        downstream_alias: str,
        tool_name: str,
        adapter: ApprovalAdapter,
        downstream_client: object | None = None,
    ) -> ExecutionScope: ...


class PolicyExecutionScopeResolver:
    """Resolve policy scope against the exact assembled downstream client."""

    def __init__(
        self,
        mirror: SchemaMirror,
        downstream_clients: Mapping[str, object],
    ) -> None:
        if not isinstance(mirror, SchemaMirror):
            raise ExecutionScopeError("a schema mirror is required")
        if any(
            not _bounded_text(alias) or not _client_identity_is_valid(client)
            for alias, client in downstream_clients.items()
        ):
            raise ExecutionScopeError("downstream client identity inventory is invalid")
        self._mirror = mirror
        self._downstream_clients = dict(downstream_clients)

    def resolve(
        self,
        downstream_alias: str,
        tool_name: str,
        adapter: ApprovalAdapter,
        downstream_client: object | None = None,
    ) -> ExecutionScope:
        if adapter.downstream_alias != downstream_alias or adapter.tool_name != tool_name:
            raise ExecutionScopeError("adapter does not match the requested route")
        try:
            reviewed = self._mirror.reviewed_execution_snapshot(
                downstream_alias,
                tool_name,
            )
        except MirrorError as exc:
            raise ExecutionScopeError("the approval route is not currently reviewed") from exc
        downstream = reviewed.downstream
        configured = reviewed.tool
        if (
            configured.mode is not PolicyMode.APPROVAL
            or configured.adapter != adapter.adapter_id
            or configured.communication_send is not adapter.communication_send
        ):
            raise ExecutionScopeError("the approval route is not currently reviewed")

        declared_accounts = tuple(
            value
            for value in (
                downstream.account_ref,
                configured.account_ref,
                getattr(adapter, "account", None),
            )
            if value is not None
        )
        if not declared_accounts or any(not _bounded_text(value) for value in declared_accounts):
            raise ExecutionScopeError("the current account scope is missing or invalid")
        if len(set(declared_accounts)) != 1:
            raise ExecutionScopeError("the current account scope is missing or contradictory")
        account_ref = declared_accounts[0]
        try:
            configured_client = self._downstream_clients[downstream_alias]
            if downstream_client is not None and downstream_client is not configured_client:
                raise ExecutionScopeError("selected downstream client is not the reviewed client")
            credential_digest = downstream_identity_digest(configured_client)
            schema_digest = reviewed.schema_digest
        except (KeyError, MirrorError) as exc:
            raise ExecutionScopeError("the current execution identity is unavailable") from exc
        return ExecutionScope(
            account_ref=account_ref,
            credential_identity_digest=credential_digest,
            schema_digest=schema_digest,
        )


class StaticExecutionScopeResolver:
    """Exact-snapshot resolver used by bounded assemblies and restart tests."""

    def __init__(
        self,
        scopes: Mapping[tuple[str, str], ExecutionScope],
        downstream_clients: Mapping[str, object] | None = None,
    ) -> None:
        if not scopes or any(
            not _bounded_text(alias)
            or not _bounded_text(tool)
            or not isinstance(scope, ExecutionScope)
            for (alias, tool), scope in scopes.items()
        ):
            raise ExecutionScopeError("execution scope registry is invalid")
        if downstream_clients is not None and any(
            not _bounded_text(alias) or not _client_identity_is_valid(client)
            for alias, client in downstream_clients.items()
        ):
            raise ExecutionScopeError("downstream client identity registry is invalid")
        self._scopes = dict(scopes)
        self._downstream_clients = (
            dict(downstream_clients) if downstream_clients is not None else None
        )

    def resolve(
        self,
        downstream_alias: str,
        tool_name: str,
        adapter: ApprovalAdapter,
        downstream_client: object | None = None,
    ) -> ExecutionScope:
        if adapter.downstream_alias != downstream_alias or adapter.tool_name != tool_name:
            raise ExecutionScopeError("adapter does not match the requested route")
        try:
            scope = self._scopes[(downstream_alias, tool_name)]
        except KeyError as exc:
            raise ExecutionScopeError("the current execution scope is unavailable") from exc
        adapter_account = getattr(adapter, "account", None)
        if adapter_account is not None and adapter_account != scope.account_ref:
            raise ExecutionScopeError("adapter account does not match the current scope")
        configured_client = None
        if self._downstream_clients is not None:
            try:
                configured_client = self._downstream_clients[downstream_alias]
            except KeyError as exc:
                raise ExecutionScopeError("the current downstream client is unavailable") from exc
            if downstream_client is not None and downstream_client is not configured_client:
                raise ExecutionScopeError("selected downstream client is not the reviewed client")
        identity_client = downstream_client if downstream_client is not None else configured_client
        if identity_client is not None and not _same_digest(
            downstream_identity_digest(identity_client),
            scope.credential_identity_digest,
        ):
            raise ExecutionScopeError("downstream client identity does not match the current scope")
        return scope


def downstream_identity_digest(downstream_client: object) -> str:
    """Read and validate the non-secret identity exposed by an executable client."""

    digest = getattr(downstream_client, "credential_identity_digest", None)
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise ExecutionScopeError("downstream client identity is unavailable or invalid")
    return digest


def _bounded_text(value: object, *, maximum: int = 512) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    try:
        return len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        return False


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _client_identity_is_valid(client: object) -> bool:
    try:
        downstream_identity_digest(client)
    except ExecutionScopeError:
        return False
    return True


def _same_digest(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
