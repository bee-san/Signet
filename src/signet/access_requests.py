"""Production freezer for gateway-internal tool-access proposals."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from signet.adapters.tool_access import ToolAccessAdapter
from signet.canonical import canonical_json
from signet.freezer import RequestFreezer
from signet.gateway_tools import AccessRequestDraft
from signet.models import EnqueueRequest

_DENIED_EVENT_REASON = "This reviewed tool was invoked while explicitly denied by policy."


class FrozenAccessRequestFactory:
    """Turn an authenticated caller proposal into one encrypted queue request."""

    def __init__(
        self,
        freezer: RequestFreezer,
        *,
        policy_version: Callable[[], int],
        schema_version: str = "gateway.request-tool-access.v1",
    ) -> None:
        if not callable(policy_version) or not schema_version:
            raise ValueError("policy version provider and schema version are required")
        self._freezer = freezer
        self._policy_version = policy_version
        self._schema_version = schema_version
        self.adapter = ToolAccessAdapter()

    def freeze(self, draft: AccessRequestDraft) -> EnqueueRequest:
        if not draft.gateway_internal:
            raise ValueError("tool-access requests must remain gateway-internal")
        return self._freeze(draft, policy_version=self._active_policy_version())

    def freeze_denied_event(
        self,
        *,
        origin_namespace: str,
        alias: str,
        tool: str,
        actor: str,
        created_at: int,
    ) -> EnqueueRequest:
        """Freeze one argument-free promotable event per policy/caller/tool tuple."""

        version = self._active_policy_version()
        draft = AccessRequestDraft(
            origin_namespace=origin_namespace,
            alias=alias,
            tool=tool,
            reason=_DENIED_EVENT_REASON,
            actor=actor,
            created_at=created_at,
        )
        invocation_key = "denied_" + hashlib.sha256(
            canonical_json(
                {
                    "alias": alias,
                    "namespace": origin_namespace,
                    "policy_version": version,
                    "tool": tool,
                }
            )
        ).hexdigest()
        return self._freeze(
            draft,
            policy_version=version,
            idempotency_key=invocation_key,
        )

    def _freeze(
        self,
        draft: AccessRequestDraft,
        *,
        policy_version: int,
        idempotency_key: str | None = None,
    ) -> EnqueueRequest:
        frozen = self._freezer.freeze(
            self.adapter,
            {"alias": draft.alias, "tool": draft.tool, "reason": draft.reason},
            origin_namespace=draft.origin_namespace,
            policy_version=policy_version,
            schema_version=self._schema_version,
            editor_actor=draft.actor,
            idempotency_key=idempotency_key,
            gateway_internal=True,
            created_at=draft.created_at,
        )
        return frozen.enqueue_request

    def _active_policy_version(self) -> int:
        version = self._policy_version()
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise RuntimeError("active policy version is invalid")
        return version
