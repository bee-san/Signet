"""Production freezer for gateway-internal tool-access proposals."""

from __future__ import annotations

from collections.abc import Callable

from signet.adapters.tool_access import ToolAccessAdapter
from signet.freezer import RequestFreezer
from signet.gateway_tools import AccessRequestDraft
from signet.models import EnqueueRequest


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
        version = self._policy_version()
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise RuntimeError("active policy version is invalid")
        frozen = self._freezer.freeze(
            self.adapter,
            {"alias": draft.alias, "tool": draft.tool, "reason": draft.reason},
            origin_namespace=draft.origin_namespace,
            policy_version=version,
            schema_version=self._schema_version,
            editor_actor=draft.actor,
            gateway_internal=True,
            created_at=draft.created_at,
        )
        return frozen.enqueue_request
