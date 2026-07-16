"""Bounded, read-only downstream outcome reconciliation."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, cast

from signet.adapters.base import (
    ExecutionAttempt,
    MCPClient,
    ReadOnlyMCPClient,
    Reconciliation,
)
from signet.async_support import run_sync_non_abandoning as _run_sync
from signet.delivery import (
    DeliveryDispatcher,
    DispatchResult,
    FrozenRequestLoader,
    LoadedFrozenRequest,
    result_aliases_from_metadata,
)
from signet.models import (
    ExecutionLease,
    ExecutionPhase,
    ReconciliationAction,
    ReconciliationDecision,
    ReconciliationRejected,
    ReconciliationResult,
    ResultAlias,
)
from signet.state_machine import ApprovalStateMachine


class ReconciliationError(RuntimeError):
    """The coordinator could not safely evaluate a due unknown outcome."""


@dataclass(frozen=True, slots=True)
class ReconciliationRun:
    request_id: str
    decision: ReconciliationDecision
    result: ReconciliationResult
    redispatch: DispatchResult | None = None


@dataclass(frozen=True, slots=True)
class _AttemptSnapshot:
    request_id: str
    version: int
    payload_hash: str
    attempt_id: str
    fencing_token: str
    worker_generation: int
    downstream_idempotency_key: str | None
    reconciliation_attempt_count: int
    reconciliation_next_at: int | None
    started_at: int
    safe_completion: Mapping[str, str | int | bool | None]
    failure_reason: str | None

    def lease(self) -> ExecutionLease:
        return ExecutionLease(
            request_id=self.request_id,
            version=self.version,
            payload_hash=self.payload_hash,
            attempt_id=self.attempt_id,
            fencing_token=self.fencing_token,
            worker_generation=self.worker_generation,
            lease_expires_at=0,
            phase=ExecutionPhase.OUTCOME_UNKNOWN,
            downstream_idempotency_key=self.downstream_idempotency_key,
        )


@dataclass(frozen=True, slots=True)
class _PreparedReconciliation:
    loaded: LoadedFrozenRequest
    downstream: MCPClient
    restricted: ReadOnlyMCPClient
    attempt: ExecutionAttempt


class ReconciliationCoordinator:
    """Run finite adapter lookups and apply their result through durable CAS gates."""

    def __init__(
        self,
        state_machine: ApprovalStateMachine,
        loader: FrozenRequestLoader,
        dispatcher: DeliveryDispatcher,
        downstream_clients: Mapping[str, MCPClient],
        *,
        schedule: tuple[int, ...] = (60, 5 * 60, 30 * 60, 2 * 60 * 60, 12 * 60 * 60),
        reviewed_tools: Mapping[tuple[str, str], frozenset[str]] | None = None,
        redispatch_lease_seconds: int = 30,
        max_batch_size: int = 100,
    ) -> None:
        if (
            not schedule
            or len(schedule) > 16
            or any(delay <= 0 for delay in schedule)
            or tuple(sorted(schedule)) != schedule
        ):
            raise ValueError("reconciliation schedule must be finite, positive, and ordered")
        if redispatch_lease_seconds <= 0 or max_batch_size <= 0 or max_batch_size > 1_000:
            raise ValueError("reconciliation lease and batch limits are invalid")
        self.state_machine = state_machine
        self.loader = loader
        self.dispatcher = dispatcher
        self._downstream_clients = dict(downstream_clients)
        self.schedule = schedule
        # The adapter declaration is necessary but not sufficient. A missing
        # policy review must collapse the intersection to an empty allowlist.
        self._reviewed_tools = dict(reviewed_tools or {})
        self.redispatch_lease_seconds = redispatch_lease_seconds
        self.max_batch_size = max_batch_size

    def due_request_ids(self, *, now: int, limit: int | None = None) -> tuple[str, ...]:
        selected_limit = self.max_batch_size if limit is None else limit
        if selected_limit <= 0 or selected_limit > self.max_batch_size:
            raise ValueError("reconciliation query exceeds the configured batch limit")
        with self.state_machine.database.read() as connection:
            rows = connection.execute(
                """
                SELECT attempt.request_id
                FROM execution_attempts AS attempt
                JOIN approval_requests AS request
                  ON request.request_id = attempt.request_id
                WHERE request.state = 'outcome_unknown'
                  AND attempt.phase = 'outcome_unknown'
                  AND (
                      attempt.reconciliation_resolution IS NULL
                      OR attempt.reconciliation_resolution != 'exhausted'
                  )
                  AND attempt.reconciliation_next_at IS NOT NULL
                  AND attempt.reconciliation_next_at <= ?
                ORDER BY attempt.reconciliation_next_at, attempt.request_id
                LIMIT ?
                """,
                (now, selected_limit),
            ).fetchall()
        return tuple(row["request_id"] for row in rows)

    async def run_due(
        self,
        *,
        worker_id: str,
        now: int,
        limit: int | None = None,
    ) -> tuple[ReconciliationRun, ...]:
        results: list[ReconciliationRun] = []
        request_ids = await _run_sync(self.due_request_ids, now=now, limit=limit)
        for request_id in request_ids:
            try:
                results.append(await self.reconcile_once(request_id, worker_id=worker_id, now=now))
            except ReconciliationRejected:
                # Another worker won the count/state CAS after this bounded due query.
                continue
        return tuple(results)

    async def reconcile_once(
        self,
        request_id: str,
        *,
        worker_id: str,
        now: int,
    ) -> ReconciliationRun:
        snapshot = await _run_sync(self._snapshot, request_id)
        if snapshot.reconciliation_next_at is None or snapshot.reconciliation_next_at > now:
            raise ReconciliationRejected("reconciliation is not due")
        loaded = None
        try:
            prepared = await _run_sync(self._prepare_reconciliation, snapshot)
            loaded = prepared.loaded
            self.loader.require_current_scope(loaded, prepared.downstream)
            adapter_decision = await loaded.adapter.reconcile(
                prepared.restricted,
                loaded.request,
                prepared.attempt,
            )
            if not isinstance(adapter_decision, Reconciliation):
                adapter_decision = Reconciliation.INCONCLUSIVE
            decision = _state_decision(adapter_decision)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Corrupt payloads, missing reviewed adapters/clients, and provider
            # lookup failures all consume one bounded inconclusive attempt. A
            # permanently bad row therefore cannot stay immediately due forever
            # or prevent later rows in the same batch from being considered.
            decision = ReconciliationDecision.INCONCLUSIVE

        state_result = await _run_sync(
            self._apply_reconciliation,
            request_id,
            snapshot,
            decision,
            loaded,
            worker_id=worker_id,
            now=now,
        )
        redispatch: DispatchResult | None = None
        if state_result.action is ReconciliationAction.REDISPATCH:
            if loaded is None:  # pragma: no cover - only confirmed-no-effect can redispatch
                raise ReconciliationError("redispatch has no loaded frozen request")
            if state_result.lease is None:
                raise ReconciliationError("state machine omitted the authorized redispatch lease")
            if not loaded.adapter.supports_idempotency:
                raise ReconciliationError("non-idempotent adapter received a redispatch lease")
            redispatch = await self.dispatcher.dispatch_claimed(state_result.lease, now=now)
        return ReconciliationRun(
            request_id=request_id,
            decision=decision,
            result=state_result,
            redispatch=redispatch,
        )

    def _prepare_reconciliation(
        self,
        snapshot: _AttemptSnapshot,
    ) -> _PreparedReconciliation:
        loaded = self.loader.load(snapshot.lease())
        downstream = self._downstream_clients[loaded.request.downstream_alias]
        reviewed = loaded.adapter.reconciliation_tools & self._reviewed_tools.get(
            (loaded.request.downstream_alias, loaded.request.tool_name), frozenset()
        )
        return _PreparedReconciliation(
            loaded=loaded,
            downstream=downstream,
            restricted=ReadOnlyMCPClient(downstream, reviewed),
            attempt=ExecutionAttempt(
                attempt_id=snapshot.attempt_id,
                started_at=datetime.fromtimestamp(snapshot.started_at, tz=UTC),
                downstream_result=snapshot.safe_completion or None,
                error_code=snapshot.failure_reason,
            ),
        )

    def _apply_reconciliation(
        self,
        request_id: str,
        snapshot: _AttemptSnapshot,
        decision: ReconciliationDecision,
        loaded: LoadedFrozenRequest | None,
        *,
        worker_id: str,
        now: int,
    ) -> ReconciliationResult:
        safe_outcome: Mapping[str, Any] | None = None
        aliases: tuple[ResultAlias, ...] = ()
        next_check_at: int | None = None
        exhausted = False
        if decision is ReconciliationDecision.CONFIRMED_EFFECT:
            if loaded is None:  # pragma: no cover - decision requires a loaded adapter
                raise ReconciliationError("confirmed effect has no loaded frozen request")
            merged = dict(snapshot.safe_completion)
            merged["reconciled_at"] = now
            safe_outcome = MappingProxyType(merged)
            aliases = result_aliases_from_metadata(
                snapshot.safe_completion,
                account_namespace=loaded.request.account,
            )
        elif decision is ReconciliationDecision.INCONCLUSIVE:
            completed_count = snapshot.reconciliation_attempt_count + 1
            exhausted = completed_count >= len(self.schedule)
            if not exhausted:
                next_check_at = now + self.schedule[completed_count]

        return self.state_machine.reconcile(
            request_id,
            expected_reconciliation_count=snapshot.reconciliation_attempt_count,
            decision=decision,
            worker_id=worker_id,
            now=now,
            next_check_at=next_check_at,
            exhausted=exhausted,
            lease_seconds=self.redispatch_lease_seconds,
            safe_outcome=safe_outcome,
            result_aliases=aliases,
        )

    def _snapshot(self, request_id: str) -> _AttemptSnapshot:
        with self.state_machine.database.read() as connection:
            row = connection.execute(
                """
                SELECT attempt.*
                FROM execution_attempts AS attempt
                JOIN approval_requests AS request
                  ON request.request_id = attempt.request_id
                 AND request.current_version = attempt.version
                 AND request.current_payload_hash = attempt.payload_hash
                WHERE attempt.request_id = ?
                  AND request.state = 'outcome_unknown'
                  AND attempt.phase = 'outcome_unknown'
                """,
                (request_id,),
            ).fetchone()
        if row is None:
            raise ReconciliationRejected("request has no reconcilable unknown outcome")
        started_at = row["redispatch_started_at"] or row["dispatch_started_at"] or row["claimed_at"]
        return _AttemptSnapshot(
            request_id=row["request_id"],
            version=row["version"],
            payload_hash=row["payload_hash"],
            attempt_id=row["attempt_id"],
            fencing_token=row["fencing_token"],
            worker_generation=row["worker_generation"],
            downstream_idempotency_key=row["downstream_idempotency_key"],
            reconciliation_attempt_count=row["reconciliation_attempt_count"],
            reconciliation_next_at=row["reconciliation_next_at"],
            started_at=started_at,
            safe_completion=_safe_completion(row["safe_completion_json"]),
            failure_reason=row["failure_reason"],
        )


def _safe_completion(value: object) -> Mapping[str, str | int | bool | None]:
    if not isinstance(value, str):
        return MappingProxyType({})
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return MappingProxyType({})
    if not isinstance(parsed, dict) or any(
        not isinstance(key, str) or (item is not None and not isinstance(item, (str, int, bool)))
        for key, item in parsed.items()
    ):
        return MappingProxyType({})
    return MappingProxyType(cast(dict[str, str | int | bool | None], parsed))


def _state_decision(value: Reconciliation) -> ReconciliationDecision:
    return {
        Reconciliation.CONFIRMED_EFFECT: ReconciliationDecision.CONFIRMED_EFFECT,
        Reconciliation.CONFIRMED_NO_EFFECT: ReconciliationDecision.CONFIRMED_NO_EFFECT,
        Reconciliation.INCONCLUSIVE: ReconciliationDecision.INCONCLUSIVE,
    }[value]
