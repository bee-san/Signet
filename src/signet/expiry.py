"""Bounded periodic expiry maintenance for pending approval requests."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass

from signet.state_machine import ApprovalStateMachine


@dataclass(frozen=True, slots=True)
class ExpirySweepReport:
    expired: int
    batch_limit: int
    batch_full: bool


class ExpirySweeper:
    """Run fixed-size expiry batches without retaining request identifiers."""

    def __init__(
        self,
        state_machine: ApprovalStateMachine,
        *,
        batch_limit: int = 250,
        interval_seconds: float = 60.0,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(state_machine, ApprovalStateMachine):
            raise TypeError("expiry sweeper requires an approval state machine")
        if (
            not isinstance(batch_limit, int)
            or isinstance(batch_limit, bool)
            or batch_limit <= 0
            or batch_limit > 1_000
            or not isinstance(interval_seconds, int | float)
            or isinstance(interval_seconds, bool)
            or interval_seconds < 1
            or interval_seconds > 3_600
            or clock is not None
            and not callable(clock)
        ):
            raise ValueError("expiry sweeper limits are invalid")
        self._state_machine = state_machine
        self._batch_limit = batch_limit
        self._interval_seconds = float(interval_seconds)
        self._clock = clock or _unix_time

    def run_once(self) -> ExpirySweepReport:
        now = self._clock()
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise RuntimeError("expiry sweeper clock returned an invalid timestamp")
        expired = self._state_machine.sweep_expired(
            now=now,
            limit=self._batch_limit,
        )
        return ExpirySweepReport(
            expired=expired,
            batch_limit=self._batch_limit,
            batch_full=expired == self._batch_limit,
        )

    async def serve(self, stop: asyncio.Event) -> None:
        """Sweep once per interval until an owning lifespan requests shutdown."""

        if not isinstance(stop, asyncio.Event):
            raise TypeError("expiry sweeper stop signal must be an asyncio event")
        while not stop.is_set():
            await asyncio.to_thread(self.run_once)
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._interval_seconds)
            except TimeoutError:
                continue


def _unix_time() -> int:
    return int(time.time())
