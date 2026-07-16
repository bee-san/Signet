"""Cancellation-safe boundaries for synchronous work in async services."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from functools import partial
from typing import Any

import anyio


async def run_sync_non_abandoning[T](
    function: Callable[..., T],
    /,
    *args: Any,
    **kwargs: Any,
) -> T:
    """Run synchronous work off-loop and finish it before propagating cancellation."""

    operation = asyncio.create_task(
        anyio.to_thread.run_sync(
            partial(function, *args, **kwargs),
            abandon_on_cancel=False,
        )
    )
    cancellation: asyncio.CancelledError | None = None
    while not operation.done():
        try:
            await asyncio.shield(operation)
        except asyncio.CancelledError as exc:
            cancellation = cancellation or exc
        except BaseException:
            break
    if cancellation is not None:
        with suppress(BaseException):
            operation.result()
        raise cancellation
    return operation.result()
