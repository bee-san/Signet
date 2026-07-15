"""Fail-closed queue and reviewed per-tool admission limits."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from signet.config import Settings

_MAX_QUEUE_LIMIT = 100_000
_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
_MAX_REQUESTS_PER_MINUTE = 10_000
_DEFAULT_ORIGIN_PENDING_LIMIT = 100
_DEFAULT_TOOL_PENDING_LIMIT = 250
_SUPPORTED_TOOL_LIMITS = frozenset({"payload_bytes", "requests_per_minute", "pending_requests"})


@dataclass(frozen=True, slots=True)
class QueueAdmissionLimits:
    """Process-wide queue limits applied to every durable enqueue."""

    queue_limit: int = 1_000
    origin_pending_limit: int = _DEFAULT_ORIGIN_PENDING_LIMIT
    tool_pending_limit: int = _DEFAULT_TOOL_PENDING_LIMIT
    maximum_payload_bytes: int = 16 * 1024 * 1024
    minimum_free_bytes: int = 100 * 1024 * 1024
    write_reserve_bytes: int = 64 * 1024
    enqueue_expiry_sweep_limit: int = 100

    def __post_init__(self) -> None:
        bounded_positive = (
            self.queue_limit,
            self.origin_pending_limit,
            self.tool_pending_limit,
            self.maximum_payload_bytes,
            self.write_reserve_bytes,
            self.enqueue_expiry_sweep_limit,
        )
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in bounded_positive
        ):
            raise ValueError("queue admission limits must be positive integers")
        if (
            self.queue_limit > _MAX_QUEUE_LIMIT
            or self.origin_pending_limit > _MAX_QUEUE_LIMIT
            or self.tool_pending_limit > _MAX_QUEUE_LIMIT
            or self.maximum_payload_bytes > _MAX_PAYLOAD_BYTES
            or self.write_reserve_bytes > _MAX_PAYLOAD_BYTES
            or self.enqueue_expiry_sweep_limit > 1_000
        ):
            raise ValueError("queue admission limits exceed supported bounds")
        if (
            not isinstance(self.minimum_free_bytes, int)
            or isinstance(self.minimum_free_bytes, bool)
            or self.minimum_free_bytes < 0
            or self.minimum_free_bytes > 2**63 - 1
        ):
            raise ValueError("minimum free-space headroom is invalid")

    @classmethod
    def from_settings(cls, settings: Settings) -> QueueAdmissionLimits:
        """Bind the public runtime queue settings to enforceable limits."""

        if not isinstance(settings, Settings):
            raise TypeError("queue admission requires Signet settings")
        return cls(
            queue_limit=settings.queue_limit,
            origin_pending_limit=min(settings.queue_limit, _DEFAULT_ORIGIN_PENDING_LIMIT),
            tool_pending_limit=min(settings.queue_limit, _DEFAULT_TOOL_PENDING_LIMIT),
            minimum_free_bytes=settings.minimum_free_bytes,
        )


@dataclass(frozen=True, slots=True)
class ReviewedToolLimits:
    """Exact policy limits supplied by the reviewed gateway tool policy."""

    payload_bytes: int | None = None
    requests_per_minute: int | None = None
    pending_requests: int | None = None

    def __post_init__(self) -> None:
        values_and_bounds = (
            (self.payload_bytes, _MAX_PAYLOAD_BYTES),
            (self.requests_per_minute, _MAX_REQUESTS_PER_MINUTE),
            (self.pending_requests, _MAX_QUEUE_LIMIT),
        )
        if any(
            value is not None
            and (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
                or value > maximum
            )
            for value, maximum in values_and_bounds
        ):
            raise ValueError("reviewed tool limits are outside supported bounds")

    @classmethod
    def from_policy(cls, limits: Mapping[str, int]) -> ReviewedToolLimits:
        """Parse exact supported keys, rejecting silent policy no-ops."""

        if not isinstance(limits, Mapping):
            raise TypeError("reviewed tool limits must be a mapping")
        unknown = set(limits) - _SUPPORTED_TOOL_LIMITS
        if unknown:
            raise ValueError("reviewed tool policy contains unsupported admission limits")
        return cls(
            payload_bytes=limits.get("payload_bytes"),
            requests_per_minute=limits.get("requests_per_minute"),
            pending_requests=limits.get("pending_requests"),
        )
