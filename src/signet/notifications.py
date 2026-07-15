"""Privacy-safe browser push messages and best-effort delivery."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import urlsplit

from pywebpush import WebPushException, webpush  # type: ignore[import-untyped]

from signet.credential_broker import Secret
from signet.db import Database

_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-/]{0,63}$")
_CATEGORY_VALUES = frozenset(
    {
        "new_pending",
        "approaching_expiry",
        "mcp_approved",
        "outcome_unknown_entered",
        "outcome_unknown_resolved",
        "outcome_unknown_exhausted",
        "daily_digest",
    }
)


class NotificationKind(StrEnum):
    NEW_PENDING = "new_pending"
    APPROACHING_EXPIRY = "approaching_expiry"
    MCP_APPROVED = "mcp_approved"
    OUTCOME_UNKNOWN_ENTERED = "outcome_unknown_entered"
    OUTCOME_UNKNOWN_RESOLVED = "outcome_unknown_resolved"
    OUTCOME_UNKNOWN_EXHAUSTED = "outcome_unknown_exhausted"
    DAILY_DIGEST = "daily_digest"


@dataclass(frozen=True, slots=True)
class PushMessage:
    kind: NotificationKind
    service: str | None = None
    action: str | None = None
    count: int | None = None

    def __post_init__(self) -> None:
        if self.kind is NotificationKind.DAILY_DIGEST:
            if (
                self.count is None
                or self.count < 0
                or self.service is not None
                or self.action is not None
            ):
                raise ValueError("daily digest requires only a non-negative count")
            return
        if (
            self.service is None
            or self.action is None
            or not _LABEL_RE.fullmatch(self.service)
            or not _LABEL_RE.fullmatch(self.action)
            or self.count is not None
        ):
            raise ValueError("event notifications require bounded service and action labels")

    def payload(self) -> dict[str, str | int]:
        body_by_kind = {
            NotificationKind.NEW_PENDING: "New request waiting for approval",
            NotificationKind.APPROACHING_EXPIRY: "Request approaching expiry",
            NotificationKind.MCP_APPROVED: "Request approved via chat",
            NotificationKind.OUTCOME_UNKNOWN_ENTERED: "Delivery outcome needs attention",
            NotificationKind.OUTCOME_UNKNOWN_RESOLVED: "Unknown delivery outcome resolved",
            NotificationKind.OUTCOME_UNKNOWN_EXHAUSTED: "Delivery reconciliation exhausted",
        }
        payload: dict[str, str | int] = {
            "title": "Signet",
            "kind": self.kind.value,
            "tag": f"signet-{self.kind.value}",
            "url": "/",
        }
        if self.kind is NotificationKind.DAILY_DIGEST:
            if self.count is None:
                raise ValueError("daily digest count is unavailable")
            payload.update(
                {
                    "body": f"{self.count} requests waiting for approval",
                    "count": self.count,
                }
            )
        else:
            if self.service is None or self.action is None:
                raise ValueError("event notification labels are unavailable")
            payload.update(
                {
                    "body": body_by_kind[self.kind],
                    "service": self.service,
                    "action": self.action,
                }
            )
        return payload


@dataclass(frozen=True, slots=True, repr=False)
class PushSubscription:
    subscription_id: str
    user_id: str
    endpoint: str
    p256dh: str
    auth: str
    device_label: str
    categories: frozenset[NotificationKind]
    created_at: int
    failure_count: int = 0
    disabled_at: int | None = None

    def __repr__(self) -> str:
        return (
            "PushSubscription("
            f"subscription_id={self.subscription_id!r}, user_id={self.user_id!r}, "
            "endpoint=<redacted>, keys=<redacted>, "
            f"device_label={self.device_label!r}, failure_count={self.failure_count!r}, "
            f"disabled_at={self.disabled_at!r})"
        )


class PushRepository(Protocol):
    def save(self, subscription: PushSubscription) -> None: ...

    def active_for(self, user_id: str, kind: NotificationKind) -> tuple[PushSubscription, ...]: ...

    def mark_success(self, subscription_id: str, *, now: int) -> None: ...

    def mark_failure(self, subscription_id: str, *, now: int, disable_after: int) -> None: ...

    def unsubscribe(self, user_id: str, endpoint: str, *, now: int) -> bool: ...


class InMemoryPushRepository:
    def __init__(self) -> None:
        self._records: dict[str, PushSubscription] = {}
        self._lock = threading.Lock()

    def save(self, subscription: PushSubscription) -> None:
        _validate_subscription(subscription)
        with self._lock:
            existing_id = next(
                (
                    record.subscription_id
                    for record in self._records.values()
                    if record.endpoint == subscription.endpoint
                ),
                None,
            )
            if existing_id is not None and existing_id != subscription.subscription_id:
                del self._records[existing_id]
            self._records[subscription.subscription_id] = subscription

    def active_for(self, user_id: str, kind: NotificationKind) -> tuple[PushSubscription, ...]:
        with self._lock:
            return tuple(
                record
                for record in self._records.values()
                if record.user_id == user_id
                and record.disabled_at is None
                and (not record.categories or kind in record.categories)
            )

    def mark_success(self, subscription_id: str, *, now: int) -> None:
        del now
        with self._lock:
            record = self._records.get(subscription_id)
            if record is not None and record.disabled_at is None:
                self._records[subscription_id] = replace(record, failure_count=0)

    def mark_failure(self, subscription_id: str, *, now: int, disable_after: int) -> None:
        with self._lock:
            record = self._records.get(subscription_id)
            if record is None or record.disabled_at is not None:
                return
            failures = record.failure_count + 1
            self._records[subscription_id] = replace(
                record,
                failure_count=failures,
                disabled_at=now if failures >= disable_after else None,
            )

    def unsubscribe(self, user_id: str, endpoint: str, *, now: int) -> bool:
        with self._lock:
            for identifier, record in self._records.items():
                if record.user_id == user_id and record.endpoint == endpoint:
                    self._records[identifier] = replace(record, disabled_at=now)
                    return True
        return False

    def get(self, subscription_id: str) -> PushSubscription | None:
        with self._lock:
            return self._records.get(subscription_id)


class SQLitePushRepository:
    """Durable per-device subscription storage in the approval database."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def save(self, subscription: PushSubscription) -> None:
        _validate_subscription(subscription)
        categories_json = json.dumps(
            sorted(kind.value for kind in subscription.categories),
            separators=(",", ":"),
        )
        with self.database.transaction() as connection:
            existing = connection.execute(
                """
                SELECT subscription_id, user_id FROM push_subscriptions
                WHERE endpoint = ? OR subscription_id = ?
                """,
                (subscription.endpoint, subscription.subscription_id),
            ).fetchall()
            if any(row["user_id"] != subscription.user_id for row in existing):
                raise ValueError("push endpoint is already owned by another user")
            identifiers = {str(row["subscription_id"]) for row in existing}
            if len(identifiers) > 1:
                raise ValueError("push subscription ID and endpoint identify different devices")
            if existing:
                identifier = next(iter(identifiers))
                connection.execute(
                    """
                    UPDATE push_subscriptions
                    SET endpoint = ?, p256dh_key = ?, auth_key = ?,
                        device_label = ?, categories_json = ?, failure_count = 0,
                        disabled_at = NULL
                    WHERE subscription_id = ? AND user_id = ?
                    """,
                    (
                        subscription.endpoint,
                        subscription.p256dh.encode(),
                        subscription.auth.encode(),
                        subscription.device_label,
                        categories_json,
                        identifier,
                        subscription.user_id,
                    ),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO push_subscriptions(
                        subscription_id, user_id, endpoint, p256dh_key, auth_key,
                        device_label, categories_json, created_at, failure_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        subscription.subscription_id,
                        subscription.user_id,
                        subscription.endpoint,
                        subscription.p256dh.encode(),
                        subscription.auth.encode(),
                        subscription.device_label,
                        categories_json,
                        subscription.created_at,
                    ),
                )

    def active_for(self, user_id: str, kind: NotificationKind) -> tuple[PushSubscription, ...]:
        with self.database.read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM push_subscriptions
                WHERE user_id = ? AND disabled_at IS NULL
                ORDER BY created_at, subscription_id
                """,
                (user_id,),
            ).fetchall()
        records = tuple(self._record(row) for row in rows)
        return tuple(
            record for record in records if not record.categories or kind in record.categories
        )

    def mark_success(self, subscription_id: str, *, now: int) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                UPDATE push_subscriptions
                SET last_success_at = ?, failure_count = 0
                WHERE subscription_id = ? AND disabled_at IS NULL
                """,
                (now, subscription_id),
            )

    def mark_failure(self, subscription_id: str, *, now: int, disable_after: int) -> None:
        if disable_after < 1:
            raise ValueError("push disable threshold must be positive")
        with self.database.transaction() as connection:
            connection.execute(
                """
                UPDATE push_subscriptions
                SET failure_count = failure_count + 1,
                    disabled_at = CASE
                        WHEN failure_count + 1 >= ? THEN ? ELSE NULL
                    END
                WHERE subscription_id = ? AND disabled_at IS NULL
                """,
                (disable_after, now, subscription_id),
            )

    def unsubscribe(self, user_id: str, endpoint: str, *, now: int) -> bool:
        with self.database.transaction() as connection:
            updated = int(
                connection.execute(
                    """
                UPDATE push_subscriptions SET disabled_at = ?
                WHERE user_id = ? AND endpoint = ? AND disabled_at IS NULL
                """,
                    (now, user_id, endpoint),
                ).rowcount
            )
        return updated == 1

    @staticmethod
    def _record(row: Any) -> PushSubscription:
        try:
            raw_categories = json.loads(row["categories_json"])
            if not isinstance(raw_categories, list) or not all(
                isinstance(value, str) for value in raw_categories
            ):
                raise ValueError
            categories = frozenset(NotificationKind(value) for value in raw_categories)
            record = PushSubscription(
                subscription_id=row["subscription_id"],
                user_id=row["user_id"],
                endpoint=row["endpoint"],
                p256dh=bytes(row["p256dh_key"]).decode(),
                auth=bytes(row["auth_key"]).decode(),
                device_label=row["device_label"],
                categories=categories,
                created_at=row["created_at"],
                failure_count=row["failure_count"],
                disabled_at=row["disabled_at"],
            )
            _validate_subscription(record)
        except (UnicodeError, ValueError):
            raise ValueError("stored push subscription is invalid") from None
        return record


class PushTransport(Protocol):
    async def send(
        self,
        subscription: PushSubscription,
        payload: Mapping[str, str | int],
    ) -> None: ...


class WebPushTransport:
    """Production pywebpush transport with injected VAPID private material."""

    def __init__(self, vapid_private_key: Secret, *, subject: str) -> None:
        parsed = urlsplit(subject)
        if not (
            subject.startswith("mailto:")
            or (parsed.scheme == "https" and parsed.netloc and not parsed.username)
        ):
            raise ValueError("VAPID subject must be mailto: or an HTTPS URL")
        self._key = vapid_private_key
        self.subject = subject

    async def send(
        self,
        subscription: PushSubscription,
        payload: Mapping[str, str | int],
    ) -> None:
        serialized = json.dumps(dict(payload), ensure_ascii=False, separators=(",", ":"))

        def deliver() -> None:
            try:
                webpush(
                    subscription_info={
                        "endpoint": subscription.endpoint,
                        "keys": {"p256dh": subscription.p256dh, "auth": subscription.auth},
                    },
                    data=serialized,
                    vapid_private_key=self._key.reveal(),
                    vapid_claims={"sub": self.subject},
                    timeout=10,
                )
            except WebPushException as exc:
                raise PushDeliveryError("browser push delivery failed") from exc

        await asyncio.to_thread(deliver)

    def __repr__(self) -> str:
        return f"WebPushTransport(subject={self.subject!r}, vapid_private_key=<redacted>)"


class PushDeliveryError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class NotificationReport:
    attempted: int
    delivered: int
    failed: int
    attempted_subscription_ids: tuple[str, ...] = ()
    delivered_subscription_ids: tuple[str, ...] = ()
    failed_subscription_ids: tuple[str, ...] = ()


class NotificationDispatcher:
    """Deliver after state commits; per-device failures never escape this boundary."""

    def __init__(
        self,
        repository: PushRepository,
        transport: PushTransport,
        *,
        disable_after: int = 5,
    ) -> None:
        if disable_after < 1 or disable_after > 100:
            raise ValueError("push disable threshold must be between 1 and 100")
        self._repository = repository
        self._transport = transport
        self.disable_after = disable_after

    async def notify(
        self,
        user_id: str,
        message: PushMessage,
        *,
        now: int,
        skip_subscription_ids: frozenset[str] = frozenset(),
    ) -> NotificationReport:
        if any(not identifier or len(identifier) > 256 for identifier in skip_subscription_ids):
            raise ValueError("notification skip identifiers are invalid")
        subscriptions = tuple(
            subscription
            for subscription in self._repository.active_for(user_id, message.kind)
            if subscription.subscription_id not in skip_subscription_ids
        )
        payload = message.payload()
        delivered_ids: list[str] = []
        failed_ids: list[str] = []
        for subscription in subscriptions:
            try:
                await self._transport.send(subscription, payload)
            except Exception:
                failed_ids.append(subscription.subscription_id)
                self._repository.mark_failure(
                    subscription.subscription_id,
                    now=now,
                    disable_after=self.disable_after,
                )
            else:
                delivered_ids.append(subscription.subscription_id)
                self._repository.mark_success(subscription.subscription_id, now=now)
        return NotificationReport(
            attempted=len(subscriptions),
            delivered=len(delivered_ids),
            failed=len(failed_ids),
            attempted_subscription_ids=tuple(
                subscription.subscription_id for subscription in subscriptions
            ),
            delivered_subscription_ids=tuple(delivered_ids),
            failed_subscription_ids=tuple(failed_ids),
        )


def new_subscription(
    *,
    user_id: str,
    endpoint: str,
    p256dh: str,
    auth: str,
    device_label: str,
    categories: frozenset[NotificationKind] = frozenset(),
    created_at: int,
) -> PushSubscription:
    record = PushSubscription(
        subscription_id=f"push_{secrets.token_urlsafe(18)}",
        user_id=user_id,
        endpoint=endpoint,
        p256dh=p256dh,
        auth=auth,
        device_label=device_label,
        categories=categories,
        created_at=created_at,
    )
    _validate_subscription(record)
    return record


def _validate_subscription(subscription: PushSubscription) -> None:
    parsed = urlsplit(subscription.endpoint)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("invalid push subscription") from None
    if (
        not subscription.subscription_id
        or not subscription.user_id
        or len(subscription.user_id.encode("utf-8")) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in subscription.user_id)
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port is not None
        and not 1 <= port <= 65535
        or len(subscription.endpoint) > 4096
        or not subscription.device_label
        or len(subscription.device_label.encode("utf-8")) > 80
        or any(
            ord(character) < 32 or ord(character) == 127 for character in subscription.device_label
        )
        or subscription.failure_count < 0
        or any(
            not isinstance(kind, NotificationKind) or kind.value not in _CATEGORY_VALUES
            for kind in subscription.categories
        )
    ):
        raise ValueError("invalid push subscription")
    for value, expected_size in ((subscription.p256dh, 65), (subscription.auth, 16)):
        if not value or len(value) > 512:
            raise ValueError("invalid push subscription key")
        try:
            decoded = base64.b64decode(
                value + "=" * (-len(value) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, TypeError, UnicodeError):
            raise ValueError("invalid push subscription key") from None
        canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
        if canonical != value or len(decoded) != expected_size:
            raise ValueError("invalid push subscription key")
    if _decode_subscription_key(subscription.p256dh)[0] != 0x04:
        raise ValueError("invalid push subscription key")


def _decode_subscription_key(value: str) -> bytes:
    return base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_",
        validate=True,
    )
