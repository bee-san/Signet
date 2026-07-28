"""Transactional browser-notification intent and restart-safe delivery."""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from signet.async_support import run_sync_non_abandoning as _run_sync
from signet.db import Database
from signet.notifications import NotificationDispatcher, NotificationKind, PushMessage

_SAFE_ERROR_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.\-/]{0,511}$")
_EXPIRY_SCAN_PAGE_SIZE = 256
_EXPIRY_DEDUPE_V2_PREFIX = "approaching_expiry:v2:"


def _expiry_dedupe_key(user_id: str, request_id: str, version: int) -> str:
    digest = hashlib.sha256()
    for component in (user_id, request_id, str(version)):
        encoded = component.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return f"{_EXPIRY_DEDUPE_V2_PREFIX}{digest.hexdigest()}:{version}"


class NotificationOutboxError(RuntimeError):
    """Stored notification state is invalid or a claim was lost."""


@dataclass(frozen=True, slots=True)
class NotificationIntent:
    outbox_id: str
    dedupe_key: str
    user_id: str
    message: PushMessage
    request_id: str | None
    created_at: int
    available_at: int
    attempts: int
    claim_token: str


@dataclass(frozen=True, slots=True)
class OutboxRunReport:
    claimed: int
    delivered: int
    deferred: int


def enqueue_notification(
    connection: Any,
    *,
    dedupe_key: str,
    user_id: str,
    message: PushMessage,
    created_at: int,
    request_id: str | None = None,
    available_at: int | None = None,
) -> bool:
    """Insert one intent using the caller's existing SQLite transaction."""

    _validate_identity(dedupe_key, "notification dedupe key")
    _validate_user_id(user_id)
    if request_id is not None:
        _validate_identity(request_id, "notification request ID")
    if not isinstance(created_at, int) or isinstance(created_at, bool) or created_at < 0:
        raise ValueError("notification creation time is invalid")
    due = created_at if available_at is None else available_at
    if not isinstance(due, int) or isinstance(due, bool) or due < created_at:
        raise ValueError("notification availability time is invalid")

    inserted = connection.execute(
        """
        INSERT INTO notification_outbox(
            outbox_id, dedupe_key, user_id, kind, request_id,
            service, action, count, created_at, available_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(dedupe_key) DO NOTHING
        """,
        (
            f"notify_{secrets.token_urlsafe(18)}",
            dedupe_key,
            user_id,
            message.kind.value,
            request_id,
            message.service,
            message.action,
            message.count,
            created_at,
            due,
        ),
    ).rowcount
    return int(inserted) == 1


class SQLiteNotificationOutbox:
    """Claim and settle notification intents with short SQLite transactions."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def enqueue(
        self,
        *,
        dedupe_key: str,
        user_id: str,
        message: PushMessage,
        created_at: int,
        request_id: str | None = None,
        available_at: int | None = None,
    ) -> bool:
        with self.database.transaction() as connection:
            return enqueue_notification(
                connection,
                dedupe_key=dedupe_key,
                user_id=user_id,
                message=message,
                created_at=created_at,
                request_id=request_id,
                available_at=available_at,
            )

    def claim_due(
        self,
        *,
        worker_id: str,
        now: int,
        lease_seconds: int = 60,
        limit: int = 100,
    ) -> tuple[NotificationIntent, ...]:
        _validate_identity(worker_id, "notification worker ID")
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise ValueError("notification claim time is invalid")
        if lease_seconds <= 0 or lease_seconds > 24 * 60 * 60:
            raise ValueError("notification claim lease is invalid")
        if limit <= 0 or limit > 1_000:
            raise ValueError("notification claim limit is invalid")

        claimed: list[NotificationIntent] = []
        stale_before = now - lease_seconds
        with self.database.transaction() as connection:
            rows = connection.execute(
                """
                SELECT * FROM notification_outbox
                WHERE delivered_at IS NULL AND available_at <= ?
                  AND (claim_token IS NULL OR claimed_at <= ?)
                ORDER BY available_at, created_at, outbox_id
                LIMIT ?
                """,
                (now, stale_before, limit),
            ).fetchall()
            for row in rows:
                claim_token = secrets.token_urlsafe(24)
                updated = connection.execute(
                    """
                    UPDATE notification_outbox
                    SET claim_token = ?, claim_owner = ?, claimed_at = ?,
                        attempts = attempts + 1, last_error = NULL
                    WHERE outbox_id = ? AND delivered_at IS NULL
                      AND (claim_token IS NULL OR claimed_at <= ?)
                    """,
                    (claim_token, worker_id, now, row["outbox_id"], stale_before),
                ).rowcount
                if updated != 1:
                    continue
                values = dict(row)
                values.update(
                    {
                        "claim_token": claim_token,
                        "claim_owner": worker_id,
                        "claimed_at": now,
                        "attempts": int(row["attempts"]) + 1,
                    }
                )
                claimed.append(_intent(values))
        return tuple(claimed)

    def delivered_subscription_ids(self, outbox_id: str) -> frozenset[str]:
        _validate_identity(outbox_id, "notification outbox ID")
        with self.database.read() as connection:
            rows = connection.execute(
                """
                SELECT subscription_id FROM notification_outbox_deliveries
                WHERE outbox_id = ?
                """,
                (outbox_id,),
            ).fetchall()
        return frozenset(str(row["subscription_id"]) for row in rows)

    def mark_delivered(
        self,
        intent: NotificationIntent,
        *,
        now: int,
        delivered_subscription_ids: tuple[str, ...] = (),
    ) -> bool:
        if now < intent.created_at:
            raise ValueError("notification delivery time is invalid")
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE notification_outbox
                SET delivered_at = ?, claim_token = NULL, claim_owner = NULL,
                    claimed_at = NULL, last_error = NULL
                WHERE outbox_id = ? AND claim_token = ? AND delivered_at IS NULL
                """,
                (now, intent.outbox_id, intent.claim_token),
            ).rowcount
            if updated == 1:
                self._record_deliveries(
                    connection,
                    intent,
                    delivered_subscription_ids,
                    now=now,
                )
        return int(updated) == 1

    def defer(
        self,
        intent: NotificationIntent,
        *,
        now: int,
        error_code: str,
        retry_delay: int,
        delivered_subscription_ids: tuple[str, ...] = (),
    ) -> bool:
        if _SAFE_ERROR_RE.fullmatch(error_code) is None:
            raise ValueError("notification failure requires a safe error code")
        if retry_delay <= 0 or retry_delay > 24 * 60 * 60:
            raise ValueError("notification retry delay is invalid")
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE notification_outbox
                SET available_at = ?, claim_token = NULL, claim_owner = NULL,
                    claimed_at = NULL, last_error = ?
                WHERE outbox_id = ? AND claim_token = ? AND delivered_at IS NULL
                """,
                (
                    now + retry_delay,
                    error_code,
                    intent.outbox_id,
                    intent.claim_token,
                ),
            ).rowcount
            if updated == 1:
                self._record_deliveries(
                    connection,
                    intent,
                    delivered_subscription_ids,
                    now=now,
                )
        return int(updated) == 1

    @staticmethod
    def _record_deliveries(
        connection: Any,
        intent: NotificationIntent,
        subscription_ids: tuple[str, ...],
        *,
        now: int,
    ) -> None:
        if len(set(subscription_ids)) != len(subscription_ids) or any(
            not identifier or len(identifier) > 256 for identifier in subscription_ids
        ):
            raise ValueError("notification delivery identifiers are invalid")
        for subscription_id in subscription_ids:
            connection.execute(
                """
                INSERT INTO notification_outbox_deliveries(
                    outbox_id, subscription_id, delivered_at
                ) VALUES (?, ?, ?)
                ON CONFLICT(outbox_id, subscription_id) DO NOTHING
                """,
                (intent.outbox_id, subscription_id, now),
            )

    def schedule_approaching_expiry(
        self,
        *,
        user_id: str,
        now: int,
        horizon_seconds: int = 24 * 60 * 60,
        limit: int = 1_000,
    ) -> int:
        _validate_user_id(user_id)
        if horizon_seconds <= 0 or horizon_seconds > 7 * 24 * 60 * 60:
            raise ValueError("expiry notification horizon is invalid")
        if limit <= 0 or limit > 10_000:
            raise ValueError("expiry notification limit is invalid")
        inserted = 0
        legacy_prefix = "approaching_expiry:"
        previous_user_prefix = f"approaching_expiry:{hashlib.sha256(user_id.encode()).hexdigest()}:"
        cursor_expires_at = now
        cursor_request_id = ""
        with self.database.transaction() as connection:
            while inserted < limit:
                rows = connection.execute(
                    """
                    SELECT request.request_id, request.downstream_alias,
                           request.tool_name, request.current_version,
                           request.expires_at
                    FROM approval_requests AS request
                    WHERE request.state = 'pending_approval'
                      AND request.expires_at > ? AND request.expires_at <= ?
                      AND (
                          request.expires_at > ?
                          OR (
                              request.expires_at = ? AND request.request_id > ?
                          )
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM notification_outbox AS outbox
                          WHERE outbox.user_id = ?
                            AND outbox.kind = 'approaching_expiry'
                            AND outbox.request_id = request.request_id
                            AND (
                              outbox.dedupe_key =
                                  ? || request.request_id || ':' || request.current_version
                              OR outbox.dedupe_key =
                                  ? || request.request_id || ':' || request.current_version
                              OR outbox.dedupe_key LIKE
                                  ? || '%' || ':' || request.current_version
                          )
                      )
                    ORDER BY request.expires_at, request.request_id LIMIT ?
                    """,
                    (
                        now,
                        now + horizon_seconds,
                        cursor_expires_at,
                        cursor_expires_at,
                        cursor_request_id,
                        user_id,
                        legacy_prefix,
                        previous_user_prefix,
                        _EXPIRY_DEDUPE_V2_PREFIX,
                        _EXPIRY_SCAN_PAGE_SIZE,
                    ),
                ).fetchall()
                if not rows:
                    break
                for row in rows:
                    inserted += int(
                        enqueue_notification(
                            connection,
                            dedupe_key=_expiry_dedupe_key(
                                user_id,
                                str(row["request_id"]),
                                int(row["current_version"]),
                            ),
                            user_id=user_id,
                            message=PushMessage(
                                NotificationKind.APPROACHING_EXPIRY,
                                service=row["downstream_alias"],
                                action=row["tool_name"],
                            ),
                            request_id=row["request_id"],
                            created_at=now,
                        )
                    )
                    if inserted >= limit:
                        break
                cursor_expires_at = int(rows[-1]["expires_at"])
                cursor_request_id = str(rows[-1]["request_id"])
        return inserted

    def schedule_daily_digest(self, *, user_id: str, now: int) -> bool:
        _validate_user_id(user_id)
        day = datetime.fromtimestamp(now, tz=UTC).date().isoformat()
        with self.database.transaction() as connection:
            count = int(
                connection.execute(
                    """
                    SELECT count(*) FROM approval_requests
                    WHERE state = 'pending_approval' AND expires_at > ?
                    """,
                    (now,),
                ).fetchone()[0]
            )
            return enqueue_notification(
                connection,
                dedupe_key=(f"daily_digest:{hashlib.sha256(user_id.encode()).hexdigest()}:{day}"),
                user_id=user_id,
                message=PushMessage(NotificationKind.DAILY_DIGEST, count=count),
                created_at=now,
            )


class NotificationOutboxWorker:
    """Deliver a bounded claimed batch without coupling push to state commits."""

    def __init__(
        self,
        outbox: SQLiteNotificationOutbox,
        dispatcher: NotificationDispatcher,
        *,
        worker_id: str,
        retry_base_seconds: int = 30,
        retry_max_seconds: int = 60 * 60,
    ) -> None:
        _validate_identity(worker_id, "notification worker ID")
        if (
            retry_base_seconds <= 0
            or retry_max_seconds < retry_base_seconds
            or retry_max_seconds > 24 * 60 * 60
        ):
            raise ValueError("notification retry schedule is invalid")
        self.outbox = outbox
        self.dispatcher = dispatcher
        self.worker_id = worker_id
        self.retry_base_seconds = retry_base_seconds
        self.retry_max_seconds = retry_max_seconds

    async def run_due(self, *, now: int, limit: int = 100) -> OutboxRunReport:
        intents = await _run_sync(
            self.outbox.claim_due,
            worker_id=self.worker_id,
            now=now,
            limit=limit,
        )
        delivered = 0
        deferred = 0
        for intent in intents:
            try:
                delivered_subscription_ids = await _run_sync(
                    self.outbox.delivered_subscription_ids,
                    intent.outbox_id,
                )
                report = await self.dispatcher.notify(
                    intent.user_id,
                    intent.message,
                    now=now,
                    skip_subscription_ids=delivered_subscription_ids,
                )
            except asyncio.CancelledError:
                await _run_sync(
                    self.outbox.defer,
                    intent,
                    now=now,
                    error_code="worker_cancelled",
                    retry_delay=self._retry_delay(intent.attempts),
                )
                raise
            except Exception:
                await _run_sync(
                    self.outbox.defer,
                    intent,
                    now=now,
                    error_code="notification_dispatch_failed",
                    retry_delay=self._retry_delay(intent.attempts),
                )
                deferred += 1
            else:
                if report.failed or report.deferred:
                    deferred_intent = await _run_sync(
                        self.outbox.defer,
                        intent,
                        now=now,
                        error_code=(
                            "push_transport_unavailable"
                            if report.deferred and not report.failed
                            else "push_delivery_incomplete"
                        ),
                        retry_delay=self._retry_delay(intent.attempts),
                        delivered_subscription_ids=report.delivered_subscription_ids,
                    )
                    if not deferred_intent:
                        raise NotificationOutboxError("notification delivery claim was lost")
                    deferred += 1
                else:
                    marked_delivered = await _run_sync(
                        self.outbox.mark_delivered,
                        intent,
                        now=now,
                        delivered_subscription_ids=report.delivered_subscription_ids,
                    )
                    if not marked_delivered:
                        raise NotificationOutboxError("notification delivery claim was lost")
                    delivered += 1
        return OutboxRunReport(
            claimed=len(intents),
            delivered=delivered,
            deferred=deferred,
        )

    def _retry_delay(self, attempts: int) -> int:
        exponent = max(0, min(attempts - 1, 16))
        return min(self.retry_max_seconds, self.retry_base_seconds * (1 << exponent))


def _intent(row: dict[str, Any]) -> NotificationIntent:
    try:
        kind = NotificationKind(row["kind"])
        message = PushMessage(
            kind,
            service=row["service"],
            action=row["action"],
            count=row["count"],
        )
        claim_token = row["claim_token"]
        if not isinstance(claim_token, str) or not claim_token:
            raise ValueError
        return NotificationIntent(
            outbox_id=row["outbox_id"],
            dedupe_key=row["dedupe_key"],
            user_id=row["user_id"],
            message=message,
            request_id=row["request_id"],
            created_at=row["created_at"],
            available_at=row["available_at"],
            attempts=row["attempts"],
            claim_token=claim_token,
        )
    except (KeyError, TypeError, ValueError):
        raise NotificationOutboxError("stored notification intent is invalid") from None


def _validate_identity(value: str, label: str) -> None:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")


def _validate_user_id(user_id: str) -> None:
    if (
        not isinstance(user_id, str)
        or not user_id
        or len(user_id.encode("utf-8")) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in user_id)
    ):
        raise ValueError("notification user ID is invalid")
