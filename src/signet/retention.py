"""Durable, privacy-preserving retention jobs and consistent backup pins."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import Any, Protocol

from signet.db import Database
from signet.models import RequestState
from signet.retention_contract import (
    FAKE_UNKNOWN_PURGE_AUTHORIZED_ACTION,
    FAKE_UNKNOWN_PURGE_AUTHORIZED_DETAILS,
    FAKE_UNKNOWN_PURGE_COMPLETED_ACTION,
    fake_unknown_purge_job_key,
)
from signet.staging import StagingError, StagingStore

_MICROSECONDS = 1_000_000
_MAX_UNIX_SECONDS = 9_000_000_000_000
_ONE_DAY = 24 * 60 * 60
_DEFAULT_SCHEDULE_PAGE_SIZE = 256
_SAFE_ERROR_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAFE_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,255}$")
_REDACTED_ATTACHMENT_TEXT = "<redacted>"
_REDACTED_ATTACHMENT_MIME = "application/octet-stream"
_REDACTED_ATTACHMENT_SHA256 = "0" * 64

_NONTERMINAL_STATES = frozenset(
    {
        RequestState.RECEIVED,
        RequestState.VALIDATING,
        RequestState.PENDING_APPROVAL,
        RequestState.APPROVED,
        RequestState.EXECUTING,
    }
)
_PURGEABLE_STATES = frozenset(
    {
        RequestState.SUCCEEDED,
        RequestState.FAILED,
        RequestState.DENIED,
        RequestState.EXPIRED,
        RequestState.CANCELLED,
    }
)


class RetentionError(RuntimeError):
    """Retention configuration or durable state is invalid."""


class BackupPinConflict(RetentionError):
    """A backup could not pin a request while its purge was in progress."""


class RetentionMode(StrEnum):
    LOGICAL = "logical"
    ISOLATED_PER_REQUEST_KEY = "isolated_per_request_key"


class PurgeIntent(StrEnum):
    SENSITIVE_ROWS = "sensitive_rows"
    ATTACHMENTS = "attachments"
    ENCRYPTION_KEY = "encryption_key"


class KeyDestroyer(Protocol):
    """Idempotently destroy one isolated key and confirm the result."""

    def destroy(self, key_reference: str, *, idempotency_key: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class RetentionMatrix:
    """Explicit delays in seconds for every request state and data class."""

    attachment_delays: Mapping[RequestState, int | None]
    payload_delays: Mapping[RequestState, int | None]

    def __post_init__(self) -> None:
        attachments = _validated_delays(self.attachment_delays, label="attachment")
        payloads = _validated_delays(self.payload_delays, label="payload")
        if attachments[RequestState.SUCCEEDED] != 0:
            raise ValueError("succeeded attachments must purge immediately")
        if attachments[RequestState.DENIED] != 0:
            raise ValueError("denied attachments must purge immediately")
        if attachments[RequestState.EXPIRED] != _ONE_DAY:
            raise ValueError("expired attachments must retain for exactly 24 hours")
        if attachments[RequestState.CANCELLED] != _ONE_DAY:
            raise ValueError("cancelled attachments must retain for exactly 24 hours")
        failed_delay = attachments[RequestState.FAILED]
        if failed_delay is None or failed_delay < _ONE_DAY:
            raise ValueError("definite-failed attachments require a conservative delay")
        for state in _PURGEABLE_STATES:
            if payloads[state] is None:
                raise ValueError(f"payload retention for {state.value} must be explicit")
        object.__setattr__(self, "attachment_delays", MappingProxyType(attachments))
        object.__setattr__(self, "payload_delays", MappingProxyType(payloads))

    def delay(self, intent: PurgeIntent, state: RequestState) -> int | None:
        if intent is PurgeIntent.ATTACHMENTS:
            return self.attachment_delays[state]
        if intent is PurgeIntent.ENCRYPTION_KEY:
            attachment_delay = self.attachment_delays[state]
            payload_delay = self.payload_delays[state]
            if attachment_delay is None or payload_delay is None:
                return None
            return max(attachment_delay, payload_delay)
        return self.payload_delays[state]


@dataclass(frozen=True, slots=True)
class PurgeClaim:
    purge_job_id: str
    request_id: str
    intent: PurgeIntent
    claim_marker: int
    state: RequestState


@dataclass(frozen=True, slots=True)
class PurgeRunReport:
    scheduled: int
    claimed: int
    completed: int
    failed: int


@dataclass(frozen=True, slots=True)
class PurgeRetryStatus:
    """Safe operator guidance derived from incomplete purge job clocks."""

    reason: str
    retry_after: int


@dataclass(frozen=True, slots=True)
class BackupPinLease:
    group_id: str
    purge_job_ids: tuple[str, ...]
    request_ids: tuple[str, ...]


class BackupPins:
    """Serialize attachment snapshots against request-level purge claims."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def acquire(self, *, now: int) -> BackupPinLease:
        _validate_time(now, "backup pin time")
        group_id = secrets.token_urlsafe(18)
        job_ids: list[str] = []
        request_ids: list[str] = []
        with self.database.transaction() as connection:
            rows = connection.execute(
                """
                SELECT request_id FROM attachments
                WHERE storage_path IS NOT NULL AND purged_at IS NULL
                UNION
                SELECT request_id FROM payload_versions
                WHERE encrypted_payload IS NOT NULL AND purged_at IS NULL
                ORDER BY request_id
                """
            ).fetchall()
            request_ids = [str(row["request_id"]) for row in rows]
            if request_ids:
                conflict = connection.execute(
                    """
                    SELECT 1 FROM purge_jobs
                    WHERE request_id IN (SELECT value FROM json_each(?))
                      AND intent != 'backup_pin'
                      AND completed_at IS NULL
                      AND (
                          started_at IS NOT NULL
                          OR idempotency_key LIKE 'fake\\_unknown:%' ESCAPE '\\'
                      )
                    LIMIT 1
                    """,
                    (json.dumps(request_ids, separators=(",", ":")),),
                ).fetchone()
                if conflict is not None:
                    raise BackupPinConflict("attachment purge is already in progress")
            for request_id in request_ids:
                job_id = f"pin_{secrets.token_urlsafe(18)}"
                connection.execute(
                    """
                    INSERT INTO purge_jobs(
                        purge_job_id, request_id, intent, idempotency_key,
                        created_at, started_at
                    ) VALUES (?, ?, 'backup_pin', ?, ?, ?)
                    """,
                    (
                        job_id,
                        request_id,
                        f"backup_pin:{group_id}:{_digest(request_id)}",
                        now,
                        now,
                    ),
                )
                job_ids.append(job_id)
        return BackupPinLease(group_id, tuple(job_ids), tuple(request_ids))

    def release(self, lease: BackupPinLease, *, now: int) -> None:
        _validate_time(now, "backup pin release time")
        if not lease.purge_job_ids:
            return
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE purge_jobs SET completed_at = ?, last_error = NULL
                WHERE purge_job_id IN (SELECT value FROM json_each(?))
                  AND intent = 'backup_pin' AND completed_at IS NULL
                """,
                (now, json.dumps(lease.purge_job_ids, separators=(",", ":"))),
            ).rowcount
        if updated != len(lease.purge_job_ids):
            raise RetentionError("backup pin release was incomplete")

    @contextmanager
    def pinned(self, *, now: int) -> Iterator[BackupPinLease]:
        lease = self.acquire(now=now)
        try:
            yield lease
        finally:
            self.release(lease, now=max(now, _wall_time()))

    def release_abandoned(self, *, before: int, now: int) -> int:
        """Explicitly release pins after operators know no old backup is active."""

        _validate_time(before, "abandoned backup cutoff")
        _validate_time(now, "abandoned backup release time")
        if before > now:
            raise ValueError("abandoned backup cutoff cannot be in the future")
        with self.database.transaction() as connection:
            return int(
                connection.execute(
                    """
                    UPDATE purge_jobs SET completed_at = ?, last_error = NULL
                    WHERE intent = 'backup_pin' AND completed_at IS NULL
                      AND created_at <= ?
                    """,
                    (now, before),
                ).rowcount
            )

    @staticmethod
    def release_snapshot_pins(snapshot: Path, *, now: int) -> None:
        """Make copied pin rows inert because no live worker owns the snapshot."""

        _validate_time(now, "snapshot pin release time")
        connection = sqlite3.connect(str(snapshot), isolation_level=None)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE purge_jobs SET completed_at = ?, last_error = NULL
                WHERE intent = 'backup_pin' AND completed_at IS NULL
                """,
                (now,),
            )
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        descriptor = os.open(snapshot, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class RetentionManager:
    """Schedule, claim, and settle bounded purge work without deleting audit facts."""

    def __init__(
        self,
        database: Database,
        staging: StagingStore,
        *,
        matrix: RetentionMatrix,
        mode: RetentionMode = RetentionMode.LOGICAL,
        key_destroyer: KeyDestroyer | None = None,
        claim_lease_seconds: int = 5 * 60,
        retry_delay_seconds: int = 60,
        allow_fake_only_unknown_purge: bool = False,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        if claim_lease_seconds <= 0 or claim_lease_seconds > _ONE_DAY:
            raise ValueError("purge claim lease is invalid")
        if retry_delay_seconds <= 0 or retry_delay_seconds > _ONE_DAY:
            raise ValueError("purge retry delay is invalid")
        if not isinstance(matrix, RetentionMatrix):
            raise TypeError("retention matrix is invalid")
        if not isinstance(mode, RetentionMode):
            raise TypeError("retention mode is invalid")
        if mode is RetentionMode.LOGICAL and key_destroyer is not None:
            raise ValueError("logical retention must not receive a key destroyer")
        if mode is RetentionMode.ISOLATED_PER_REQUEST_KEY and key_destroyer is None:
            raise ValueError("isolated-key retention requires a key destroyer")
        if not isinstance(allow_fake_only_unknown_purge, bool):
            raise TypeError("fake-only unknown purge setting must be boolean")
        self.database = database
        self.staging = staging
        self.matrix = matrix
        self.mode = mode
        self.key_destroyer = key_destroyer
        self.claim_lease_seconds = claim_lease_seconds
        self.retry_delay_seconds = retry_delay_seconds
        self.allow_fake_only_unknown_purge = allow_fake_only_unknown_purge
        self._fault_injector = fault_injector
        self._schedule_cursor: str | None = None
        self._schedule_lock = Lock()

    def schedule(self, *, now: int, limit: int = _DEFAULT_SCHEDULE_PAGE_SIZE) -> int:
        _validate_time(now, "purge scheduling time")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0 or limit > 1_000:
            raise ValueError("purge scheduling page limit is invalid")
        inserted = 0
        with self._schedule_lock:
            with self.database.transaction() as connection:
                requests = self._schedule_page(
                    connection,
                    after_request_id=self._schedule_cursor,
                    limit=limit,
                )
                if not requests and self._schedule_cursor is not None:
                    requests = self._schedule_page(
                        connection,
                        after_request_id=None,
                        limit=limit,
                    )
                for request in requests:
                    try:
                        state = RequestState(request["state"])
                    except ValueError as exc:
                        raise RetentionError("stored request state is invalid") from exc
                    completed_at = request["completed_at"]
                    if state not in _PURGEABLE_STATES or not isinstance(completed_at, int):
                        continue
                    request_id = str(request["request_id"])
                    if bool(request["has_unpurged_attachments"]):
                        inserted += self._schedule_intent(
                            connection,
                            request_id=request_id,
                            intent=PurgeIntent.ATTACHMENTS,
                            due_at=completed_at
                            + self._required_delay(PurgeIntent.ATTACHMENTS, state),
                        )
                    if bool(request["has_sensitive_payload"]) or bool(
                        request["has_untombstoned_idempotency"]
                    ):
                        inserted += self._schedule_intent(
                            connection,
                            request_id=request_id,
                            intent=PurgeIntent.SENSITIVE_ROWS,
                            due_at=completed_at
                            + self._required_delay(PurgeIntent.SENSITIVE_ROWS, state),
                        )
                    if self.mode is RetentionMode.ISOLATED_PER_REQUEST_KEY and bool(
                        request["has_undestroyed_keys"]
                    ):
                        inserted += self._schedule_intent(
                            connection,
                            request_id=request_id,
                            intent=PurgeIntent.ENCRYPTION_KEY,
                            due_at=completed_at
                            + self._required_delay(PurgeIntent.ENCRYPTION_KEY, state),
                        )
            self._schedule_cursor = (
                str(requests[-1]["request_id"]) if len(requests) == limit else None
            )
        return inserted

    def authorize_fake_only_exhausted_unknown_purge(
        self,
        *,
        request_id: str,
        expected_version: int,
        expected_payload_hash: str,
        acknowledge_possible_external_effect: bool,
        now: int,
    ) -> int:
        """Authorize fake-data redaction for an exact exhausted unknown outcome.

        The request remains ``outcome_unknown`` after redaction. This operation must
        never be enabled by a live/provider-capable assembly.
        """

        if not self.allow_fake_only_unknown_purge:
            raise RetentionError("unknown-content purge is unavailable outside fake-only mode")
        _validate_fake_unknown_inputs(
            request_id=request_id,
            expected_version=expected_version,
            expected_payload_hash=expected_payload_hash,
            acknowledge_possible_external_effect=acknowledge_possible_external_effect,
            now=now,
        )
        scheduled = 0
        with self.database.transaction() as connection:
            row = connection.execute(
                """
                SELECT request.state, request.current_version,
                       request.current_payload_hash,
                       attempt.phase, attempt.reconciliation_next_at,
                       attempt.reconciliation_resolution,
                       attempt.reconciliation_exhausted_at,
                       attempt.reconciliation_notification_required
                FROM approval_requests AS request
                LEFT JOIN execution_attempts AS attempt
                  ON attempt.request_id = request.request_id
                 AND attempt.version = request.current_version
                 AND attempt.payload_hash = request.current_payload_hash
                WHERE request.request_id = ?
                """,
                (request_id,),
            ).fetchone()
            if row is None:
                raise RetentionError("fake-only purge request was not found")
            if (
                row["state"] != RequestState.OUTCOME_UNKNOWN.value
                or row["current_version"] != expected_version
                or row["current_payload_hash"] != expected_payload_hash
            ):
                raise RetentionError("fake-only purge revision is not the current unknown outcome")
            if (
                row["phase"] != RequestState.OUTCOME_UNKNOWN.value
                or row["reconciliation_next_at"] is not None
                or row["reconciliation_resolution"] != "exhausted"
                or not isinstance(row["reconciliation_exhausted_at"], int)
                or row["reconciliation_notification_required"] != 1
            ):
                raise RetentionError("fake-only purge requires exhausted reconciliation")
            if self._active_pin(connection, request_id):
                raise RetentionError("fake-only purge cannot start while a backup is active")

            existing_event = connection.execute(
                """
                SELECT 1 FROM request_events
                WHERE request_id = ? AND action = ? AND version = ?
                  AND payload_hash = ? AND safe_details_json = ?
                LIMIT 1
                """,
                (
                    request_id,
                    FAKE_UNKNOWN_PURGE_AUTHORIZED_ACTION,
                    expected_version,
                    expected_payload_hash,
                    FAKE_UNKNOWN_PURGE_AUTHORIZED_DETAILS,
                ),
            ).fetchone()
            authorization_preexisting = existing_event is not None
            if existing_event is None:
                connection.execute(
                    """
                    INSERT INTO request_events(
                        request_id, actor, action, occurred_at,
                        version, payload_hash, safe_details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request_id,
                        "fake:operator",
                        FAKE_UNKNOWN_PURGE_AUTHORIZED_ACTION,
                        now,
                        expected_version,
                        expected_payload_hash,
                        FAKE_UNKNOWN_PURGE_AUTHORIZED_DETAILS,
                    ),
                )
                updated = connection.execute(
                    """
                    UPDATE approval_requests SET revision = revision + 1
                    WHERE request_id = ? AND state = 'outcome_unknown'
                      AND current_version = ? AND current_payload_hash = ?
                    """,
                    (request_id, expected_version, expected_payload_hash),
                ).rowcount
                if updated != 1:
                    raise RetentionError("fake-only purge lost the current request revision")

            intents = [PurgeIntent.ATTACHMENTS, PurgeIntent.SENSITIVE_ROWS]
            if self.mode is RetentionMode.ISOLATED_PER_REQUEST_KEY:
                intents.append(PurgeIntent.ENCRYPTION_KEY)
            for intent in intents:
                scheduled += self._schedule_fake_unknown_intent(
                    connection,
                    request_id=request_id,
                    version=expected_version,
                    payload_hash=expected_payload_hash,
                    intent=intent,
                    now=now,
                    allow_existing=authorization_preexisting,
                )
        return scheduled

    def _schedule_page(
        self,
        connection: Any,
        *,
        after_request_id: str | None,
        limit: int,
    ) -> list[Any]:
        key_mode = int(self.mode is RetentionMode.ISOLATED_PER_REQUEST_KEY)
        rows: list[Any] = connection.execute(
            """
            SELECT
                request.request_id,
                request.state,
                request.completed_at,
                EXISTS (
                    SELECT 1 FROM payload_versions AS payload
                    WHERE payload.request_id = request.request_id
                      AND payload.encrypted_payload IS NOT NULL
                ) AS has_sensitive_payload,
                EXISTS (
                    SELECT 1 FROM idempotency_records AS idempotency
                    WHERE idempotency.request_id = request.request_id
                      AND idempotency.tombstoned_at IS NULL
                ) AS has_untombstoned_idempotency,
                EXISTS (
                    SELECT 1 FROM attachments AS attachment
                    WHERE attachment.request_id = request.request_id
                      AND attachment.storage_path IS NOT NULL
                      AND attachment.purged_at IS NULL
                ) AS has_unpurged_attachments,
                (? = 1 AND (
                    EXISTS (
                        SELECT 1 FROM payload_versions AS payload_key
                        WHERE payload_key.request_id = request.request_id
                          AND payload_key.encryption_key_ref IS NOT NULL
                          AND payload_key.key_destroyed_at IS NULL
                    ) OR EXISTS (
                        SELECT 1 FROM staged_objects AS staged_key
                        WHERE staged_key.consumed_request_id = request.request_id
                          AND staged_key.encryption_key_ref IS NOT NULL
                          AND staged_key.key_destroyed_at IS NULL
                    )
                )) AS has_undestroyed_keys
            FROM approval_requests AS request
            WHERE request.request_id > ?
            ORDER BY request.request_id
            LIMIT ?
            """,
            (key_mode, after_request_id or "", limit),
        ).fetchall()
        return rows

    def claim_due(self, *, now: int, request_id: str | None = None) -> PurgeClaim | None:
        _validate_time(now, "purge claim time")
        if request_id is not None and _SAFE_REQUEST_ID_RE.fullmatch(request_id) is None:
            raise ValueError("purge request ID is invalid")
        stale_before = max(0, now - self.claim_lease_seconds) * _MICROSECONDS
        with self.database.transaction() as connection:
            rows = connection.execute(
                """
                SELECT job.*, request.state,
                       request.current_version, request.current_payload_hash,
                       request.completed_at AS request_completed_at
                FROM purge_jobs AS job
                JOIN approval_requests AS request USING(request_id)
                WHERE job.intent != 'backup_pin' AND job.completed_at IS NULL
                  AND job.created_at <= ?
                  AND (job.started_at IS NULL OR job.started_at < ?)
                  AND (? IS NULL OR job.request_id = ?)
                ORDER BY job.created_at,
                         CASE job.intent
                             WHEN 'attachments' THEN 0
                             WHEN 'sensitive_rows' THEN 1
                             WHEN 'encryption_key' THEN 2
                             ELSE 3
                         END,
                         job.purge_job_id
                LIMIT 256
                """,
                (now, stale_before, request_id, request_id),
            ).fetchall()
            for row in rows:
                try:
                    intent = PurgeIntent(row["intent"])
                    state = RequestState(row["state"])
                except ValueError as exc:
                    raise RetentionError("stored purge job is invalid") from exc
                completed_at = row["request_completed_at"]
                fake_unknown = (
                    self.allow_fake_only_unknown_purge
                    and (state is RequestState.OUTCOME_UNKNOWN)
                    and (
                        self._fake_unknown_job_authorized(
                            connection,
                            request_id=str(row["request_id"]),
                            intent=intent,
                            idempotency_key=str(row["idempotency_key"]),
                        )
                    )
                )
                if not fake_unknown and (
                    state not in _PURGEABLE_STATES or not isinstance(completed_at, int)
                ):
                    continue
                if intent is PurgeIntent.ENCRYPTION_KEY and (
                    self.mode is not RetentionMode.ISOLATED_PER_REQUEST_KEY
                ):
                    continue
                if intent is PurgeIntent.ENCRYPTION_KEY and self._earlier_purge_incomplete(
                    connection,
                    request_id=str(row["request_id"]),
                    state=state,
                    version=int(row["current_version"]),
                    payload_hash=str(row["current_payload_hash"]),
                ):
                    continue
                if not fake_unknown:
                    delay = self.matrix.delay(intent, state)
                    if delay is None or completed_at + delay > now:
                        continue
                if self._active_pin(connection, str(row["request_id"])):
                    continue
                if self._active_purge_claim(
                    connection,
                    request_id=str(row["request_id"]),
                    stale_before=stale_before,
                    excluding_job_id=str(row["purge_job_id"]),
                ):
                    continue
                marker = now * _MICROSECONDS + secrets.randbelow(_MICROSECONDS)
                updated = connection.execute(
                    """
                    UPDATE purge_jobs SET started_at = ?, last_error = NULL
                    WHERE purge_job_id = ? AND completed_at IS NULL
                      AND (started_at IS NULL OR started_at < ?)
                      AND NOT EXISTS (
                          SELECT 1 FROM purge_jobs AS pin
                          WHERE pin.request_id = purge_jobs.request_id
                            AND pin.intent = 'backup_pin' AND pin.completed_at IS NULL
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM purge_jobs AS active
                          WHERE active.request_id = purge_jobs.request_id
                            AND active.purge_job_id != purge_jobs.purge_job_id
                            AND active.intent != 'backup_pin'
                            AND active.started_at IS NOT NULL
                            AND active.started_at >= ?
                            AND active.completed_at IS NULL
                      )
                    """,
                    (marker, row["purge_job_id"], stale_before, stale_before),
                ).rowcount
                if updated == 1:
                    return PurgeClaim(
                        purge_job_id=str(row["purge_job_id"]),
                        request_id=str(row["request_id"]),
                        intent=intent,
                        claim_marker=marker,
                        state=state,
                    )
        return None

    def process(self, claim: PurgeClaim, *, now: int) -> bool:
        _validate_time(now, "purge completion time")
        try:
            if claim.intent is PurgeIntent.ATTACHMENTS:
                self._purge_attachments(claim, now=now)
            elif claim.intent is PurgeIntent.SENSITIVE_ROWS:
                self._purge_sensitive_rows(claim, now=now)
            elif claim.intent is PurgeIntent.ENCRYPTION_KEY:
                self._destroy_isolated_key(claim, now=now)
            else:  # pragma: no cover - the enum is exhaustive
                raise _JobFailure("invalid_job")
        except _JobFailure as exc:
            self._record_failure(claim, now=now, error_code=exc.error_code)
            return False
        except Exception:
            self._record_failure(claim, now=now, error_code="worker_failure")
            return False
        return True

    def run_due(self, *, now: int, limit: int = 100) -> PurgeRunReport:
        _validate_time(now, "purge run time")
        if limit <= 0 or limit > 1_000:
            raise ValueError("purge batch limit is invalid")
        scheduled = self.schedule(now=now, limit=limit)
        claimed = completed = failed = 0
        for _ in range(limit):
            claim = self.claim_due(now=now)
            if claim is None:
                break
            claimed += 1
            if self.process(claim, now=now):
                completed += 1
            else:
                failed += 1
        return PurgeRunReport(scheduled, claimed, completed, failed)

    def pending_retry_status(
        self,
        *,
        idempotency_keys: tuple[str, ...],
        now: int,
    ) -> PurgeRetryStatus | None:
        """Return bounded guidance for an exact set of incomplete purge jobs."""

        _validate_time(now, "purge retry status time")
        if (
            not isinstance(idempotency_keys, tuple)
            or not idempotency_keys
            or len(idempotency_keys) > 16
            or any(
                not isinstance(key, str) or not key or len(key) > 1_024 for key in idempotency_keys
            )
        ):
            raise ValueError("purge retry status keys are invalid")
        with self.database.read() as connection:
            rows = connection.execute(
                """
                SELECT created_at, started_at, last_error
                FROM purge_jobs
                WHERE idempotency_key IN (SELECT value FROM json_each(?))
                  AND intent != 'backup_pin' AND completed_at IS NULL
                """,
                (json.dumps(idempotency_keys, separators=(",", ":")),),
            ).fetchall()
        if not rows:
            return None

        blockers: list[tuple[int, str]] = []
        for row in rows:
            started_at = row["started_at"]
            if isinstance(started_at, int):
                retry_at = started_at // _MICROSECONDS + self.claim_lease_seconds + 1
                reason = "claim_lease_active" if retry_at > now else "purge_incomplete"
            else:
                created_at = row["created_at"]
                retry_at = int(created_at) if isinstance(created_at, int) else now + 1
                last_error = row["last_error"]
                if isinstance(last_error, str) and _SAFE_ERROR_RE.fullmatch(last_error):
                    reason = last_error
                else:
                    reason = "retry_backoff" if retry_at > now else "purge_incomplete"
            blockers.append((retry_at, reason))

        retry_at, reason = max(blockers, key=lambda blocker: blocker[0])
        return PurgeRetryStatus(reason=reason, retry_after=max(1, retry_at - now))

    def _purge_attachments(self, claim: PurgeClaim, *, now: int) -> None:
        with self.database.transaction() as connection:
            self._ensure_claim(connection, claim)
            rows = connection.execute(
                """
                SELECT attachment_id, version, size_bytes, sha256, storage_path
                FROM attachments
                WHERE request_id = ? AND storage_path IS NOT NULL AND purged_at IS NULL
                ORDER BY version, attachment_id
                """,
                (claim.request_id,),
            ).fetchall()
        for row in rows:
            try:
                self.staging.purge_verified(
                    str(row["attachment_id"]),
                    expected_path=Path(str(row["storage_path"])),
                    expected_size=int(row["size_bytes"]),
                    expected_sha256=str(row["sha256"]),
                    purged_at=now,
                    missing_ok=True,
                )
            except (StagingError, ValueError) as exc:
                raise _JobFailure("attachment_verification_failed") from exc
            self._fault("attachment_unlinked")
            with self.database.transaction() as connection:
                self._ensure_claim(connection, claim)
                updated = connection.execute(
                    """
                    UPDATE attachments
                    SET filename = ?, mime_type = ?, size_bytes = 0, sha256 = ?,
                        storage_path = NULL, purged_at = ?
                    WHERE attachment_id = ? AND request_id = ? AND version = ?
                      AND size_bytes = ? AND sha256 = ? AND storage_path = ?
                      AND purged_at IS NULL
                    """,
                    (
                        _REDACTED_ATTACHMENT_TEXT,
                        _REDACTED_ATTACHMENT_MIME,
                        _REDACTED_ATTACHMENT_SHA256,
                        now,
                        row["attachment_id"],
                        claim.request_id,
                        row["version"],
                        row["size_bytes"],
                        row["sha256"],
                        row["storage_path"],
                    ),
                ).rowcount
                if updated != 1:
                    current = connection.execute(
                        """
                        SELECT purged_at FROM attachments
                        WHERE attachment_id = ? AND request_id = ? AND version = ?
                        """,
                        (row["attachment_id"], claim.request_id, row["version"]),
                    ).fetchone()
                    if current is None or current["purged_at"] is None:
                        raise _JobFailure("attachment_database_conflict")
                catalog_updated = connection.execute(
                    """
                    UPDATE staged_objects
                    SET adapter = ?, account = ?, filename = ?, declared_mime = ?,
                        detected_mime = ?, size_bytes = 0, sha256 = ?,
                        envelope_size = 1, envelope_sha256 = ?
                    WHERE attachment_id = ? AND consumed_request_id = ?
                      AND storage_path IS NULL AND purged_at IS NOT NULL
                    """,
                    (
                        _REDACTED_ATTACHMENT_TEXT,
                        _REDACTED_ATTACHMENT_TEXT,
                        _REDACTED_ATTACHMENT_TEXT,
                        _REDACTED_ATTACHMENT_MIME,
                        _REDACTED_ATTACHMENT_MIME,
                        _REDACTED_ATTACHMENT_SHA256,
                        _REDACTED_ATTACHMENT_SHA256,
                        row["attachment_id"],
                        claim.request_id,
                    ),
                ).rowcount
                if catalog_updated != 1:
                    raise _JobFailure("attachment_catalog_redaction_failed")
                connection.execute(
                    """
                    UPDATE attachment_metadata_privacy_maintenance SET pending = 1
                    WHERE singleton = 1
                    """
                )
        with self.database.transaction() as connection:
            self._ensure_claim(connection, claim)
            self._complete_claim(connection, claim, now=now)

    def _purge_sensitive_rows(self, claim: PurgeClaim, *, now: int) -> None:
        with self.database.transaction() as connection:
            self._ensure_claim(connection, claim)
            connection.execute(
                """
                UPDATE payload_versions
                SET encrypted_payload = NULL, purged_at = ?, purge_reason = ?
                WHERE request_id = ? AND encrypted_payload IS NOT NULL
                  AND purged_at IS NULL
                """,
                (now, self._purge_reason(claim), claim.request_id),
            )
            self._tombstone_idempotency(connection, claim.request_id, now=now)
            self._clear_fake_unknown_metadata(connection, claim)
            self._complete_claim(connection, claim, now=now)

    def _destroy_isolated_key(self, claim: PurgeClaim, *, now: int) -> None:
        if self.mode is not RetentionMode.ISOLATED_PER_REQUEST_KEY:
            raise _JobFailure("key_mode_mismatch")
        if self.key_destroyer is None:  # pragma: no cover - constructor enforces this
            raise _JobFailure("key_destroyer_unavailable")
        with self.database.transaction() as connection:
            self._ensure_claim(connection, claim)
            remaining_attachments = connection.execute(
                """
                SELECT 1 FROM staged_objects
                WHERE consumed_request_id = ? AND storage_path IS NOT NULL
                  AND purged_at IS NULL LIMIT 1
                """,
                (claim.request_id,),
            ).fetchone()
            if remaining_attachments is not None:
                raise _JobFailure("attachment_key_still_required")
            key_references = self._verified_isolated_references(connection, claim.request_id)
        for key_reference in key_references:
            try:
                confirmed = self.key_destroyer.destroy(
                    key_reference,
                    idempotency_key=f"destroy:{_digest(key_reference)}",
                )
            except Exception as exc:
                raise _JobFailure("key_destroy_failed") from exc
            if confirmed is not True:
                raise _JobFailure("key_destroy_unconfirmed")
            self._fault("key_destroy_confirmed")
        with self.database.transaction() as connection:
            self._ensure_claim(connection, claim)
            current_references = self._verified_isolated_references(connection, claim.request_id)
            if current_references != key_references:
                raise _JobFailure("key_reference_changed")
            connection.execute(
                """
                UPDATE payload_versions
                SET encrypted_payload = NULL, encryption_key_ref = NULL,
                    purged_at = COALESCE(purged_at, ?),
                    key_destroyed_at = COALESCE(key_destroyed_at, ?),
                    purge_reason = COALESCE(purge_reason, ?)
                WHERE request_id = ? AND key_destroyed_at IS NULL
                """,
                (
                    now,
                    now,
                    self._purge_reason(claim),
                    claim.request_id,
                ),
            )
            connection.execute(
                """
                UPDATE staged_objects
                SET encryption_key_ref = NULL,
                    key_destroyed_at = COALESCE(key_destroyed_at, ?)
                WHERE consumed_request_id = ? AND key_destroyed_at IS NULL
                  AND storage_path IS NULL AND purged_at IS NOT NULL
                """,
                (now, claim.request_id),
            )
            self._tombstone_idempotency(connection, claim.request_id, now=now)
            self._clear_fake_unknown_metadata(connection, claim)
            self._complete_claim(connection, claim, now=now)

    def _verified_isolated_references(self, connection: Any, request_id: str) -> tuple[str, ...]:
        rows = connection.execute(
            """
            SELECT encryption_key_ref FROM payload_versions
            WHERE request_id = ? AND key_destroyed_at IS NULL
            UNION ALL
            SELECT encryption_key_ref FROM staged_objects
            WHERE consumed_request_id = ? AND key_destroyed_at IS NULL
            """,
            (request_id, request_id),
        ).fetchall()
        if not rows:
            return ()
        references: set[str] = set()
        for row in rows:
            reference = row["encryption_key_ref"]
            if not isinstance(reference, str) or not reference:
                raise _JobFailure("key_reference_missing")
            references.add(reference)
        for reference in references:
            owners = connection.execute(
                """
                SELECT request_id FROM payload_versions
                WHERE encryption_key_ref = ?
                UNION
                SELECT COALESCE(consumed_request_id, '') AS request_id FROM staged_objects
                WHERE encryption_key_ref = ?
                """,
                (reference, reference),
            ).fetchall()
            if len(owners) != 1 or owners[0]["request_id"] != request_id:
                raise _JobFailure("key_reference_shared")
        return tuple(sorted(references))

    def _ensure_claim(self, connection: Any, claim: PurgeClaim) -> None:
        row = connection.execute(
            """
            SELECT job.started_at, job.completed_at AS job_completed_at,
                   job.idempotency_key, request.state,
                   request.completed_at AS request_completed_at
            FROM purge_jobs AS job
            JOIN approval_requests AS request USING(request_id)
            WHERE job.purge_job_id = ? AND job.request_id = ? AND job.intent = ?
            """,
            (claim.purge_job_id, claim.request_id, claim.intent.value),
        ).fetchone()
        if (
            row is None
            or row["started_at"] != claim.claim_marker
            or row["job_completed_at"] is not None
            or row["state"] != claim.state.value
            or self._active_pin(connection, claim.request_id)
        ):
            raise _JobFailure("claim_lost")
        request_completed_at = row["request_completed_at"]
        if claim.state in _PURGEABLE_STATES and isinstance(request_completed_at, int):
            return
        if (
            self.allow_fake_only_unknown_purge
            and claim.state is RequestState.OUTCOME_UNKNOWN
            and self._fake_unknown_job_authorized(
                connection,
                request_id=claim.request_id,
                intent=claim.intent,
                idempotency_key=str(row["idempotency_key"]),
            )
        ):
            return
        if not isinstance(request_completed_at, int) or claim.state not in _PURGEABLE_STATES:
            raise _JobFailure("state_not_purgeable")

    @staticmethod
    def _active_pin(connection: Any, request_id: str) -> bool:
        return (
            connection.execute(
                """
                SELECT 1 FROM purge_jobs
                WHERE request_id = ? AND intent = 'backup_pin'
                  AND completed_at IS NULL LIMIT 1
                """,
                (request_id,),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _active_purge_claim(
        connection: Any,
        *,
        request_id: str,
        stale_before: int,
        excluding_job_id: str,
    ) -> bool:
        return (
            connection.execute(
                """
                SELECT 1 FROM purge_jobs
                WHERE request_id = ? AND purge_job_id != ?
                  AND intent != 'backup_pin' AND started_at IS NOT NULL
                  AND started_at >= ? AND completed_at IS NULL
                LIMIT 1
                """,
                (request_id, excluding_job_id, stale_before),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _earlier_purge_incomplete(
        connection: Any,
        *,
        request_id: str,
        state: RequestState,
        version: int,
        payload_hash: str,
    ) -> bool:
        if state is RequestState.OUTCOME_UNKNOWN:
            keys = tuple(
                fake_unknown_purge_job_key(
                    request_id=request_id,
                    version=version,
                    payload_hash=payload_hash,
                    intent=intent.value,
                )
                for intent in (PurgeIntent.ATTACHMENTS, PurgeIntent.SENSITIVE_ROWS)
            )
        else:
            keys = tuple(
                f"retention:{intent.value}:{_digest(request_id)}"
                for intent in (PurgeIntent.ATTACHMENTS, PurgeIntent.SENSITIVE_ROWS)
            )
        return (
            connection.execute(
                """
                SELECT 1 FROM purge_jobs
                WHERE request_id = ? AND idempotency_key IN (?, ?)
                  AND completed_at IS NULL
                LIMIT 1
                """,
                (request_id, *keys),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _has_unpurged_attachments(connection: Any, request_id: str) -> bool:
        return (
            connection.execute(
                """
                SELECT 1 FROM attachments
                WHERE request_id = ? AND storage_path IS NOT NULL AND purged_at IS NULL
                LIMIT 1
                """,
                (request_id,),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _has_sensitive_rows(connection: Any, request_id: str) -> bool:
        payload = connection.execute(
            """
            SELECT 1 FROM payload_versions
            WHERE request_id = ? AND encrypted_payload IS NOT NULL LIMIT 1
            """,
            (request_id,),
        ).fetchone()
        tombstone = connection.execute(
            """
            SELECT 1 FROM idempotency_records
            WHERE request_id = ? AND tombstoned_at IS NULL LIMIT 1
            """,
            (request_id,),
        ).fetchone()
        return payload is not None or tombstone is not None

    @staticmethod
    def _has_undestroyed_keys(connection: Any, request_id: str) -> bool:
        return (
            connection.execute(
                """
                SELECT 1 FROM (
                    SELECT encryption_key_ref FROM payload_versions
                    WHERE request_id = ? AND key_destroyed_at IS NULL
                    UNION ALL
                    SELECT encryption_key_ref FROM staged_objects
                    WHERE consumed_request_id = ? AND key_destroyed_at IS NULL
                ) WHERE encryption_key_ref IS NOT NULL LIMIT 1
                """,
                (request_id, request_id),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _schedule_intent(
        connection: Any,
        *,
        request_id: str,
        intent: PurgeIntent,
        due_at: int,
    ) -> int:
        return int(
            connection.execute(
                """
                INSERT INTO purge_jobs(
                    purge_job_id, request_id, intent, idempotency_key, created_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(idempotency_key) DO NOTHING
                """,
                (
                    f"purge_{secrets.token_urlsafe(18)}",
                    request_id,
                    intent.value,
                    f"retention:{intent.value}:{_digest(request_id)}",
                    due_at,
                ),
            ).rowcount
        )

    @staticmethod
    def _schedule_fake_unknown_intent(
        connection: Any,
        *,
        request_id: str,
        version: int,
        payload_hash: str,
        intent: PurgeIntent,
        now: int,
        allow_existing: bool,
    ) -> int:
        idempotency_key = fake_unknown_purge_job_key(
            request_id=request_id,
            version=version,
            payload_hash=payload_hash,
            intent=intent.value,
        )
        inserted = int(
            connection.execute(
                """
                INSERT INTO purge_jobs(
                    purge_job_id, request_id, intent, idempotency_key, created_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(idempotency_key) DO NOTHING
                """,
                (
                    f"purge_{secrets.token_urlsafe(18)}",
                    request_id,
                    intent.value,
                    idempotency_key,
                    now,
                ),
            ).rowcount
        )
        if inserted == 0 and not allow_existing:
            raise RetentionError("fake-only purge job predates its authorization")
        row = connection.execute(
            """
            SELECT request_id, intent, started_at, completed_at
            FROM purge_jobs WHERE idempotency_key = ?
            """,
            (idempotency_key,),
        ).fetchone()
        if row is None or row["request_id"] != request_id or row["intent"] != intent.value:
            raise RetentionError("fake-only purge job identity conflicts with durable state")
        # An authorized replay must not erase a worker failure or bypass its backoff.
        return inserted

    @staticmethod
    def _fake_unknown_job_authorized(
        connection: Any,
        *,
        request_id: str,
        intent: PurgeIntent,
        idempotency_key: str,
    ) -> bool:
        row = connection.execute(
            """
            SELECT request.current_version, request.current_payload_hash,
                   attempt.phase, attempt.reconciliation_next_at,
                   attempt.reconciliation_resolution,
                   attempt.reconciliation_exhausted_at,
                   attempt.reconciliation_notification_required
            FROM approval_requests AS request
            JOIN execution_attempts AS attempt
              ON attempt.request_id = request.request_id
             AND attempt.version = request.current_version
             AND attempt.payload_hash = request.current_payload_hash
            WHERE request.request_id = ? AND request.state = 'outcome_unknown'
            """,
            (request_id,),
        ).fetchone()
        if row is None:
            return False
        version = row["current_version"]
        payload_hash = row["current_payload_hash"]
        if not isinstance(version, int) or not isinstance(payload_hash, str):
            return False
        if idempotency_key != fake_unknown_purge_job_key(
            request_id=request_id,
            version=version,
            payload_hash=payload_hash,
            intent=intent.value,
        ):
            return False
        if (
            row["phase"] != RequestState.OUTCOME_UNKNOWN.value
            or row["reconciliation_next_at"] is not None
            or row["reconciliation_resolution"] != "exhausted"
            or not isinstance(row["reconciliation_exhausted_at"], int)
            or row["reconciliation_notification_required"] != 1
        ):
            return False
        event = connection.execute(
            """
            SELECT 1 FROM request_events
            WHERE request_id = ? AND action = ? AND version = ?
              AND payload_hash = ? AND safe_details_json = ?
            LIMIT 1
            """,
            (
                request_id,
                FAKE_UNKNOWN_PURGE_AUTHORIZED_ACTION,
                version,
                payload_hash,
                FAKE_UNKNOWN_PURGE_AUTHORIZED_DETAILS,
            ),
        ).fetchone()
        return event is not None

    @staticmethod
    def _purge_reason(claim: PurgeClaim) -> str:
        if claim.state is RequestState.OUTCOME_UNKNOWN:
            return "fake_only_unknown_content"
        return f"retention_{claim.state.value}"

    @staticmethod
    def _clear_fake_unknown_metadata(connection: Any, claim: PurgeClaim) -> None:
        if claim.state is not RequestState.OUTCOME_UNKNOWN:
            return
        connection.execute(
            """
            UPDATE approval_requests SET safe_outcome_json = NULL
            WHERE request_id = ? AND state = 'outcome_unknown'
            """,
            (claim.request_id,),
        )
        connection.execute(
            """
            UPDATE execution_attempts SET safe_completion_json = NULL
            WHERE request_id = ? AND phase = 'outcome_unknown'
            """,
            (claim.request_id,),
        )

    def _required_delay(self, intent: PurgeIntent, state: RequestState) -> int:
        delay = self.matrix.delay(intent, state)
        if delay is None:
            raise RetentionError("protected request state cannot be scheduled for purge")
        return delay

    @staticmethod
    def _tombstone_idempotency(connection: Any, request_id: str, *, now: int) -> None:
        connection.execute(
            """
            UPDATE idempotency_records SET tombstoned_at = COALESCE(tombstoned_at, ?)
            WHERE request_id = ?
            """,
            (now, request_id),
        )

    def _complete_claim(self, connection: Any, claim: PurgeClaim, *, now: int) -> None:
        updated = connection.execute(
            """
            UPDATE purge_jobs SET completed_at = ?, last_error = NULL
            WHERE purge_job_id = ? AND started_at = ? AND completed_at IS NULL
            """,
            (now, claim.purge_job_id, claim.claim_marker),
        ).rowcount
        if updated != 1:
            raise _JobFailure("claim_lost")
        if claim.state is RequestState.OUTCOME_UNKNOWN:
            self._complete_fake_unknown_authorization(
                connection,
                request_id=claim.request_id,
                now=now,
            )

    @staticmethod
    def _complete_fake_unknown_authorization(
        connection: Any,
        *,
        request_id: str,
        now: int,
    ) -> None:
        request = connection.execute(
            """
            SELECT current_version, current_payload_hash
            FROM approval_requests
            WHERE request_id = ? AND state = 'outcome_unknown'
            """,
            (request_id,),
        ).fetchone()
        if request is None:
            raise _JobFailure("state_not_purgeable")
        version = int(request["current_version"])
        payload_hash = str(request["current_payload_hash"])
        required: list[tuple[PurgeIntent, str]] = []
        for intent in (PurgeIntent.ATTACHMENTS, PurgeIntent.SENSITIVE_ROWS):
            required.append(
                (
                    intent,
                    fake_unknown_purge_job_key(
                        request_id=request_id,
                        version=version,
                        payload_hash=payload_hash,
                        intent=intent.value,
                    ),
                )
            )
        encryption_key = fake_unknown_purge_job_key(
            request_id=request_id,
            version=version,
            payload_hash=payload_hash,
            intent=PurgeIntent.ENCRYPTION_KEY.value,
        )
        encryption_job = connection.execute(
            "SELECT completed_at FROM purge_jobs WHERE idempotency_key = ?",
            (encryption_key,),
        ).fetchone()
        if encryption_job is not None:
            required.append((PurgeIntent.ENCRYPTION_KEY, encryption_key))
        for _intent, idempotency_key in required:
            job = connection.execute(
                "SELECT completed_at FROM purge_jobs WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if job is None or job["completed_at"] is None:
                return
        if encryption_job is not None and RetentionManager._has_undestroyed_keys(
            connection, request_id
        ):
            raise _JobFailure("key_destroy_incomplete")
        details = json.dumps(
            {"isolated_key_destruction": encryption_job is not None},
            sort_keys=True,
            separators=(",", ":"),
        )
        existing = connection.execute(
            """
            SELECT 1 FROM request_events
            WHERE request_id = ? AND action = ? AND version = ?
              AND payload_hash = ? AND safe_details_json = ?
            LIMIT 1
            """,
            (
                request_id,
                FAKE_UNKNOWN_PURGE_COMPLETED_ACTION,
                version,
                payload_hash,
                details,
            ),
        ).fetchone()
        if existing is not None:
            return
        connection.execute(
            """
            INSERT INTO request_events(
                request_id, actor, action, occurred_at,
                version, payload_hash, safe_details_json
            ) VALUES (?, 'gateway:retention', ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                FAKE_UNKNOWN_PURGE_COMPLETED_ACTION,
                now,
                version,
                payload_hash,
                details,
            ),
        )
        updated_request = connection.execute(
            """
            UPDATE approval_requests SET revision = revision + 1
            WHERE request_id = ? AND state = 'outcome_unknown'
              AND current_version = ? AND current_payload_hash = ?
            """,
            (request_id, version, payload_hash),
        ).rowcount
        if updated_request != 1:
            raise _JobFailure("claim_lost")

    def _record_failure(self, claim: PurgeClaim, *, now: int, error_code: str) -> None:
        if _SAFE_ERROR_RE.fullmatch(error_code) is None:
            error_code = "worker_failure"
        with self.database.transaction() as connection:
            connection.execute(
                """
                UPDATE purge_jobs
                SET started_at = NULL, created_at = ?, last_error = ?
                WHERE purge_job_id = ? AND started_at = ? AND completed_at IS NULL
                """,
                (
                    now + self.retry_delay_seconds,
                    error_code,
                    claim.purge_job_id,
                    claim.claim_marker,
                ),
            )

    def _fault(self, stage: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(stage)


class _JobFailure(RuntimeError):
    def __init__(self, error_code: str) -> None:
        if _SAFE_ERROR_RE.fullmatch(error_code) is None:
            raise ValueError("purge failure code is unsafe")
        super().__init__(error_code)
        self.error_code = error_code


def _validated_delays(
    values: Mapping[RequestState, int | None], *, label: str
) -> dict[RequestState, int | None]:
    if not isinstance(values, Mapping):
        raise TypeError(f"{label} retention delays must be a mapping")
    if any(not isinstance(state, RequestState) for state in values):
        raise ValueError(f"{label} retention matrix keys must be request states")
    if set(values) != set(RequestState):
        raise ValueError(f"{label} retention matrix must name every request state")
    result: dict[RequestState, int | None] = {}
    for state in RequestState:
        delay = values[state]
        if delay is not None and (
            isinstance(delay, bool) or not isinstance(delay, int) or delay < 0
        ):
            raise ValueError(f"{label} retention delay for {state.value} is invalid")
        if (
            state in _NONTERMINAL_STATES or state is RequestState.OUTCOME_UNKNOWN
        ) and delay is not None:
            raise ValueError(f"{state.value} must be protected from automatic purge")
        result[state] = delay
    return result


def _validate_time(value: int, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_UNIX_SECONDS
    ):
        raise ValueError(f"{label} is invalid")


def _validate_fake_unknown_inputs(
    *,
    request_id: str,
    expected_version: int,
    expected_payload_hash: str,
    acknowledge_possible_external_effect: bool,
    now: int,
) -> None:
    if _SAFE_REQUEST_ID_RE.fullmatch(request_id) is None:
        raise ValueError("fake-only purge request ID is invalid")
    if (
        isinstance(expected_version, bool)
        or not isinstance(expected_version, int)
        or expected_version <= 0
    ):
        raise ValueError("fake-only purge version is invalid")
    if (
        not isinstance(expected_payload_hash, str)
        or len(expected_payload_hash) != 64
        or expected_payload_hash.lower() != expected_payload_hash
    ):
        raise ValueError("fake-only purge payload hash is invalid")
    try:
        bytes.fromhex(expected_payload_hash)
    except ValueError:
        raise ValueError("fake-only purge payload hash is invalid") from None
    if acknowledge_possible_external_effect is not True:
        raise RetentionError("fake-only purge requires explicit possible-effect acknowledgement")
    _validate_time(now, "fake-only purge authorization time")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _wall_time() -> int:
    import time

    return int(time.time())
