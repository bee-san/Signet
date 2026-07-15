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
from types import MappingProxyType
from typing import Any, Protocol

from signet.db import Database
from signet.models import RequestState
from signet.staging import StagingError, StagingStore

_MICROSECONDS = 1_000_000
_MAX_UNIX_SECONDS = 9_000_000_000_000
_ONE_DAY = 24 * 60 * 60
_SAFE_ERROR_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

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
                SELECT DISTINCT request_id FROM attachments
                WHERE storage_path IS NOT NULL AND purged_at IS NULL
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
                      AND started_at IS NOT NULL AND completed_at IS NULL
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
        self.database = database
        self.staging = staging
        self.matrix = matrix
        self.mode = mode
        self.key_destroyer = key_destroyer
        self.claim_lease_seconds = claim_lease_seconds
        self.retry_delay_seconds = retry_delay_seconds
        self._fault_injector = fault_injector

    def schedule(self, *, now: int) -> int:
        _validate_time(now, "purge scheduling time")
        inserted = 0
        with self.database.transaction() as connection:
            retained_predicates = [
                """
                EXISTS (
                    SELECT 1 FROM payload_versions AS payload
                    WHERE payload.request_id = approval_requests.request_id
                      AND payload.encrypted_payload IS NOT NULL
                      AND payload.purged_at IS NULL
                )
                """,
                """
                EXISTS (
                    SELECT 1 FROM attachments AS attachment
                    WHERE attachment.request_id = approval_requests.request_id
                      AND attachment.storage_path IS NOT NULL
                      AND attachment.purged_at IS NULL
                )
                """,
            ]
            if self.mode is RetentionMode.ISOLATED_PER_REQUEST_KEY:
                retained_predicates.append(
                    """
                    EXISTS (
                        SELECT 1 FROM payload_versions AS payload_key
                        WHERE payload_key.request_id = approval_requests.request_id
                          AND payload_key.encryption_key_ref IS NOT NULL
                          AND payload_key.key_destroyed_at IS NULL
                    )
                    """
                )
            requests = connection.execute(
                f"""
                SELECT request_id, state, completed_at FROM approval_requests
                WHERE state IN ('succeeded', 'failed', 'denied', 'expired', 'cancelled')
                  AND ({" OR ".join(retained_predicates)})
                ORDER BY request_id
                """
            ).fetchall()
            for request in requests:
                try:
                    state = RequestState(request["state"])
                except ValueError as exc:
                    raise RetentionError("stored request state is invalid") from exc
                completed_at = request["completed_at"]
                if state not in _PURGEABLE_STATES or not isinstance(completed_at, int):
                    continue
                request_id = str(request["request_id"])
                if self._has_unpurged_attachments(connection, request_id):
                    inserted += self._schedule_intent(
                        connection,
                        request_id=request_id,
                        intent=PurgeIntent.ATTACHMENTS,
                        due_at=completed_at + self._required_delay(PurgeIntent.ATTACHMENTS, state),
                    )
                if self._has_sensitive_rows(connection, request_id):
                    inserted += self._schedule_intent(
                        connection,
                        request_id=request_id,
                        intent=PurgeIntent.SENSITIVE_ROWS,
                        due_at=completed_at
                        + self._required_delay(PurgeIntent.SENSITIVE_ROWS, state),
                    )
                if self.mode is RetentionMode.ISOLATED_PER_REQUEST_KEY and (
                    self._has_undestroyed_keys(connection, request_id)
                ):
                    inserted += self._schedule_intent(
                        connection,
                        request_id=request_id,
                        intent=PurgeIntent.ENCRYPTION_KEY,
                        due_at=completed_at
                        + self._required_delay(PurgeIntent.ENCRYPTION_KEY, state),
                    )
        return inserted

    def claim_due(self, *, now: int) -> PurgeClaim | None:
        _validate_time(now, "purge claim time")
        stale_before = max(0, now - self.claim_lease_seconds) * _MICROSECONDS
        with self.database.transaction() as connection:
            rows = connection.execute(
                """
                SELECT job.*, request.state, request.completed_at AS request_completed_at
                FROM purge_jobs AS job
                JOIN approval_requests AS request USING(request_id)
                WHERE job.intent != 'backup_pin' AND job.completed_at IS NULL
                  AND job.created_at <= ?
                  AND (job.started_at IS NULL OR job.started_at < ?)
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
                (now, stale_before),
            ).fetchall()
            for row in rows:
                try:
                    intent = PurgeIntent(row["intent"])
                    state = RequestState(row["state"])
                except ValueError as exc:
                    raise RetentionError("stored purge job is invalid") from exc
                completed_at = row["request_completed_at"]
                if state not in _PURGEABLE_STATES or not isinstance(completed_at, int):
                    continue
                if intent is PurgeIntent.ENCRYPTION_KEY and (
                    self.mode is not RetentionMode.ISOLATED_PER_REQUEST_KEY
                ):
                    continue
                delay = self.matrix.delay(intent, state)
                if delay is None or completed_at + delay > now:
                    continue
                if self._active_pin(connection, str(row["request_id"])):
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
                    """,
                    (marker, row["purge_job_id"], stale_before),
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
        scheduled = self.schedule(now=now)
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
                    UPDATE attachments SET storage_path = NULL, purged_at = ?
                    WHERE attachment_id = ? AND request_id = ? AND version = ?
                      AND size_bytes = ? AND sha256 = ? AND storage_path = ?
                      AND purged_at IS NULL
                    """,
                    (
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
                (now, f"retention_{claim.state.value}", claim.request_id),
            )
            self._tombstone_idempotency(connection, claim.request_id, now=now)
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
                    f"retention_{claim.state.value}",
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
                   request.state,
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
        if not isinstance(request_completed_at, int):
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

    @staticmethod
    def _complete_claim(connection: Any, claim: PurgeClaim, *, now: int) -> None:
        updated = connection.execute(
            """
            UPDATE purge_jobs SET completed_at = ?, last_error = NULL
            WHERE purge_job_id = ? AND started_at = ? AND completed_at IS NULL
            """,
            (now, claim.purge_job_id, claim.claim_marker),
        ).rowcount
        if updated != 1:
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


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _wall_time() -> int:
    import time

    return int(time.time())
