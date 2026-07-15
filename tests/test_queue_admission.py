from __future__ import annotations

import asyncio
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest

from signet.admission import QueueAdmissionLimits, ReviewedToolLimits
from signet.config import Settings
from signet.db import LATEST_SCHEMA_VERSION, Database
from signet.expiry import ExpirySweeper
from signet.models import AdmissionRejected, EnqueueRequest, RequestNotFound
from signet.state_machine import ApprovalStateMachine

NOW = 1_900_000_000


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _request(
    request_id: str,
    *,
    namespace: str = "profile:one",
    alias: str = "fastmail",
    tool: str = "send_email",
    payload: str | None = None,
    canonical_size: int | None = None,
    invocation_key: str | None = None,
    created_at: int = NOW,
    expires_at: int | None = None,
) -> EnqueueRequest:
    selected_payload = payload or request_id
    payload_hash = _digest(selected_payload)
    encrypted = f"fake:encrypted:{selected_payload}".encode()
    return EnqueueRequest(
        request_id=request_id,
        downstream_alias=alias,
        tool_name=tool,
        policy_mode="approval",
        origin_namespace=namespace,
        encrypted_payload=encrypted,
        payload_hash=payload_hash,
        payload_fingerprint=_digest(f"fingerprint:{selected_payload}"),
        pending_result=json.dumps(
            {"status": "pending_approval", "request_id": request_id},
            separators=(",", ":"),
        ).encode(),
        created_at=created_at,
        expires_at=expires_at if expires_at is not None else created_at + 600,
        policy_version="1",
        adapter_version="1",
        schema_version="1",
        editor_actor=f"caller:{namespace}",
        canonical_size=(
            len(selected_payload.encode()) if canonical_size is None else canonical_size
        ),
        idempotency_key=invocation_key,
    )


@pytest.fixture
def database(tmp_path: Path) -> Database:
    selected = Database(tmp_path / "admission.sqlite3")
    selected.initialize()
    return selected


def _limits(
    *,
    queue: int = 10,
    origin: int = 10,
    tool: int = 10,
    minimum_free: int = 0,
    sweep: int = 100,
) -> QueueAdmissionLimits:
    return QueueAdmissionLimits(
        queue_limit=queue,
        origin_pending_limit=origin,
        tool_pending_limit=tool,
        minimum_free_bytes=minimum_free,
        enqueue_expiry_sweep_limit=sweep,
    )


def test_settings_bind_to_conservative_scoped_defaults() -> None:
    settings = Settings(queue_limit=7, minimum_free_bytes=123)
    limits = QueueAdmissionLimits.from_settings(settings)

    assert limits.queue_limit == 7
    assert limits.origin_pending_limit == 7
    assert limits.tool_pending_limit == 7
    assert limits.minimum_free_bytes == 123
    assert QueueAdmissionLimits.from_settings(Settings()).origin_pending_limit == 100
    with pytest.raises(TypeError, match="Signet settings"):
        QueueAdmissionLimits.from_settings(object())  # type: ignore[arg-type]


def test_schema_has_admission_indexes(database: Database) -> None:
    with database.read() as connection:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        indexes = {
            str(row[1]) for row in connection.execute("PRAGMA index_list(approval_requests)")
        }
    assert version == LATEST_SCHEMA_VERSION
    assert {
        "approval_requests_tool_admission_idx",
        "approval_requests_tool_rate_idx",
    } <= indexes


def test_global_capacity_boundary_is_atomic_across_connections(database: Database) -> None:
    barrier = Barrier(2)
    limits = _limits(queue=1)

    def contender(index: int) -> tuple[str, bool]:
        barrier.wait()
        try:
            result = ApprovalStateMachine(database, admission_limits=limits).enqueue(
                _request(f"req_Concurrent{index}")
            )
        except AdmissionRejected as exc:
            return exc.reason, False
        return result.request_id, result.created

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(contender, range(2)))

    assert sum(created for _value, created in outcomes) == 1
    assert [value for value, created in outcomes if not created] == ["queue_capacity"]
    with database.read() as connection:
        assert int(connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0]) == 1


@pytest.mark.parametrize("boundary", ["origin", "tool", "rate"])
def test_scoped_and_rate_boundaries_are_atomic_across_connections(
    database: Database,
    boundary: str,
) -> None:
    barrier = Barrier(2)
    limits = _limits(
        origin=1 if boundary == "origin" else 10,
        tool=1 if boundary == "tool" else 10,
    )
    reviewed = ReviewedToolLimits(requests_per_minute=1) if boundary == "rate" else None

    def contender(index: int) -> str:
        namespace = f"profile:{index}" if boundary == "tool" else "profile:shared"
        tool = f"send_{index}" if boundary == "origin" else "send"
        barrier.wait()
        try:
            ApprovalStateMachine(database, admission_limits=limits).enqueue(
                _request(
                    f"req_ScopedConcurrent{index}",
                    namespace=namespace,
                    tool=tool,
                ),
                reviewed_limits=reviewed,
            )
        except AdmissionRejected as exc:
            return exc.reason
        return "created"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(contender, range(2)))

    expected_rejection = "request_rate" if boundary == "rate" else "queue_capacity"
    assert sorted(outcomes) == ["created", expected_rejection]


def test_replay_bypasses_full_queue_and_new_storage_admission(database: Database) -> None:
    free_bytes = [10_000_000]
    calls: list[str] = []

    def disk_free(path: str) -> int:
        calls.append(path)
        return free_bytes[0]

    limits = _limits(queue=1, minimum_free=1)
    machine = ApprovalStateMachine(
        database,
        admission_limits=limits,
        free_space_provider=disk_free,
    )
    original = machine.enqueue(
        _request(
            "req_ReplayOriginal",
            payload="same",
            invocation_key="stable-invocation",
        ),
        reviewed_limits=ReviewedToolLimits(
            requests_per_minute=1,
            pending_requests=1,
        ),
    )
    free_bytes[0] = 0
    replay = machine.enqueue(
        _request(
            "req_ReplayCandidate",
            payload="same",
            invocation_key="stable-invocation",
        ),
        reviewed_limits=ReviewedToolLimits(
            requests_per_minute=1,
            pending_requests=1,
        ),
    )

    assert replay.created is False
    assert replay.request_id == original.request_id
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("first", "second", "limits"),
    [
        (
            _request("req_OriginFirst", namespace="profile:a", tool="send_one"),
            _request("req_OriginSecond", namespace="profile:a", tool="send_two"),
            _limits(origin=1),
        ),
        (
            _request("req_ToolFirst", namespace="profile:a", tool="send"),
            _request("req_ToolSecond", namespace="profile:b", tool="send"),
            _limits(tool=1),
        ),
    ],
)
def test_scoped_pending_quotas_reject_unique_invocation_abuse(
    database: Database,
    first: EnqueueRequest,
    second: EnqueueRequest,
    limits: QueueAdmissionLimits,
) -> None:
    machine = ApprovalStateMachine(database, admission_limits=limits)
    machine.enqueue(replace(first, idempotency_key="unique-one"))
    with pytest.raises(AdmissionRejected, match="queue_capacity") as rejected:
        machine.enqueue(replace(second, idempotency_key="unique-two"))
    assert rejected.value.reason == "queue_capacity"
    with database.read() as connection:
        assert int(connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0]) == 1
        assert int(connection.execute("SELECT COUNT(*) FROM request_events").fetchone()[0]) == 1


def test_reviewed_payload_pending_and_rate_limits_are_enforced_atomically(
    database: Database,
) -> None:
    machine = ApprovalStateMachine(database, admission_limits=_limits())
    with pytest.raises(AdmissionRejected) as oversized:
        machine.enqueue(
            _request("req_Oversized", canonical_size=11),
            reviewed_limits=ReviewedToolLimits(payload_bytes=10),
        )
    assert oversized.value.reason == "payload_limit"

    pending_limit = ReviewedToolLimits(pending_requests=1)
    machine.enqueue(_request("req_PendingOne", tool="pending"), reviewed_limits=pending_limit)
    with pytest.raises(AdmissionRejected) as pending:
        machine.enqueue(_request("req_PendingTwo", tool="pending"), reviewed_limits=pending_limit)
    assert pending.value.reason == "queue_capacity"

    rate_limit = ReviewedToolLimits(requests_per_minute=2)
    machine.enqueue(_request("req_RateOne", tool="rate"), reviewed_limits=rate_limit)
    machine.enqueue(
        _request("req_RateTwo", tool="rate", created_at=NOW + 1),
        reviewed_limits=rate_limit,
    )
    with pytest.raises(AdmissionRejected) as rate:
        machine.enqueue(
            _request("req_RateThree", tool="rate", created_at=NOW + 59),
            reviewed_limits=rate_limit,
        )
    assert rate.value.reason == "request_rate"
    machine.enqueue(
        _request("req_RateBoundary", tool="rate", created_at=NOW + 60),
        reviewed_limits=rate_limit,
    )

    with database.read() as connection:
        identifiers = {
            str(row[0]) for row in connection.execute("SELECT request_id FROM approval_requests")
        }
    assert "req_Oversized" not in identifiers
    assert "req_PendingTwo" not in identifiers
    assert "req_RateThree" not in identifiers


def test_unknown_or_unmeasurable_reviewed_limits_fail_closed(database: Database) -> None:
    with pytest.raises(ValueError, match="unsupported"):
        ReviewedToolLimits.from_policy({"silently_ignored": 1})
    machine = ApprovalStateMachine(database, admission_limits=_limits())
    request = replace(_request("req_Unmeasured"), canonical_size=None)
    with pytest.raises(AdmissionRejected) as rejected:
        machine.enqueue(request, reviewed_limits=ReviewedToolLimits(payload_bytes=10))
    assert rejected.value.reason == "payload_limit"


def test_low_disk_and_probe_failure_leave_no_partial_state(database: Database) -> None:
    limits = _limits(minimum_free=100)
    low_disk = ApprovalStateMachine(
        database,
        admission_limits=limits,
        free_space_provider=lambda _path: 100,
    )
    with pytest.raises(AdmissionRejected) as low:
        low_disk.enqueue(_request("req_LowDisk"))
    assert low.value.reason == "storage_headroom"

    def failed_probe(_path: str) -> int:
        raise OSError("fake disk probe failure")

    failed = ApprovalStateMachine(
        database,
        admission_limits=limits,
        free_space_provider=failed_probe,
    )
    with pytest.raises(AdmissionRejected) as unavailable:
        failed.enqueue(_request("req_ProbeFailure"))
    assert unavailable.value.reason == "storage_headroom"

    with database.read() as connection:
        for table in (
            "approval_requests",
            "payload_versions",
            "idempotency_records",
            "request_events",
            "notification_outbox",
        ):
            assert int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) == 0


def test_failed_admission_rolls_back_tentative_expiry_sweep(database: Database) -> None:
    limits = _limits(queue=1, minimum_free=100)
    healthy = ApprovalStateMachine(
        database,
        admission_limits=limits,
        free_space_provider=lambda _path: 10_000_000,
    )
    healthy.enqueue(_request("req_ExpiryRollback", expires_at=NOW + 1))
    low_disk = ApprovalStateMachine(
        database,
        admission_limits=limits,
        free_space_provider=lambda _path: 100,
    )

    with pytest.raises(AdmissionRejected, match="storage_headroom"):
        low_disk.enqueue(_request("req_RejectedAfterSweep", created_at=NOW + 1))

    assert low_disk.get_request("req_ExpiryRollback")["state"] == "pending_approval"
    with pytest.raises(RequestNotFound):
        low_disk.get_request("req_RejectedAfterSweep")


def test_enqueue_sweeps_expired_capacity_and_invalidates_review_artifacts(
    database: Database,
) -> None:
    machine = ApprovalStateMachine(database, admission_limits=_limits(queue=1))
    expired = _request("req_ExpiredCapacity", expires_at=NOW + 1)
    machine.enqueue(expired)
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO approval_challenges(
                challenge_id, kind, request_id, version, payload_hash,
                created_at, expires_at
            ) VALUES ('challenge-expired', 'webauthn', ?, 1, ?, ?, ?)
            """,
            (expired.request_id, expired.payload_hash, NOW, NOW + 60),
        )
        connection.execute(
            """
            INSERT INTO browser_views(
                view_id, request_id, version, payload_hash,
                request_revision, created_at
            ) VALUES ('view-expired', ?, 1, ?, 1, ?)
            """,
            (expired.request_id, expired.payload_hash, NOW),
        )

    admitted = machine.enqueue(_request("req_Replacement", created_at=NOW + 1))
    assert admitted.created
    with database.read() as connection:
        old = connection.execute(
            "SELECT state, completed_at FROM approval_requests WHERE request_id = ?",
            (expired.request_id,),
        ).fetchone()
        challenge_invalidated = connection.execute(
            """
            SELECT invalidated_at FROM approval_challenges
            WHERE challenge_id = 'challenge-expired'
            """
        ).fetchone()[0]
        view_invalidated = connection.execute(
            "SELECT invalidated_at FROM browser_views WHERE view_id = 'view-expired'"
        ).fetchone()[0]
    assert tuple(old) == ("expired", NOW + 1)
    assert challenge_invalidated == NOW + 1
    assert view_invalidated == NOW + 1


def test_expiry_service_is_bounded_restart_safe_and_failure_atomic(database: Database) -> None:
    machine = ApprovalStateMachine(database, admission_limits=_limits())
    for index in range(3):
        machine.enqueue(_request(f"req_Sweep{index}", expires_at=NOW + 1))

    sweeper = ExpirySweeper(machine, batch_limit=2, clock=lambda: NOW + 1)
    first = sweeper.run_once()
    second = ExpirySweeper(
        ApprovalStateMachine(database, admission_limits=_limits()),
        batch_limit=2,
        clock=lambda: NOW + 1,
    ).run_once()
    assert (first.expired, first.batch_full) == (2, True)
    assert (second.expired, second.batch_full) == (1, False)

    machine.enqueue(_request("req_SweepRollback", created_at=NOW + 2, expires_at=NOW + 3))

    def fail(stage: str) -> None:
        if stage == "expiry_sweep:before_commit":
            raise RuntimeError("fake expiry crash")

    crashing = ApprovalStateMachine(
        database,
        admission_limits=_limits(),
        fault_injector=fail,
    )
    with pytest.raises(RuntimeError, match="fake expiry crash"):
        crashing.sweep_expired(now=NOW + 3)
    assert crashing.get_request("req_SweepRollback")["state"] == "pending_approval"


@pytest.mark.asyncio
async def test_periodic_expiry_service_starts_and_stops_cleanly(database: Database) -> None:
    machine = ApprovalStateMachine(database, admission_limits=_limits())
    machine.enqueue(_request("req_PeriodicSweep", expires_at=NOW + 1))
    sweeper = ExpirySweeper(
        machine,
        batch_limit=1,
        interval_seconds=1,
        clock=lambda: NOW + 1,
    )
    stop = asyncio.Event()
    serving = asyncio.create_task(sweeper.serve(stop))
    for _ in range(100):
        if machine.get_request("req_PeriodicSweep")["state"] == "expired":
            break
        await asyncio.sleep(0.01)
    stop.set()
    await asyncio.wait_for(serving, timeout=1)
    assert machine.get_request("req_PeriodicSweep")["state"] == "expired"
