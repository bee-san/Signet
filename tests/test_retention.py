from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from signet.db import Database
from signet.models import AttachmentReference, EnqueueRequest, RequestState
from signet.retention import (
    BackupPinConflict,
    BackupPins,
    PurgeIntent,
    RetentionManager,
    RetentionMatrix,
    RetentionMode,
)
from signet.staging import StagedFile, StagingStore
from signet.state_machine import ApprovalStateMachine

DAY = 24 * 60 * 60
COMPLETED_AT = 1_000


class FakeKeyDestroyer:
    def __init__(self, *, confirmed: bool = True) -> None:
        self.confirmed = confirmed
        self.calls: list[tuple[str, str]] = []

    def destroy(self, key_reference: str, *, idempotency_key: str) -> bool:
        self.calls.append((key_reference, idempotency_key))
        return self.confirmed


class SimulatedCrash(BaseException):
    pass


@pytest.fixture
def database(tmp_path: Path) -> Database:
    value = Database(tmp_path / "data" / "approvals.sqlite3")
    value.initialize()
    return value


@pytest.fixture
def staging(tmp_path: Path) -> StagingStore:
    sources = tmp_path / "sources"
    sources.mkdir()
    return StagingStore(
        tmp_path / "staging",
        allowed_source_roots=(sources,),
        max_file_bytes=1024 * 1024,
        max_total_bytes=8 * 1024 * 1024,
        minimum_free_bytes=0,
    )


def _matrix(
    *,
    payload_delays: dict[RequestState, int] | None = None,
    failed_attachment_delay: int = 2 * DAY,
) -> RetentionMatrix:
    attachments: dict[RequestState, int | None] = dict.fromkeys(RequestState)
    attachments.update(
        {
            RequestState.SUCCEEDED: 0,
            RequestState.FAILED: failed_attachment_delay,
            RequestState.DENIED: 0,
            RequestState.EXPIRED: DAY,
            RequestState.CANCELLED: DAY,
        }
    )
    payloads: dict[RequestState, int | None] = dict.fromkeys(RequestState)
    payloads.update(
        payload_delays
        or {
            RequestState.SUCCEEDED: 10,
            RequestState.FAILED: 20,
            RequestState.DENIED: 30,
            RequestState.EXPIRED: 40,
            RequestState.CANCELLED: 50,
        }
    )
    return RetentionMatrix(attachments, payloads)


def _stage(staging: StagingStore, name: str, content: bytes | None = None) -> StagedFile:
    source = staging.allowed_source_roots[0] / f"{name}.txt"
    source.write_bytes(content or f"fake attachment {name}".encode())
    return staging.stage_path(
        source,
        adapter="fake-adapter",
        account="fake-account",
        filename=f"{name}.txt",
        declared_mime="text/plain",
    )


def _request(
    database: Database,
    *,
    request_id: str,
    state: RequestState,
    staged: StagedFile | None = None,
    key_reference: str | None = None,
    idempotency: bool = True,
    completed_at: int = COMPLETED_AT,
) -> None:
    digest = hashlib.sha256(request_id.encode()).hexdigest()
    attachments = ()
    if staged is not None:
        attachments = (
            AttachmentReference(
                attachment_id=staged.opaque_id,
                filename=staged.filename,
                mime_type=staged.declared_mime,
                size_bytes=staged.size,
                sha256=staged.sha256,
                storage_path=str(staged.path),
            ),
        )
    ApprovalStateMachine(database).enqueue(
        EnqueueRequest(
            request_id=request_id,
            downstream_alias="fake-service",
            tool_name="fake_write",
            policy_mode="approval",
            origin_namespace="profile:fake",
            encrypted_payload=f"fake encrypted {request_id}".encode(),
            payload_hash=digest,
            payload_fingerprint=f"fake-fingerprint-{request_id}",
            pending_result=b'{"status":"pending_approval"}',
            created_at=100,
            expires_at=10_000,
            policy_version="policy-fake",
            adapter_version="adapter-fake",
            schema_version="schema-fake",
            editor_actor="caller:profile:fake",
            encryption_key_ref=key_reference,
            idempotency_key=f"fake-invocation-{request_id}" if idempotency else None,
            attachments=attachments,
        )
    )
    if state is not RequestState.PENDING_APPROVAL:
        with database.transaction() as connection:
            connection.execute(
                """
                UPDATE approval_requests SET state = ?, completed_at = ?
                WHERE request_id = ?
                """,
                (state.value, completed_at, request_id),
            )


def _payload_rows(database: Database, request_id: str) -> list[dict[str, object]]:
    with database.read() as connection:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM payload_versions WHERE request_id = ? ORDER BY version",
                (request_id,),
            )
        ]


def test_matrix_is_explicit_for_every_state_and_validates_fixed_attachment_rules() -> None:
    matrix = _matrix()
    assert set(matrix.attachment_delays) == set(RequestState)
    assert set(matrix.payload_delays) == set(RequestState)
    for state in (
        *tuple(
            value
            for value in RequestState
            if value
            not in {
                RequestState.SUCCEEDED,
                RequestState.FAILED,
                RequestState.DENIED,
                RequestState.EXPIRED,
                RequestState.CANCELLED,
            }
        ),
    ):
        assert matrix.attachment_delays[state] is None
        assert matrix.payload_delays[state] is None

    missing = dict(matrix.attachment_delays)
    missing.pop(RequestState.RECEIVED)
    with pytest.raises(ValueError, match="every request state"):
        RetentionMatrix(missing, matrix.payload_delays)
    for state, invalid in (
        (RequestState.SUCCEEDED, 1),
        (RequestState.DENIED, 1),
        (RequestState.EXPIRED, DAY + 1),
        (RequestState.CANCELLED, DAY - 1),
        (RequestState.FAILED, DAY - 1),
        (RequestState.OUTCOME_UNKNOWN, 0),
        (RequestState.EXECUTING, 0),
    ):
        values = dict(matrix.attachment_delays)
        values[state] = invalid
        with pytest.raises(ValueError):
            RetentionMatrix(values, matrix.payload_delays)
    missing_payload_delay = dict(matrix.payload_delays)
    missing_payload_delay[RequestState.DENIED] = None
    with pytest.raises(ValueError, match="must be explicit"):
        RetentionMatrix(matrix.attachment_delays, missing_payload_delay)


def test_scheduler_persists_exact_matrix_due_times_and_is_idempotent(
    database: Database, staging: StagingStore
) -> None:
    matrix = _matrix()
    for state in RequestState:
        _request(
            database,
            request_id=f"matrix-{state.value}",
            state=state,
            staged=_stage(staging, state.value),
            key_reference=f"keychain://Signet/fake-{state.value}",
        )
    manager = RetentionManager(database, staging, matrix=matrix)

    assert manager.schedule(now=COMPLETED_AT) == 10
    assert manager.schedule(now=COMPLETED_AT) == 0
    with database.read() as connection:
        rows = connection.execute(
            "SELECT request_id, intent, created_at FROM purge_jobs ORDER BY request_id, intent"
        ).fetchall()
    expected: set[tuple[str, str, int]] = set()
    for state in (
        RequestState.SUCCEEDED,
        RequestState.FAILED,
        RequestState.DENIED,
        RequestState.EXPIRED,
        RequestState.CANCELLED,
    ):
        expected.add(
            (
                f"matrix-{state.value}",
                PurgeIntent.ATTACHMENTS.value,
                COMPLETED_AT + int(matrix.attachment_delays[state] or 0),
            )
        )
        expected.add(
            (
                f"matrix-{state.value}",
                PurgeIntent.SENSITIVE_ROWS.value,
                COMPLETED_AT + int(matrix.payload_delays[state] or 0),
            )
        )
    assert {(row["request_id"], row["intent"], row["created_at"]) for row in rows} == (
        expected
    )


def test_attachment_retention_boundaries_match_each_terminal_state(
    database: Database, staging: StagingStore
) -> None:
    records: dict[RequestState, StagedFile] = {}
    for state in (
        RequestState.SUCCEEDED,
        RequestState.FAILED,
        RequestState.DENIED,
        RequestState.EXPIRED,
        RequestState.CANCELLED,
    ):
        records[state] = _stage(staging, f"timing-{state.value}")
        _request(
            database,
            request_id=f"timing-{state.value}",
            state=state,
            staged=records[state],
            key_reference=f"keychain://Signet/timing-{state.value}",
        )
    payload_delays = {state: 10 * DAY for state in _PURGEABLE_FIXTURE_STATES}
    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(payload_delays=payload_delays),
    )

    manager.run_due(now=COMPLETED_AT)
    assert not records[RequestState.SUCCEEDED].path.exists()
    assert not records[RequestState.DENIED].path.exists()
    assert records[RequestState.FAILED].path.exists()
    assert records[RequestState.EXPIRED].path.exists()
    assert records[RequestState.CANCELLED].path.exists()

    manager.run_due(now=COMPLETED_AT + DAY - 1)
    assert records[RequestState.EXPIRED].path.exists()
    assert records[RequestState.CANCELLED].path.exists()
    manager.run_due(now=COMPLETED_AT + DAY)
    assert not records[RequestState.EXPIRED].path.exists()
    assert not records[RequestState.CANCELLED].path.exists()
    assert records[RequestState.FAILED].path.exists()
    manager.run_due(now=COMPLETED_AT + 2 * DAY)
    assert not records[RequestState.FAILED].path.exists()


def test_outcome_unknown_is_protected_even_from_a_preexisting_due_job(
    database: Database, staging: StagingStore
) -> None:
    staged = _stage(staging, "unknown")
    _request(
        database,
        request_id="unknown-protected",
        state=RequestState.OUTCOME_UNKNOWN,
        staged=staged,
        key_reference="keychain://Signet/fake-unknown",
    )
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO purge_jobs(
                purge_job_id, request_id, intent, idempotency_key, created_at
            ) VALUES ('fake-malicious-job', 'unknown-protected', 'attachments',
                      'fake:unknown:attachments', 1)
            """
        )
    manager = RetentionManager(database, staging, matrix=_matrix())

    assert manager.schedule(now=10_000_000) == 0
    assert manager.claim_due(now=10_000_000) is None
    assert staged.path.exists()
    assert _payload_rows(database, "unknown-protected")[0]["encrypted_payload"] is not None


def test_logical_purge_clears_body_but_never_claims_key_destruction(
    database: Database, staging: StagingStore
) -> None:
    _request(
        database,
        request_id="logical-purge",
        state=RequestState.DENIED,
        key_reference="keychain://Signet/fake-logical",
    )
    matrix = _matrix(
        payload_delays={state: 0 for state in _PURGEABLE_FIXTURE_STATES}
    )
    manager = RetentionManager(database, staging, matrix=matrix)

    report = manager.run_due(now=COMPLETED_AT)
    assert report.completed == 1
    row = _payload_rows(database, "logical-purge")[0]
    assert row["encrypted_payload"] is None
    assert row["purged_at"] == COMPLETED_AT
    assert row["key_destroyed_at"] is None
    assert row["encryption_key_ref"] == "keychain://Signet/fake-logical"
    assert row["purge_reason"] == "retention_denied"
    with database.read() as connection:
        tombstone = connection.execute(
            "SELECT * FROM idempotency_records WHERE request_id = 'logical-purge'"
        ).fetchone()
        request = connection.execute(
            "SELECT * FROM approval_requests WHERE request_id = 'logical-purge'"
        ).fetchone()
        events = connection.execute(
            "SELECT payload_hash FROM request_events WHERE request_id = 'logical-purge'"
        ).fetchall()
        key_jobs = connection.execute(
            """
            SELECT count(*) FROM purge_jobs
            WHERE request_id = 'logical-purge' AND intent = 'encryption_key'
            """
        ).fetchone()[0]
    assert tombstone["tombstoned_at"] == COMPLETED_AT
    assert tombstone["payload_fingerprint"] == "fake-fingerprint-logical-purge"
    assert request["current_payload_hash"] == row["payload_hash"]
    assert [event["payload_hash"] for event in events] == [row["payload_hash"]]
    assert key_jobs == 0
    assert manager.run_due(now=COMPLETED_AT + 1).completed == 0
    with pytest.raises(ValueError, match="must not receive"):
        RetentionManager(
            database,
            staging,
            matrix=matrix,
            mode=RetentionMode.LOGICAL,
            key_destroyer=FakeKeyDestroyer(),
        )


def test_isolated_key_purge_requires_unique_refs_and_marks_only_confirmed_destruction(
    database: Database, staging: StagingStore
) -> None:
    _request(
        database,
        request_id="isolated-purge",
        state=RequestState.SUCCEEDED,
        key_reference="keychain://Signet/fake-isolated",
    )
    destroyer = FakeKeyDestroyer()
    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(payload_delays={state: 0 for state in _PURGEABLE_FIXTURE_STATES}),
        mode=RetentionMode.ISOLATED_PER_REQUEST_KEY,
        key_destroyer=destroyer,
    )

    report = manager.run_due(now=COMPLETED_AT)
    assert report.completed == 2
    assert len(destroyer.calls) == 1
    assert destroyer.calls[0][0] == "keychain://Signet/fake-isolated"
    assert re.fullmatch(r"destroy:[0-9a-f]{64}", destroyer.calls[0][1])
    row = _payload_rows(database, "isolated-purge")[0]
    assert row["encrypted_payload"] is None
    assert row["encryption_key_ref"] is None
    assert row["purged_at"] == COMPLETED_AT
    assert row["key_destroyed_at"] == COMPLETED_AT
    assert manager.run_due(now=COMPLETED_AT + 1).completed == 0
    assert len(destroyer.calls) == 1


def test_shared_key_ref_is_refused_without_calling_destroyer_or_leaking_details(
    database: Database, staging: StagingStore
) -> None:
    shared = "keychain://Signet/fake-shared-private-ref"
    for suffix in ("one", "two"):
        _request(
            database,
            request_id=f"shared-{suffix}",
            state=RequestState.DENIED,
            key_reference=shared,
        )
    destroyer = FakeKeyDestroyer()
    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(payload_delays={state: 0 for state in _PURGEABLE_FIXTURE_STATES}),
        mode=RetentionMode.ISOLATED_PER_REQUEST_KEY,
        key_destroyer=destroyer,
    )

    report = manager.run_due(now=COMPLETED_AT, limit=10)
    assert report.failed == 2
    assert destroyer.calls == []
    with database.read() as connection:
        jobs = connection.execute(
            """
            SELECT last_error FROM purge_jobs
            WHERE intent = 'encryption_key' ORDER BY request_id
            """
        ).fetchall()
    assert [job["last_error"] for job in jobs] == [
        "key_reference_shared",
        "key_reference_shared",
    ]
    assert all(shared not in job["last_error"] for job in jobs)
    for suffix in ("one", "two"):
        row = _payload_rows(database, f"shared-{suffix}")[0]
        assert row["key_destroyed_at"] is None
        assert row["encryption_key_ref"] == shared


def test_attachment_purge_verifies_hash_and_path_and_stores_only_generic_error(
    database: Database, staging: StagingStore, tmp_path: Path
) -> None:
    staged = _stage(staging, "tampered", b"fake approved bytes")
    _request(
        database,
        request_id="attachment-tampered",
        state=RequestState.DENIED,
        staged=staged,
    )
    staged.path.write_bytes(b"fake changed bytes")
    manager = RetentionManager(database, staging, matrix=_matrix())

    report = manager.run_due(now=COMPLETED_AT)
    assert report.failed == 1
    with database.read() as connection:
        job = connection.execute(
            """
            SELECT last_error FROM purge_jobs
            WHERE request_id = 'attachment-tampered' AND intent = 'attachments'
            """
        ).fetchone()
    assert job["last_error"] == "attachment_verification_failed"
    assert str(staged.path) not in job["last_error"]
    assert staged.path.exists()

    outside = tmp_path / "outside-private"
    outside.write_bytes(b"fake changed bytes")
    with database.transaction() as connection:
        connection.execute(
            """
            UPDATE attachments SET storage_path = ?
            WHERE request_id = 'attachment-tampered'
            """,
            (str(outside),),
        )
        connection.execute(
            """
            UPDATE purge_jobs SET created_at = ?, started_at = NULL
            WHERE request_id = 'attachment-tampered' AND intent = 'attachments'
            """,
            (COMPLETED_AT,),
        )
    assert manager.run_due(now=COMPLETED_AT).failed == 1
    assert outside.exists()


def test_attachment_unlink_before_database_commit_recovers_after_restart(
    database: Database, staging: StagingStore
) -> None:
    staged = _stage(staging, "crash-recovery")
    _request(
        database,
        request_id="attachment-crash",
        state=RequestState.DENIED,
        staged=staged,
    )

    def crash(stage: str) -> None:
        if stage == "attachment_unlinked":
            raise SimulatedCrash

    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(),
        claim_lease_seconds=10,
        fault_injector=crash,
    )
    with pytest.raises(SimulatedCrash):
        manager.run_due(now=COMPLETED_AT)
    assert not staged.path.exists()
    assert not (staging.root / ".metadata" / f"{staged.opaque_id}.json").exists()
    with database.read() as connection:
        attachment = connection.execute(
            "SELECT storage_path, purged_at FROM attachments WHERE request_id = 'attachment-crash'"
        ).fetchone()
        job = connection.execute(
            """
            SELECT started_at, completed_at FROM purge_jobs
            WHERE request_id = 'attachment-crash' AND intent = 'attachments'
            """
        ).fetchone()
    assert attachment["storage_path"] == str(staged.path)
    assert attachment["purged_at"] is None
    assert job["started_at"] is not None and job["completed_at"] is None

    restarted = RetentionManager(
        database,
        staging,
        matrix=_matrix(),
        claim_lease_seconds=10,
    )
    report = restarted.run_due(now=COMPLETED_AT + 11)
    assert report.completed == 1
    with database.read() as connection:
        attachment = connection.execute(
            "SELECT storage_path, purged_at FROM attachments WHERE request_id = 'attachment-crash'"
        ).fetchone()
    assert attachment["storage_path"] is None
    assert attachment["purged_at"] == COMPLETED_AT + 11


def test_backup_pin_blocks_claims_and_conflicts_with_an_existing_purge_claim(
    database: Database, staging: StagingStore
) -> None:
    staged = _stage(staging, "pin-race")
    _request(
        database,
        request_id="pin-race",
        state=RequestState.DENIED,
        staged=staged,
    )
    manager = RetentionManager(database, staging, matrix=_matrix())
    assert manager.schedule(now=COMPLETED_AT) == 2
    pins = BackupPins(database)
    lease = pins.acquire(now=COMPLETED_AT)
    assert manager.claim_due(now=COMPLETED_AT) is None
    pins.release(lease, now=COMPLETED_AT + 1)

    claim = manager.claim_due(now=COMPLETED_AT + 1)
    assert claim is not None and claim.intent is PurgeIntent.ATTACHMENTS
    with pytest.raises(BackupPinConflict, match="in progress"):
        pins.acquire(now=COMPLETED_AT + 1)
    assert manager.process(claim, now=COMPLETED_AT + 1)


def test_abandoned_backup_pin_requires_explicit_release_after_restart(
    database: Database, staging: StagingStore
) -> None:
    staged = _stage(staging, "pin-restart")
    _request(
        database,
        request_id="pin-restart",
        state=RequestState.DENIED,
        staged=staged,
    )
    manager = RetentionManager(database, staging, matrix=_matrix())
    manager.schedule(now=COMPLETED_AT)
    BackupPins(database).acquire(now=COMPLETED_AT)

    restarted_pins = BackupPins(Database(database.path))
    restarted_manager = RetentionManager(
        Database(database.path), staging, matrix=_matrix()
    )
    assert restarted_manager.claim_due(now=COMPLETED_AT + 10_000) is None
    assert restarted_pins.release_abandoned(
        before=COMPLETED_AT,
        now=COMPLETED_AT + 10_000,
    ) == 1
    claim = restarted_manager.claim_due(now=COMPLETED_AT + 10_000)
    assert claim is not None


_PURGEABLE_FIXTURE_STATES = {
    RequestState.SUCCEEDED,
    RequestState.FAILED,
    RequestState.DENIED,
    RequestState.EXPIRED,
    RequestState.CANCELLED,
}
