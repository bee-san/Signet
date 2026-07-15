from __future__ import annotations

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from signet.db import Database, IntegrityError
from signet.models import (
    AttachmentReference,
    EnqueueRequest,
    ReconciliationDecision,
    ReconciliationRejected,
    RequestState,
)
from signet.retention import (
    BackupPinConflict,
    BackupPinLease,
    BackupPins,
    PurgeIntent,
    RetentionError,
    RetentionManager,
    RetentionMatrix,
    RetentionMode,
)
from signet.retention_contract import fake_unknown_purge_job_key
from signet.staging import StagedFile, StagingStore
from signet.state_machine import ApprovalStateMachine
from tests.attachment_fixtures import FAKE_ATTACHMENT_KEY_REF, attachment_cipher

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
def staging(tmp_path: Path, database: Database) -> StagingStore:
    sources = tmp_path / "sources"
    sources.mkdir()
    return StagingStore(
        tmp_path / "staging",
        database=database,
        cipher=attachment_cipher(),
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
        adapter="fake-service",
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


def _exhausted_unknown(
    database: Database,
    *,
    request_id: str,
    staged: StagedFile | None = None,
    key_reference: str | None = None,
) -> str:
    _request(
        database,
        request_id=request_id,
        state=RequestState.OUTCOME_UNKNOWN,
        staged=staged,
        key_reference=key_reference,
    )
    payload_hash = hashlib.sha256(request_id.encode()).hexdigest()
    with database.transaction() as connection:
        connection.execute(
            """
            UPDATE approval_requests
            SET completed_at = NULL,
                safe_outcome_json = '{"provider_candidate":"private-candidate"}'
            WHERE request_id = ?
            """,
            (request_id,),
        )
        connection.execute(
            """
            INSERT INTO execution_attempts(
                attempt_id, request_id, version, payload_hash, fencing_token,
                worker_id, worker_generation, phase, claimed_at,
                dispatch_started_at, reconciliation_attempt_count,
                reconciliation_next_at, reconciliation_resolution,
                reconciliation_exhausted_at,
                reconciliation_notification_required, safe_completion_json,
                outcome_classification
            ) VALUES (?, ?, 1, ?, ?, 'fake-worker', 1, 'outcome_unknown', 200,
                      201, 2, NULL, 'exhausted', 300, 1,
                      '{"provider_candidate":"private-candidate"}',
                      'outcome_unknown')
            """,
            (
                f"attempt-{request_id}",
                request_id,
                payload_hash,
                f"fence-{request_id}",
            ),
        )
    return payload_hash


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
    assert {(row["request_id"], row["intent"], row["created_at"]) for row in rows} == (expected)


def test_scheduler_finds_untombstoned_idempotency_after_payload_was_purged(
    database: Database,
    staging: StagingStore,
) -> None:
    _request(
        database,
        request_id="partial-idempotency",
        state=RequestState.DENIED,
    )
    with database.transaction() as connection:
        connection.execute(
            """
            UPDATE payload_versions
            SET encrypted_payload = NULL, purged_at = ?, purge_reason = 'partial_recovery'
            WHERE request_id = ?
            """,
            (COMPLETED_AT, "partial-idempotency"),
        )
    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(),
        allow_fake_only_unknown_purge=True,
    )

    assert manager.schedule(now=COMPLETED_AT) == 1
    with database.read() as connection:
        jobs = connection.execute(
            "SELECT intent FROM purge_jobs WHERE request_id = ?",
            ("partial-idempotency",),
        ).fetchall()
    assert [row["intent"] for row in jobs] == [PurgeIntent.SENSITIVE_ROWS.value]


def test_scheduler_finds_isolated_staged_key_after_other_data_was_purged(
    database: Database,
    staging: StagingStore,
) -> None:
    staged = _stage(staging, "partial-staged-key")
    _request(
        database,
        request_id="partial-staged-key",
        state=RequestState.DENIED,
        staged=staged,
        key_reference="keychain://Signet/partial-payload-key",
    )
    staging.purge_verified(
        staged.opaque_id,
        expected_path=staged.path,
        expected_size=staged.size,
        expected_sha256=staged.sha256,
        purged_at=COMPLETED_AT,
    )
    with database.transaction() as connection:
        connection.execute(
            """
            UPDATE attachments SET storage_path = NULL, purged_at = ?
            WHERE request_id = ?
            """,
            (COMPLETED_AT, "partial-staged-key"),
        )
        connection.execute(
            """
            UPDATE payload_versions
            SET encrypted_payload = NULL, encryption_key_ref = NULL,
                purged_at = ?, key_destroyed_at = ?, purge_reason = 'partial_recovery'
            WHERE request_id = ?
            """,
            (COMPLETED_AT, COMPLETED_AT, "partial-staged-key"),
        )
        connection.execute(
            "UPDATE idempotency_records SET tombstoned_at = ? WHERE request_id = ?",
            (COMPLETED_AT, "partial-staged-key"),
        )
    destroyer = FakeKeyDestroyer()
    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(payload_delays={state: 0 for state in _PURGEABLE_FIXTURE_STATES}),
        mode=RetentionMode.ISOLATED_PER_REQUEST_KEY,
        key_destroyer=destroyer,
    )

    assert manager.schedule(now=COMPLETED_AT) == 1
    report = manager.run_due(now=COMPLETED_AT)
    assert report.completed == 1
    assert destroyer.calls[0][0] == FAKE_ATTACHMENT_KEY_REF


def test_scheduler_pages_bounded_rows_and_wraps_to_revisit_partial_state(
    database: Database,
    staging: StagingStore,
) -> None:
    _request(
        database,
        request_id="cursor-00",
        state=RequestState.DENIED,
        idempotency=False,
    )
    with database.transaction() as connection:
        connection.execute(
            """
            UPDATE payload_versions
            SET encrypted_payload = NULL, purged_at = ?, purge_reason = 'partial_recovery'
            WHERE request_id = 'cursor-00'
            """,
            (COMPLETED_AT,),
        )
    for index in range(1, 5):
        _request(
            database,
            request_id=f"cursor-{index:02d}",
            state=RequestState.DENIED,
        )
    manager = RetentionManager(database, staging, matrix=_matrix())

    assert manager.schedule(now=COMPLETED_AT, limit=2) == 1
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO idempotency_records(
                origin_namespace, downstream_alias, tool_name, invocation_key,
                payload_fingerprint, request_id, pending_result, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "profile:fake",
                "fake-service",
                "fake_write",
                "late-partial-record",
                "late-partial-fingerprint",
                "cursor-00",
                b'{"status":"pending_approval"}',
                100,
                10_000,
            ),
        )
    assert manager.schedule(now=COMPLETED_AT, limit=2) == 2
    assert manager.schedule(now=COMPLETED_AT, limit=2) == 1
    assert manager.schedule(now=COMPLETED_AT, limit=2) == 1
    with database.read() as connection:
        jobs = connection.execute(
            """
            SELECT request_id FROM purge_jobs
            WHERE intent = 'sensitive_rows' ORDER BY request_id
            """
        ).fetchall()
    assert [row["request_id"] for row in jobs] == [f"cursor-{index:02d}" for index in range(5)]

    for invalid in (0, 1_001, True):
        with pytest.raises(ValueError, match="page limit"):
            manager.schedule(now=COMPLETED_AT, limit=invalid)


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


def test_fake_unknown_purge_requires_acknowledgement_exact_revision_and_exhaustion(
    database: Database, staging: StagingStore
) -> None:
    payload_hash = _exhausted_unknown(database, request_id="unknown-guarded")
    disabled = RetentionManager(database, staging, matrix=_matrix())
    with pytest.raises(RetentionError, match="outside fake-only mode"):
        disabled.authorize_fake_only_exhausted_unknown_purge(
            request_id="unknown-guarded",
            expected_version=1,
            expected_payload_hash=payload_hash,
            acknowledge_possible_external_effect=True,
            now=COMPLETED_AT,
        )
    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(),
        allow_fake_only_unknown_purge=True,
    )

    with pytest.raises(RetentionError, match="explicit possible-effect acknowledgement"):
        manager.authorize_fake_only_exhausted_unknown_purge(
            request_id="unknown-guarded",
            expected_version=1,
            expected_payload_hash=payload_hash,
            acknowledge_possible_external_effect=False,
            now=COMPLETED_AT,
        )
    with pytest.raises(RetentionError, match="current unknown outcome"):
        manager.authorize_fake_only_exhausted_unknown_purge(
            request_id="unknown-guarded",
            expected_version=1,
            expected_payload_hash="0" * 64,
            acknowledge_possible_external_effect=True,
            now=COMPLETED_AT,
        )
    with database.transaction() as connection:
        connection.execute(
            """
            UPDATE execution_attempts
            SET reconciliation_resolution = 'inconclusive',
                reconciliation_next_at = ?
            WHERE request_id = 'unknown-guarded'
            """,
            (COMPLETED_AT + 10,),
        )
    with pytest.raises(RetentionError, match="exhausted reconciliation"):
        manager.authorize_fake_only_exhausted_unknown_purge(
            request_id="unknown-guarded",
            expected_version=1,
            expected_payload_hash=payload_hash,
            acknowledge_possible_external_effect=True,
            now=COMPLETED_AT,
        )
    with database.read() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM request_events WHERE action = ?",
                ("fake_only_unknown_content_purge_authorized",),
            ).fetchone()[0]
            == 0
        )
        assert connection.execute("SELECT count(*) FROM purge_jobs").fetchone()[0] == 0


def test_malformed_fake_purge_event_does_not_block_reconciliation(
    database: Database, staging: StagingStore
) -> None:
    payload_hash = _exhausted_unknown(database, request_id="unknown-malformed-event")
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO request_events(
                request_id, actor, action, occurred_at,
                version, payload_hash, safe_details_json
            ) VALUES (?, 'fake:forged', 'fake_only_unknown_content_purge_authorized',
                      ?, 1, ?, '{}')
            """,
            ("unknown-malformed-event", COMPLETED_AT, payload_hash),
        )

    result = ApprovalStateMachine(database).reconcile(
        "unknown-malformed-event",
        expected_reconciliation_count=2,
        decision=ReconciliationDecision.CONFIRMED_EFFECT,
        worker_id="reconciler",
        now=COMPLETED_AT + 1,
    )
    assert result.action.value == "succeeded"


def test_fake_unknown_purge_rejects_a_job_that_predates_authorization(
    database: Database, staging: StagingStore
) -> None:
    payload_hash = _exhausted_unknown(database, request_id="unknown-preexisting-job")
    job_key = fake_unknown_purge_job_key(
        request_id="unknown-preexisting-job",
        version=1,
        payload_hash=payload_hash,
        intent=PurgeIntent.ATTACHMENTS.value,
    )
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO purge_jobs(
                purge_job_id, request_id, intent, idempotency_key, created_at
            ) VALUES ('preexisting-exact-job', 'unknown-preexisting-job',
                      'attachments', ?, 1)
            """,
            (job_key,),
        )
    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(),
        allow_fake_only_unknown_purge=True,
    )

    with pytest.raises(RetentionError, match="predates its authorization"):
        manager.authorize_fake_only_exhausted_unknown_purge(
            request_id="unknown-preexisting-job",
            expected_version=1,
            expected_payload_hash=payload_hash,
            acknowledge_possible_external_effect=True,
            now=COMPLETED_AT,
        )
    with database.read() as connection:
        events = connection.execute(
            """
            SELECT count(*) FROM request_events
            WHERE request_id = 'unknown-preexisting-job'
              AND action = 'fake_only_unknown_content_purge_authorized'
            """
        ).fetchone()[0]
    assert events == 0


def test_fake_unknown_purge_is_audited_idempotent_and_preserves_uncertainty(
    database: Database, staging: StagingStore
) -> None:
    staged = _stage(staging, "manual-unknown", b"private fake unknown attachment")
    payload_hash = _exhausted_unknown(
        database,
        request_id="unknown-manual",
        staged=staged,
        key_reference="keychain://Signet/manual-unknown-logical",
    )
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO purge_jobs(
                purge_job_id, request_id, intent, idempotency_key, created_at
            ) VALUES ('malicious-unknown-job', 'unknown-manual', 'sensitive_rows',
                      'malicious:unknown', 1)
            """
        )
    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(),
        allow_fake_only_unknown_purge=True,
    )

    assert (
        manager.authorize_fake_only_exhausted_unknown_purge(
            request_id="unknown-manual",
            expected_version=1,
            expected_payload_hash=payload_hash,
            acknowledge_possible_external_effect=True,
            now=COMPLETED_AT,
        )
        == 2
    )
    assert (
        manager.authorize_fake_only_exhausted_unknown_purge(
            request_id="unknown-manual",
            expected_version=1,
            expected_payload_hash=payload_hash,
            acknowledge_possible_external_effect=True,
            now=COMPLETED_AT + 1,
        )
        == 0
    )
    with pytest.raises(ReconciliationRejected, match="purge was already authorized"):
        ApprovalStateMachine(database).reconcile(
            "unknown-manual",
            expected_reconciliation_count=2,
            decision=ReconciliationDecision.CONFIRMED_EFFECT,
            worker_id="late-reconciler",
            now=COMPLETED_AT + 1,
        )
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO request_events(
                request_id, actor, action, occurred_at,
                version, payload_hash, safe_details_json
            ) VALUES ('unknown-manual', 'fake:forged',
                      'fake_only_unknown_content_purge_completed', ?, 1, ?, '{}')
            """,
            (COMPLETED_AT, payload_hash),
        )

    completed = 0
    while claim := manager.claim_due(now=COMPLETED_AT + 1, request_id="unknown-manual"):
        assert claim.state is RequestState.OUTCOME_UNKNOWN
        assert manager.process(claim, now=COMPLETED_AT + 1)
        completed += 1
    assert completed == 2
    assert not staged.path.exists()

    with database.read() as connection:
        request = connection.execute(
            """
            SELECT state, current_version, current_payload_hash, safe_outcome_json,
                   completed_at, revision
            FROM approval_requests WHERE request_id = 'unknown-manual'
            """
        ).fetchone()
        attempt = connection.execute(
            """
            SELECT phase, reconciliation_resolution, reconciliation_exhausted_at,
                   safe_completion_json
            FROM execution_attempts WHERE request_id = 'unknown-manual'
            """
        ).fetchone()
        payload = connection.execute(
            """
            SELECT encrypted_payload, payload_hash, purged_at, purge_reason,
                   encryption_key_ref, key_destroyed_at
            FROM payload_versions WHERE request_id = 'unknown-manual'
            """
        ).fetchone()
        attachment = connection.execute(
            """
            SELECT storage_path, purged_at FROM attachments
            WHERE request_id = 'unknown-manual'
            """
        ).fetchone()
        idempotency = connection.execute(
            """
            SELECT tombstoned_at FROM idempotency_records
            WHERE request_id = 'unknown-manual'
            """
        ).fetchone()
        events = connection.execute(
            """
            SELECT actor, action, version, payload_hash, safe_details_json
            FROM request_events
            WHERE request_id = 'unknown-manual'
              AND action = 'fake_only_unknown_content_purge_authorized'
            """
        ).fetchall()
        completion = connection.execute(
            """
            SELECT actor, safe_details_json FROM request_events
            WHERE request_id = 'unknown-manual'
              AND action = 'fake_only_unknown_content_purge_completed'
            ORDER BY event_id
            """
        ).fetchall()
        jobs = connection.execute(
            """
            SELECT idempotency_key, completed_at FROM purge_jobs
            WHERE request_id = 'unknown-manual' ORDER BY idempotency_key
            """
        ).fetchall()
    assert tuple(request) == (
        "outcome_unknown",
        1,
        payload_hash,
        None,
        None,
        3,
    )
    assert tuple(attempt) == ("outcome_unknown", "exhausted", 300, None)
    assert tuple(payload) == (
        None,
        payload_hash,
        COMPLETED_AT + 1,
        "fake_only_unknown_content",
        "keychain://Signet/manual-unknown-logical",
        None,
    )
    assert tuple(attachment) == (None, COMPLETED_AT + 1)
    assert idempotency["tombstoned_at"] == COMPLETED_AT + 1
    assert [tuple(event) for event in events] == [
        (
            "fake:operator",
            "fake_only_unknown_content_purge_authorized",
            1,
            payload_hash,
            '{"acknowledged_possible_external_effect":true,"fake_only":true}',
        )
    ]
    assert [tuple(event) for event in completion] == [
        ("fake:forged", "{}"),
        ("gateway:retention", '{"isolated_key_destruction":false}'),
    ]
    assert len(jobs) == 3
    malicious = next(row for row in jobs if row["idempotency_key"] == "malicious:unknown")
    assert malicious["completed_at"] is None
    assert all(
        row["completed_at"] == COMPLETED_AT + 1
        for row in jobs
        if row["idempotency_key"] != "malicious:unknown"
    )


def test_fake_unknown_purge_honors_backup_pins_and_recovers_after_unlink_crash(
    database: Database, staging: StagingStore
) -> None:
    staged = _stage(staging, "manual-unknown-crash")
    payload_hash = _exhausted_unknown(
        database,
        request_id="unknown-crash",
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
        allow_fake_only_unknown_purge=True,
        fault_injector=crash,
    )
    pins = BackupPins(database)
    lease = pins.acquire(now=COMPLETED_AT)
    with pytest.raises(RetentionError, match="backup is active"):
        manager.authorize_fake_only_exhausted_unknown_purge(
            request_id="unknown-crash",
            expected_version=1,
            expected_payload_hash=payload_hash,
            acknowledge_possible_external_effect=True,
            now=COMPLETED_AT,
        )
    with database.read() as connection:
        assert (
            connection.execute(
                """
                SELECT count(*) FROM request_events
                WHERE request_id = 'unknown-crash'
                  AND action = 'fake_only_unknown_content_purge_authorized'
                """
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                """
                SELECT count(*) FROM purge_jobs
                WHERE request_id = 'unknown-crash' AND intent != 'backup_pin'
                """
            ).fetchone()[0]
            == 0
        )
    pins.release(lease, now=COMPLETED_AT + 1)
    manager.authorize_fake_only_exhausted_unknown_purge(
        request_id="unknown-crash",
        expected_version=1,
        expected_payload_hash=payload_hash,
        acknowledge_possible_external_effect=True,
        now=COMPLETED_AT + 1,
    )
    disabled = RetentionManager(database, staging, matrix=_matrix())
    assert disabled.claim_due(now=COMPLETED_AT + 1, request_id="unknown-crash") is None
    with pytest.raises(BackupPinConflict, match="in progress"):
        pins.acquire(now=COMPLETED_AT + 1)

    claim = manager.claim_due(now=COMPLETED_AT + 1, request_id="unknown-crash")
    assert claim is not None and claim.intent is PurgeIntent.ATTACHMENTS
    with pytest.raises(SimulatedCrash):
        manager.process(claim, now=COMPLETED_AT + 1)
    assert not staged.path.exists()

    restarted = RetentionManager(
        database,
        staging,
        matrix=_matrix(),
        claim_lease_seconds=10,
        allow_fake_only_unknown_purge=True,
    )
    recovered = restarted.claim_due(now=COMPLETED_AT + 12, request_id="unknown-crash")
    assert recovered is not None and recovered.intent is PurgeIntent.ATTACHMENTS
    assert restarted.process(recovered, now=COMPLETED_AT + 12)


def test_payload_only_backup_pin_blocks_fake_unknown_purge_claim(
    database: Database, staging: StagingStore
) -> None:
    payload_hash = _exhausted_unknown(database, request_id="unknown-payload-pin")
    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(),
        allow_fake_only_unknown_purge=True,
    )
    pins = BackupPins(database)
    lease = pins.acquire(now=COMPLETED_AT)
    assert lease.request_ids == ("unknown-payload-pin",)
    with pytest.raises(RetentionError, match="backup is active"):
        manager.authorize_fake_only_exhausted_unknown_purge(
            request_id="unknown-payload-pin",
            expected_version=1,
            expected_payload_hash=payload_hash,
            acknowledge_possible_external_effect=True,
            now=COMPLETED_AT,
        )
    pins.release(lease, now=COMPLETED_AT + 1)
    manager.authorize_fake_only_exhausted_unknown_purge(
        request_id="unknown-payload-pin",
        expected_version=1,
        expected_payload_hash=payload_hash,
        acknowledge_possible_external_effect=True,
        now=COMPLETED_AT + 1,
    )
    assert manager.claim_due(now=COMPLETED_AT + 1, request_id="unknown-payload-pin") is not None


def test_purge_claims_are_serialized_per_request(database: Database, staging: StagingStore) -> None:
    staged = _stage(staging, "serialized-purge")
    payload_hash = _exhausted_unknown(
        database,
        request_id="unknown-serialized",
        staged=staged,
    )
    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(),
        allow_fake_only_unknown_purge=True,
    )
    manager.authorize_fake_only_exhausted_unknown_purge(
        request_id="unknown-serialized",
        expected_version=1,
        expected_payload_hash=payload_hash,
        acknowledge_possible_external_effect=True,
        now=COMPLETED_AT,
    )

    first = manager.claim_due(now=COMPLETED_AT, request_id="unknown-serialized")
    assert first is not None and first.intent is PurgeIntent.ATTACHMENTS
    assert manager.claim_due(now=COMPLETED_AT, request_id="unknown-serialized") is None
    assert manager.process(first, now=COMPLETED_AT)
    second = manager.claim_due(now=COMPLETED_AT, request_id="unknown-serialized")
    assert second is not None and second.intent is PurgeIntent.SENSITIVE_ROWS


def test_fake_unknown_purge_destroys_isolated_request_keys(
    database: Database, staging: StagingStore
) -> None:
    staged = _stage(staging, "manual-unknown-isolated")
    payload_key = "keychain://Signet/manual-unknown-isolated"
    payload_hash = _exhausted_unknown(
        database,
        request_id="unknown-isolated",
        staged=staged,
        key_reference=payload_key,
    )
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO purge_jobs(
                purge_job_id, request_id, intent, idempotency_key, created_at
            ) VALUES ('unrelated-isolated-job', 'unknown-isolated', 'sensitive_rows',
                      'malicious:isolated', 1)
            """
        )
    destroyer = FakeKeyDestroyer()
    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(),
        mode=RetentionMode.ISOLATED_PER_REQUEST_KEY,
        key_destroyer=destroyer,
        allow_fake_only_unknown_purge=True,
    )

    assert (
        manager.authorize_fake_only_exhausted_unknown_purge(
            request_id="unknown-isolated",
            expected_version=1,
            expected_payload_hash=payload_hash,
            acknowledge_possible_external_effect=True,
            now=COMPLETED_AT,
        )
        == 3
    )
    intents: list[PurgeIntent] = []
    while claim := manager.claim_due(now=COMPLETED_AT, request_id="unknown-isolated"):
        assert manager.process(claim, now=COMPLETED_AT)
        intents.append(claim.intent)
    assert intents == [
        PurgeIntent.ATTACHMENTS,
        PurgeIntent.SENSITIVE_ROWS,
        PurgeIntent.ENCRYPTION_KEY,
    ]
    assert {call[0] for call in destroyer.calls} == {payload_key, FAKE_ATTACHMENT_KEY_REF}
    with database.read() as connection:
        payload = connection.execute(
            """
            SELECT encrypted_payload, encryption_key_ref, purged_at,
                   key_destroyed_at, purge_reason
            FROM payload_versions WHERE request_id = 'unknown-isolated'
            """
        ).fetchone()
    assert tuple(payload) == (
        None,
        None,
        COMPLETED_AT,
        COMPLETED_AT,
        "fake_only_unknown_content",
    )


def test_logical_purge_clears_body_but_never_claims_key_destruction(
    database: Database, staging: StagingStore
) -> None:
    _request(
        database,
        request_id="logical-purge",
        state=RequestState.DENIED,
        key_reference="keychain://Signet/fake-logical",
    )
    matrix = _matrix(payload_delays={state: 0 for state in _PURGEABLE_FIXTURE_STATES})
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


def test_isolated_purge_destroys_payload_and_attachment_keys_after_unlink(
    database: Database, staging: StagingStore
) -> None:
    staged = _stage(staging, "isolated-attachment")
    payload_key = "keychain://Signet/fake-isolated-payload"
    _request(
        database,
        request_id="isolated-attachment",
        state=RequestState.DENIED,
        staged=staged,
        key_reference=payload_key,
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
    assert report.completed == 3
    assert {call[0] for call in destroyer.calls} == {
        payload_key,
        FAKE_ATTACHMENT_KEY_REF,
    }
    assert not staged.path.exists()
    with database.read() as connection:
        catalog = connection.execute(
            """
            SELECT storage_path, encryption_key_ref, purged_at, key_destroyed_at
            FROM staged_objects WHERE attachment_id = ?
            """,
            (staged.opaque_id,),
        ).fetchone()
    assert tuple(catalog) == (None, None, COMPLETED_AT, COMPLETED_AT)


def test_isolated_key_destruction_refuses_a_ref_used_by_unconsumed_staging(
    database: Database, staging: StagingStore
) -> None:
    _stage(staging, "unconsumed-shared-key")
    _request(
        database,
        request_id="payload-sharing-staging-key",
        state=RequestState.DENIED,
        key_reference=FAKE_ATTACHMENT_KEY_REF,
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
    assert report.failed == 1
    assert destroyer.calls == []
    with database.read() as connection:
        error = connection.execute(
            """
            SELECT last_error FROM purge_jobs
            WHERE request_id = 'payload-sharing-staging-key'
              AND intent = 'encryption_key'
            """
        ).fetchone()[0]
    assert error == "key_reference_shared"


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
    with (
        pytest.raises(IntegrityError, match="catalog path mismatch"),
        database.transaction() as connection,
    ):
        connection.execute(
            """
            UPDATE attachments SET storage_path = ?
            WHERE request_id = 'attachment-tampered'
            """,
            (str(outside),),
        )
    assert outside.exists()


def test_purge_retry_status_matches_failure_backoff_and_due_replay(
    database: Database, staging: StagingStore
) -> None:
    staged = _stage(staging, "retry-status")
    _request(
        database,
        request_id="retry-status",
        state=RequestState.DENIED,
        staged=staged,
    )
    failed_once = False

    def fail_after_unlink(stage: str) -> None:
        nonlocal failed_once
        if stage == "attachment_unlinked" and not failed_once:
            failed_once = True
            raise RuntimeError("synthetic worker failure")

    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(
            payload_delays={state: 0 for state in _PURGEABLE_FIXTURE_STATES},
        ),
        claim_lease_seconds=10,
        retry_delay_seconds=60,
        fault_injector=fail_after_unlink,
    )
    assert manager.schedule(now=COMPLETED_AT) == 2
    with database.read() as connection:
        keys = tuple(
            str(row["idempotency_key"])
            for row in connection.execute(
                """
                SELECT idempotency_key FROM purge_jobs
                WHERE request_id = 'retry-status' AND intent != 'backup_pin'
                ORDER BY intent
                """
            ).fetchall()
        )

    failed = manager.claim_due(now=COMPLETED_AT, request_id="retry-status")
    assert failed is not None and failed.intent is PurgeIntent.ATTACHMENTS
    assert manager.process(failed, now=COMPLETED_AT) is False
    remaining = manager.claim_due(now=COMPLETED_AT, request_id="retry-status")
    assert remaining is not None and remaining.intent is PurgeIntent.SENSITIVE_ROWS
    assert manager.process(remaining, now=COMPLETED_AT)

    status = manager.pending_retry_status(idempotency_keys=keys, now=COMPLETED_AT)
    assert status is not None
    assert status.reason == "worker_failure"
    assert status.retry_after == 60
    assert manager.claim_due(now=COMPLETED_AT + 59, request_id="retry-status") is None
    early = manager.pending_retry_status(
        idempotency_keys=keys,
        now=COMPLETED_AT + 59,
    )
    assert early is not None and early.retry_after == 1

    replay = manager.claim_due(now=COMPLETED_AT + 60, request_id="retry-status")
    assert replay is not None and replay.intent is PurgeIntent.ATTACHMENTS
    assert manager.process(replay, now=COMPLETED_AT + 60)
    assert manager.pending_retry_status(idempotency_keys=keys, now=COMPLETED_AT + 60) is None


def test_purge_retry_status_matches_strict_abandoned_claim_lease(
    database: Database, staging: StagingStore
) -> None:
    staged = _stage(staging, "claim-retry-status")
    _request(
        database,
        request_id="claim-retry-status",
        state=RequestState.DENIED,
        staged=staged,
    )
    manager = RetentionManager(
        database,
        staging,
        matrix=_matrix(
            payload_delays={state: 0 for state in _PURGEABLE_FIXTURE_STATES},
        ),
        claim_lease_seconds=10,
    )
    assert manager.schedule(now=COMPLETED_AT) == 2
    with database.read() as connection:
        keys = tuple(
            str(row["idempotency_key"])
            for row in connection.execute(
                """
                SELECT idempotency_key FROM purge_jobs
                WHERE request_id = 'claim-retry-status' AND intent != 'backup_pin'
                ORDER BY intent
                """
            ).fetchall()
        )
    abandoned = manager.claim_due(now=COMPLETED_AT, request_id="claim-retry-status")
    assert abandoned is not None

    active = manager.pending_retry_status(idempotency_keys=keys, now=COMPLETED_AT)
    assert active is not None
    assert active.reason == "claim_lease_active"
    assert active.retry_after == 11
    assert manager.claim_due(now=COMPLETED_AT + 10, request_id="claim-retry-status") is None
    boundary = manager.pending_retry_status(
        idempotency_keys=keys,
        now=COMPLETED_AT + 10,
    )
    assert boundary is not None and boundary.retry_after == 1
    reclaimed = manager.claim_due(now=COMPLETED_AT + 11, request_id="claim-retry-status")
    assert reclaimed is not None and reclaimed.purge_job_id == abandoned.purge_job_id
    assert manager.process(reclaimed, now=COMPLETED_AT + 11)


def test_purge_retry_status_rejects_unbounded_keys_and_never_echoes_unsafe_errors(
    database: Database, staging: StagingStore
) -> None:
    _request(database, request_id="retry-status-safe", state=RequestState.DENIED)
    manager = RetentionManager(database, staging, matrix=_matrix())
    assert manager.schedule(now=COMPLETED_AT) == 1
    with database.transaction() as connection:
        job = connection.execute(
            """
            SELECT idempotency_key FROM purge_jobs
            WHERE request_id = 'retry-status-safe'
            """
        ).fetchone()
        connection.execute(
            """
            UPDATE purge_jobs SET created_at = ?, last_error = ?
            WHERE idempotency_key = ?
            """,
            (COMPLETED_AT + 5, "private/path\noperator-secret", job["idempotency_key"]),
        )
    status = manager.pending_retry_status(
        idempotency_keys=(str(job["idempotency_key"]),),
        now=COMPLETED_AT,
    )
    assert status is not None
    assert status.reason == "retry_backoff"
    assert status.retry_after == 5
    assert "private" not in repr(status)
    for invalid in ((), ("",), ("x" * 1_025,), tuple("x" for _ in range(17))):
        with pytest.raises(ValueError, match="keys are invalid"):
            manager.pending_retry_status(idempotency_keys=invalid, now=COMPLETED_AT)


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
    restarted_manager = RetentionManager(Database(database.path), staging, matrix=_matrix())
    assert restarted_manager.claim_due(now=COMPLETED_AT + 10_000) is None
    assert (
        restarted_pins.release_abandoned(
            before=COMPLETED_AT,
            now=COMPLETED_AT + 10_000,
        )
        == 1
    )
    claim = restarted_manager.claim_due(now=COMPLETED_AT + 10_000)
    assert claim is not None


def test_authorization_and_backup_pin_creation_are_atomic_across_threads(
    database: Database, staging: StagingStore
) -> None:
    request_id = "unknown-threaded-pin-race"
    payload_hash = _exhausted_unknown(
        database,
        request_id=request_id,
        staged=_stage(staging, "unknown-threaded-pin-race"),
    )
    _request(
        database,
        request_id="threaded-unrelated-pin-target",
        state=RequestState.PENDING_APPROVAL,
    )
    barrier = Barrier(2)

    def authorize() -> bool:
        manager = RetentionManager(
            Database(database.path),
            staging,
            matrix=_matrix(),
            allow_fake_only_unknown_purge=True,
        )
        barrier.wait()
        try:
            manager.authorize_fake_only_exhausted_unknown_purge(
                request_id=request_id,
                expected_version=1,
                expected_payload_hash=payload_hash,
                acknowledge_possible_external_effect=True,
                now=COMPLETED_AT,
            )
        except RetentionError as exc:
            assert str(exc) == "fake-only purge cannot start while a backup is active"
            return False
        return True

    def pin() -> BackupPinLease | None:
        pins = BackupPins(Database(database.path))
        barrier.wait()
        try:
            return pins.acquire(now=COMPLETED_AT)
        except BackupPinConflict as exc:
            assert str(exc) == "attachment purge is already in progress"
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        authorization_future = pool.submit(authorize)
        pin_future = pool.submit(pin)
        authorized = authorization_future.result(timeout=10)
        lease = pin_future.result(timeout=10)

    assert authorized is (lease is None)
    with database.read() as connection:
        authorized_events = connection.execute(
            """
            SELECT count(*) FROM request_events
            WHERE request_id = ?
              AND action = 'fake_only_unknown_content_purge_authorized'
            """,
            (request_id,),
        ).fetchone()[0]
        purge_jobs = connection.execute(
            """
            SELECT count(*) FROM purge_jobs
            WHERE request_id = ? AND intent != 'backup_pin'
            """,
            (request_id,),
        ).fetchone()[0]
    if authorized:
        assert authorized_events == 1
        assert purge_jobs == 2
        manager = RetentionManager(
            Database(database.path),
            staging,
            matrix=_matrix(),
            allow_fake_only_unknown_purge=True,
        )
        while claim := manager.claim_due(now=COMPLETED_AT, request_id=request_id):
            assert manager.process(claim, now=COMPLETED_AT)
        post_purge_pins = BackupPins(Database(database.path))
        post_purge_lease = post_purge_pins.acquire(now=COMPLETED_AT + 1)
        assert post_purge_lease.request_ids == ("threaded-unrelated-pin-target",)
        post_purge_pins.release(post_purge_lease, now=COMPLETED_AT + 2)
    else:
        assert lease is not None
        assert authorized_events == 0
        assert purge_jobs == 0
        restarted_pins = BackupPins(Database(database.path))
        restarted_pins.release(lease, now=COMPLETED_AT + 1)
        restarted_manager = RetentionManager(
            Database(database.path),
            staging,
            matrix=_matrix(),
            allow_fake_only_unknown_purge=True,
        )
        assert (
            restarted_manager.authorize_fake_only_exhausted_unknown_purge(
                request_id=request_id,
                expected_version=1,
                expected_payload_hash=payload_hash,
                acknowledge_possible_external_effect=True,
                now=COMPLETED_AT + 1,
            )
            == 2
        )


_PURGEABLE_FIXTURE_STATES = {
    RequestState.SUCCEEDED,
    RequestState.FAILED,
    RequestState.DENIED,
    RequestState.EXPIRED,
    RequestState.CANCELLED,
}
