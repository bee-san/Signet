from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from signet.db import Database
from signet.models import EnqueueRequest
from signet.notification_outbox import (
    NotificationOutboxWorker,
    SQLiteNotificationOutbox,
    enqueue_notification,
)
from signet.notifications import (
    InMemoryPushRepository,
    NotificationDispatcher,
    NotificationKind,
    PushMessage,
    PushSubscription,
)
from signet.state_machine import ApprovalStateMachine

NOW = 1_900_000_000


def _encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _request(request_id: str, *, expires_at: int = NOW + 60) -> EnqueueRequest:
    payload_hash = "a" * 64
    return EnqueueRequest(
        request_id=request_id,
        downstream_alias="fastmail",
        tool_name="send_email",
        policy_mode="approval",
        origin_namespace="profile:test",
        encrypted_payload=b"fake:encrypted",
        payload_hash=payload_hash,
        payload_fingerprint="b" * 64,
        pending_result=b'{"status":"pending_approval"}',
        created_at=NOW,
        expires_at=expires_at,
        policy_version="1",
        adapter_version="1",
        schema_version="1",
        editor_actor="caller:test",
    )


@pytest.fixture
def database(tmp_path: Path) -> Database:
    selected = Database(tmp_path / "outbox.sqlite3")
    selected.initialize()
    return selected


def test_transactional_insert_rolls_back_and_dedupe_survives_restart(
    database: Database,
) -> None:
    message = PushMessage(
        NotificationKind.NEW_PENDING,
        service="Fastmail",
        action="send_email",
    )
    with (
        pytest.raises(RuntimeError, match="fake rollback"),
        database.transaction() as connection,
    ):
        enqueue_notification(
            connection,
            dedupe_key="new_pending:req_Fake:1",
            user_id="human@example.test",
            message=message,
            created_at=NOW,
        )
        raise RuntimeError("fake rollback")

    outbox = SQLiteNotificationOutbox(database)
    assert outbox.enqueue(
        dedupe_key="new_pending:req_Fake:1",
        user_id="human@example.test",
        message=message,
        created_at=NOW,
    )
    restarted = SQLiteNotificationOutbox(Database(database.path))
    assert not restarted.enqueue(
        dedupe_key="new_pending:req_Fake:1",
        user_id="human@example.test",
        message=message,
        created_at=NOW,
    )
    with database.read() as connection:
        assert connection.execute("SELECT count(*) FROM notification_outbox").fetchone()[0] == 1


def test_claims_are_fenced_and_stale_claims_are_restart_recoverable(
    database: Database,
) -> None:
    outbox = SQLiteNotificationOutbox(database)
    outbox.enqueue(
        dedupe_key="daily_digest:test:2026-07-15",
        user_id="human",
        message=PushMessage(NotificationKind.DAILY_DIGEST, count=3),
        created_at=NOW,
    )

    first = outbox.claim_due(worker_id="worker-one", now=NOW, lease_seconds=60)
    assert len(first) == 1 and first[0].attempts == 1
    assert outbox.claim_due(worker_id="worker-two", now=NOW + 59, lease_seconds=60) == ()

    restarted = SQLiteNotificationOutbox(Database(database.path))
    second = restarted.claim_due(worker_id="worker-two", now=NOW + 60, lease_seconds=60)
    assert len(second) == 1 and second[0].attempts == 2
    assert second[0].claim_token != first[0].claim_token
    assert not outbox.mark_delivered(first[0], now=NOW + 60)
    assert restarted.mark_delivered(second[0], now=NOW + 60)
    assert restarted.claim_due(worker_id="worker-three", now=NOW + 120) == ()


class RecordingTransport:
    def __init__(self) -> None:
        self.payloads: list[dict[str, str | int]] = []

    async def send(
        self,
        subscription: PushSubscription,
        payload: Mapping[str, str | int],
    ) -> None:
        del subscription
        self.payloads.append(dict(payload))


@pytest.mark.asyncio
async def test_worker_delivers_privacy_safe_payload_and_settles_intent(
    database: Database,
) -> None:
    repository = InMemoryPushRepository()
    repository.save(
        PushSubscription(
            subscription_id="push_test",
            user_id="human",
            endpoint="https://push.example.test/device",
            p256dh=_encoded(b"\x04" + b"p" * 64),
            auth=_encoded(b"a" * 16),
            device_label="Test phone",
            categories=frozenset(),
            created_at=NOW,
        )
    )
    transport = RecordingTransport()
    dispatcher = NotificationDispatcher(repository, transport)
    outbox = SQLiteNotificationOutbox(database)
    outbox.enqueue(
        dedupe_key="outcome_unknown_entered:attempt:1",
        user_id="human",
        message=PushMessage(
            NotificationKind.OUTCOME_UNKNOWN_ENTERED,
            service="WhatsApp",
            action="send_text",
        ),
        created_at=NOW,
    )
    worker = NotificationOutboxWorker(outbox, dispatcher, worker_id="push-worker")

    report = await worker.run_due(now=NOW)

    assert (report.claimed, report.delivered, report.deferred) == (1, 1, 0)
    assert len(transport.payloads) == 1
    serialized = json.dumps(transport.payloads[0])
    assert "outcome_unknown_entered:attempt:1" not in serialized
    assert "request_id" not in serialized
    with database.read() as connection:
        row = connection.execute(
            "SELECT delivered_at, claim_token, last_error FROM notification_outbox"
        ).fetchone()
    assert tuple(row) == (NOW, None, None)


class BrokenDispatcher:
    async def notify(self, user_id: str, message: PushMessage, *, now: int) -> None:
        del user_id, message, now
        raise RuntimeError("explicit fake dispatcher outage")


@pytest.mark.asyncio
async def test_worker_defers_system_failure_with_bounded_backoff(database: Database) -> None:
    outbox = SQLiteNotificationOutbox(database)
    outbox.enqueue(
        dedupe_key="daily_digest:test:2026-07-16",
        user_id="human",
        message=PushMessage(NotificationKind.DAILY_DIGEST, count=0),
        created_at=NOW,
    )
    worker = NotificationOutboxWorker(
        outbox,
        cast(Any, BrokenDispatcher()),
        worker_id="broken-worker",
        retry_base_seconds=7,
    )

    report = await worker.run_due(now=NOW)

    assert report.deferred == 1
    assert outbox.claim_due(worker_id="early", now=NOW + 6) == ()
    retried = outbox.claim_due(worker_id="retry", now=NOW + 7)
    assert len(retried) == 1 and retried[0].attempts == 2
    with database.read() as connection:
        assert connection.execute(
            "SELECT last_error FROM notification_outbox"
        ).fetchone()[0] is None


def test_expiry_and_daily_schedulers_are_idempotent(database: Database) -> None:
    machine = ApprovalStateMachine(database)
    machine.enqueue(_request("req_DueSoon", expires_at=NOW + 30))
    machine.enqueue(_request("req_Later", expires_at=NOW + 10_000))
    outbox = SQLiteNotificationOutbox(database)

    assert outbox.schedule_approaching_expiry(
        user_id="human@example.test",
        now=NOW,
        horizon_seconds=60,
    ) == 1
    assert outbox.schedule_approaching_expiry(
        user_id="human@example.test",
        now=NOW,
        horizon_seconds=60,
    ) == 0
    assert outbox.schedule_daily_digest(user_id="human@example.test", now=NOW)
    assert not outbox.schedule_daily_digest(user_id="human@example.test", now=NOW + 1)

    claimed = outbox.claim_due(worker_id="scheduler-test", now=NOW)
    assert sorted(intent.message.kind for intent in claimed) == [
        NotificationKind.APPROACHING_EXPIRY,
        NotificationKind.DAILY_DIGEST,
    ]
    digest = next(
        intent for intent in claimed if intent.message.kind is NotificationKind.DAILY_DIGEST
    )
    assert digest.message.count == 2


def test_state_enqueue_and_notification_intent_commit_or_rollback_together(
    database: Database,
) -> None:
    def fail(point: str) -> None:
        if point == "enqueue:before_commit":
            raise RuntimeError("explicit fake enqueue fault")

    failing = ApprovalStateMachine(
        database,
        notification_user_id="human",
        fault_injector=fail,
    )
    with pytest.raises(RuntimeError, match="enqueue fault"):
        failing.enqueue(_request("req_RolledBack"))
    with database.read() as connection:
        assert connection.execute("SELECT count(*) FROM approval_requests").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM notification_outbox").fetchone()[0] == 0

    restarted = ApprovalStateMachine(database, notification_user_id="human")
    restarted.enqueue(_request("req_Committed"))
    with database.read() as connection:
        row = connection.execute(
            "SELECT kind, request_id, service, action FROM notification_outbox"
        ).fetchone()
    assert tuple(row) == ("new_pending", "req_Committed", "fastmail", "send_email")
