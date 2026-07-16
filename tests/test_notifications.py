from __future__ import annotations

import asyncio
import base64
import json
import threading
import time
import traceback
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest
import requests

import signet.notifications as notifications_module
from signet.credential_broker import Secret
from signet.db import Database
from signet.notifications import (
    InMemoryPushRepository,
    NotificationDispatcher,
    NotificationKind,
    PushDeliveryError,
    PushMessage,
    PushSubscription,
    SQLitePushRepository,
    WebPushTransport,
    new_subscription,
)


class FakeTransport:
    def __init__(self, *, failing: set[str] | None = None) -> None:
        self.failing = failing or set()
        self.calls: list[tuple[str, dict[str, str | int]]] = []

    async def send(
        self,
        subscription: PushSubscription,
        payload: Mapping[str, str | int],
    ) -> None:
        self.calls.append((subscription.subscription_id, dict(payload)))
        if subscription.subscription_id in self.failing:
            raise RuntimeError("explicit fake push failure")


class BlockingRepository(InMemoryPushRepository):
    def __init__(self, operation: str) -> None:
        super().__init__()
        self.operation = operation
        self.started = threading.Event()
        self.release = threading.Event()

    def _block(self, operation: str) -> None:
        if self.operation != operation:
            return
        self.started.set()
        if not self.release.wait(timeout=5):
            raise AssertionError("blocking notification repository call was not released")

    def active_for(
        self,
        user_id: str,
        kind: NotificationKind,
    ) -> tuple[PushSubscription, ...]:
        self._block("read")
        return super().active_for(user_id, kind)

    def mark_success(self, subscription_id: str, *, now: int) -> None:
        self._block("success")
        super().mark_success(subscription_id, now=now)

    def mark_failure(self, subscription_id: str, *, now: int, disable_after: int) -> None:
        self._block("failure")
        super().mark_failure(subscription_id, now=now, disable_after=disable_after)


def subscription(
    identifier: str,
    *,
    user_id: str = "autumn",
    categories: frozenset[NotificationKind] = frozenset(),
) -> PushSubscription:
    return PushSubscription(
        subscription_id=identifier,
        user_id=user_id,
        endpoint=f"https://push.example.test/{identifier}",
        p256dh=_encoded(b"\x04" + b"p" * 64),
        auth=_encoded(b"a" * 16),
        device_label="Test phone",
        categories=categories,
        created_at=1_800_000_000,
    )


def _encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@pytest.mark.parametrize("kind", tuple(NotificationKind)[:-1])
def test_event_payloads_exclude_request_and_downstream_metadata(kind: NotificationKind) -> None:
    message = PushMessage(kind, service="Fastmail", action="send_email")
    payload = message.payload()
    serialized = json.dumps(payload)
    assert set(payload) == {"title", "kind", "tag", "url", "body"}
    assert payload["title"] == "Signet"
    assert payload["url"] == "/"
    for secret in (
        "Fastmail",
        "send_email",
        "person@example.test",
        "Viewing on Tuesday",
        "private message body",
        "req_01JSECRET",
    ):
        assert secret not in serialized


def test_daily_digest_contains_only_count() -> None:
    payload = PushMessage(NotificationKind.DAILY_DIGEST, count=4).payload()
    assert payload["count"] == 4
    assert "service" not in payload and "action" not in payload
    with pytest.raises(ValueError):
        PushMessage(NotificationKind.DAILY_DIGEST, service="Fastmail", count=1)


@pytest.mark.parametrize(
    ("service", "action"),
    [
        ("provider", "send:thing"),
        ("provider", "x" * 65),
        ("provider", "send\nthing"),
        ("provider", "envoyer_é"),
        (None, None),
    ],
)
def test_invalid_event_labels_degrade_to_privacy_safe_fallbacks(
    service: str | None,
    action: str | None,
) -> None:
    payload = PushMessage(
        NotificationKind.NEW_PENDING,
        service=service,
        action=action,
    ).payload()

    assert "service" not in payload
    assert "action" not in payload
    assert "send:thing" not in str(payload)


def test_mcp_approval_copy_does_not_claim_delivery_before_dispatch() -> None:
    payload = PushMessage(
        NotificationKind.MCP_APPROVED,
        service="Fastmail",
        action="send_email",
    ).payload()

    assert payload["body"] == "Request approved via chat"
    assert "dispatch" not in str(payload["body"]).lower()


@pytest.mark.asyncio
async def test_push_failure_never_escapes_and_disables_only_failing_device() -> None:
    repository = InMemoryPushRepository()
    repository.save(subscription("ok"))
    repository.save(subscription("bad"))
    transport = FakeTransport(failing={"bad"})
    dispatcher = NotificationDispatcher(repository, transport, disable_after=2)
    message = PushMessage(
        NotificationKind.OUTCOME_UNKNOWN_ENTERED,
        service="WhatsApp",
        action="send_text",
    )

    first = await dispatcher.notify("autumn", message, now=1_800_000_001)
    second = await dispatcher.notify("autumn", message, now=1_800_000_002)
    third = await dispatcher.notify("autumn", message, now=1_800_000_003)

    assert (first.attempted, first.delivered, first.failed) == (2, 1, 1)
    assert (second.attempted, second.delivered, second.failed) == (2, 1, 1)
    assert (third.attempted, third.delivered, third.failed) == (1, 1, 0)
    assert repository.get("bad").disabled_at == 1_800_000_002  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_categories_users_and_unsubscribe_are_enforced_before_transport() -> None:
    repository = InMemoryPushRepository()
    repository.save(subscription("digest", categories=frozenset({NotificationKind.DAILY_DIGEST})))
    repository.save(subscription("other-user", user_id="other"))
    repository.save(subscription("all"))
    assert repository.unsubscribe(
        "autumn",
        "https://push.example.test/all",
        now=1_800_000_001,
    )
    transport = FakeTransport()
    dispatcher = NotificationDispatcher(repository, transport)

    report = await dispatcher.notify(
        "autumn",
        PushMessage(NotificationKind.NEW_PENDING, service="Fastmail", action="send_email"),
        now=1_800_000_002,
    )
    assert report.attempted == 0
    assert transport.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "transport_fails"),
    [("read", False), ("success", False), ("failure", True)],
)
async def test_blocking_notification_repository_does_not_stall_event_loop(
    operation: str,
    transport_fails: bool,
) -> None:
    repository = BlockingRepository(operation)
    repository.save(subscription("device"))
    transport = FakeTransport(failing={"device"} if transport_fails else set())
    dispatcher = NotificationDispatcher(repository, transport)
    safety_release = threading.Timer(3, repository.release.set)
    safety_release.start()
    waiting_started_at = time.monotonic()
    try:
        notifying = asyncio.create_task(
            dispatcher.notify(
                "autumn",
                PushMessage(
                    NotificationKind.NEW_PENDING,
                    service="Fastmail",
                    action="send_email",
                ),
                now=1_800_000_001,
            )
        )
        assert await asyncio.to_thread(repository.started.wait, 1)
        assert time.monotonic() - waiting_started_at < 2
        assert not repository.release.is_set()
        await asyncio.wait_for(asyncio.sleep(0), timeout=1)
        repository.release.set()
        report = await notifying
    finally:
        repository.release.set()
        safety_release.cancel()

    assert report.attempted == 1
    assert (report.delivered, report.failed) == ((0, 1) if transport_fails else (1, 0))


def test_subscription_validation_and_representations_redact_endpoint_and_keys() -> None:
    created = new_subscription(
        user_id="autumn",
        endpoint="https://push.example.test/device-secret",
        p256dh=_encoded(b"\x04" + b"p" * 64),
        auth=_encoded(b"a" * 16),
        device_label="Phone",
        created_at=1_800_000_000,
    )
    assert "device-secret" not in repr(created)
    assert created.p256dh not in repr(created)
    with pytest.raises(ValueError):
        new_subscription(
            user_id="autumn",
            endpoint="http://push.example.test/device",
            p256dh="fake",
            auth="fake",
            device_label="Phone",
            created_at=1_800_000_000,
        )
    for changes in (
        {"p256dh": _encoded(b"\x04" + b"p" * 63)},
        {"p256dh": _encoded(b"\x03" + b"p" * 64)},
        {"auth": _encoded(b"a" * 15)},
        {"auth": "not+base64"},
        {"endpoint": "https://user@push.example.test/device"},
        {"device_label": "Phone\nInjected"},
    ):
        with pytest.raises(ValueError):
            new_subscription(
                user_id="autumn",
                endpoint=str(changes.get("endpoint", "https://push.example.test/device")),
                p256dh=str(changes.get("p256dh", _encoded(b"\x04" + b"p" * 64))),
                auth=str(changes.get("auth", _encoded(b"a" * 16))),
                device_label=str(changes.get("device_label", "Phone")),
                created_at=1_800_000_000,
            )

    transport = WebPushTransport(
        Secret("vapid-private-material"),
        subject="mailto:test@example.test",
        allowed_push_origins=frozenset({"https://push.example.test"}),
    )
    assert "vapid-private-material" not in repr(transport)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1/device",
        "https://10.0.0.1/device",
        "https://172.16.0.1/device",
        "https://192.168.1.1/device",
        "https://169.254.169.254/latest/meta-data",
        "https://127.1/device",
        "https://127.0.1/device",
        "https://127.000.000.001/device",
        "https://0x7f.0.0.1/device",
        "https://0177.0.0.1/device",
        "https://0300.0250.0001.0001/device",
        "https://[::1]/device",
        "https://[fe80::1]/device",
        "https://localhost/device",
        "https://push.local/device",
        "https://push.internal/device",
        "https://push.example.test./device",
        "https://user@push.example.test/device",
        "https://other.example.test/device",
    ],
)
@pytest.mark.asyncio
async def test_web_push_rejects_nonpublic_or_nonallowlisted_endpoints_before_network(
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(notifications_module, "webpush", lambda **kwargs: calls.append(kwargs))
    transport = WebPushTransport(
        Secret("vapid-private-material"),
        subject="mailto:test@example.test",
        allowed_push_origins=frozenset({"https://push.example.test"}),
    )

    with pytest.raises(PushDeliveryError, match="browser push delivery failed"):
        await transport.send(
            replace(subscription("blocked"), endpoint=endpoint),
            {"title": "Signet"},
        )

    assert calls == []


@pytest.mark.asyncio
async def test_web_push_uses_exact_allowlist_without_proxy_or_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[dict[str, object]] = []

    def capture(**kwargs: object) -> None:
        captured.append(dict(kwargs))

    monkeypatch.setattr(notifications_module, "webpush", capture)
    transport = WebPushTransport(
        Secret("vapid-private-material"),
        subject="mailto:test@example.test",
        allowed_push_origins=frozenset({"https://push.example.test"}),
    )
    record = replace(
        subscription("allowed"),
        endpoint="https://push.example.test/send/device?provider_token=fake",
    )

    await transport.send(record, {"title": "Signet"})

    assert len(captured) == 1
    supplied_session = captured[0]["requests_session"]
    assert isinstance(supplied_session, requests.Session)
    assert supplied_session.trust_env is False
    assert supplied_session.max_redirects == 0
    assert captured[0]["timeout"] == 10
    assert captured[0]["subscription_info"] == {
        "endpoint": record.endpoint,
        "keys": {"p256dh": record.p256dh, "auth": record.auth},
    }


@pytest.mark.asyncio
async def test_web_push_redirect_failure_is_generic_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def redirect(**kwargs: object) -> None:
        raise requests.TooManyRedirects("secret redirect location")

    monkeypatch.setattr(notifications_module, "webpush", redirect)
    transport = WebPushTransport(
        Secret("vapid-private-material"),
        subject="mailto:test@example.test",
        allowed_push_origins=frozenset({"https://push.example.test"}),
    )

    with pytest.raises(PushDeliveryError) as caught:
        await transport.send(subscription("redirect"), {"title": "Signet"})

    assert str(caught.value) == "browser push delivery failed"
    assert "secret redirect" not in str(caught.value)
    assert caught.value.__cause__ is None
    rendered = "".join(traceback.format_exception(caught.value))
    assert "secret redirect location" not in rendered
    assert "push.example.test/redirect" not in rendered


@pytest.mark.parametrize(
    "origin",
    [
        frozenset(),
        frozenset({"https://127.0.0.1"}),
        frozenset({"https://127.1"}),
        frozenset({"https://127.000.000.001"}),
        frozenset({"https://0x7f.0.0.1"}),
        frozenset({"https://0177.0.0.1"}),
        frozenset({"https://0300.0250.0001.0001"}),
        frozenset({"https://push.example.test/path"}),
        frozenset({"https://push.example.test?query=1"}),
        frozenset({"https://user@push.example.test"}),
    ],
)
def test_web_push_origin_allowlist_rejects_unsafe_configuration(origin: frozenset[str]) -> None:
    with pytest.raises(ValueError, match="origin"):
        WebPushTransport(
            Secret("vapid-private-material"),
            subject="mailto:test@example.test",
            allowed_push_origins=origin,
        )


def test_sqlite_subscriptions_survive_restart_and_enforce_endpoint_ownership(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "approval.sqlite3")
    database.initialize()
    repository = SQLitePushRepository(database)
    record = subscription(
        "durable",
        categories=frozenset({NotificationKind.NEW_PENDING}),
    )
    repository.save(record)

    restarted = SQLitePushRepository(Database(database.path))
    assert restarted.active_for("autumn", NotificationKind.NEW_PENDING) == (record,)
    assert restarted.active_for("autumn", NotificationKind.DAILY_DIGEST) == ()
    restarted.mark_failure("durable", now=1_800_000_001, disable_after=2)
    assert len(restarted.active_for("autumn", NotificationKind.NEW_PENDING)) == 1
    restarted.mark_failure("durable", now=1_800_000_002, disable_after=2)
    assert restarted.active_for("autumn", NotificationKind.NEW_PENDING) == ()

    hostile = subscription("other", user_id="other")
    hostile = replace(hostile, endpoint=record.endpoint)
    with pytest.raises(ValueError, match="another user"):
        restarted.save(hostile)
