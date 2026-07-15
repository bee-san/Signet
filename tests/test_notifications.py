from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from signet.credential_broker import Secret
from signet.notifications import (
    InMemoryPushRepository,
    NotificationDispatcher,
    NotificationKind,
    PushMessage,
    PushSubscription,
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
        p256dh="ZmFrZS1wMjU2ZGg",
        auth="ZmFrZS1hdXRo",
        device_label="Test phone",
        categories=categories,
        created_at=1_800_000_000,
    )


@pytest.mark.parametrize("kind", tuple(NotificationKind)[:-1])
def test_event_payloads_contain_only_safe_service_action_and_count(kind: NotificationKind) -> None:
    message = PushMessage(kind, service="Fastmail", action="send_email")
    payload = message.payload()
    serialized = json.dumps(payload)
    assert set(payload) == {"title", "kind", "tag", "url", "body", "service", "action"}
    assert payload["title"] == "Signet"
    assert payload["url"] == "/"
    for secret in (
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
    repository.save(
        subscription("digest", categories=frozenset({NotificationKind.DAILY_DIGEST}))
    )
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


def test_subscription_validation_and_representations_redact_endpoint_and_keys() -> None:
    created = new_subscription(
        user_id="autumn",
        endpoint="https://push.example.test/device-secret",
        p256dh="ZmFrZS1wMjU2ZGg",
        auth="ZmFrZS1hdXRo",
        device_label="Phone",
        created_at=1_800_000_000,
    )
    assert "device-secret" not in repr(created)
    assert "ZmFrZ" not in repr(created)
    with pytest.raises(ValueError):
        new_subscription(
            user_id="autumn",
            endpoint="http://push.example.test/device",
            p256dh="fake",
            auth="fake",
            device_label="Phone",
            created_at=1_800_000_000,
        )

    transport = WebPushTransport(
        Secret("vapid-private-material"),
        subject="mailto:test@example.test",
    )
    assert "vapid-private-material" not in repr(transport)
