import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import DBAPIError, OperationalError

from sentinel_security.events import DeadLetterNotice
from sentinel_security.messaging import DEAD_QUEUE
from sentinel_worker.consumer import EventConsumer, is_transient


def delivery(body):
    return MagicMock(body=body, ack=AsyncMock())


def setup(settings):
    store = MagicMock(persist=AsyncMock(return_value=True))
    channel = MagicMock(default_exchange=MagicMock(publish=AsyncMock()))
    settings = settings.model_copy(update={"event_retry_delay_seconds": 0.01})
    return EventConsumer(store, channel, settings), store, channel


@pytest.mark.parametrize("inserted", [True, False])
async def test_acknowledgement_follows_successful_commit_or_duplicate(
    settings, security_event, inserted
):
    consumer, store, channel = setup(settings)
    message = delivery(security_event.model_dump_json().encode())
    order = []

    async def persist(event):
        assert event == security_event
        order.append("commit")
        return inserted

    async def acknowledge():
        assert order == ["commit"]
        order.append("ack")

    store.persist.side_effect = persist
    message.ack.side_effect = acknowledge
    await consumer.handle(message)
    assert order == ["commit", "ack"]
    channel.default_exchange.publish.assert_not_awaited()


async def test_transient_database_failure_retries_before_ack(settings, security_event):
    consumer, store, channel = setup(settings)
    message = delivery(security_event.model_dump_json().encode())
    store.persist.side_effect = [OperationalError("", {}, OSError("private-db-url")), True]
    await consumer.handle(message)
    assert store.persist.await_count == 2
    message.ack.assert_awaited_once()
    channel.default_exchange.publish.assert_not_awaited()


@pytest.mark.parametrize(
    "failure,reason,attempts",
    [
        (OSError("db-password"), "retry_exhausted", 4),
        (ValueError("db-password"), "permanent_storage_error", 1),
    ],
)
async def test_storage_failure_quarantines_valid_event_before_ack(
    settings, security_event, failure, reason, attempts
):
    consumer, store, channel = setup(settings)
    store.persist.side_effect = failure
    message = delivery(security_event.model_dump_json().encode())

    async def confirmed(*args, **kwargs):
        message.ack.assert_not_awaited()

    channel.default_exchange.publish.side_effect = confirmed
    await consumer.handle(message)
    assert store.persist.await_count == attempts
    call = channel.default_exchange.publish.call_args
    notice = DeadLetterNotice.model_validate_json(call.args[0].body)
    assert notice.reason == reason
    assert notice.event.event_id == security_event.event_id
    assert call.kwargs["routing_key"] == DEAD_QUEUE
    assert call.kwargs["mandatory"] is True
    assert b"db-password" not in call.args[0].body
    message.ack.assert_awaited_once()


@pytest.mark.parametrize(
    "body,reason",
    [
        (b'{"authorization":"Bearer raw-secret"}', "invalid_event"),
        (b"malformed-raw-secret", "invalid_event"),
        (b"raw-secret" * 500, "oversized_event"),
    ],
)
async def test_invalid_messages_are_redacted_in_dead_letter_queue(settings, body, reason):
    consumer, store, channel = setup(settings)
    message = delivery(body)
    await consumer.handle(message)
    notice_body = channel.default_exchange.publish.call_args.args[0].body
    notice = DeadLetterNotice.model_validate_json(notice_body)
    assert notice.reason == reason
    assert notice.event is None
    assert b"raw-secret" not in notice_body
    assert b"authorization" not in notice_body
    assert len(notice.payload_sha256) == 64
    store.persist.assert_not_awaited()
    message.ack.assert_awaited_once()


async def test_dead_letter_failure_leaves_original_unacknowledged(settings):
    consumer, store, channel = setup(settings)
    channel.default_exchange.publish.side_effect = ConnectionError("unavailable")
    message = delivery(b"invalid")
    with pytest.raises(ConnectionError):
        await consumer.handle(message)
    message.ack.assert_not_awaited()


async def test_uncertain_ack_after_commit_propagates_for_redelivery(settings, security_event):
    consumer, store, channel = setup(settings)
    message = delivery(security_event.model_dump_json().encode())
    message.ack.side_effect = ConnectionError("ack lost")
    with pytest.raises(ConnectionError):
        await consumer.handle(message)
    store.persist.assert_awaited_once()
    channel.default_exchange.publish.assert_not_awaited()


async def test_cancellation_does_not_acknowledge_uncommitted_event(settings, security_event):
    consumer, store, channel = setup(settings)
    store.persist.side_effect = asyncio.CancelledError()
    message = delivery(security_event.model_dump_json().encode())
    with pytest.raises(asyncio.CancelledError):
        await consumer.handle(message)
    message.ack.assert_not_awaited()
    channel.default_exchange.publish.assert_not_awaited()


async def test_database_timeout_is_bounded(settings, security_event):
    consumer, store, channel = setup(
        settings.model_copy(
            update={
                "worker_storage_timeout_seconds": 0.1,
                "worker_storage_attempts": 1,
            }
        )
    )

    async def hang(*args):
        await asyncio.Event().wait()

    store.persist.side_effect = hang
    message = delivery(security_event.model_dump_json().encode())
    await asyncio.wait_for(consumer.handle(message), timeout=1)
    notice = DeadLetterNotice.model_validate_json(
        channel.default_exchange.publish.call_args.args[0].body
    )
    assert notice.reason == "retry_exhausted"


@pytest.mark.parametrize(
    "sqlstate,expected",
    [("40001", True), ("08006", True), ("53300", True), ("57P03", True), ("23505", False)],
)
def test_database_error_classification(sqlstate, expected):
    original = Exception()
    original.sqlstate = sqlstate
    assert is_transient(DBAPIError("", {}, original)) is expected
    assert is_transient(ValueError("permanent")) is False
    assert is_transient(DBAPIError("", {}, Exception(), connection_invalidated=True)) is True
