import asyncio
from unittest.mock import AsyncMock, MagicMock

from sentinel_security.messaging import EVENT_QUEUE
from sentinel_security.publisher import EventPublisher


def connection():
    exchange = MagicMock(publish=AsyncMock())
    channel = MagicMock(default_exchange=exchange, is_closed=False)
    connection = MagicMock(
        channel=AsyncMock(return_value=channel), close=AsyncMock(), is_closed=False
    )
    return connection, channel


async def test_confirmed_publication_uses_persistent_message_and_reuses_connection(
    settings, security_event, monkeypatch
):
    broker, channel = connection()
    connect = AsyncMock(return_value=broker)
    topology = AsyncMock()
    monkeypatch.setattr("sentinel_security.publisher.aio_pika.connect", connect)
    monkeypatch.setattr("sentinel_security.publisher.declare_topology", topology)
    async with EventPublisher(settings) as publisher:
        assert publisher.offer(security_event)
        assert publisher.offer(security_event)
        await asyncio.wait_for(publisher.queue.join(), 1)
        assert publisher.stats.published == 2
        assert publisher.stats.dropped == 0
    connect.assert_awaited_once()
    broker.close.assert_awaited_once()
    call = channel.default_exchange.publish.call_args
    assert call.kwargs["mandatory"] is True
    assert call.kwargs["routing_key"] == EVENT_QUEUE
    assert call.args[0].delivery_mode == 2
    assert call.args[0].message_id == str(security_event.event_id)


async def test_bounded_buffer_and_nonblocking_offer(settings, security_event):
    settings = settings.model_copy(update={"event_buffer_capacity": 1})
    entered, release = asyncio.Event(), asyncio.Event()
    async with EventPublisher(settings) as publisher:

        async def paused(*args):
            entered.set()
            await release.wait()
            return True

        publisher._deliver = paused
        assert publisher.offer(security_event)
        await entered.wait()
        assert publisher.offer(security_event)
        assert publisher.offer(security_event) is False
        assert publisher.queue.qsize() == 1
        assert publisher.stats.dropped == 1
        release.set()
        await publisher.queue.join()
    assert publisher.offer(security_event) is False


async def test_broker_outage_has_bounded_retries_and_loss_accounting(
    settings, security_event, monkeypatch
):
    settings = settings.model_copy(update={"event_retry_delay_seconds": 0.01})
    connect = AsyncMock(side_effect=ConnectionError("secret-broker-url"))
    monkeypatch.setattr("sentinel_security.publisher.aio_pika.connect", connect)
    async with EventPublisher(settings) as publisher:
        assert publisher.offer(security_event)
        await asyncio.wait_for(publisher.queue.join(), 1)
        assert publisher.stats.publish_failures == settings.event_publish_attempts
        assert publisher.stats.dropped == 1
        assert publisher.stats.published == 0
    assert connect.await_count == settings.event_publish_attempts


async def test_retry_keeps_same_id_after_uncertain_confirmation(
    settings, security_event, monkeypatch
):
    first, channel1 = connection()
    second, channel2 = connection()
    channel1.default_exchange.publish.side_effect = ConnectionError("lost confirm")
    monkeypatch.setattr(
        "sentinel_security.publisher.aio_pika.connect", AsyncMock(side_effect=[first, second])
    )
    monkeypatch.setattr("sentinel_security.publisher.declare_topology", AsyncMock())
    settings = settings.model_copy(update={"event_retry_delay_seconds": 0.01})
    async with EventPublisher(settings) as publisher:
        publisher.offer(security_event)
        await publisher.queue.join()
        assert publisher.stats.published == 1
        assert publisher.stats.publish_failures == 1
    assert (
        channel1.default_exchange.publish.call_args.args[0].message_id
        == channel2.default_exchange.publish.call_args.args[0].message_id
    )
    first.close.assert_awaited_once()


async def test_shutdown_is_bounded_and_accounts_for_buffered_and_inflight_loss(
    settings, security_event
):
    settings = settings.model_copy(update={"event_shutdown_timeout_seconds": 0.1})
    publisher = EventPublisher(settings)
    entered = asyncio.Event()

    async def hanging(*args):
        entered.set()
        await asyncio.Event().wait()

    publisher._deliver = hanging
    await publisher.__aenter__()
    publisher.offer(security_event)
    await entered.wait()
    publisher.offer(security_event)
    await asyncio.wait_for(publisher.close(), timeout=1)
    assert publisher.stats.dropped == 2
    assert publisher.queue.empty()
    assert publisher._task is None


async def test_event_size_limit(settings, security_event):
    async with EventPublisher(settings.model_copy(update={"event_max_bytes": 1})) as publisher:
        assert publisher.offer(security_event) is False
        assert publisher.stats.dropped == 1


async def test_broker_operations_have_timeouts(settings, security_event, monkeypatch):
    async def hang(*args, **kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr("sentinel_security.publisher.aio_pika.connect", hang)
    settings = settings.model_copy(
        update={"event_operation_timeout_seconds": 0.1, "event_publish_attempts": 1}
    )
    async with EventPublisher(settings) as publisher:
        publisher.offer(security_event)
        await asyncio.wait_for(publisher.queue.join(), 1)
        assert publisher.stats.dropped == 1
