import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel_security.infrastructure import Resources


async def test_probes_run_concurrently_and_cleanup(settings):
    resources = Resources(settings)
    started = []
    all_started = asyncio.Event()

    async def probe(name):
        started.append(name)
        if len(started) == 3:
            all_started.set()
        await asyncio.wait_for(all_started.wait(), timeout=1)

    resources._postgresql = lambda: probe("postgresql")
    resources._redis = lambda: probe("redis")
    resources._rabbitmq = lambda: probe("rabbitmq")
    resources.redis.aclose = AsyncMock()
    resources.engine = MagicMock(dispose=AsyncMock())
    async with resources:
        assert await resources.health() == {"postgresql": "up", "redis": "up", "rabbitmq": "up"}
    resources.redis.aclose.assert_awaited_once()
    resources.engine.dispose.assert_awaited_once()


async def test_probe_failure_and_timeout_are_bounded(settings):
    resources = Resources(settings.model_copy(update={"dependency_timeout_seconds": 0.1}))
    resources._postgresql = AsyncMock(side_effect=ConnectionError("secret-url"))
    resources._redis = AsyncMock()

    async def hanging_broker():
        await asyncio.sleep(10)

    resources._rabbitmq = hanging_broker
    async with resources:
        result = await asyncio.wait_for(resources.health(), timeout=1)
    assert result == {"postgresql": "down", "redis": "up", "rabbitmq": "down"}


async def test_redis_probe_checks_acknowledgement(settings):
    async with Resources(settings) as resources:
        resources.redis.ping = AsyncMock(return_value=False)
        with pytest.raises(ConnectionError):
            await resources._redis()
        resources.redis.ping = AsyncMock(return_value=True)
        await resources._redis()


@pytest.mark.parametrize("channel_fails", [False, True])
async def test_amqp_connection_always_closes(settings, monkeypatch, channel_fails):
    channel = MagicMock(close=AsyncMock())
    connection = MagicMock(channel=AsyncMock(return_value=channel), close=AsyncMock())
    if channel_fails:
        connection.channel.side_effect = RuntimeError("unavailable")
    monkeypatch.setattr(
        "sentinel_security.infrastructure.aio_pika.connect", AsyncMock(return_value=connection)
    )
    async with Resources(settings) as resources:
        if channel_fails:
            with pytest.raises(RuntimeError):
                await resources._rabbitmq()
        else:
            await resources._rabbitmq()
            channel.close.assert_awaited_once()
    connection.close.assert_awaited_once()
