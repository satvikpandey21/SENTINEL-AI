import asyncio
import json
from time import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel_worker import healthcheck, runtime


@pytest.mark.parametrize("content", ["not-json", "{}", '{"ready":true}', "null"])
def test_corrupt_heartbeat_is_unhealthy(tmp_path, monkeypatch, content):
    path = tmp_path / "health.json"
    path.write_text(content)
    monkeypatch.setattr(healthcheck, "HEARTBEAT_PATH", path)
    assert healthcheck.is_healthy() is False


def test_heartbeat_contract_and_expiry(tmp_path, monkeypatch):
    path = tmp_path / "health.json"
    monkeypatch.setattr(healthcheck, "HEARTBEAT_PATH", path)
    assert healthcheck.is_healthy() is False
    healthcheck.write_health(True)
    assert healthcheck.is_healthy() is True
    healthcheck.write_health(False)
    assert healthcheck.is_healthy() is False
    path.write_text(json.dumps({"ready": True, "checked_at": time() - 30}))
    assert healthcheck.is_healthy() is False
    path.write_text(json.dumps({"ready": True, "checked_at": time() + 30}))
    assert healthcheck.is_healthy() is False


async def test_worker_reconnects_then_stops_and_closes_resources(settings, monkeypatch):
    stop = asyncio.Event()
    settings = settings.model_copy(update={"event_retry_delay_seconds": 0.01})
    resources = MagicMock(settings=settings, session_factory=MagicMock(), _postgresql=AsyncMock())
    resources.__aenter__ = AsyncMock(return_value=resources)
    resources.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(runtime, "Resources", lambda _: resources)
    broker = MagicMock(channel=AsyncMock(), close=AsyncMock())
    closed = asyncio.get_running_loop().create_future()
    broker.closed.return_value = closed
    broker.channel.return_value = MagicMock(set_qos=AsyncMock())
    connect = AsyncMock(side_effect=[ConnectionError("secret-url"), broker])
    monkeypatch.setattr(runtime.aio_pika, "connect", connect)
    monkeypatch.setattr(runtime, "declare_topology", AsyncMock())

    async def waiting_consumer(*args):
        await asyncio.Event().wait()

    monkeypatch.setattr(runtime, "consume", waiting_consumer)
    states = []

    def health(ready):
        states.append(ready)
        if ready:
            stop.set()

    monkeypatch.setattr(runtime, "write_health", health)
    await asyncio.wait_for(runtime.run_worker(settings, stop), timeout=1)
    assert connect.await_count == 2
    assert True in states
    assert states[-1] is False
    broker.close.assert_awaited_once()
    resources.__aexit__.assert_awaited_once()
    broker.channel.return_value.set_qos.assert_awaited_once_with(
        prefetch_count=settings.worker_prefetch
    )


async def test_database_failure_marks_worker_unhealthy(settings, monkeypatch):
    stop = asyncio.Event()
    resources = MagicMock(
        settings=settings, _postgresql=AsyncMock(side_effect=OSError("private-url"))
    )
    states = []

    def health(ready):
        states.append(ready)
        stop.set()

    monkeypatch.setattr(runtime, "write_health", health)
    await runtime.heartbeat(resources, stop)
    assert states == [False]


async def test_consume_iterator_passes_each_message_to_consumer():
    messages = [object(), object()]

    class Iterator:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            pass

        def __aiter__(self):
            return self

        async def __anext__(self):
            if not messages:
                raise StopAsyncIteration
            return messages.pop()

    queue = MagicMock(iterator=Iterator)
    consumer = MagicMock(handle=AsyncMock())
    await runtime.consume(queue, consumer)
    assert consumer.handle.await_count == 2
