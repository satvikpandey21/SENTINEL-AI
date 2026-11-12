from unittest.mock import AsyncMock, MagicMock

import pytest
from scripts import replay_dead_letters

from sentinel_security.events import DeadLetterNotice


def broker(monkeypatch, settings, messages):
    queue = MagicMock(get=AsyncMock(side_effect=[*messages, None]))
    channel = MagicMock(
        declare_queue=AsyncMock(return_value=queue), default_exchange=MagicMock(publish=AsyncMock())
    )
    connection = MagicMock(channel=AsyncMock(return_value=channel))
    connection.__aenter__ = AsyncMock(return_value=connection)
    connection.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(replay_dead_letters, "Settings", lambda: settings)
    monkeypatch.setattr(replay_dead_letters.aio_pika, "connect", AsyncMock(return_value=connection))
    return channel


def message(body):
    return MagicMock(body=body, ack=AsyncMock(), nack=AsyncMock())


async def test_replay_acknowledges_only_after_confirm(monkeypatch, settings, security_event):
    notice = DeadLetterNotice(
        reason="retry_exhausted", payload_sha256="a" * 64, event=security_event
    )
    delivery = message(notice.model_dump_json().encode())
    channel = broker(monkeypatch, settings, [delivery])

    async def confirmed(*args, **kwargs):
        delivery.ack.assert_not_awaited()

    channel.default_exchange.publish.side_effect = confirmed
    await replay_dead_letters.replay(10)
    delivery.ack.assert_awaited_once()
    assert channel.default_exchange.publish.call_args.args[0].message_id == str(
        security_event.event_id
    )


@pytest.mark.parametrize("body", [b"invalid-secret", b"x" * 16385])
async def test_replay_retains_invalid_messages_without_forwarding(monkeypatch, settings, body):
    delivery = message(body)
    channel = broker(monkeypatch, settings, [delivery])
    await replay_dead_letters.replay(10)
    delivery.ack.assert_not_awaited()
    delivery.nack.assert_awaited_once_with(requeue=True)
    channel.default_exchange.publish.assert_not_awaited()


async def test_replay_failed_confirm_does_not_acknowledge(monkeypatch, settings, security_event):
    notice = DeadLetterNotice(
        reason="retry_exhausted", payload_sha256="a" * 64, event=security_event
    )
    delivery = message(notice.model_dump_json().encode())
    channel = broker(monkeypatch, settings, [delivery])
    channel.default_exchange.publish.side_effect = ConnectionError("unavailable")
    with pytest.raises(ConnectionError):
        await replay_dead_letters.replay(10)
    delivery.ack.assert_not_awaited()
