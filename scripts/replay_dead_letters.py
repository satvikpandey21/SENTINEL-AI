"""Operator-only bounded replay of validated events; malformed notices stay quarantined."""

import argparse
import asyncio

import aio_pika

from sentinel_security.config import Settings
from sentinel_security.events import DeadLetterNotice, SecurityEvent
from sentinel_security.messaging import DEAD_QUEUE, EVENT_QUEUE, event_message


async def replay(limit: int) -> None:
    settings = Settings()
    connection = await aio_pika.connect(settings.rabbitmq_url.get_secret_value(), timeout=5)
    replayed = 0
    skipped = []
    async with connection:
        channel = await connection.channel(publisher_confirms=True, on_return_raises=True)
        queue = await channel.declare_queue(DEAD_QUEUE, passive=True, timeout=5)
        try:
            for _ in range(limit):
                message = await queue.get(fail=False, timeout=5)
                if message is None:
                    break
                try:
                    if len(message.body) > 16384:
                        raise ValueError("oversized notice")
                    notice = DeadLetterNotice.model_validate_json(message.body)
                    if notice.event is None:
                        raise ValueError("notice has no replayable event")
                    body = notice.event.model_dump_json().encode()
                    SecurityEvent.from_wire(body, settings.event_max_bytes)
                except ValueError:
                    skipped.append(message)
                    continue
                async with asyncio.timeout(settings.event_operation_timeout_seconds):
                    await channel.default_exchange.publish(
                        event_message(body, str(notice.event.event_id)),
                        routing_key=EVENT_QUEUE,
                        mandatory=True,
                        timeout=settings.event_operation_timeout_seconds,
                    )
                await message.ack()
                replayed += 1
        finally:
            for message in skipped:
                await message.nack(requeue=True)
    print(f"Replayed {replayed} validated events; retained {len(skipped)} redacted notices.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=25)
    arguments = parser.parse_args()
    if not 1 <= arguments.limit <= 100:
        parser.error("--limit must be between 1 and 100")
    try:
        asyncio.run(replay(arguments.limit))
    except Exception as error:
        raise SystemExit(f"Replay failed: {type(error).__name__}") from None
