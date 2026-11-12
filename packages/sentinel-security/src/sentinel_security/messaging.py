"""Durable, bounded queues with explicit publisher confirms and routing failures."""

import aio_pika
from aio_pika.abc import AbstractChannel, AbstractQueue

from sentinel_security.config import Settings

EVENT_QUEUE = "sentinel.security.events.v1"
DEAD_QUEUE = "sentinel.security.events.v1.dead"


async def declare_topology(channel: AbstractChannel, settings: Settings) -> AbstractQueue:
    arguments = {
        "x-max-length": settings.broker_queue_max_messages,
        "x-max-length-bytes": settings.broker_queue_max_bytes,
        "x-overflow": "reject-publish",
    }
    await channel.declare_queue(
        DEAD_QUEUE,
        durable=True,
        arguments=arguments,
        timeout=settings.event_operation_timeout_seconds,
    )
    return await channel.declare_queue(
        EVENT_QUEUE,
        durable=True,
        arguments=arguments,
        timeout=settings.event_operation_timeout_seconds,
    )


def event_message(body: bytes, message_id: str | None = None) -> aio_pika.Message:
    return aio_pika.Message(
        body=body,
        content_type="application/json",
        content_encoding="utf-8",
        delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        message_id=message_id,
    )
