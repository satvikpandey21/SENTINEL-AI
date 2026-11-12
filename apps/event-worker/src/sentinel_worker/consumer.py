"""Acknowledge only after commit or confirmed quarantine; all retry buffers are bounded."""

import asyncio
import hashlib

import structlog
from aio_pika.abc import AbstractChannel, AbstractIncomingMessage
from pydantic import ValidationError
from sqlalchemy.exc import DBAPIError, DisconnectionError, InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError

from sentinel_security.config import Settings
from sentinel_security.events import DeadLetterNotice, MonitoringEvent, parse_event
from sentinel_security.messaging import DEAD_QUEUE, event_message
from sentinel_security.storage import EventStore


def is_transient(error: Exception) -> bool:
    if isinstance(
        error,
        (
            OperationalError,
            InterfaceError,
            DisconnectionError,
            SQLAlchemyTimeoutError,
            TimeoutError,
            OSError,
        ),
    ):
        return True
    if isinstance(error, DBAPIError):
        code = getattr(error.orig, "sqlstate", None)
        return error.connection_invalidated or (
            isinstance(code, str)
            and (code[:2] in ("08", "40", "53") or code in ("57P01", "57P02", "57P03"))
        )
    return False


class EventConsumer:
    def __init__(self, store: EventStore, channel: AbstractChannel, settings: Settings) -> None:
        self.store = store
        self.channel = channel
        self.settings = settings

    async def _quarantine(self, message, reason, event: MonitoringEvent | None = None) -> None:
        notice = DeadLetterNotice(
            reason=reason, payload_sha256=hashlib.sha256(message.body).hexdigest(), event=event
        )
        async with asyncio.timeout(self.settings.event_operation_timeout_seconds):
            await self.channel.default_exchange.publish(
                event_message(notice.model_dump_json().encode("utf-8")),
                routing_key=DEAD_QUEUE,
                mandatory=True,
                timeout=self.settings.event_operation_timeout_seconds,
            )
        await message.ack()
        structlog.get_logger().warning("event_quarantined", reason=reason)

    async def handle(self, message: AbstractIncomingMessage) -> None:
        if len(message.body) > self.settings.event_max_bytes:
            await self._quarantine(message, "oversized_event")
            return
        try:
            event = parse_event(message.body, self.settings.event_max_bytes)
        except (ValidationError, ValueError):
            await self._quarantine(message, "invalid_event")
            return
        for attempt in range(self.settings.worker_storage_attempts):
            try:
                async with asyncio.timeout(self.settings.worker_storage_timeout_seconds):
                    inserted = await self.store.persist(event)
            except Exception as error:
                transient = is_transient(error)
                structlog.get_logger().warning(
                    "event_storage_failed",
                    error_type=type(error).__name__,
                    transient=transient,
                    attempt=attempt + 1,
                )
                if not transient:
                    await self._quarantine(message, "permanent_storage_error", event)
                    return
                if attempt + 1 == self.settings.worker_storage_attempts:
                    await self._quarantine(message, "retry_exhausted", event)
                    return
                await asyncio.sleep(min(5.0, self.settings.event_retry_delay_seconds * 2**attempt))
            else:
                await message.ack()
                structlog.get_logger().info(
                    "event_persisted" if inserted else "event_duplicate",
                    event_id=str(event.event_id),
                    request_id=event.request_id,
                )
                return
