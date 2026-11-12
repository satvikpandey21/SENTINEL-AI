"""Bounded best-effort ingress; broker confirms provide the durable handoff boundary."""

import asyncio
from dataclasses import dataclass
from time import monotonic

import aio_pika
import structlog

from sentinel_security.config import Settings
from sentinel_security.events import SecurityEvent
from sentinel_security.messaging import EVENT_QUEUE, declare_topology, event_message


@dataclass
class PublisherStats:
    accepted: int = 0
    published: int = 0
    dropped: int = 0
    publish_failures: int = 0


class EventPublisher:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.stats = PublisherStats()
        self.queue: asyncio.Queue[tuple[bytes, str]] = asyncio.Queue(settings.event_buffer_capacity)
        self._task: asyncio.Task | None = None
        self._connection = None
        self._channel = None
        self._accepting = False
        self._last_loss_log = float("-inf")

    async def __aenter__(self):
        self._accepting = True
        self._task = asyncio.create_task(self._run(), name="sentinel-event-publisher")
        return self

    async def __aexit__(self, *exc):
        await self.close()

    def _drop(self, reason: str) -> None:
        self.stats.dropped += 1
        if monotonic() - self._last_loss_log >= 30:
            self._last_loss_log = monotonic()
            structlog.get_logger().warning(
                "telemetry_dropped", reason=reason, dropped_total=self.stats.dropped
            )

    def offer(self, event: SecurityEvent) -> bool:
        # No awaits, socket I/O, retry sleep, or database work on the request path.
        if not self._accepting:
            self._drop("publisher_stopped")
            return False
        body = event.model_dump_json().encode("utf-8")
        if len(body) > self.settings.event_max_bytes:
            self._drop("event_too_large")
            return False
        try:
            self.queue.put_nowait((body, str(event.event_id)))
        except asyncio.QueueFull:
            self._drop("buffer_full")
            return False
        self.stats.accepted += 1
        return True

    async def _connect(self) -> None:
        if self._connection is not None and not self._connection.is_closed:
            if self._channel is not None and not self._channel.is_closed:
                return
        await self._disconnect()
        self._connection = await aio_pika.connect(
            self.settings.rabbitmq_url.get_secret_value(),
            timeout=self.settings.event_operation_timeout_seconds,
        )
        self._channel = await self._connection.channel(
            publisher_confirms=True, on_return_raises=True
        )
        await declare_topology(self._channel, self.settings)

    async def _disconnect(self) -> None:
        connection, self._connection, self._channel = self._connection, None, None
        if connection is not None:
            try:
                async with asyncio.timeout(self.settings.event_operation_timeout_seconds):
                    await connection.close()
            except Exception as error:
                structlog.get_logger().debug(
                    "publisher_close_failed", error_type=type(error).__name__
                )

    async def _deliver(self, body: bytes, message_id: str) -> bool:
        for attempt in range(self.settings.event_publish_attempts):
            try:
                async with asyncio.timeout(self.settings.event_operation_timeout_seconds):
                    await self._connect()
                    await self._channel.default_exchange.publish(
                        event_message(body, message_id),
                        routing_key=EVENT_QUEUE,
                        mandatory=True,
                        timeout=self.settings.event_operation_timeout_seconds,
                    )
                self.stats.published += 1
                return True
            except Exception as error:
                self.stats.publish_failures += 1
                structlog.get_logger().warning(
                    "event_publish_failed", error_type=type(error).__name__, attempt=attempt + 1
                )
                await self._disconnect()
                if attempt + 1 < self.settings.event_publish_attempts:
                    await asyncio.sleep(
                        min(5.0, self.settings.event_retry_delay_seconds * 2**attempt)
                    )
        return False

    async def _run(self) -> None:
        while True:
            body, message_id = await self.queue.get()
            try:
                if not await self._deliver(body, message_id):
                    self._drop("publish_attempts_exhausted")
            except asyncio.CancelledError:
                self._drop("shutdown_inflight")
                raise
            except Exception as error:
                self._drop("publisher_error")
                structlog.get_logger().error("publisher_error", error_type=type(error).__name__)
            finally:
                self.queue.task_done()

    async def close(self) -> None:
        self._accepting = False
        if self._task is not None:
            try:
                async with asyncio.timeout(self.settings.event_shutdown_timeout_seconds):
                    await self.queue.join()
            except TimeoutError:
                pass
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        while not self.queue.empty():
            self.queue.get_nowait()
            self.queue.task_done()
            self._drop("shutdown_buffered")
        await self._disconnect()
        structlog.get_logger().info(
            "publisher_stopped",
            accepted=self.stats.accepted,
            published=self.stats.published,
            dropped=self.stats.dropped,
            publish_failures=self.stats.publish_failures,
        )
