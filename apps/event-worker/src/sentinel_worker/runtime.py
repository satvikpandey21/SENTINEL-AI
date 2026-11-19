"""Reconnect supervisor with bounded prefetch, safe shutdown, and independent DB health."""

import asyncio
from time import monotonic

import aio_pika
import structlog

from sentinel_security.analysis_storage import AnalysisEngine, cleanup_analysis
from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources
from sentinel_security.messaging import declare_topology
from sentinel_security.metrics import Metrics, metrics_runtime
from sentinel_security.realtime import NotificationPublisher
from sentinel_security.storage import EventStore
from sentinel_worker.consumer import EventConsumer
from sentinel_worker.healthcheck import write_health


async def heartbeat(resources: Resources, stop: asyncio.Event) -> None:
    next_cleanup = monotonic() + 60
    while not stop.is_set():
        ready = False
        try:
            async with asyncio.timeout(resources.settings.dependency_timeout_seconds):
                await resources._postgresql()
            ready = True
            if monotonic() >= next_cleanup:
                async with asyncio.timeout(resources.settings.worker_storage_timeout_seconds):
                    removed = await cleanup_analysis(
                        resources.session_factory, resources.settings.analysis
                    )
                structlog.get_logger().info("analysis_retention", removed=removed)
                next_cleanup = monotonic() + 60
        except Exception as error:
            structlog.get_logger().warning(
                "worker_database_unavailable", error_type=type(error).__name__
            )
        write_health(ready)
        metrics = getattr(resources, "metrics", None)
        if metrics is not None:
            metrics.set("worker_ready", int(ready))
        try:
            await asyncio.wait_for(stop.wait(), timeout=3)
        except TimeoutError:
            pass


async def consume(queue, consumer: EventConsumer) -> None:
    async with queue.iterator() as iterator:
        async for message in iterator:
            await consumer.handle(message)


async def consume_connection(connection, resources: Resources, stop: asyncio.Event) -> None:
    settings = resources.settings
    async with asyncio.timeout(settings.event_operation_timeout_seconds):
        channel = await connection.channel(publisher_confirms=True, on_return_raises=True)
        await channel.set_qos(prefetch_count=settings.worker_prefetch)
        queue = await declare_topology(channel, settings)
    consumer = EventConsumer(
        EventStore(
            resources.session_factory,
            resources.analysis,
            resources.notifications,
            resources.metrics,
        ),
        channel,
        settings,
        metrics=resources.metrics,
    )
    consume_task = asyncio.create_task(consume(queue, consumer))
    health_task = asyncio.create_task(heartbeat(resources, stop))
    stop_task = asyncio.create_task(stop.wait())
    closed_task = asyncio.ensure_future(connection.closed())
    tasks = (consume_task, health_task, stop_task, closed_task)
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        if stop.is_set():
            return
        for task in (consume_task, health_task):
            if task in done:
                task.result()
        raise ConnectionError("consumer connection closed")
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def run_worker(settings: Settings, stop: asyncio.Event) -> None:
    write_health(False)
    metrics = Metrics("sentinel-event-worker", enabled=settings.metrics_enabled, component="worker")
    from contextlib import AsyncExitStack

    async with (
        Resources(settings) as resources,
        AsyncExitStack() as observability,
        NotificationPublisher(
            resources.redis,
            settings.realtime_buffer_capacity,
            settings.realtime_publish_timeout_seconds,
            metrics=metrics,
        ) as notifications,
    ):
        resources.metrics = metrics
        resources.notifications = notifications
        resources.analysis = AnalysisEngine(settings.analysis, metrics=metrics)
        await observability.enter_async_context(metrics_runtime(metrics, settings, resources))
        while not stop.is_set():
            connection = None
            try:
                connection = await aio_pika.connect(
                    settings.rabbitmq_url.get_secret_value(),
                    timeout=settings.event_operation_timeout_seconds,
                )
                metrics.set("worker_connected", 1)
                structlog.get_logger().info("worker_connected")
                await consume_connection(connection, resources, stop)
            except Exception as error:
                metrics.inc("worker_reconnects")
                structlog.get_logger().warning(
                    "worker_disconnected", error_type=type(error).__name__
                )
            finally:
                metrics.set("worker_connected", 0)
                metrics.set("worker_ready", 0)
                write_health(False)
                if connection is not None:
                    try:
                        async with asyncio.timeout(settings.event_operation_timeout_seconds):
                            await connection.close()
                    except Exception as error:
                        structlog.get_logger().debug(
                            "worker_close_failed", error_type=type(error).__name__
                        )
            if not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=settings.event_retry_delay_seconds)
                except TimeoutError:
                    pass
    structlog.get_logger().info("worker_stopped")
