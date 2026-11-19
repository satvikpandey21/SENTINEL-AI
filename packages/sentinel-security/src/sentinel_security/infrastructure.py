"""Per-process dependency clients with bounded probes and deterministic cleanup."""

import asyncio
from contextlib import AsyncExitStack
from time import monotonic

import aio_pika
import structlog
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_security.config import Settings


class Resources:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.engine = create_async_engine(
            settings.database_url.get_secret_value(),
            pool_pre_ping=True,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_timeout=settings.dependency_timeout_seconds,
            connect_args={"timeout": settings.dependency_timeout_seconds},
            hide_parameters=True,
        )
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.redis = Redis.from_url(
            settings.redis_url.get_secret_value(),
            socket_connect_timeout=settings.dependency_timeout_seconds,
            socket_timeout=settings.dependency_timeout_seconds,
            decode_responses=True,
        )
        self._stack = AsyncExitStack()

    async def __aenter__(self):
        await self._stack.__aenter__()
        self._stack.push_async_callback(self.engine.dispose)
        self._stack.push_async_callback(self.redis.aclose)
        return self

    async def __aexit__(self, *exc):
        await self._stack.__aexit__(*exc)

    async def _postgresql(self) -> None:
        async with self.engine.connect() as connection:
            await connection.execute(text("SELECT 1"))

    async def _redis(self) -> None:
        if not await self.redis.ping():
            raise ConnectionError("Redis did not acknowledge ping")

    async def _rabbitmq(self) -> None:
        # A bounded, short-lived AMQP handshake verifies authentication, not merely an open port.
        # No connection is required by the request middleware or future synchronous enforcement.
        connection = await aio_pika.connect(
            self.settings.rabbitmq_url.get_secret_value(),
            timeout=self.settings.dependency_timeout_seconds,
        )
        try:
            channel = await connection.channel()
            await channel.close()
        finally:
            await connection.close()

    async def health(self) -> dict[str, str]:
        async def probe(name, check):
            started = monotonic()
            up = False
            try:
                async with asyncio.timeout(self.settings.dependency_timeout_seconds):
                    await check()
                up = True
                return name, "up"
            except Exception as error:
                # Dependency library errors can contain connection URLs. Never log str(error).
                structlog.get_logger().warning(
                    "dependency_unavailable", dependency=name, error_type=type(error).__name__
                )
                return name, "down"
            finally:
                metrics = getattr(self, "metrics", None)
                if metrics is not None:
                    metrics.dependency(name, up, monotonic() - started)

        return dict(
            await asyncio.gather(
                probe("postgresql", self._postgresql),
                probe("redis", self._redis),
                probe("rabbitmq", self._rabbitmq),
            )
        )
