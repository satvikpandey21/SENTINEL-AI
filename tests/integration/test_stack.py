"""Real dependency and HTTP smoke checks, enabled explicitly by the Compose test service."""

import os
from uuid import uuid4

import aio_pika
import httpx2 as httpx
import pytest
from sqlalchemy import text

from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("SENTINEL_RUN_INTEGRATION") != "1", reason="Run via Compose test profile"
    ),
]


async def test_real_dependency_health_and_migration():
    async with Resources(Settings()) as resources:
        assert await resources.health() == {"postgresql": "up", "redis": "up", "rabbitmq": "up"}
        async with resources.session_factory() as session:
            revision = await session.scalar(text("SELECT version_num FROM alembic_version"))
            assert revision == "0001_baseline"
            assert await session.scalar(text("SELECT 42")) == 42


async def test_real_redis_write_read_delete():
    async with Resources(Settings()) as resources:
        key = f"sentinel:integration:{uuid4().hex}"
        try:
            assert await resources.redis.set(key, "probe", ex=30)
            assert await resources.redis.get(key) == "probe"
        finally:
            await resources.redis.delete(key)


async def test_real_rabbitmq_message_roundtrip():
    connection = await aio_pika.connect(Settings().rabbitmq_url.get_secret_value(), timeout=5)
    async with connection:
        channel = await connection.channel(publisher_confirms=True)
        queue = await channel.declare_queue(exclusive=True, auto_delete=True)
        await channel.default_exchange.publish(
            aio_pika.Message(body=b"sentinel-health-probe"), routing_key=queue.name
        )
        message = await queue.get(timeout=5)
        async with message.process():
            assert message.body == b"sentinel-health-probe"


@pytest.mark.parametrize("service", ["admin-api", "demo-api"])
async def test_running_services(service):
    async with httpx.AsyncClient(base_url=f"http://{service}:8000", timeout=10) as client:
        assert (await client.get("/health/live")).status_code == 200
        response = await client.get("/health/ready")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"
        assert len(response.headers["X-Request-ID"]) == 32
        if service == "demo-api":
            assert (await client.get("/api/demo/ping")).json() == {"message": "pong"}
