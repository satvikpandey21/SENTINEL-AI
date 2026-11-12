"""Actual HTTP -> ASGI -> confirmed RabbitMQ publication -> worker -> PostgreSQL."""

import asyncio
import hashlib
import json
import os
from time import monotonic
from uuid import uuid4

import aio_pika
import httpx2 as httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import delete, func, select, text

from sentinel_security.config import Settings
from sentinel_security.events import DeadLetterNotice
from sentinel_security.infrastructure import Resources
from sentinel_security.messaging import DEAD_QUEUE, EVENT_QUEUE, event_message
from sentinel_security.storage import EventStore, SecurityEventRecord
from sentinel_worker.consumer import EventConsumer

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("SENTINEL_RUN_INTEGRATION") != "1", reason="Run via Compose test profile"
    ),
]


@pytest.fixture
async def resources():
    async with Resources(Settings()) as dependencies:
        yield dependencies


async def find_requests(resources, request_ids):
    deadline = monotonic() + 15
    while monotonic() < deadline:
        async with resources.session_factory() as session:
            records = (
                await session.scalars(
                    select(SecurityEventRecord).where(
                        SecurityEventRecord.request_id.in_(request_ids)
                    )
                )
            ).all()
        if len(records) == len(request_ids):
            return records
        await asyncio.sleep(0.05)
    raise AssertionError(
        f"Expected {len(request_ids)} persisted request events, found {len(records)}"
    )


async def remove_event(resources, event_id):
    async with resources.session_factory() as session, session.begin():
        await session.execute(
            delete(SecurityEventRecord).where(SecurityEventRecord.event_id == event_id)
        )


async def test_real_http_event_persistence_and_sensitive_data_exclusion(resources):
    marker = uuid4().hex
    async with httpx.AsyncClient(base_url="http://demo-api:8000", timeout=10) as client:
        response = await client.request(
            "GET",
            f"/api/demo/ping?password=query-{marker}",
            content=f'{{"password":"body-{marker}"}}'.encode(),
            headers={
                "Authorization": f"Bearer token-{marker}",
                "Cookie": f"session=cookie-{marker}",
                "X-Forwarded-For": "198.51.100.77",
                "X-Request-ID": f"caller-{marker}",
            },
        )
        assert response.status_code == 200
        assert response.json() == {"message": "pong"}
    records = await find_requests(resources, [response.headers["X-Request-ID"]])
    (event,) = records
    assert event.schema_version == 1
    assert event.service == "sentinel-demo-api"
    assert event.endpoint == "/api/demo/ping"
    assert event.status_code == 200
    assert event.response_completed
    assert event.duration_ms >= 0
    assert event.occurred_at.tzinfo is not None
    assert event.authentication_outcome == "not_provided"
    assert len(event.client_identifier) == 64
    stored = json.dumps(
        {column.name: getattr(event, column.name) for column in event.__table__.columns},
        default=str,
    )
    assert marker not in stored
    assert "198.51.100.77" not in stored
    assert "authorization" not in stored.lower()
    assert "password" not in stored.lower()


async def test_failed_request_persists_sanitized_endpoint(resources):
    raw_path = f"/missing-private-{uuid4().hex}"
    async with httpx.AsyncClient(base_url="http://demo-api:8000", timeout=10) as client:
        response = await client.get(raw_path)
    assert response.status_code == 404
    (event,) = await find_requests(resources, [response.headers["X-Request-ID"]])
    assert event.endpoint == "unmatched"
    assert event.severity == "warning"
    assert event.status_code == 404
    assert raw_path not in event.endpoint


async def test_concurrent_real_requests_are_all_persisted(resources):
    async with httpx.AsyncClient(base_url="http://demo-api:8000", timeout=10) as client:
        responses = await asyncio.gather(*(client.get("/api/demo/ping") for _ in range(25)))
    assert all(response.status_code == 200 for response in responses)
    identifiers = [response.headers["X-Request-ID"] for response in responses]
    assert len(set(identifiers)) == 25
    records = await find_requests(resources, identifiers)
    assert len({event.event_id for event in records}) == 25
    assert len({event.client_identifier for event in records}) == 1


async def test_health_and_docs_requests_do_not_create_security_events(resources):
    async with httpx.AsyncClient(base_url="http://demo-api:8000", timeout=10) as client:
        responses = [
            await client.get(path)
            for path in ("/health/live", "/health/ready", "/docs", "/openapi.json")
        ]
    identifiers = [response.headers["X-Request-ID"] for response in responses]
    # Let preceding API publication drain; these excluded IDs must never appear.
    await asyncio.sleep(0.2)
    async with resources.session_factory() as session:
        assert (
            await session.scalar(
                select(func.count())
                .select_from(SecurityEventRecord)
                .where(SecurityEventRecord.request_id.in_(identifiers))
            )
            == 0
        )


async def test_concurrent_duplicate_inserts_are_idempotent(resources, security_event):
    store = EventStore(resources.session_factory)
    try:
        results = await asyncio.gather(*(store.persist(security_event) for _ in range(8)))
        assert sum(results) == 1
        async with resources.session_factory() as session:
            assert (
                await session.scalar(
                    select(func.count())
                    .select_from(SecurityEventRecord)
                    .where(SecurityEventRecord.event_id == security_event.event_id)
                )
                == 1
            )
    finally:
        await remove_event(resources, security_event.event_id)


async def test_duplicate_broker_deliveries_ack_without_duplicate_rows(resources, security_event):
    connection = await aio_pika.connect(Settings().rabbitmq_url.get_secret_value(), timeout=5)
    try:
        async with connection:
            channel = await connection.channel(publisher_confirms=True, on_return_raises=True)
            queue = await channel.declare_queue(exclusive=True, auto_delete=True)
            consumer = EventConsumer(EventStore(resources.session_factory), channel, Settings())
            for _ in range(2):
                await channel.default_exchange.publish(
                    event_message(security_event.model_dump_json().encode()),
                    routing_key=queue.name,
                    mandatory=True,
                )
                message = await queue.get(timeout=5)
                await consumer.handle(message)
                assert message.processed
            async with resources.session_factory() as session:
                assert (
                    await session.scalar(
                        select(func.count())
                        .select_from(SecurityEventRecord)
                        .where(SecurityEventRecord.event_id == security_event.event_id)
                    )
                    == 1
                )
    finally:
        await remove_event(resources, security_event.event_id)


@pytest.mark.parametrize(
    "body,reason",
    [
        (b'{"password":"must-not-be-copied","schema_version":999}', "invalid_event"),
        (b"must-not-be-copied" * 300, "oversized_event"),
    ],
)
async def test_running_worker_redacts_malformed_and_oversized_events(body, reason):
    fingerprint = hashlib.sha256(body).hexdigest()
    connection = await aio_pika.connect(Settings().rabbitmq_url.get_secret_value(), timeout=5)
    async with connection:
        channel = await connection.channel(publisher_confirms=True, on_return_raises=True)
        await channel.set_qos(prefetch_count=16)
        dead = await channel.declare_queue(DEAD_QUEUE, passive=True)
        await channel.default_exchange.publish(
            event_message(body), routing_key=EVENT_QUEUE, mandatory=True
        )
        held = []
        try:
            deadline = monotonic() + 10
            while monotonic() < deadline:
                message = await dead.get(fail=False, timeout=3)
                if message is None:
                    await asyncio.sleep(0.05)
                    continue
                notice = DeadLetterNotice.model_validate_json(message.body)
                if notice.payload_sha256 != fingerprint:
                    held.append(message)
                    if len(held) >= 16:
                        raise AssertionError("Dead-letter backlog exceeds bounded test scan")
                    continue
                assert notice.reason == reason
                assert notice.event is None
                assert b"must-not-be-copied" not in message.body
                assert b"password" not in message.body
                await message.ack()
                break
            else:
                raise AssertionError("Worker did not produce a redacted dead-letter notice")
        finally:
            for message in held:
                await message.nack(requeue=True)


async def test_unavailable_database_quarantines_safely_and_preserves_replayable_event(
    resources, security_event, monkeypatch
):
    settings = Settings().model_copy(
        update={
            "database_url": SecretStr("postgresql+asyncpg://unused:unused@127.0.0.1:1/unavailable"),
            "worker_storage_attempts": 2,
            "event_retry_delay_seconds": 0.01,
        }
    )
    connection = await aio_pika.connect(settings.rabbitmq_url.get_secret_value(), timeout=5)
    async with connection, Resources(settings) as unavailable:
        channel = await connection.channel(publisher_confirms=True, on_return_raises=True)
        source = await channel.declare_queue(exclusive=True, auto_delete=True)
        dead = await channel.declare_queue(exclusive=True, auto_delete=True)
        monkeypatch.setattr("sentinel_worker.consumer.DEAD_QUEUE", dead.name)
        await channel.default_exchange.publish(
            event_message(security_event.model_dump_json().encode()),
            routing_key=source.name,
            mandatory=True,
        )
        message = await source.get(timeout=5)
        await EventConsumer(EventStore(unavailable.session_factory), channel, settings).handle(
            message
        )
        assert message.processed
        quarantined = await dead.get(timeout=5)
        notice = DeadLetterNotice.model_validate_json(quarantined.body)
        assert notice.reason == "retry_exhausted"
        assert notice.event.event_id == security_event.event_id
        try:
            assert await EventStore(resources.session_factory).persist(notice.event)
            await quarantined.ack()
        finally:
            await remove_event(resources, security_event.event_id)


async def test_investigation_indexes_and_no_unauthenticated_event_api(resources):
    async with resources.session_factory() as session:
        indexes = set(
            (
                await session.scalars(
                    text("SELECT indexname FROM pg_indexes WHERE tablename = 'security_events'")
                )
            ).all()
        )
    assert {
        "ix_security_events_time",
        "ix_security_events_service_time",
        "ix_security_events_severity_time",
        "ix_security_events_client_time",
        "ix_security_events_request_id",
    } <= indexes
    async with httpx.AsyncClient(base_url="http://admin-api:8000", timeout=10) as client:
        for path in ("/events", "/api/events", "/api/security/events"):
            assert (await client.get(path)).status_code == 404
