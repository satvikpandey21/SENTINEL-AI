"""Real Redis atomicity across independent clients and real demo ASGI instances."""

import asyncio
import os
from uuid import uuid4

import aio_pika
import httpx2 as httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import delete, select

from sentinel_demo.auth import DemoAuthSettings
from sentinel_demo.credentials import hash_password
from sentinel_demo.main import create_app
from sentinel_security.config import Settings
from sentinel_security.events import DetectionEvent, parse_event
from sentinel_security.infrastructure import Resources
from sentinel_security.messaging import EVENT_QUEUE, event_message
from sentinel_security.policies import AuthenticationRule, EndpointPolicy, RateLimitRule
from sentinel_security.protection import RedisProtectionStore, SecurityEngine, record_verified_login
from sentinel_security.storage import EventStore, SecurityEventRecord

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("SENTINEL_RUN_INTEGRATION") != "1", reason="Run in Compose test profile"
    ),
]


@pytest.fixture
async def backing():
    settings = Settings()
    async with Resources(settings) as resources:
        second = Redis.from_url(settings.redis_url.get_secret_value(), decode_responses=True)
        try:
            yield resources, second
        finally:
            await second.aclose()


def scope(path="/api/demo/limited"):
    return {"path": path, "method": "GET", "state": {"request_id": uuid4().hex}}


def make_policy(**changes):
    return EndpointPolicy(
        id="test-" + uuid4().hex,
        path_prefix="/api/demo/limited",
        rate=RateLimitRule(requests=5, window_seconds=0.3),
        **changes,
    )


def engine(redis, policy):
    return SecurityEngine(RedisProtectionStore(lambda: redis, 1), "sentinel-demo-api", (policy,))


async def test_atomic_limit_is_shared_by_independent_redis_clients(backing):
    resources, second = backing
    policy = make_policy()
    engines = (engine(resources.redis, policy), engine(second, policy))
    decisions = await asyncio.gather(
        *(engines[i % 2].before_request(scope(), "a" * 64) for i in range(30))
    )
    assert sum(decision.action == "allow" for decision in decisions) == 5
    assert sum(decision.response_status == 429 for decision in decisions) == 25
    rate, block, auth = engines[0].keys(policy, "a" * 64)
    assert await resources.redis.zcard(rate) == 5
    assert 0 < await resources.redis.pttl(rate) <= 300
    assert not await resources.redis.exists(block, auth)
    assert (await engines[1].before_request(scope(), "b" * 64)).action == "allow"
    await asyncio.sleep(0.35)
    assert not await resources.redis.exists(rate)
    assert (await engines[1].before_request(scope(), "a" * 64)).action == "allow"


async def test_temporary_block_does_not_extend_and_expires(backing):
    resources, _ = backing
    policy = make_policy().model_copy(
        update={
            "rate": RateLimitRule(
                requests=2, window_seconds=0.2, exceed_action="block", block_seconds=0.3
            )
        }
    )
    security = engine(resources.redis, policy)
    for _ in range(2):
        assert (await security.before_request(scope(), "a" * 64)).action == "allow"
    rejected = await security.before_request(scope(), "a" * 64)
    assert rejected.action == "temporary_block" and rejected.retry_after_seconds == 1
    _, block, _ = security.keys(policy, "a" * 64)
    ttl = await resources.redis.pttl(block)
    await asyncio.sleep(0.05)
    assert (await security.before_request(scope(), "a" * 64)).response_status == 429
    assert await resources.redis.pttl(block) < ttl
    assert (await security.before_request(scope(), "b" * 64)).action == "allow"
    await asyncio.sleep(0.3)
    assert not await resources.redis.exists(block)
    assert (await security.before_request(scope(), "a" * 64)).action == "allow"


async def test_observe_only_is_bounded_and_does_not_reject(backing):
    resources, _ = backing
    policy = make_policy().model_copy(
        update={"rate": RateLimitRule(requests=2, window_seconds=1, exceed_action="record")}
    )
    security = engine(resources.redis, policy)
    decisions = [await security.before_request(scope(), "c" * 64) for _ in range(12)]
    assert all(decision.response_status is None for decision in decisions)
    assert decisions[-1].action == "record"
    assert await resources.redis.zcard(security.keys(policy, "c" * 64)[0]) == 2


async def test_verified_failures_block_success_resets_and_generic_outcomes_do_not_count(backing):
    resources, _ = backing
    policy = make_policy(
        authentication=AuthenticationRule(failures=3, window_seconds=1, block_seconds=0.2)
    )
    security = engine(resources.redis, policy)
    request = scope()
    request["state"]["sentinel_authentication_outcome"] = "failed"
    for _ in range(5):
        assert (await security.after_authentication(request, "d" * 64)).action == "allow"
    for _ in range(2):
        request = scope()
        record_verified_login(request, succeeded=False)
        assert (await security.after_authentication(request, "d" * 64)).action == "allow"
    request = scope()
    record_verified_login(request, succeeded=True)
    await security.after_authentication(request, "d" * 64)
    auth_key = security.keys(policy, "d" * 64)[2]
    assert not await resources.redis.exists(auth_key)
    for index in range(3):
        request = scope()
        record_verified_login(request, succeeded=False)
        result = await security.after_authentication(request, "d" * 64)
        assert result.action == ("temporary_block" if index == 2 else "allow")
    assert (await security.before_request(scope(), "d" * 64)).response_status == 429
    assert (await security.before_request(scope(), "e" * 64)).action == "allow"
    await asyncio.sleep(0.25)
    # Auth-only scope avoids the unrelated request-rate quota for this assertion.
    assert not await resources.redis.exists(security.keys(policy, "d" * 64)[1])


async def test_two_demo_instances_share_limits_and_ignore_spoofed_headers(backing):
    resources, _ = backing
    policy = make_policy().model_copy(update={"rate": RateLimitRule(requests=4, window_seconds=2)})
    settings = Settings(
        **{
            **resources.settings.model_dump(),
            "protection_enabled": True,
            # This checks atomicity; allow instrumented in-process setup to finish.
            # Production retains its 200 ms deadline; timeout policy has separate tests.
            "protection_redis_timeout_seconds": 1.0,
            "client_identity_key": "c" * 64,
            "protection_policies": (policy,),
        }
    )
    apps = [create_app(settings, DemoAuthSettings()) for _ in range(2)]
    async with apps[0].router.lifespan_context(apps[0]), apps[1].router.lifespan_context(apps[1]):
        async with (
            httpx.AsyncClient(
                transport=httpx.ASGITransport(apps[0], client=("198.51.100.1", 1)),
                base_url="http://test",
            ) as a,
            httpx.AsyncClient(
                transport=httpx.ASGITransport(apps[1], client=("198.51.100.1", 2)),
                base_url="http://test",
            ) as b,
            httpx.AsyncClient(
                transport=httpx.ASGITransport(apps[1], client=("198.51.100.2", 3)),
                base_url="http://test",
            ) as unrelated,
        ):
            responses = await asyncio.gather(
                *(
                    client.get("/api/demo/limited", headers={"X-Forwarded-For": f"192.0.2.{i}"})
                    for i, client in enumerate([a, b] * 8)
                )
            )
            assert sum(response.status_code == 200 for response in responses) == 4
            assert sum(response.status_code == 429 for response in responses) == 12
            assert all(
                int(response.headers["Retry-After"]) >= 1
                for response in responses
                if response.status_code == 429
            )
            assert (await unrelated.get("/api/demo/limited")).status_code == 200


async def test_real_demo_login_brute_force_restriction_and_success(backing):
    resources, _ = backing
    policy = EndpointPolicy(
        id="login-" + uuid4().hex,
        path_prefix="/api/demo/login",
        failure_mode="closed",
        rate=None,
        authentication=AuthenticationRule(failures=3, window_seconds=1, block_seconds=0.2),
    )
    settings = Settings(
        **{
            **resources.settings.model_dump(),
            "protection_enabled": True,
            "client_identity_key": "e" * 64,
            "protection_policies": (policy,),
        }
    )
    auth = DemoAuthSettings(
        auth_enabled=True,
        username="test-demo",
        password_hash=hash_password("real-private-test-password"),
    )
    app = create_app(settings, auth)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app, client=("198.51.100.7", 1)), base_url="http://test"
        ) as client:
            good = {"username": "test-demo", "password": "real-private-test-password"}
            bad = {"username": "test-demo", "password": "wrong-private-test-password"}
            assert (await client.post("/api/demo/login", json=good)).status_code == 200
            for _ in range(3):
                assert (await client.post("/api/demo/login", json=bad)).status_code == 401
            assert (await client.post("/api/demo/login", json=good)).status_code == 429
            await asyncio.sleep(0.25)
            assert (await client.post("/api/demo/login", json=good)).status_code == 200


async def test_decision_rows_are_idempotent_and_v1_v2_replay_compatible(backing, security_event):
    resources, _ = backing
    event = DetectionEvent(
        **{
            **security_event.model_dump(),
            "schema_version": 2,
            "event_type": "security.decision",
            "rule_id": "test.rate",
            "security_action": "rate_limit",
            "counter_value": 6,
            "threshold": 5,
            "window_seconds": 3.0,
            "retry_after_seconds": 1,
        }
    )
    assert isinstance(parse_event(event.model_dump_json().encode(), 4096), DetectionEvent)
    store = EventStore(resources.session_factory)
    try:
        assert await store.persist(event)
        assert not await store.persist(event)
        async with resources.session_factory() as session:
            row = await session.scalar(
                select(SecurityEventRecord).where(SecurityEventRecord.event_id == event.event_id)
            )
            assert row.rule_id == "test.rate" and row.security_action == "rate_limit"
            assert row.counter_value == 6
    finally:
        async with resources.session_factory() as session, session.begin():
            await session.execute(
                delete(SecurityEventRecord).where(SecurityEventRecord.event_id == event.event_id)
            )


async def test_real_redis_connection_failure_is_open_for_reads_closed_for_login(backing):
    resources, _ = backing
    settings = Settings(
        **{
            **resources.settings.model_dump(),
            "protection_enabled": True,
            "client_identity_key": "f" * 64,
            "redis_url": "redis://127.0.0.1:1/0",
            "protection_policies": None,
        }
    )
    auth = DemoAuthSettings(
        auth_enabled=True,
        username="test-demo",
        password_hash=hash_password("private-outage-password"),
    )
    app = create_app(settings, auth)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://test"
        ) as client:
            assert (await client.get("/api/demo/ping")).status_code == 200
            response = await client.post(
                "/api/demo/login",
                json={"username": "test-demo", "password": "private-outage-password"},
            )
            assert response.status_code == 503
            assert response.headers["Retry-After"] == "1"
            assert response.json() == {"detail": "Service temporarily unavailable"}
            assert (await client.get("/health/live")).status_code == 200


async def test_broker_and_database_connection_failures_do_not_bypass_real_redis(backing):
    resources, _ = backing
    policy = make_policy().model_copy(update={"rate": RateLimitRule(requests=2, window_seconds=2)})
    settings = Settings(
        **{
            **resources.settings.model_dump(),
            "protection_enabled": True,
            "monitoring_enabled": True,
            "client_identity_key": "f" * 64,
            "protection_policies": (policy,),
            "database_url": "postgresql+asyncpg://unused:unused@127.0.0.1:1/unavailable",
            "rabbitmq_url": "amqp://unused:unused@127.0.0.1:1/",
            "event_publish_attempts": 1,
            "event_operation_timeout_seconds": 0.1,
            "event_shutdown_timeout_seconds": 0.1,
        }
    )
    app = create_app(settings, DemoAuthSettings())
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://test"
        ) as client:
            responses = [await client.get("/api/demo/limited") for _ in range(3)]
            assert [response.status_code for response in responses] == [200, 200, 429]
    assert app.state.event_publisher.stats.dropped > 0


async def test_real_worker_consumes_version_two_and_deduplicates(backing, security_event):
    resources, _ = backing
    event = DetectionEvent(
        **{
            **security_event.model_dump(),
            "schema_version": 2,
            "event_type": "security.decision",
            "rule_id": "worker-test.rate",
            "security_action": "rate_limit",
            "counter_value": 6,
            "threshold": 5,
        }
    )
    connection = await aio_pika.connect(
        resources.settings.rabbitmq_url.get_secret_value(), timeout=5
    )
    try:
        async with connection:
            channel = await connection.channel(publisher_confirms=True, on_return_raises=True)
            for _ in range(2):
                await channel.default_exchange.publish(
                    event_message(event.model_dump_json().encode(), str(event.event_id)),
                    routing_key=EVENT_QUEUE,
                    mandatory=True,
                )
        row = None
        for _ in range(100):
            async with resources.session_factory() as session:
                row = await session.scalar(
                    select(SecurityEventRecord).where(
                        SecurityEventRecord.event_id == event.event_id
                    )
                )
            if row:
                break
            await asyncio.sleep(0.05)
        assert row is not None and row.schema_version == 2
        assert row.rule_id == "worker-test.rate" and row.counter_value == 6
    finally:
        async with resources.session_factory() as session, session.begin():
            await session.execute(
                delete(SecurityEventRecord).where(SecurityEventRecord.event_id == event.event_id)
            )


async def test_observed_auth_failures_are_bounded_and_success_reset_is_configurable(backing):
    resources, _ = backing
    policy = make_policy().model_copy(
        update={
            "rate": None,
            "authentication": AuthenticationRule(
                failures=2, window_seconds=1, exceed_action="record", clear_on_success=False
            ),
        }
    )
    security = engine(resources.redis, policy)
    for _ in range(10):
        request = scope()
        record_verified_login(request, succeeded=False)
        decision = await security.after_authentication(request, "f" * 64)
    assert decision.action == "record" and decision.response_status is None
    _, block, auth = security.keys(policy, "f" * 64)
    assert await resources.redis.zcard(auth) == 2
    assert not await resources.redis.exists(block)
    request = scope()
    record_verified_login(request, succeeded=True)
    await security.after_authentication(request, "f" * 64)
    assert await resources.redis.zcard(auth) == 2
