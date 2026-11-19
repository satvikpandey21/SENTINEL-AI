"""Actual PostgreSQL sessions, atomic Redis redemption and cross-instance Pub/Sub."""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import delete, select, update
from test_admin_api import admin_env as real_admin_env
from test_admin_api import login

from sentinel_api.auth import digest
from sentinel_api.main import create_app
from sentinel_api.models import AdminAccount, AdminSession
from sentinel_security.analysis_storage import AnalysisEngine, AnalysisState, RiskAssessment
from sentinel_security.realtime import NotificationPublisher
from sentinel_security.storage import EventStore, SecurityEventRecord

admin_env = real_admin_env

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("SENTINEL_RUN_INTEGRATION") != "1", reason="Run through Compose test profile"
    ),
]


async def ticket(env, authorization):
    result = await env[1].post("/api/admin/ws/v1/ticket", headers=authorization)
    assert result.status_code == 200, result.text
    return result.json()["ticket"]


async def subscribed(app):
    async with asyncio.timeout(5):
        while not app.state.security_hub.available:  # noqa: ASYNC110 - bounded readiness poll
            await asyncio.sleep(0.01)


async def test_atomic_redemption_expiration_and_issuance_limit(admin_env, socket_factory):
    resources, client, _, _, _ = admin_env
    _, auth = await login(admin_env)
    app = client._transport.app
    await subscribed(app)
    secret = await ticket(admin_env, auth)
    async with socket_factory(app, secret) as first:
        assert first.handshake["type"] == "websocket.accept"
        async with socket_factory(app, secret) as replay:
            assert replay.handshake["code"] == 4401
    secret = await ticket(admin_env, auth)
    await resources.redis.expire("sentinel:ws:ticket:" + digest(secret), 0)
    async with socket_factory(app, secret) as expired:
        assert expired.handshake["code"] == 4401
    secret = await ticket(admin_env, auth)
    async with socket_factory(app, secret) as first, socket_factory(app, secret) as second:
        assert sorted([first.handshake["type"], second.handshake["type"]]) == [
            "websocket.accept",
            "websocket.close",
        ]
    for _ in range(9):
        await ticket(admin_env, auth)
    assert (await client.post("/api/admin/ws/v1/ticket", headers=auth)).status_code == 429


@pytest.mark.parametrize("change", ["disabled", "role", "revoked", "expired", "logout"])
async def test_live_authorization_and_handshake_follow_database(admin_env, socket_factory, change):
    resources, client, _, _, config = admin_env
    data, auth = await login(admin_env)
    app = client._transport.app
    app.state.admin_settings = config.model_copy(update={"ws_revalidate_seconds": 0.1})
    await subscribed(app)
    secret, next_secret = await ticket(admin_env, auth), await ticket(admin_env, auth)
    account_id = UUID(data["account"]["id"])
    async with socket_factory(app, secret) as ws:
        assert (await ws.json())["type"] == "connection.ready"
        if change == "logout":
            csrf = (await client.post("/api/admin/auth/csrf")).json()["csrf_token"]
            assert (
                await client.post("/api/admin/auth/logout", headers={"X-CSRF-Token": csrf})
            ).status_code == 204
        else:
            async with resources.session_factory() as session, session.begin():
                if change in ("disabled", "role"):
                    await session.execute(
                        update(AdminAccount)
                        .where(AdminAccount.id == account_id)
                        .values(
                            **({"active": False} if change == "disabled" else {"role": "ANALYST"})
                        )
                    )
                else:
                    await session.execute(
                        update(AdminSession)
                        .where(AdminSession.account_id == account_id)
                        .values(
                            **(
                                {"revoked_at": datetime.now(UTC)}
                                if change == "revoked"
                                else {
                                    "created_at": datetime.now(UTC) - timedelta(hours=1),
                                    "expires_at": datetime.now(UTC) - timedelta(seconds=1),
                                }
                            )
                        )
                    )
        assert (await ws.receive())["code"] == 4401
    async with socket_factory(app, next_secret) as rejected:
        assert rejected.handshake["code"] == 4401


async def test_committed_assessment_cross_instance_fanout_dedup_and_rest(
    admin_env, socket_factory, security_event
):
    resources, client, _, _, config = admin_env
    _, auth = await login(admin_env)
    app = client._transport.app

    @asynccontextmanager
    async def factory(settings):
        yield resources

    second = create_app(resources.settings, config, factory)
    async with second.router.lifespan_context(second):
        await subscribed(app)
        await subscribed(second)
        async with (
            socket_factory(app, await ticket(admin_env, auth)) as one,
            socket_factory(second, await ticket(admin_env, auth)) as two,
        ):
            await one.json()
            await two.json()
            async with NotificationPublisher(resources.redis) as publisher:
                store = EventStore(
                    resources.session_factory,
                    AnalysisEngine(resources.settings.analysis),
                    publisher,
                )
                assert await store.persist(security_event)
                assert not await store.persist(security_event)
                await publisher.queue.join()
                a, b = await one.json(), await two.json()
                assert a == b
                assert a["event_id"] == str(security_event.event_id)
                assert a["assessment_id"]
                result = await client.get("/api/admin/events/" + a["event_id"], headers=auth)
                assert result.status_code == 200
                assert result.json()["event_id"] == a["event_id"]
                async with resources.session_factory() as session:
                    assert (
                        await session.scalar(
                            select(RiskAssessment.event_id).where(
                                RiskAssessment.assessment_id == UUID(a["assessment_id"])
                            )
                        )
                        == security_event.event_id
                    )
                with pytest.raises(TimeoutError):
                    await asyncio.wait_for(one.outgoing.get(), 0.1)
                # Transport duplicates also cannot become duplicate visible frames.
                await resources.redis.publish("sentinel:security:notifications:v1", json.dumps(a))
                with pytest.raises(TimeoutError):
                    await asyncio.wait_for(two.outgoing.get(), 0.1)
    async with resources.session_factory() as session, session.begin():
        await session.execute(
            delete(SecurityEventRecord).where(
                SecurityEventRecord.event_id == security_event.event_id
            )
        )
        await session.execute(
            delete(AnalysisState).where(AnalysisState.service == security_event.service)
        )


async def test_atomic_concurrent_ticket_redemption(admin_env, socket_factory):
    resources, client, _, _, _ = admin_env
    _, auth = await login(admin_env)
    app = client._transport.app
    await subscribed(app)
    secret = await ticket(admin_env, auth)
    sockets = [socket_factory(app, secret), socket_factory(app, secret)]
    opened = await asyncio.gather(*(socket.__aenter__() for socket in sockets))
    try:
        assert sum(s.handshake["type"] == "websocket.accept" for s in opened) == 1
        assert sum(s.handshake.get("code") == 4401 for s in opened) == 1
    finally:
        await asyncio.gather(*(s.__aexit__(None, None, None) for s in opened))


async def test_distributed_connection_cap_and_release(admin_env, socket_factory):
    from contextlib import AsyncExitStack

    resources, client, _, _, config = admin_env
    _, auth = await login(admin_env)
    app = client._transport.app

    @asynccontextmanager
    async def factory(settings):
        yield resources

    second = create_app(resources.settings, config, factory)
    async with second.router.lifespan_context(second):
        await subscribed(app)
        await subscribed(second)
        async with AsyncExitStack() as stack:
            for index in range(4):
                ws = await stack.enter_async_context(
                    socket_factory(app if index % 2 else second, await ticket(admin_env, auth))
                )
                assert ws.handshake["type"] == "websocket.accept"
            async with socket_factory(second, await ticket(admin_env, auth)) as excess:
                assert excess.handshake["code"] == 4429
        async with socket_factory(app, await ticket(admin_env, auth)) as resumed:
            assert resumed.handshake["type"] == "websocket.accept"
