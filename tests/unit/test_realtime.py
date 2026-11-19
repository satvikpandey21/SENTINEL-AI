"""Notification isolation, bounded fan-out, handshake and lifecycle regression checks."""

import asyncio
import json
import secrets
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import httpx2 as httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError

from sentinel_api import realtime as rt
from sentinel_api.auth import current_account, digest
from sentinel_api.settings import AdminSettings
from sentinel_security.realtime import (
    MAX_BYTES,
    NotificationPublisher,
    SecurityNotification,
    notification_for,
)
from sentinel_security.storage import EventStore


@pytest.fixture
def ws_env(monkeypatch):
    app = FastAPI()
    app.include_router(rt.router, prefix="/api/admin")
    config = AdminSettings(
        signing_key=secrets.token_hex(32),
        allowed_origins=("https://dashboard.test",),
        ws_revalidate_seconds=0.1,
        ws_heartbeat_seconds=1,
    )
    redis = MagicMock(
        getdel=AsyncMock(),
        eval=AsyncMock(side_effect=lambda script, *args: 0 if script == rt.LIMIT_SCRIPT else 1),
        zrem=AsyncMock(),
        set=AsyncMock(),
    )
    app.state.admin_settings = config
    app.state.resources = SimpleNamespace(redis=redis)
    hub = rt.SecurityHub(redis, config)
    hub.available = True
    app.state.security_hub = hub
    identity = {
        "account": str(uuid4()),
        "session": str(uuid4()),
        "origin": config.allowed_origins[0],
        "role": "ADMIN",
    }
    redis.getdel.return_value = json.dumps(identity)
    check = AsyncMock(return_value=True)
    monkeypatch.setattr(rt, "authorized", check)
    return app, redis, hub, identity, check


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST"])
async def test_authenticated_upgrade_fixed_protocol_and_cleanup(ws_env, socket_factory, role):
    app, redis, hub, identity, _ = ws_env
    identity["role"] = role
    redis.getdel.return_value = json.dumps(identity)
    async with socket_factory(app, secrets.token_urlsafe(32)) as ws:
        assert ws.handshake == {
            "type": "websocket.accept",
            "subprotocol": rt.PROTOCOL,
            "headers": [],
        }
        assert (await ws.json())["type"] == "connection.ready"
        assert len(hub.clients) == 1
    assert not hub.clients
    assert redis.zrem.await_count == 2


@pytest.mark.parametrize(
    "kwargs,code",
    [
        ({"ticket": None}, 4401),
        ({"protocols": [rt.PROTOCOL, "sentinel.ticket.bad"]}, 4401),
        ({"origin": "https://evil.test"}, 4403),
        ({"query": b"token=forbidden"}, 4403),
        ({"protocols": [rt.PROTOCOL, "extra", "sentinel.ticket." + "a" * 43]}, 4401),
    ],
)
async def test_handshake_rejections(ws_env, socket_factory, kwargs, code):
    app, _, hub, _, _ = ws_env
    values = {"ticket": secrets.token_urlsafe(32), **kwargs}
    async with socket_factory(app, **values) as ws:
        assert ws.handshake["code"] == code
    assert not hub.clients


@pytest.mark.parametrize("reason", ["missing", "expired", "reused"])
async def test_invalid_expired_reused_ticket_rejected(ws_env, socket_factory, reason):
    app, redis, _, _, _ = ws_env
    redis.getdel.return_value = None
    async with socket_factory(app, secrets.token_urlsafe(32)) as ws:
        assert ws.handshake["code"] == 4401


async def test_revocation_and_bad_origin_bound_ticket(ws_env, socket_factory):
    app, redis, _, identity, check = ws_env
    check.return_value = False
    async with socket_factory(app, secrets.token_urlsafe(32)) as ws:
        assert ws.handshake["code"] == 4401
    check.return_value = True
    identity["origin"] = "https://other.test"
    redis.getdel.return_value = json.dumps(identity)
    async with socket_factory(app, secrets.token_urlsafe(32)) as ws:
        assert ws.handshake["code"] == 4401


async def test_existing_stream_revalidates_and_closes(ws_env, socket_factory):
    app, _, hub, _, check = ws_env
    async with socket_factory(app, secrets.token_urlsafe(32)) as ws:
        await ws.json()
        check.return_value = False
        assert (await ws.receive())["code"] == 4401
    assert not hub.clients


@pytest.mark.parametrize("failure", [OSError("secret"), TimeoutError(), RuntimeError("private")])
async def test_dependency_failure_closes_safely(ws_env, socket_factory, failure):
    app, redis, hub, _, _ = ws_env
    redis.getdel.side_effect = failure
    async with socket_factory(app, secrets.token_urlsafe(32)) as ws:
        assert ws.handshake["code"] == 1013
    assert not hub.clients


async def test_connection_limit_and_transport_unavailable(ws_env, socket_factory):
    app, redis, hub, _, _ = ws_env
    redis.eval.side_effect = [0, 0]  # attempt allowed; lease rejected
    async with socket_factory(app, secrets.token_urlsafe(32)) as ws:
        assert ws.handshake["code"] == 4429
    hub.available = False
    redis.eval.side_effect = None
    async with socket_factory(app, secrets.token_urlsafe(32)) as ws:
        assert ws.handshake["code"] == 1013


async def test_ticket_requires_auth_origin_intent_and_rate_limit(ws_env):
    app, redis, _, identity, _ = ws_env
    redis.eval.side_effect = None
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://admin.test"
    ) as client:
        assert (await client.post("/api/admin/ws/v1/ticket")).status_code == 401

        async def account(request: __import__("fastapi").Request):
            request.state.admin_session_id = identity["session"]
            return SimpleNamespace(id=identity["account"], role="ADMIN")

        app.dependency_overrides[current_account] = account
        assert (await client.post("/api/admin/ws/v1/ticket")).status_code == 403
        headers = {"Origin": identity["origin"], "X-CSRF-Intent": "sentinel-admin"}
        redis.eval.return_value = 0
        result = await client.post("/api/admin/ws/v1/ticket", headers=headers)
        assert result.status_code == 200
        ticket = result.json()["ticket"]
        assert len(ticket) == 43
        args, kwargs = redis.set.call_args
        assert ticket not in args[0] and digest(ticket) in args[0]
        assert kwargs["ex"] == 20
        redis.eval.return_value = 1
        assert (await client.post("/api/admin/ws/v1/ticket", headers=headers)).status_code == 429


def test_schema_privacy_dedupe_and_backpressure(security_event):
    n = notification_for(security_event)
    body = n.model_dump_json()
    assert len(body.encode()) < MAX_BYTES
    assert security_event.client_identifier not in body
    assert set(json.loads(body)).isdisjoint(
        {"cookies", "authorization", "request_id", "body", "client_ip"}
    )
    with pytest.raises(ValidationError):
        SecurityNotification.model_validate({**n.model_dump(), "secret": "bad"})
    with pytest.raises(ValidationError):
        SecurityNotification.model_validate({**n.model_dump(), "endpoint": "/api?token=secret"})
    hub = rt.SecurityHub(None, None)
    fast, slow = rt.Client(asyncio.Queue(4)), rt.Client(asyncio.Queue(1))
    hub.clients.update((fast, slow))
    hub.fanout(body)
    hub.fanout(body)
    assert fast.queue.qsize() == 1
    other_id = uuid4()
    other = n.model_copy(update={"notification_id": other_id, "event_id": other_id})
    hub.fanout(other.model_dump_json())
    assert slow.closed.is_set() and not fast.closed.is_set()
    hub.fanout("a" * (MAX_BYTES + 1))
    hub.fanout("{}")
    assert fast.queue.qsize() == 2


async def test_publisher_failure_is_bounded_and_nonblocking(security_event):
    redis = SimpleNamespace(publish=AsyncMock(side_effect=OSError("private-url")))
    publisher = NotificationPublisher(redis, capacity=1, timeout=0.01)
    publisher.offer(notification_for(security_event))
    publisher.offer(notification_for(security_event))
    assert publisher.dropped == 1
    async with publisher:
        await asyncio.wait_for(publisher.queue.join(), 1)
    assert publisher.dropped == 2
    assert publisher.task.done()


@pytest.mark.parametrize("inserted", [True, False])
async def test_publish_after_commit_only_and_duplicate_suppression(security_event, inserted):
    order = []
    session = MagicMock(execute=AsyncMock())
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=uuid4() if inserted else None)
    )
    transaction = MagicMock(
        __aenter__=AsyncMock(), __aexit__=AsyncMock(side_effect=lambda *a: order.append("commit"))
    )
    session.begin.return_value = transaction
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    notifier = SimpleNamespace(offer=lambda n: order.append("notify"))
    store = EventStore(lambda: session, notifier=notifier)
    assert await store.persist(security_event) is inserted
    assert order == (["commit", "notify"] if inserted else ["commit"])
    transaction.__aexit__.side_effect = OSError("commit failed")
    order.clear()
    with pytest.raises(OSError):
        await store.persist(security_event)
    assert order == []


async def test_heartbeat_invalid_client_message_and_shutdown(ws_env, socket_factory):
    app, _, hub, _, _ = ws_env
    async with socket_factory(app, secrets.token_urlsafe(32)) as ws:
        await ws.json()
        assert (await ws.json())["type"] == "connection.heartbeat"
        await ws.incoming.put({"type": "websocket.receive", "text": "unexpected"})
        assert (await ws.receive())["code"] == 4400
    assert not hub.clients


async def test_subscription_failure_closes_clients_and_shutdown_cancels_task(ws_env):
    _, redis, hub, _, _ = ws_env
    client = rt.Client(asyncio.Queue(1))
    hub.clients.add(client)
    subscription = MagicMock(__aenter__=AsyncMock(side_effect=OSError("private-redis")))
    redis.pubsub.return_value = subscription
    async with hub:
        await asyncio.wait_for(client.closed.wait(), 1)
        assert client.code == 1013
        assert not hub.available
    assert hub.task.done()


async def test_idle_and_database_failure_close_open_stream(ws_env, socket_factory):
    app, _, hub, _, check = ws_env
    async with socket_factory(app, secrets.token_urlsafe(32)) as ws:
        await ws.json()
        for client in hub.clients:
            client.last_pong -= 100
        assert (await ws.receive())["code"] == 1013
    async with socket_factory(app, secrets.token_urlsafe(32)) as ws:
        await ws.json()
        check.side_effect = OSError("private-database-url")
        assert (await ws.receive())["code"] == 1013


async def test_failing_notification_offer_does_not_change_commit(security_event):
    session = MagicMock(
        execute=AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: uuid4()))
    )
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    transaction = MagicMock(__aenter__=AsyncMock(), __aexit__=AsyncMock(return_value=False))
    session.begin.return_value = transaction
    notifier = MagicMock(offer=MagicMock(side_effect=RuntimeError("private")))
    assert await EventStore(lambda: session, notifier=notifier).persist(security_event)
    transaction.__aexit__.assert_awaited_once()


async def test_binary_client_input_rejected(ws_env, socket_factory):
    app, _, _, _, _ = ws_env
    async with socket_factory(app, secrets.token_urlsafe(32)) as ws:
        await ws.json()
        await ws.incoming.put({"type": "websocket.receive", "bytes": b"private-input"})
        assert (await ws.receive())["code"] == 4400


async def test_heartbeats_are_not_starved_by_busy_outbound_queue():
    sent = []
    client = rt.Client(asyncio.Queue(100))
    for _ in range(100):
        client.queue.put_nowait("activity")

    async def send(body):
        sent.append(body)
        await asyncio.sleep(0.005)
        if len(sent) >= 15:
            raise WebSocketDisconnect()

    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect):
        await rt.send_messages(
            SimpleNamespace(send_text=send), client, SimpleNamespace(ws_heartbeat_seconds=0.02)
        )
    assert any("connection.heartbeat" in body for body in sent)
    assert not client.queue.empty()
