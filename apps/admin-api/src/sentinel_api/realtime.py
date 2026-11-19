"""Ticket-authenticated, bounded WebSockets with one Redis subscription per API process."""

import asyncio
import hashlib
import hmac
import json
import secrets
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import monotonic
from typing import Annotated
from uuid import UUID, uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select

from sentinel_api.auth import LIMIT_SCRIPT, TOKEN_PATTERN, current_account, digest, origin
from sentinel_api.models import AdminAccount, AdminSession
from sentinel_security.realtime import CHANNEL, MAX_BYTES, SecurityNotification

router = APIRouter(tags=["realtime"])
PROTOCOL = "sentinel.security.v1"
TICKET_PREFIX = "sentinel.ticket."
# Server-time leases bound connections across processes. Crash remnants expire in 60 seconds.
LEASE = """
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
for _, key in ipairs(KEYS) do redis.call('ZREMRANGEBYSCORE', key, '-inf', now) end
if ARGV[2] == 'renew' then
    if not redis.call('ZSCORE', KEYS[1], ARGV[1]) or
       not redis.call('ZSCORE', KEYS[2], ARGV[1]) then return 0 end
else
    if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) or
       redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[4]) then return 0 end
end
for _, key in ipairs(KEYS) do
    redis.call('ZADD', key, now + 60, ARGV[1])
    redis.call('EXPIRE', key, 65)
end
return 1
"""


class TicketOut(BaseModel):
    ticket: str = Field(min_length=43, max_length=43)
    expires_in: int
    protocol: str = PROTOCOL


def control(kind):
    return json.dumps(
        {
            "schema_version": 1,
            "type": "connection." + kind,
            "notification_id": str(uuid4()),
            "occurred_at": datetime.now(UTC).isoformat(),
        }
    )


async def limit(connection, namespace, identities, limits):
    redis = connection.app.state.resources.redis
    secret = bytes.fromhex(connection.app.state.admin_settings.signing_key.get_secret_value())
    keys = [
        "sentinel:ws:limit:"
        + namespace
        + ":"
        + hmac.new(secret, str(value).encode(), hashlib.sha256).hexdigest()
        for value in identities
    ]
    denied = await redis.eval(LIMIT_SCRIPT, len(keys), *keys, 60, *limits)
    if denied:
        raise HTTPException(429, "Streaming temporarily restricted", headers={"Retry-After": "60"})


@router.post("/ws/v1/ticket", response_model=TicketOut)
async def issue_ticket(
    request: Request, account: Annotated[AdminAccount, Depends(current_account)]
):
    origin(request)
    if account.role not in ("ADMIN", "ANALYST"):
        raise HTTPException(403, "Read permission required")
    settings = request.app.state.admin_settings
    async with asyncio.timeout(3):
        await limit(
            request,
            "ticket",
            [request.state.admin_session_id, account.id],
            [settings.ws_ticket_limit, settings.ws_ticket_limit * 2],
        )
        ticket = secrets.token_urlsafe(32)
        await request.app.state.resources.redis.set(
            "sentinel:ws:ticket:" + digest(ticket),
            json.dumps(
                {
                    "account": str(account.id),
                    "session": str(request.state.admin_session_id),
                    "origin": request.headers["origin"],
                    "role": account.role,
                }
            ),
            ex=settings.ws_ticket_seconds,
        )
    return TicketOut(ticket=ticket, expires_in=settings.ws_ticket_seconds)


async def authorized(resources, identity):
    async with asyncio.timeout(3), resources.session_factory() as session:
        return (
            await session.scalar(
                select(AdminAccount.id)
                .join(AdminSession, AdminSession.account_id == AdminAccount.id)
                .where(
                    AdminAccount.id == UUID(identity["account"]),
                    AdminAccount.active.is_(True),
                    AdminAccount.role == identity["role"],
                    AdminAccount.role.in_(("ADMIN", "ANALYST")),
                    AdminSession.id == UUID(identity["session"]),
                    AdminSession.revoked_at.is_(None),
                    AdminSession.expires_at > datetime.now(UTC),
                )
            )
            is not None
        )


def lease_keys(identity):
    return [
        "sentinel:ws:account:" + identity["account"],
        "sentinel:ws:session:" + identity["session"],
    ]


@dataclass(eq=False)
class Client:
    queue: asyncio.Queue
    closed: asyncio.Event = field(default_factory=asyncio.Event)
    code: int = 1013
    last_pong: float = field(default_factory=monotonic)

    def close(self, code=1013):
        self.code = code
        self.closed.set()


class SecurityHub:
    def __init__(self, redis, settings, metrics=None):
        self.redis, self.settings = redis, settings
        self.metrics = metrics
        self.clients = set()
        self.seen = OrderedDict()
        self.available = False
        self.task = None

    async def __aenter__(self):
        self.task = asyncio.create_task(self.listen())
        return self

    async def __aexit__(self, *exc):
        self.available = False
        for client in tuple(self.clients):
            client.close(1001)
        self.task.cancel()
        await asyncio.gather(self.task, return_exceptions=True)

    def fanout(self, body):
        started = monotonic()
        if not isinstance(body, str) or len(body.encode()) > MAX_BYTES:
            if self.metrics is not None:
                self.metrics.inc("notification_dropped", component="hub", reason="schema")
            return
        try:
            notification = SecurityNotification.model_validate_json(body)
        except (ValidationError, ValueError):
            if self.metrics is not None:
                self.metrics.inc("notification_dropped", component="hub", reason="schema")
            return
        key = notification.notification_id
        if key in self.seen:
            if self.metrics is not None:
                self.metrics.inc("notification_duplicates")
            return
        self.seen[key] = None
        if len(self.seen) > 4096:
            self.seen.popitem(last=False)
        # Re-serialize validated allowlist; never forward raw transport input.
        safe = notification.model_dump_json()
        for client in tuple(self.clients):
            if client.closed.is_set():
                continue
            try:
                client.queue.put_nowait(safe)
                if self.metrics is not None:
                    self.metrics.inc("notification_enqueued")
            except asyncio.QueueFull:
                if self.metrics is not None:
                    self.metrics.inc("notification_dropped", component="hub", reason="backpressure")
                    self.metrics.inc("ws_slow_consumers")
                client.close(1013)
        if self.metrics is not None:
            self.metrics.observe("notification_fanout_duration_seconds", monotonic() - started)

    async def listen(self):
        while True:
            try:
                async with self.redis.pubsub() as subscription:
                    await subscription.subscribe(CHANNEL)
                    while True:
                        message = await subscription.get_message(timeout=1)
                        if message and message["type"] == "subscribe":
                            self.available = True
                            if self.metrics is not None:
                                self.metrics.set("notification_subscription_up", 1)
                        elif message and message["type"] == "message":
                            self.fanout(message["data"])
                        await asyncio.sleep(0.01)
            except Exception as error:
                self.available = False
                if self.metrics is not None:
                    self.metrics.set("notification_subscription_up", 0)
                    self.metrics.inc("notification_subscription_errors")
                for client in tuple(self.clients):
                    client.close(1013)
                structlog.get_logger().warning(
                    "notification_subscription_failed", error_type=type(error).__name__
                )
                await asyncio.sleep(1)


async def send_messages(ws, client, settings, metrics=None):
    async def send(body):
        async with asyncio.timeout(3):
            await ws.send_text(body)

    await send(control("ready"))
    # Heartbeats have their own deadline, even under a continuous activity burst.
    next_heartbeat = monotonic() + settings.ws_heartbeat_seconds
    while True:
        if monotonic() >= next_heartbeat:
            await send(control("heartbeat"))
            next_heartbeat = monotonic() + settings.ws_heartbeat_seconds
        try:
            body = await asyncio.wait_for(
                client.queue.get(), max(0.001, next_heartbeat - monotonic())
            )
            await send(body)
            if metrics is not None:
                metrics.inc("notification_sent")
        except TimeoutError:
            await send(control("heartbeat"))
            next_heartbeat = monotonic() + settings.ws_heartbeat_seconds


async def receive_messages(ws, client):
    while True:
        message = await ws.receive()
        if message["type"] == "websocket.disconnect":
            raise WebSocketDisconnect(message.get("code", 1000))
        if message.get("text") != '{"type":"connection.pong"}':
            client.close(4400)
            return
        client.last_pong = monotonic()
        # Inbound traffic is heartbeat-only; bound application processing during abuse.
        await asyncio.sleep(0.1)


async def revalidate(ws, client, identity, connection_id):
    settings, resources = ws.app.state.admin_settings, ws.app.state.resources
    while True:
        await asyncio.sleep(settings.ws_revalidate_seconds)
        if not await authorized(resources, identity):
            metrics = getattr(ws.app.state, "metrics", None)
            if metrics is not None:
                metrics.inc("ws_revalidation_failures", reason="authorization")
            client.close(4401)
            return
        async with asyncio.timeout(3):
            renewed = await resources.redis.eval(
                LEASE, 2, *lease_keys(identity), connection_id, "renew", 0, 0
            )
        if not renewed or monotonic() - client.last_pong > settings.ws_idle_seconds:
            client.close(1013)
            return


@router.websocket("/ws/v1/security")
async def security_socket(ws: WebSocket):
    settings, resources, hub = (
        ws.app.state.admin_settings,
        ws.app.state.resources,
        ws.app.state.security_hub,
    )
    client, identity, acquired = None, None, False
    metrics = getattr(ws.app.state, "metrics", None)
    accepted, rejection, started = False, "unavailable", monotonic()
    if metrics is not None:
        metrics.inc("ws_attempts")
    connection_id = uuid4().hex
    try:
        # CORS middleware does not protect WebSockets. Reject ambiguous Origin/header input.
        if (
            ws.query_params
            or len(ws.headers.getlist("origin")) != 1
            or ws.headers.get("origin") not in settings.allowed_origins
        ):
            rejection = "invalid_origin"
            await ws.close(code=4403)
            return
        async with asyncio.timeout(3):
            await limit(ws, "handshake", [ws.client.host if ws.client else "unknown"], [120])
            protocols = ws.scope.get("subprotocols", [])
            if (
                len(protocols) != 2
                or PROTOCOL not in protocols
                or len(ws.headers.get("sec-websocket-protocol", "")) > 160
            ):
                rejection = "invalid_ticket"
                await ws.close(code=4401)
                return
            bearer = next(p for p in protocols if p != PROTOCOL)
            if not bearer.startswith(TICKET_PREFIX) or not TOKEN_PATTERN.fullmatch(
                bearer[len(TICKET_PREFIX) :]
            ):
                rejection = "invalid_ticket"
                await ws.close(code=4401)
                return
            raw = await resources.redis.getdel(
                "sentinel:ws:ticket:" + digest(bearer[len(TICKET_PREFIX) :])
            )
            if raw is None:
                rejection = "invalid_ticket"
                await ws.close(code=4401)
                return
            identity = json.loads(raw)
            if identity["origin"] != ws.headers["origin"] or not await authorized(
                resources, identity
            ):
                rejection = "invalid_ticket"
                await ws.close(code=4401)
                return
            if not hub.available or len(hub.clients) >= settings.ws_max_connections:
                await ws.close(code=1013)
                return
            acquired = bool(
                await resources.redis.eval(
                    LEASE,
                    2,
                    *lease_keys(identity),
                    connection_id,
                    "acquire",
                    settings.ws_account_connections,
                    settings.ws_session_connections,
                )
            )
            if not acquired:
                rejection = "capacity"
                await ws.close(code=4429)
                return
        client = Client(asyncio.Queue(maxsize=settings.ws_queue_capacity))
        # No await between capacity check and registration after the lease round trip.
        if len(hub.clients) >= settings.ws_max_connections:
            await ws.close(code=1013)
            return
        hub.clients.add(client)
        await ws.accept(subprotocol=PROTOCOL)  # Never echo the ticket subprotocol.
        accepted = True
        if metrics is not None:
            metrics.inc("ws_connections", outcome="accepted", reason="other")
            metrics.inc("ws_active")
        tasks = [
            asyncio.create_task(send_messages(ws, client, settings, metrics)),
            asyncio.create_task(receive_messages(ws, client)),
            asyncio.create_task(revalidate(ws, client, identity, connection_id)),
            asyncio.create_task(client.closed.wait()),
        ]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        await ws.close(code=client.code)
    except WebSocketDisconnect:
        pass
    except Exception as error:
        # Never log protocol headers, ticket state, URLs, or exception text.
        structlog.get_logger().warning("security_stream_closed", error_type=type(error).__name__)
        try:
            await ws.close(code=1013)
        except (RuntimeError, OSError):
            pass
    finally:
        if metrics is not None:
            if accepted:
                metrics.inc("ws_active", amount=-1)
                metrics.observe("ws_lifetime_seconds", monotonic() - started)
            else:
                metrics.inc("ws_connections", outcome="rejected", reason=rejection)
        if client is not None:
            hub.clients.discard(client)
        if acquired:
            try:
                async with asyncio.timeout(1):
                    for key in lease_keys(identity):
                        await resources.redis.zrem(key, connection_id)
            except Exception:
                structlog.get_logger().debug("stream_lease_cleanup_deferred")
