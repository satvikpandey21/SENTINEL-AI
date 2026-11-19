from datetime import UTC, datetime
from uuid import uuid4

import pytest

from sentinel_security.config import Settings
from sentinel_security.events import SecurityEvent


@pytest.fixture
def settings(monkeypatch):
    for key in (
        "METRICS_ENABLED",
        "DATABASE_URL",
        "REDIS_URL",
        "RABBITMQ_URL",
        "ENVIRONMENT",
        "LOG_LEVEL",
        "DEPENDENCY_TIMEOUT_SECONDS",
        "DATABASE_POOL_SIZE",
        "DATABASE_MAX_OVERFLOW",
        "TRUSTED_PROXY_CIDRS",
        "PROTECTION_ENABLED",
        "PROTECTION_POLICIES",
        "PROTECTION_REDIS_TIMEOUT_SECONDS",
        "DEMO_AUTH_ENABLED",
        "DEMO_USERNAME",
        "DEMO_PASSWORD_HASH",
    ):
        monkeypatch.delenv(f"SENTINEL_{key}", raising=False)
    return Settings(
        environment="test",
        database_url="postgresql+asyncpg://test:unit-secret@localhost/sentinel_test",
        redis_url="redis://:unit-secret@localhost/0",
        rabbitmq_url="amqp://test:unit-secret@localhost/",
    )


@pytest.fixture
def security_event():
    return SecurityEvent(
        schema_version=1,
        event_type="http.request.completed",
        event_id=uuid4(),
        request_id=uuid4().hex,
        occurred_at=datetime.now(UTC),
        service="unit-service",
        method="GET",
        endpoint="/api/items/{item_id}",
        status_code=200,
        duration_ms=1.25,
        client_identifier="a" * 64,
        severity="info",
        authentication_outcome="not_provided",
        response_completed=True,
    )


class ASGISocket:
    """Real ASGI upgrade on the test's event loop, without a thread-bound DB pool."""

    def __init__(
        self, app, ticket=None, origin="https://dashboard.test", protocols=None, query=b""
    ):
        import asyncio

        self.incoming, self.outgoing = asyncio.Queue(), asyncio.Queue()
        self.app = app
        self.scope = {
            "type": "websocket",
            "asgi": {"version": "3.0", "spec_version": "2.4"},
            "path": "/api/admin/ws/v1/security",
            "raw_path": b"/api/admin/ws/v1/security",
            "query_string": query,
            "scheme": "wss",
            "root_path": "",
            "server": ("admin.test", 443),
            "client": ("127.0.0.1", 1234),
            "subprotocols": protocols
            if protocols is not None
            else (["sentinel.security.v1", "sentinel.ticket." + ticket] if ticket else []),
            "headers": [
                (b"origin", origin.encode()),
                (
                    b"sec-websocket-protocol",
                    ", ".join(
                        protocols
                        if protocols is not None
                        else (
                            ["sentinel.security.v1", "sentinel.ticket." + ticket] if ticket else []
                        )
                    ).encode(),
                ),
            ],
        }

    async def __aenter__(self):
        import asyncio

        await self.incoming.put({"type": "websocket.connect"})
        self.task = asyncio.create_task(self.app(self.scope, self.incoming.get, self.outgoing.put))
        self.handshake = await self.receive()
        return self

    async def receive(self):
        import asyncio

        return await asyncio.wait_for(self.outgoing.get(), 5)

    async def json(self):
        import json

        frame = await self.receive()
        assert frame["type"] == "websocket.send", frame
        return json.loads(frame["text"])

    async def __aexit__(self, *exc):
        import asyncio

        await self.incoming.put({"type": "websocket.disconnect", "code": 1000})
        try:
            await asyncio.wait_for(self.task, 2)
        except TimeoutError:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)


@pytest.fixture
def socket_factory():
    return ASGISocket
