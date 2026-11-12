import asyncio
from types import SimpleNamespace

import httpx2 as httpx
import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient
from starlette.responses import StreamingResponse

from sentinel_security.application import create_application
from sentinel_security.config import Settings
from sentinel_security.events import record_authentication_outcome
from sentinel_security.middleware import RequestContextMiddleware


class MemorySink:
    def __init__(self):
        self.events = []
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        self.closed = True

    def offer(self, event):
        self.events.append(event)
        return True


class Dependencies:
    def __init__(self, settings):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        pass

    async def health(self):
        return {"postgresql": "up", "redis": "up", "rabbitmq": "up"}


@pytest.fixture
def monitored(settings):
    settings = Settings(
        **{
            **settings.model_dump(),
            "monitoring_enabled": True,
            "client_identity_key": "b" * 64,
        }
    )
    sink = MemorySink()
    app = create_application("test-service", settings, Dependencies, lambda _: sink)

    @app.post("/items/{item_id}")
    async def item(request: Request, item_id: str):
        await request.body()
        await asyncio.sleep(0.01)
        return {"ok": True}

    @app.get("/auth-result")
    async def auth_result(request: Request):
        record_authentication_outcome(request.scope, "failed")
        raise HTTPException(status_code=401, detail="Authentication required")

    @app.get("/broken")
    async def broken():
        raise RuntimeError("secret-exception-text")

    return app, sink


def test_success_metadata_and_sensitive_data_exclusion(monitored):
    app, sink = monitored
    with TestClient(app) as client:
        response = client.post(
            "/items/private-person?password=query-secret",
            content=b'{"password":"body-secret"}',
            headers={
                "Authorization": "Bearer header-secret",
                "Cookie": "session=cookie-secret",
                "X-Request-ID": "caller-id",
                "X-Forwarded-For": "198.51.100.99",
            },
        )
    assert response.status_code == 200
    assert sink.closed
    (event,) = sink.events
    assert event.request_id == response.headers["X-Request-ID"]
    assert event.service == "test-service"
    assert event.endpoint == "/items/{item_id}"
    assert event.duration_ms >= 5
    assert event.response_completed
    assert event.authentication_outcome == "not_provided"
    assert event.severity == "info"
    assert len(event.client_identifier) == 64
    for secret in (
        "private-person",
        "query-secret",
        "body-secret",
        "header-secret",
        "cookie-secret",
        "198.51.100.99",
        "caller-id",
    ):
        assert secret not in event.model_dump_json()


def test_failures_and_explicit_authentication_outcome(monitored):
    app, sink = monitored
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/auth-result").status_code == 401
        assert client.get("/broken").status_code == 500
        assert client.get("/raw-secret-missing-path").status_code == 404
    auth, broken, missing = sink.events
    assert (auth.status_code, auth.severity, auth.authentication_outcome) == (
        401,
        "warning",
        "failed",
    )
    assert (broken.status_code, broken.severity, broken.response_completed) == (500, "error", False)
    assert missing.endpoint == "unmatched"
    assert missing.status_code == 404
    assert "secret-exception-text" not in broken.model_dump_json()


def test_exclusions_and_sink_failure_do_not_affect_responses(monitored):
    app, sink = monitored
    with TestClient(app) as client:
        client.get("/health/live")
        client.get("/health/ready")
        client.get("/docs")
        client.get("/openapi.json")
        assert sink.events == []

        def broken_sink(event):
            raise RuntimeError("broker-password")

        sink.offer = broken_sink
        assert client.post("/items/a").status_code == 200


async def test_concurrent_requests_have_independent_contexts(monitored):
    app, sink = monitored
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://test"
        ) as client:
            responses = await asyncio.gather(*(client.post(f"/items/{i}") for i in range(50)))
    ids = {response.headers["X-Request-ID"] for response in responses}
    assert all(response.status_code == 200 for response in responses)
    assert len(ids) == len(sink.events) == 50
    assert {event.request_id for event in sink.events} == ids
    assert len({event.client_identifier for event in sink.events}) == 1


def test_stream_failure_records_actual_status_and_incomplete_response(monitored):
    app, sink = monitored

    async def stream():
        yield b"part"
        raise RuntimeError("sensitive-stream-error")

    @app.get("/stream")
    async def streaming():
        return StreamingResponse(stream())

    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/stream").status_code == 200
    (event,) = sink.events
    assert event.status_code == 200
    assert event.severity == "error"
    assert event.response_completed is False


async def test_reusable_asgi_adapter_never_consumes_request_body():
    sink = MemorySink()
    received = []
    sent = []

    async def receive():
        received.append(True)
        return {"type": "http.request", "body": b"private-body", "more_body": False}

    async def send(message):
        sent.append(message)

    async def downstream(scope, receive, send):
        assert (await receive())["body"] == b"private-body"
        scope["route"] = SimpleNamespace(path="/generic/{id}")
        await send({"type": "http.response.start", "status": 201, "headers": []})
        await send({"type": "http.response.body", "body": b"private-response"})

    middleware = RequestContextMiddleware(downstream, event_sink=sink, identity_key=b"x" * 32)
    await middleware(
        {
            "type": "http",
            "method": "SECRET-METHOD",
            "path": "/generic/private-id",
            "headers": [],
            "client": ("198.51.100.2", 99),
        },
        receive,
        send,
    )
    assert len(received) == 1
    assert sink.events[0].method == "OTHER"
    assert sink.events[0].endpoint == "/generic/{id}"
    assert sent[-1]["body"] == b"private-response"
    assert "private" not in sink.events[0].model_dump_json()


def test_missing_identity_key_rejected():
    with pytest.raises(ValueError):
        RequestContextMiddleware(None, event_sink=MemorySink())
