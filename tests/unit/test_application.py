import json

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from starlette.responses import StreamingResponse

from sentinel_security.application import create_application
from sentinel_security.logging import configure_logging
from sentinel_security.middleware import RequestContextMiddleware


class FakeResources:
    def __init__(self, settings):
        self.states = {"postgresql": "up", "redis": "up", "rabbitmq": "up"}
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        self.closed = True

    async def health(self):
        return self.states


@pytest.fixture
def app(settings):
    return create_application("test-service", settings, FakeResources)


def test_health_lifecycle_and_docs_disabled(app):
    with TestClient(app) as client:
        assert client.get("/health/live").json() == {"status": "ok", "service": "test-service"}
        response = client.get("/health/ready")
        assert response.status_code == 200
        assert response.json()["dependencies"] == app.state.resources.states
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
        resources = app.state.resources
    assert resources.closed


@pytest.mark.parametrize("dependency", ["postgresql", "redis", "rabbitmq"])
def test_dependency_outage_marks_unready_but_keeps_liveness(app, dependency):
    with TestClient(app) as client:
        app.state.resources.states[dependency] = "down"
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert response.json()["dependencies"][dependency] == "down"
        assert client.get("/health/live").status_code == 200


def test_request_ids_generated_and_do_not_trust_caller(app):
    with TestClient(app) as client:
        first = client.get("/health/live", headers={"X-Request-ID": "spoofed"})
        second = client.get("/health/live")
    assert len(first.headers["X-Request-ID"]) == 32
    assert first.headers["X-Request-ID"] != second.headers["X-Request-ID"]
    assert first.headers["X-Request-ID"] != "spoofed"


def test_body_stream_and_sensitive_fields_are_not_logged(app, capsys):
    configure_logging("INFO")

    @app.post("/sensitive/{token}")
    async def echo(request: Request, token: str):
        assert request.state.client_ip == "unknown"  # TestClient uses a non-IP peer name.
        return StreamingResponse(iter([await request.body()]), media_type="application/json")

    with TestClient(app) as client:
        response = client.post(
            "/sensitive/path-secret?password=query-secret",
            content=b'{"password":"body-secret"}',
            headers={"Authorization": "Bearer header-secret", "X-Forwarded-For": "1.2.3.4"},
        )
    assert response.content == b'{"password":"body-secret"}'
    output = capsys.readouterr().out
    for secret in ("path-secret", "query-secret", "body-secret", "header-secret", "unit-secret"):
        assert secret not in output
    events = [json.loads(line) for line in output.splitlines()]
    access = next(event for event in events if event["event"] == "http_request")
    assert access["route"] == "/sensitive/{token}"
    assert access["status"] == 200
    assert access["request_id"] == response.headers["X-Request-ID"]
    assert access["duration_ms"] >= 0


def test_unhandled_error_returns_safe_response(app, capsys):
    configure_logging("INFO")

    @app.get("/broken")
    async def broken():
        raise RuntimeError("database-password-must-not-leak")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/broken")
    assert response.status_code == 500
    assert response.json()["detail"] == "Internal server error"
    assert response.json()["request_id"] == response.headers["X-Request-ID"]
    output = capsys.readouterr().out
    assert "unhandled_exception" in output
    assert "database-password-must-not-leak" not in output


async def test_non_http_scopes_pass_through():
    received = []

    async def downstream(scope, receive, send):
        received.append(scope["type"])

    middleware = RequestContextMiddleware(downstream)
    await middleware({"type": "websocket"}, None, None)
    assert received == ["websocket"]


def test_development_docs_enabled(settings):
    app = create_application(
        "test-service", settings.model_copy(update={"environment": "development"}), FakeResources
    )
    with TestClient(app) as client:
        assert client.get("/docs").status_code == 200
