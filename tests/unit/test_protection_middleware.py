import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import StreamingResponse

from sentinel_security.events import (
    DeadLetterNotice,
    DetectionEvent,
    parse_event,
    record_authentication_outcome,
)
from sentinel_security.middleware import RequestContextMiddleware
from sentinel_security.policies import EndpointPolicy
from sentinel_security.protection import Decision, record_verified_login


class Sink:
    def __init__(self):
        self.events = []

    def offer(self, event):
        self.events.append(event)
        return True


def app_with_engine(before=None, after=None):
    sink = Sink()
    engine = MagicMock(
        before_request=AsyncMock(return_value=before or Decision()),
        after_authentication=AsyncMock(return_value=after or Decision()),
    )
    app = FastAPI()
    app.add_middleware(
        RequestContextMiddleware,
        event_sink=sink,
        identity_key=b"x" * 32,
        security_engine=engine,
        service="test-api",
    )

    @app.get("/api")
    async def normal():
        return {"ok": True}

    @app.get("/auth")
    async def authenticated(request: Request):
        record_verified_login(request.scope, succeeded=True)
        return {"private": "must-not-be-forwarded-on-failure"}

    @app.get("/generic-401")
    async def generic(request: Request):
        record_authentication_outcome(request.scope, "failed")
        from fastapi.responses import JSONResponse

        return JSONResponse({"detail": "not a verified password attempt"}, status_code=401)

    @app.get("/stream")
    async def streaming():
        return StreamingResponse(iter([b"one", b"two"]))

    @app.get("/health/live")
    async def health():
        return {"ok": True}

    return app, engine, sink


def test_rejected_response_is_monitored_with_safe_endpoint_and_retry_after():
    decision = Decision(
        action="temporary_block",
        rule_id="p.rate",
        policy=EndpointPolicy(id="p", path_prefix="/api"),
        counter_value=6,
        threshold=5,
        window_seconds=3.0,
        retry_after_seconds=3,
        response_status=429,
    )
    app, engine, sink = app_with_engine(before=decision)
    with TestClient(app) as client:
        response = client.get(
            "/api/private?password=secret", headers={"X-Forwarded-For": "1.2.3.4"}
        )
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "3"
    assert response.json() == {"detail": "Request temporarily restricted"}
    http_event, detection = sink.events
    assert http_event.endpoint == detection.endpoint == "/api"
    assert detection.schema_version == 2
    assert detection.request_id == response.headers["X-Request-ID"]
    assert detection.security_action == "temporary_block"
    assert "secret" not in detection.model_dump_json()
    engine.after_authentication.assert_not_awaited()
    parsed = parse_event(detection.model_dump_json().encode(), 4096)
    assert isinstance(parsed, DetectionEvent)
    notice = DeadLetterNotice(reason="retry_exhausted", payload_sha256="a" * 64, event=detection)
    assert isinstance(
        DeadLetterNotice.model_validate_json(notice.model_dump_json()).event, DetectionEvent
    )


def test_post_auth_fail_closed_replaces_success_body_safely():
    decision = Decision(
        action="deny",
        rule_id="redis.unavailable",
        response_status=503,
        retry_after_seconds=1,
        degraded=True,
    )
    app, engine, sink = app_with_engine(after=decision)
    with TestClient(app) as client:
        response = client.get("/auth")
    assert response.status_code == 503
    assert "must-not-be-forwarded" not in response.text
    assert response.json() == {"detail": "Service temporarily unavailable"}
    assert sink.events[-1].degraded
    assert sink.events[0].status_code == 503


def test_fail_open_records_degradation_and_preserves_stream():
    app, engine, sink = app_with_engine(
        before=Decision(action="record", rule_id="redis.unavailable", degraded=True)
    )
    with TestClient(app) as client:
        response = client.get("/stream")
    assert response.status_code == 200 and response.content == b"onetwo"
    assert sink.events[0].response_completed
    assert sink.events[-1].degraded


def test_health_is_excluded_from_protection_and_events():
    app, engine, sink = app_with_engine()
    with TestClient(app) as client:
        assert client.get("/health/live").status_code == 200
    engine.before_request.assert_not_awaited()
    assert sink.events == []


def test_forwarded_headers_cannot_change_enforcement_identity():
    app, engine, sink = app_with_engine()
    with TestClient(app) as client:
        client.get("/api", headers={"X-Forwarded-For": "1.2.3.4"})
        client.get("/api", headers={"X-Forwarded-For": "5.6.7.8", "Forwarded": "for=6.6.6.6"})
    assert (
        engine.before_request.call_args_list[0].args[1]
        == engine.before_request.call_args_list[1].args[1]
    )
    assert sink.events[0].client_identifier == sink.events[1].client_identifier


def test_generic_401_does_not_claim_verified_login():
    app, engine, sink = app_with_engine()
    with TestClient(app) as client:
        assert client.get("/generic-401").status_code == 401
    assert "sentinel_verified_login" not in engine.after_authentication.call_args.args[0]["state"]


def test_sink_failure_cannot_disable_enforcement():
    decision = Decision(
        action="rate_limit", rule_id="p.rate", response_status=429, retry_after_seconds=1
    )
    app, engine, sink = app_with_engine(before=decision)
    sink.offer = MagicMock(side_effect=ConnectionError("private-broker-url"))
    with TestClient(app) as client:
        assert client.get("/api").status_code == 429


def test_decision_schema_rejects_invalid_action_and_v1_parser_remains_strict(security_event):
    values = {
        **json.loads(security_event.model_dump_json()),
        "schema_version": 2,
        "event_type": "security.decision",
        "rule_id": "p.rate",
        "security_action": "fake-score",
    }
    with pytest.raises(ValueError):
        parse_event(json.dumps(values).encode(), 4096)
