import json
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from sentinel_security.config import Settings
from sentinel_security.events import SecurityEvent, record_authentication_outcome, route_template


def test_wire_roundtrip_and_utc_normalization(security_event):
    event = security_event.model_copy(
        update={"occurred_at": datetime.now(timezone(timedelta(hours=5, minutes=30)))}
    )
    parsed = SecurityEvent.from_wire(event.model_dump_json().encode(), 4096)
    assert parsed.event_id == event.event_id
    assert parsed.occurred_at.utcoffset() == timedelta(0)
    assert parsed.occurred_at.tzinfo == UTC


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": 2},
        {"event_type": "unknown"},
        {"request_id": "spoofed"},
        {"status_code": 999},
        {"status_code": "200"},
        {"duration_ms": -1.0},
        {"duration_ms": float("inf")},
        {"duration_ms": float("nan")},
        {"client_identifier": "198.51.100.2"},
        {"severity": "critical"},
        {"service": "contains spaces"},
        {"endpoint": "/path?password=secret"},
        {"endpoint": "/" + "a" * 256},
        {"authorization": "Bearer secret"},
        {"authentication_outcome": "maybe"},
        {"response_completed": "true"},
        {"occurred_at": "2026-11-12T12:00:00"},
    ],
)
def test_invalid_fields_rejected(security_event, changes):
    values = json.loads(security_event.model_dump_json())
    values.update(changes)
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate_json(json.dumps(values))


@pytest.mark.parametrize("body", [b"not-json", b"{}", b"[]", b"\xff", b"a" * 4097])
def test_malformed_or_oversized_wire_rejected(body):
    with pytest.raises(ValueError):
        SecurityEvent.from_wire(body, 4096)


@pytest.mark.parametrize("path", ["/safe/{item_id}", "unmatched", "/api/a-b_v1"])
def test_registered_templates_preserved(path):
    assert route_template({"route": SimpleNamespace(path=path)}) == path


@pytest.mark.parametrize("path", ["/path?secret=token", "/path#secret", "/" + "x" * 257, None])
def test_unsafe_or_missing_templates_collapse(path):
    assert route_template({"route": SimpleNamespace(path=path)}) == "unmatched"
    assert route_template({"path": "/raw-secret"}) == "unmatched"


def test_authentication_outcome_is_explicit_and_validated():
    scope = {}
    record_authentication_outcome(scope, "failed")
    assert scope["state"]["sentinel_authentication_outcome"] == "failed"
    with pytest.raises(ValueError):
        record_authentication_outcome(scope, "raw-password")


@pytest.mark.parametrize(
    "overrides",
    [
        {"monitoring_enabled": True},
        {"client_identity_key": "bad"},
        {"event_buffer_capacity": 0},
        {"event_max_bytes": 20000},
        {"worker_prefetch": 0},
        {"event_publish_attempts": 0},
        {"monitoring_excluded_paths": ["relative"]},
        {"monitoring_excluded_paths": ["/health?secret"]},
    ],
)
def test_monitoring_configuration_is_bounded(settings, overrides):
    values = settings.model_dump()
    values.update(overrides)
    with pytest.raises(ValidationError):
        Settings(**values)


def test_monitoring_key_is_required_and_redacted(settings):
    values = settings.model_dump()
    values.update(monitoring_enabled=True, client_identity_key="b" * 64)
    configured = Settings(**values)
    assert "b" * 64 not in repr(configured)
