"""The deployment durability check must establish its own real event evidence."""

import asyncio
import io
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from scripts import deployment_events as probe


@pytest.fixture
def sample():
    return {
        "request_id": uuid4().hex,
        "event_id": str(uuid4()),
        "service": "sentinel-demo-api",
        "method": "GET",
        "endpoint": "/api/demo/ping",
        "status_code": 200,
        "response_completed": True,
    }


def test_demo_request_uses_private_api_and_server_generated_id(monkeypatch, sample):
    response = io.BytesIO(b'{"message":"pong"}')
    response.status = 200
    response.headers = {"X-Request-ID": sample["request_id"]}
    outgoing = MagicMock(return_value=response)
    monkeypatch.setattr(probe.urllib.request, "urlopen", outgoing)
    assert probe.demo_request() == sample["request_id"]
    outgoing.assert_called_once_with("http://demo-api:8000/api/demo/ping", timeout=10)


@pytest.mark.parametrize("request_id", [None, "", "caller-supplied", "A" * 32])
def test_demo_request_rejects_missing_or_invalid_identity(monkeypatch, request_id):
    response = io.BytesIO(b'{"message":"pong"}')
    response.status = 200
    response.headers = {} if request_id is None else {"X-Request-ID": request_id}
    monkeypatch.setattr(probe.urllib.request, "urlopen", lambda *a, **kw: response)
    with pytest.raises(RuntimeError, match="server request ID"):
        probe.demo_request()


@pytest.mark.parametrize("status,body", [(503, b"{}"), (200, b'{"message":"wrong"}')])
def test_demo_request_requires_success(monkeypatch, status, body):
    response = io.BytesIO(body)
    response.status, response.headers = status, {}
    monkeypatch.setattr(probe.urllib.request, "urlopen", lambda *a, **kw: response)
    with pytest.raises(RuntimeError, match="200 pong"):
        probe.demo_request()


async def test_poll_waits_for_exact_request_from_empty_database(monkeypatch, sample):
    persisted = {"events": 3, "sample": sample}
    snapshots = AsyncMock(
        side_effect=[
            {"events": 0, "sample": None},
            {"events": 2, "sample": None},  # Unrelated events cannot satisfy the check.
            persisted,
        ]
    )
    monkeypatch.setattr(probe, "snapshot", snapshots)
    result = await probe.wait_for_event(None, sample["request_id"], interval=0)
    assert result == persisted
    assert snapshots.await_count == 3
    snapshots.assert_awaited_with(None, sample["request_id"], None)


async def test_restart_check_requires_recorded_event_uuid(monkeypatch, sample):
    snapshots = AsyncMock(return_value={"events": 1, "sample": sample})
    monkeypatch.setattr(probe, "snapshot", snapshots)
    result = await probe.wait_for_event(None, sample["request_id"], sample["event_id"])
    assert result["sample"] == sample
    snapshots.assert_awaited_once_with(None, sample["request_id"], sample["event_id"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", "f" * 32),
        ("service", "another-service"),
        ("method", "POST"),
        ("endpoint", "/health/ready"),
        ("status_code", 429),
        ("response_completed", False),
        ("event_id", str(uuid4())),
    ],
)
async def test_unrelated_or_failed_event_cannot_prove_durability(monkeypatch, sample, field, value):
    wrong = {**sample, field: value}
    monkeypatch.setattr(probe, "snapshot", AsyncMock(return_value={"events": 9, "sample": wrong}))
    with pytest.raises(RuntimeError, match="Unexpected persisted|identifier changed"):
        await probe.wait_for_event(None, sample["request_id"], sample["event_id"])


async def test_poll_recovers_from_transient_database_failure(monkeypatch, sample):
    snapshots = AsyncMock(side_effect=[ConnectionError("private-url"), {"sample": sample}])
    monkeypatch.setattr(probe, "snapshot", snapshots)
    assert await probe.wait_for_event(None, sample["request_id"], interval=0) == {"sample": sample}


@pytest.mark.parametrize("failure", [False, True])
async def test_timeout_is_bounded_and_diagnostic_without_database_credentials(
    monkeypatch, sample, failure
):
    snapshots = AsyncMock(
        side_effect=ConnectionError("private-password") if failure else None,
        return_value={"events": 12, "sample": None},
    )
    monkeypatch.setattr(probe, "snapshot", snapshots)
    with pytest.raises(TimeoutError) as caught:
        await probe.wait_for_event(
            None, sample["request_id"], sample["event_id"], deadline_seconds=0.02, interval=0.001
        )
    message = str(caught.value)
    assert sample["request_id"] in message and sample["event_id"] in message
    assert "RabbitMQ -> worker -> PostgreSQL" in message
    assert "private-password" not in message
    assert ("ConnectionError" if failure else "'events': 12") in message


async def test_timeout_also_bounds_a_stalled_database_query(monkeypatch, sample):
    async def stalled(*args):
        await asyncio.Event().wait()

    monkeypatch.setattr(probe, "snapshot", stalled)
    with pytest.raises(TimeoutError, match="Timed out after 0.02s"):
        await probe.wait_for_event(None, sample["request_id"], deadline_seconds=0.02)


@pytest.mark.parametrize("empty", [True, False])
async def test_database_snapshot_reads_count_and_filters_exact_event(sample, empty):
    session = AsyncMock()
    session.scalar.side_effect = [0 if empty else 5, None if empty else uuid4()]
    row = SimpleNamespace(**{**sample, "event_id": uuid4()}) if not empty else None
    session.scalars.return_value = MagicMock(one_or_none=MagicMock(return_value=row))
    resources = SimpleNamespace(session_factory=MagicMock())
    resources.session_factory.return_value.__aenter__.return_value = session
    result = await probe.snapshot(resources, sample["request_id"], sample["event_id"])
    assert result["events"] == (0 if empty else 5)
    assert (result["sample"] is None) == empty
    query = session.scalars.call_args.args[0].compile()
    assert sample["request_id"] in query.params.values()
    assert "http.request.completed" in query.params.values()
    assert probe.UUID(sample["event_id"]) in query.params.values()


async def test_snapshot_does_not_pair_committed_sample_with_an_earlier_zero_count(sample):
    committed = False
    identifier = probe.UUID(sample["event_id"])

    async def read_sample(query):
        nonlocal committed
        committed = True  # Worker commits while the probe is reading at READ COMMITTED.
        row = SimpleNamespace(**{**sample, "event_id": identifier})
        return MagicMock(one_or_none=MagicMock(return_value=row))

    async def read_total(query):
        return (1 if committed else 0) if "count(" in str(query) else identifier

    session = AsyncMock()
    session.scalars.side_effect, session.scalar.side_effect = read_sample, read_total
    resources = SimpleNamespace(session_factory=MagicMock())
    resources.session_factory.return_value.__aenter__.return_value = session
    result = await probe.snapshot(resources, sample["request_id"])
    assert result["sample"] == sample
    assert result["events"] == 1
