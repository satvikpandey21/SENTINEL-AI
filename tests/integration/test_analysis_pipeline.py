"""Real PostgreSQL/RabbitMQ analysis verification with controlled owned telemetry."""

import asyncio
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from time import monotonic
from uuid import uuid4

import aio_pika
import httpx2 as httpx
import pytest
from sqlalchemy import delete, func, select

from sentinel_security.analysis_config import AnalysisPolicy
from sentinel_security.analysis_storage import (
    AnalysisEngine,
    AnalysisState,
    AssessmentRepository,
    RiskAssessment,
    cleanup_analysis,
)
from sentinel_security.anomaly_model import canonical_bytes
from sentinel_security.config import Settings
from sentinel_security.events import DetectionEvent
from sentinel_security.infrastructure import Resources
from sentinel_security.messaging import event_message
from sentinel_security.model_training import train_and_evaluate
from sentinel_security.storage import EventStore, SecurityEventRecord
from sentinel_worker.consumer import EventConsumer

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("SENTINEL_RUN_INTEGRATION") != "1", reason="Run via Compose test profile"
    ),
]


@pytest.fixture
async def resources():
    async with Resources(Settings()) as resources:
        yield resources


@pytest.fixture
async def scenario(resources, security_event):
    service = "analysis-" + uuid4().hex
    event = security_event.model_copy(update={"service": service})
    try:
        yield event
    finally:
        async with resources.session_factory() as session, session.begin():
            await session.execute(
                delete(SecurityEventRecord).where(SecurityEventRecord.service == service)
            )
            await session.execute(delete(AnalysisState).where(AnalysisState.service == service))


def next_event(base, **changes):
    return base.model_copy(update={"event_id": uuid4(), "request_id": uuid4().hex, **changes})


async def assessments(resources, base):
    return await AssessmentRepository(resources.session_factory).for_client(
        base.service, base.client_identifier, 200
    )


async def test_normal_authentication_rate_and_database_constraints(resources, scenario):
    engine = AnalysisEngine(AnalysisPolicy())
    store = EventStore(resources.session_factory, engine)
    base = scenario.occurred_at.replace(second=0, microsecond=0)
    for i in range(6):
        event = next_event(
            scenario,
            occurred_at=base + timedelta(milliseconds=i),
            authentication_outcome="failed" if i else "not_provided",
            endpoint="/api/demo/login",
        )
        assert await store.persist(event)
    rows = await assessments(resources, scenario)
    assert sorted(row.risk_score for row in rows) == [0, 10, 20, 30, 40, 40]
    data = next_event(scenario, occurred_at=base + timedelta(seconds=1)).model_dump()
    data.update(
        schema_version=2,
        event_type="security.decision",
        rule_id="demo.rate",
        security_action="rate_limit",
        counter_value=601,
        threshold=600,
    )
    for _ in range(3):
        data.update(event_id=uuid4(), request_id=uuid4().hex)
        assert await store.persist(DetectionEvent(**data))
    rows = await assessments(resources, scenario)
    highest = max(rows, key=lambda row: row.risk_score)
    assert highest.risk_score >= 80
    assert highest.evidence["features"]["auth_failures"] == 5
    assert any(t["category"] == "excessive_api_requests" for t in highest.evidence["threats"])
    assert all(t["timestamp"] and t["rule_ids"] for t in highest.evidence["threats"])
    print(
        "controlled_risk_examples",
        json.dumps(
            [
                {
                    "risk": row.risk_score,
                    "severity": row.severity,
                    "features": row.evidence["features"],
                }
                for row in rows
            ]
        ),
    )
    with pytest.raises(ValueError):
        await AssessmentRepository(resources.session_factory).for_client(
            scenario.service, scenario.client_identifier, 1000
        )


async def test_concurrent_events_duplicates_and_v1_v2_same_request(resources, scenario):
    engine = AnalysisEngine(AnalysisPolicy())
    store = EventStore(resources.session_factory, engine)
    events = [next_event(scenario) for _ in range(20)]
    assert all(await asyncio.gather(*(store.persist(event) for event in events)))
    assert not any(await asyncio.gather(*(store.persist(events[0]) for _ in range(5))))
    data = events[0].model_dump()
    data.update(
        event_id=uuid4(),
        schema_version=2,
        event_type="security.decision",
        rule_id="demo.rate",
        security_action="record",
    )
    assert await store.persist(DetectionEvent(**data))
    async with resources.session_factory() as session:
        state = await session.get(AnalysisState, (scenario.service, scenario.client_identifier))
        assert len(state.state["entries"]) == 20
    assert len(await assessments(resources, scenario)) == 21


async def test_statistics_real_persisted_windows(resources, scenario):
    policy = AnalysisPolicy(window_seconds=10)
    store = EventStore(resources.session_factory, AnalysisEngine(policy))
    now = datetime.now(UTC)
    start = datetime.fromtimestamp(int(now.timestamp()) // 10 * 10, UTC) - timedelta(seconds=90)
    for window in range(9):
        for request in range(10 if window < 8 else 80):
            assert await store.persist(
                next_event(
                    scenario,
                    occurred_at=start + timedelta(seconds=window * 10, milliseconds=request * 10),
                    status_code=404 if window == 8 else 200,
                )
            )
    rows = await assessments(resources, scenario)
    flagged = [row for row in rows if row.evidence["statistics"]["flags"]]
    assert flagged
    assert any(
        flag["feature"] == "request_count"
        for row in flagged
        for flag in row.evidence["statistics"]["flags"]
    )
    assert any(
        flag["feature"] == "error_rate"
        for row in flagged
        for flag in row.evidence["statistics"]["flags"]
    )
    print("controlled_statistical_flags", json.dumps(flagged[0].evidence["statistics"]))


@pytest.mark.parametrize("mode", ["disabled", "missing", "failure"])
async def test_ml_unavailability_keeps_scoring_and_persistence(resources, scenario, mode, tmp_path):
    policy = AnalysisPolicy(
        ml_enabled=mode == "missing",
        model_path=str(tmp_path / "absent-sentinel-model.json"),
        model_sha256="0" * 64,
    )
    engine = AnalysisEngine(policy)
    if mode == "failure":

        def broken(*args, **kwargs):
            raise RuntimeError("must-not-leak-private-data")

        engine.model.infer = broken
    store = EventStore(resources.session_factory, engine)
    start = datetime.now(UTC).replace(second=0, microsecond=0) - timedelta(minutes=1)
    for i in range(10):
        await store.persist(
            next_event(
                scenario, occurred_at=start + timedelta(seconds=i), authentication_outcome="failed"
            )
        )
    await store.persist(next_event(scenario, authentication_outcome="failed"))
    rows = await assessments(resources, scenario)
    assert max(row.risk_score for row in rows) == 40
    statuses = {row.evidence["ml"]["status"] for row in rows}
    assert {"disabled": "disabled", "missing": "missing_model", "failure": "inference_error"}[
        mode
    ] in statuses
    assert "must-not-leak-private-data" not in json.dumps([row.evidence for row in rows])


async def test_real_trained_model_contributes_evidence(resources, scenario, tmp_path):
    artifact, _ = train_and_evaluate()
    path = tmp_path / "model.json"
    body = canonical_bytes(artifact)
    path.write_bytes(body)
    engine = AnalysisEngine(
        AnalysisPolicy(
            ml_enabled=True, model_path=str(path), model_sha256=hashlib.sha256(body).hexdigest()
        )
    )
    store = EventStore(resources.session_factory, engine)
    start = datetime.now(UTC).replace(second=0, microsecond=0) - timedelta(minutes=3)
    for i in range(30):
        await store.persist(
            next_event(
                scenario,
                occurred_at=start + timedelta(seconds=i),
                authentication_outcome="failed",
                endpoint="/api/demo/login",
            )
        )
    await store.persist(next_event(scenario, occurred_at=start + timedelta(minutes=2)))
    await store.persist(next_event(scenario))
    rows = await assessments(resources, scenario)
    assert any(row.evidence["ml"]["status"] == "insufficient_traffic" for row in rows)
    inferred = [row for row in rows if row.model_version]
    assert len(inferred) == 1
    assert inferred[0].evidence["ml"]["window_end"] == int(start.timestamp()) + 60
    assert inferred[0].evidence["ml"]["status"] == "ready"
    assert inferred[0].evidence["ml"]["experimental"]
    assert engine.model.load_count == 1
    print("persisted_real_ml_inference", json.dumps(inferred[0].evidence["ml"]))


async def test_transaction_rollback_does_not_lose_event_or_half_apply_state(
    resources, scenario, monkeypatch
):
    engine = AnalysisEngine(AnalysisPolicy())
    store = EventStore(resources.session_factory, engine)
    original = engine.analyze

    async def fails_after_analysis(session, event):
        await original(session, event)
        raise OSError("controlled-postgres-interruption")

    monkeypatch.setattr(engine, "analyze", fails_after_analysis)
    with pytest.raises(OSError):
        await store.persist(scenario)
    async with resources.session_factory() as session:
        assert await session.get(SecurityEventRecord, scenario.event_id) is None
        assert (
            await session.get(AnalysisState, (scenario.service, scenario.client_identifier)) is None
        )
    monkeypatch.setattr(engine, "analyze", original)
    assert await store.persist(scenario)
    assert len(await assessments(resources, scenario)) == 1


async def test_rabbitmq_disconnect_after_commit_redelivery_is_idempotent(resources, scenario):
    store = EventStore(resources.session_factory, AnalysisEngine(AnalysisPolicy()))
    connection = await aio_pika.connect(Settings().rabbitmq_url.get_secret_value(), timeout=5)
    channel = await connection.channel(publisher_confirms=True)
    queue = await channel.declare_queue(
        "analysis-test-" + uuid4().hex, durable=False, auto_delete=False
    )
    name = queue.name
    try:
        await channel.default_exchange.publish(
            event_message(scenario.model_dump_json().encode()), routing_key=name, mandatory=True
        )
        message = await queue.get(timeout=5)
        assert await store.persist(scenario)
        await connection.close()  # Real unacked delivery survives channel interruption.
        connection = await aio_pika.connect(Settings().rabbitmq_url.get_secret_value(), timeout=5)
        channel = await connection.channel(publisher_confirms=True)
        queue = await channel.declare_queue(name, passive=True)
        message = await queue.get(timeout=5)
        assert message.redelivered
        await EventConsumer(store, channel, Settings()).handle(message)
        assert message.processed
        assert len(await assessments(resources, scenario)) == 1
    finally:
        if not connection.is_closed:
            await queue.delete()
            await connection.close()


async def test_running_http_worker_analysis_and_privacy(resources):
    marker = uuid4().hex
    async with httpx.AsyncClient(base_url="http://demo-api:8000", timeout=10) as client:
        response = await client.get(
            f"/api/demo/ping?secret={marker}",
            headers={"Authorization": "Bearer " + marker, "Cookie": "session=" + marker},
        )
    deadline = monotonic() + 15
    found = None
    while monotonic() < deadline:
        async with resources.session_factory() as session:
            found = await session.scalar(
                select(RiskAssessment)
                .join(SecurityEventRecord)
                .where(SecurityEventRecord.request_id == response.headers["X-Request-ID"])
            )
        if found:
            break
        await asyncio.sleep(0.05)
    assert found is not None
    assert marker not in json.dumps(found.evidence)
    async with resources.session_factory() as session:
        state = await session.get(AnalysisState, (found.service, found.client_identifier))
        assert marker not in json.dumps(state.state)
        assert "authorization" not in json.dumps(state.state).lower()
    assert found.evidence["ml"]["status"] == "disabled"
    assert found.rule_version == "risk-v1"
    assert found.feature_schema == "behavior-v1"


async def test_late_and_outside_retention_audit_is_preserved(resources, scenario):
    store = EventStore(resources.session_factory, AnalysisEngine(AnalysisPolicy()))
    await store.persist(scenario)
    for delta in (timedelta(minutes=-2), timedelta(days=-8), timedelta(minutes=5)):
        await store.persist(
            next_event(
                scenario, occurred_at=scenario.occurred_at + delta, authentication_outcome="failed"
            )
        )
    rows = await assessments(resources, scenario)
    assert all(row.risk_score == 0 for row in rows)
    assert {row.evidence["aggregation_status"] for row in rows} >= {
        "observed",
        "late_event",
        "outside_retention",
    }


async def test_bounded_retention_cleanup_preserves_original_audit(resources, scenario):
    store = EventStore(resources.session_factory, AnalysisEngine(AnalysisPolicy()))
    await store.persist(scenario)
    async with resources.session_factory() as session, session.begin():
        row = await session.scalar(
            select(RiskAssessment).where(RiskAssessment.event_id == scenario.event_id)
        )
        row.analyzed_at = datetime.now(UTC) - timedelta(days=366)
        state = await session.get(AnalysisState, (scenario.service, scenario.client_identifier))
        state.updated_at = datetime.now(UTC) - timedelta(days=91)
    assert await cleanup_analysis(resources.session_factory, AnalysisPolicy(cleanup_batch=1)) <= 2
    async with resources.session_factory() as session:
        assert await session.get(SecurityEventRecord, scenario.event_id) is not None
        assert (
            await session.scalar(
                select(func.count())
                .select_from(RiskAssessment)
                .where(RiskAssessment.event_id == scenario.event_id)
            )
            == 0
        )


async def test_analysis_disabled_preserves_audit_only(resources, scenario):
    store = EventStore(resources.session_factory, AnalysisEngine(AnalysisPolicy(enabled=False)))
    assert await store.persist(scenario)
    assert not await assessments(resources, scenario)


async def test_real_worker_runtime_with_enabled_ml(resources, scenario, tmp_path, monkeypatch):
    from sentinel_security import messaging
    from sentinel_worker.runtime import run_worker

    artifact, _ = train_and_evaluate()
    body = canonical_bytes(artifact)
    path = tmp_path / "runtime-model.json"
    path.write_bytes(body)
    policy = AnalysisPolicy(
        ml_enabled=True, model_path=str(path), model_sha256=hashlib.sha256(body).hexdigest()
    )
    settings = Settings(analysis=policy)
    queue_name = "analysis-runtime-" + uuid4().hex
    monkeypatch.setattr(messaging, "EVENT_QUEUE", queue_name)
    monkeypatch.setattr(messaging, "DEAD_QUEUE", queue_name + ".dead")
    monkeypatch.setattr("sentinel_worker.consumer.DEAD_QUEUE", queue_name + ".dead")
    stop = asyncio.Event()
    connection = await aio_pika.connect(settings.rabbitmq_url.get_secret_value(), timeout=5)
    task = None
    async with connection:
        channel = await connection.channel(publisher_confirms=True, on_return_raises=True)
        queue = await messaging.declare_topology(channel, settings)
        try:
            task = asyncio.create_task(run_worker(settings, stop))
            start = datetime.now(UTC).replace(second=0, microsecond=0) - timedelta(minutes=1)
            for i in range(31):
                event = next_event(
                    scenario,
                    occurred_at=start + timedelta(milliseconds=i) if i < 30 else datetime.now(UTC),
                    authentication_outcome="failed" if i < 30 else "not_provided",
                    endpoint="/api/demo/login",
                )
                await channel.default_exchange.publish(
                    event_message(event.model_dump_json().encode()),
                    routing_key=queue.name,
                    mandatory=True,
                )
            deadline = monotonic() + 15
            while monotonic() < deadline:
                rows = await assessments(resources, scenario)
                if len(rows) == 31:
                    break
                await asyncio.sleep(0.05)
            assert len(rows) == 31
            inferred = [row for row in rows if row.model_version]
            assert len(inferred) == 1
            assert inferred[0].evidence["ml"]["status"] == "ready"
            assert max(row.risk_score for row in rows) == 40
            print("real_worker_ml_pipeline", json.dumps(inferred[0].evidence["ml"]))
        finally:
            stop.set()
            if task is not None:
                await asyncio.wait_for(task, timeout=5)
            await queue.delete()
            await channel.queue_delete(queue_name + ".dead")
