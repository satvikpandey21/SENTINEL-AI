"""Real metric families, privacy/cardinality, instrumentation and private-listener lifecycle."""

import asyncio
import json
import secrets
import socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx2 as httpx
import pytest
from prometheus_client import generate_latest
from prometheus_client.parser import text_string_to_metric_families

from sentinel_api import realtime as rt
from sentinel_security.application import create_application
from sentinel_security.metrics import Metrics, MetricsEndpoint, metrics_runtime
from sentinel_security.protection import RedisProtectionStore, SecurityEngine
from sentinel_security.publisher import EventPublisher
from sentinel_security.realtime import NotificationPublisher, notification_for
from sentinel_worker.consumer import EventConsumer


def value(metrics, name, **labels):
    return metrics.registry.get_sample_value(
        "sentinel_" + name, {"service": metrics.service, **labels}
    )


@pytest.mark.parametrize("iteration", range(3))
def test_registry_isolation_and_finite_labels(iteration):
    a, b = Metrics("test"), Metrics("test")
    a.inc("publisher_accepted")
    assert value(a, "publisher_accepted_total") == 1
    assert value(b, "publisher_accepted_total") == 0
    for n in range(1000):
        a.http(
            {
                "path": "/token/" + str(n),
                "method": "evil-" + str(n),
                "route": SimpleNamespace(path="/token/" + str(n)),
            },
            599,
            0.01,
            True,
        )
        a.inc("policy_operations", operation="private-" + str(n), outcome="private-" + str(n))
    body = generate_latest(a.registry).decode()
    assert "private-" not in body and "/token/" not in body
    assert (
        value(a, "http_requests_total", method="OTHER", route="unmatched", status_class="5xx")
        == 1000
    )
    assert value(a, "policy_operations_total", operation="other", outcome="other") == 1000
    samples = [s for family in text_string_to_metric_families(body) for s in family.samples]
    assert len(samples) < 300
    assert all(
        set(s.labels).isdisjoint({"client", "ip", "account", "session", "event_id", "request_id"})
        for s in samples
    )


async def test_private_endpoint_authentication_no_export_on_public_api(settings):
    metrics = Metrics("test", routes=("/items/{id}",))
    token = secrets.token_hex(32)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(MetricsEndpoint(metrics, token)), base_url="http://metrics"
    ) as client:
        assert (await client.get("/metrics")).status_code == 401
        assert (
            await client.get("/metrics", headers={"Authorization": "Bearer wrong"})
        ).status_code == 401
        result = await client.get("/metrics", headers={"Authorization": "Bearer " + token})
        assert result.status_code == 200
        assert token not in result.text
        assert (
            await client.post("/metrics", headers={"Authorization": "Bearer " + token})
        ).status_code == 404
    app = create_application("unit", settings)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://api"
    ) as client:
        assert (await client.get("/metrics")).status_code == 404


async def test_real_metrics_listener_shutdown_and_counters(settings, tmp_path):
    token = secrets.token_hex(32)
    secret = tmp_path / "metrics-token"
    secret.write_text(token)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    config = settings.model_copy(
        update={"metrics_enabled": True, "metrics_port": port, "metrics_token_file": str(secret)}
    )
    metrics = Metrics("test", routes=("/items/{item_id}",))
    resources = SimpleNamespace(health=AsyncMock(return_value={"redis": "up"}))
    async with metrics_runtime(metrics, config, resources):
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
            assert (await client.get("/metrics")).status_code == 401
            result = await client.get("/metrics", headers={"Authorization": "Bearer " + token})
            assert result.status_code == 200
        metrics.http(
            {
                "method": "GET",
                "path": "/items/private-value",
                "route": SimpleNamespace(path="/items/{item_id}"),
            },
            200,
            0.25,
            True,
        )
        metrics.http({"method": "GET", "path": "/health/ready"}, 200, 1, True)
        assert (
            value(
                metrics,
                "http_requests_total",
                method="GET",
                route="/items/{item_id}",
                status_class="2xx",
            )
            == 1
        )
        assert (
            value(metrics, "http_duration_seconds_count", method="GET", route="/items/{item_id}")
            == 1
        )
        assert (
            value(metrics, "http_duration_seconds_sum", method="GET", route="/items/{item_id}")
            == 0.25
        )
        assert "private-value" not in generate_latest(metrics.registry).decode()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))


async def test_security_and_enforcement_metrics(settings):
    metrics = Metrics("test")
    store = RedisProtectionStore(lambda: None, 0.1, metrics)
    store._scripts["rate_limit"] = AsyncMock(side_effect=OSError("private-redis-url"))
    with pytest.raises(OSError):
        await store.execute("rate_limit", [], [])
    assert value(metrics, "enforcement_errors_total", operation="rate_limit") == 1
    engine = SecurityEngine(store, "unit", settings.effective_policies, metrics=metrics)
    scope = {"state": {"request_id": "a" * 32}, "path": "/api/demo/limited", "method": "GET"}
    await engine.before_request(scope, "b" * 64)
    assert value(metrics, "security_actions_total", action="record") == 1
    assert "private-redis-url" not in generate_latest(metrics.registry).decode()


async def test_publisher_accept_drop_retry_metrics(settings, security_event):
    metrics = Metrics("test")
    publisher = EventPublisher(
        settings.model_copy(
            update={
                "event_buffer_capacity": 1,
                "event_publish_attempts": 2,
                "event_retry_delay_seconds": 0.01,
            }
        )
    )
    publisher.metrics = metrics
    publisher.offer(security_event)
    publisher._accepting = True
    assert publisher.offer(security_event)
    assert not publisher.offer(security_event)
    publisher._connect = AsyncMock(side_effect=OSError("private-broker"))
    assert not await publisher._deliver(b"{}", "event")
    assert value(metrics, "publisher_accepted_total") == 1
    assert value(metrics, "publisher_dropped_total", reason="publisher_stopped") == 1
    assert value(metrics, "publisher_dropped_total", reason="buffer_full") == 1
    assert value(metrics, "publisher_failures_total") == 2
    assert value(metrics, "publisher_retries_total") == 1


async def test_worker_metrics_keep_ack_after_persist(settings, security_event):
    metrics = Metrics("test")
    order = []

    async def persist(event):
        order.append("commit")
        return True

    async def ack():
        assert order == ["commit"]
        order.append("ack")

    consumer = EventConsumer(SimpleNamespace(persist=persist), MagicMock(), settings, metrics)
    message = SimpleNamespace(body=security_event.model_dump_json().encode(), ack=ack)
    await consumer.handle(message)
    assert order == ["commit", "ack"]
    assert value(metrics, "worker_deliveries_total", outcome="persisted") == 1
    assert value(metrics, "worker_duration_seconds_count", outcome="persisted") == 1


async def test_notification_backpressure_and_transport_metrics(security_event):
    metrics = Metrics("test")
    notification = notification_for(security_event)
    hub = rt.SecurityHub(None, None, metrics)
    slow, fast = rt.Client(asyncio.Queue(1)), rt.Client(asyncio.Queue(4))
    hub.clients.update((slow, fast))
    hub.fanout(notification.model_dump_json())
    hub.fanout(notification.model_dump_json())
    other = security_event.model_copy(update={"event_id": __import__("uuid").uuid4()})
    hub.fanout(notification_for(other).model_dump_json())
    assert value(metrics, "notification_enqueued_total") == 3
    assert value(metrics, "notification_duplicates_total") == 1
    assert value(metrics, "ws_slow_consumers_total") == 1
    assert value(metrics, "notification_dropped_total", component="hub", reason="backpressure") == 1
    publisher = NotificationPublisher(
        SimpleNamespace(publish=AsyncMock(side_effect=OSError())), 1, 0.01, metrics
    )
    publisher.offer(notification)
    publisher.offer(notification)
    async with publisher:
        await publisher.queue.join()
    assert value(metrics, "notification_publish_errors_total") == 1
    assert value(metrics, "notification_dropped_total", component="worker", reason="transport") == 1


def test_provisioned_configuration_privacy_and_five_dashboards():
    root = Path("infra/observability")
    dashboards = [json.loads(p.read_text()) for p in (root / "grafana/dashboards").glob("*.json")]
    assert len(dashboards) == 5
    assert len({d["uid"] for d in dashboards}) == 5
    for dashboard in dashboards:
        assert not dashboard["editable"]
        assert all(
            p.get("datasource", {}).get("uid") == "sentinel-prometheus"
            for p in dashboard["panels"]
            if p["type"] != "text"
        )
        assert all(
            p["fieldConfig"]["defaults"]["noValue"] == "No samples"
            for p in dashboard["panels"]
            if p["type"] != "text"
        )
    config = json.loads((root / "prometheus/prometheus.yml").read_text())
    assert (
        config["scrape_configs"][0]["authorization"]["credentials_file"]
        == "/run/secrets/metrics_token"
    )
    assert "basic_auth" in config["scrape_configs"][1]
    assert "password" not in config["scrape_configs"][1]["basic_auth"]
    assert len(json.loads((root / "prometheus/alerts.yml").read_text())["groups"][0]["rules"]) == 9
    for path in root.rglob("*"):
        if path.is_file():
            assert "Bearer ey" not in path.read_text()


def test_observability_secret_initialization_preserves_and_hides_values(tmp_path, capsys):
    from scripts.init_observability import initialize

    (tmp_path / ".env").write_text("RABBITMQ_PASSWORD=existing-private-value\n")
    initialize(tmp_path)
    folder = tmp_path / ".secrets/observability"
    before = {p.name: p.read_text() for p in folder.iterdir()}
    initialize(tmp_path)
    assert before == {p.name: p.read_text() for p in folder.iterdir()}
    assert all(b"\r" not in p.read_bytes() for p in folder.iterdir())
    password = folder / "grafana_password"
    password.write_bytes(before["grafana_password"].strip().encode() + b"\r\n")
    initialize(tmp_path)
    assert password.read_bytes() == before["grafana_password"].encode()
    assert (
        len({before[n] for n in ("metrics_token", "grafana_password", "rabbitmq_metrics_password")})
        == 3
    )
    assert all(secret.strip() not in capsys.readouterr().out for secret in before.values())


@pytest.mark.parametrize(
    "component,expected,excluded",
    [
        ("worker", "worker_deliveries", "http_requests"),
        ("admin-api", "ws_attempts", "worker_deliveries"),
        ("api", "http_requests", "ws_attempts"),
    ],
)
def test_component_registry_only_exposes_owned_operations(component, expected, excluded):
    metrics = Metrics("test", component=component)
    assert expected in metrics.metrics
    assert excluded not in metrics.metrics
    metrics.inc(excluded)


async def test_disabled_runtime_has_no_listener_or_probe(settings):
    config = settings.model_copy(update={"metrics_token_file": "/missing-private-file"})
    metrics = Metrics("test", enabled=False)
    resources = SimpleNamespace(health=AsyncMock())
    async with metrics_runtime(metrics, config, resources):
        metrics.inc("publisher_accepted")
        metrics.set("worker_ready", 1)
        metrics.observe("analysis_duration_seconds", 1)
    resources.health.assert_not_awaited()
    assert generate_latest(metrics.registry) == b""


@pytest.mark.parametrize("secret", ["", "not-a-token", "g" * 64])
async def test_invalid_token_fails_before_listener_or_probe(settings, tmp_path, secret):
    path = tmp_path / "metrics-token"
    path.write_text(secret)
    config = settings.model_copy(update={"metrics_enabled": True, "metrics_token_file": str(path)})
    resources = SimpleNamespace(health=AsyncMock())
    with pytest.raises(ValueError, match="256-bit"):
        async with metrics_runtime(Metrics("test"), config, resources):
            pytest.fail("listener admitted an invalid token")
    resources.health.assert_not_awaited()


def test_errors_incomplete_responses_and_ml_statuses_are_observed():
    metrics = Metrics("test")
    metrics.http({"method": "GET", "path": "/private"}, 500, 0.2, False)
    assert value(metrics, "http_server_errors_total") == 1
    assert value(metrics, "http_incomplete_total") == 1
    assert value(metrics, "http_status_total", code="500") == 1
    for status in ("untrusted_artifact", "invalid_artifact", "version_mismatch", "timeout"):
        metrics.inc("ml_results", status=status)
        assert value(metrics, "ml_results_total", status=status) == 1


async def test_persistence_and_analysis_failures_increment_metrics(settings, security_event):
    from sentinel_security.analysis_storage import AnalysisEngine
    from sentinel_security.storage import EventStore

    metrics = Metrics("test")
    store = EventStore(None, metrics=metrics)
    store._persist = AsyncMock(side_effect=OSError("private-db-connection"))
    with pytest.raises(OSError):
        await store.persist(security_event)
    assert value(metrics, "persistence_errors_total") == 1
    assert value(metrics, "persistence_duration_seconds_count") == 1
    engine = AnalysisEngine(settings.analysis, metrics)
    engine._analyze = AsyncMock(side_effect=RuntimeError("private-features"))
    with pytest.raises(RuntimeError):
        await engine.analyze(None, security_event)
    assert value(metrics, "analysis_operations_total", outcome="error") == 1
    body = generate_latest(metrics.registry).decode()
    assert "private-" not in body
