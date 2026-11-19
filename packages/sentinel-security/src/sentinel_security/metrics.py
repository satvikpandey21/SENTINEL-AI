"""Per-process registries and strictly bounded labels; no default global registry."""

import asyncio
import hmac
import re
from contextlib import asynccontextmanager
from pathlib import Path
from time import time

import structlog
import uvicorn
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    ProcessCollector,
    generate_latest,
)
from starlette.responses import Response

METHODS = frozenset(
    ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "OTHER")
)
STATUSES = frozenset(
    str(n)
    for n in (
        200,
        201,
        202,
        204,
        301,
        302,
        303,
        304,
        307,
        308,
        400,
        401,
        403,
        404,
        405,
        409,
        413,
        415,
        422,
        429,
        499,
        500,
        502,
        503,
        504,
    )
)
BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)
# Every dynamic label is either a bounded registered route or normalized to these sets.
LABELS = {
    "method": METHODS,
    "status_class": {"1xx", "2xx", "3xx", "4xx", "5xx", "other"},
    "code": STATUSES | {"other"},
    "stage": {"admission", "authentication"},
    "action": {"allow", "record", "rate_limit", "temporary_block", "deny"},
    "source": {"rate", "authentication", "policy", "dependency", "other"},
    "degraded": {"true", "false"},
    "outcome": {
        "success",
        "error",
        "persisted",
        "duplicate",
        "quarantined",
        "accepted",
        "rejected",
        "succeeded",
        "failed",
        "transient",
        "permanent",
        "conflict",
        "other",
    },
    "operation": {"rate_limit", "auth_failures", "read", "write", "other"},
    "reason": {
        "publisher_stopped",
        "event_too_large",
        "buffer_full",
        "publish_attempts_exhausted",
        "shutdown_inflight",
        "shutdown_buffered",
        "publisher_error",
        "invalid_event",
        "oversized_event",
        "permanent_storage_error",
        "retry_exhausted",
        "invalid_origin",
        "invalid_ticket",
        "authorization",
        "capacity",
        "unavailable",
        "backpressure",
        "invalid_input",
        "queue_full",
        "schema",
        "transport",
        "duplicate",
        "other",
    },
    "component": {"worker", "hub", "socket"},
    "dependency": {"postgresql", "redis", "rabbitmq", "policy"},
    "severity": {"low", "moderate", "high", "critical"},
    "status": {
        "ready",
        "disabled",
        "missing_model",
        "untrusted_artifact",
        "invalid_artifact",
        "version_mismatch",
        "invalid_model",
        "digest_mismatch",
        "insufficient_traffic",
        "insufficient_baseline",
        "awaiting_completed_window",
        "inference_error",
        "timeout",
        "invalid_features",
        "late_event",
        "outside_retention",
        "not_applicable",
        "other",
    },
}


class Metrics:
    """Only application-owned constants cross this boundary. Unknown label values collapse."""

    def __init__(self, service, routes=(), enabled=True, component="all"):
        self.component = component
        self.enabled = enabled
        self.service = service
        self.registry = CollectorRegistry()
        self.routes = frozenset(routes)
        self.metrics = {}
        if not enabled:
            return
        ProcessCollector(registry=self.registry)
        self._add(Gauge, "build_info", "Instrumentation contract version", ("version",)).labels(
            service=service, version="1"
        ).set(1)
        counters = {
            "http_requests": ("method", "route", "status_class"),
            "http_status": ("code",),
            "http_incomplete": (),
            "http_server_errors": (),
            "security_actions": ("action",),
            "security_decisions": ("stage", "action", "source", "degraded"),
            "security_authentication": ("outcome",),
            "enforcement_errors": ("operation",),
            "policy_operations": ("operation", "outcome"),
            "publisher_accepted": (),
            "publisher_published": (),
            "publisher_dropped": ("reason",),
            "publisher_failures": (),
            "publisher_retries": (),
            "worker_deliveries": ("outcome",),
            "worker_storage_errors": ("outcome",),
            "worker_reconnects": (),
            "dead_letter_published": ("reason",),
            "persistence_events": ("outcome",),
            "persistence_errors": (),
            "assessments_committed": ("severity",),
            "analysis_operations": ("outcome",),
            "statistical_results": ("status",),
            "ml_results": ("status",),
            "ws_attempts": (),
            "ws_slow_consumers": (),
            "ws_connections": ("outcome", "reason"),
            "ws_revalidation_failures": ("reason",),
            "notification_published": (),
            "notification_publish_errors": (),
            "notification_enqueued": (),
            "notification_sent": (),
            "notification_dropped": ("component", "reason"),
            "notification_duplicates": (),
            "notification_subscription_errors": (),
        }
        for name, labels in counters.items():
            self._add(Counter, name, "Operational " + name.replace("_", " "), labels)
        for name in (
            "publisher_buffer",
            "publisher_connected",
            "worker_connected",
            "worker_ready",
            "ws_active",
            "notification_buffer",
            "notification_subscription_up",
            "ml_enabled",
            "ml_model_available",
        ):
            self._add(Gauge, name, "Current " + name.replace("_", " "), ())
        for name, labels in {
            "http_duration_seconds": ("method", "route"),
            "enforcement_redis_duration_seconds": ("operation", "outcome"),
            "worker_duration_seconds": ("outcome",),
            "persistence_duration_seconds": (),
            "analysis_duration_seconds": (),
            "ml_inference_duration_seconds": ("status",),
            "ws_lifetime_seconds": (),
            "notification_fanout_duration_seconds": (),
            "dependency_probe_duration_seconds": ("dependency",),
        }.items():
            self._add(
                Histogram,
                name,
                name.replace("_", " "),
                labels,
                buckets=(1, 5, 15, 30, 60, 300, 1800, 28800)
                if name == "ws_lifetime_seconds"
                else BUCKETS,
            )
        for action in LABELS["action"]:
            self.inc("security_actions", amount=0, action=action)
        for outcome in ("succeeded", "failed"):
            self.inc("security_authentication", amount=0, outcome=outcome)
        for outcome in ("persisted", "duplicate", "quarantined", "error"):
            self.inc("worker_deliveries", amount=0, outcome=outcome)
        for outcome in ("persisted", "duplicate"):
            self.inc("persistence_events", amount=0, outcome=outcome)
        for operation in ("rate_limit", "auth_failures"):
            self.inc("enforcement_errors", amount=0, operation=operation)
        for component, reason in (
            ("worker", "queue_full"),
            ("worker", "transport"),
            ("hub", "schema"),
            ("hub", "backpressure"),
        ):
            self.inc("notification_dropped", amount=0, component=component, reason=reason)
        self._add(
            Gauge,
            "dependency_up",
            "Last completed dependency probe: 1 up / 0 down",
            ("dependency",),
        )
        self._add(
            Gauge, "dependency_checked_timestamp_seconds", "Time of last probe", ("dependency",)
        )

    def _add(self, kind, name, description, labels, **kwargs):
        worker = name.startswith(
            (
                "worker_",
                "persistence_",
                "assessments_",
                "analysis_",
                "statistical_",
                "ml_",
                "dead_letter_",
            )
        ) or name in {
            "notification_buffer",
            "notification_published",
            "notification_publish_errors",
        }
        admin = name.startswith("ws_") or name in {
            "notification_enqueued",
            "notification_sent",
            "notification_subscription_up",
            "notification_subscription_errors",
            "notification_duplicates",
            "notification_fanout_duration_seconds",
        }
        api = name.startswith(("http_", "security_", "publisher_", "enforcement_"))
        if self.component != "all" and (
            (worker and self.component != "worker")
            or (admin and self.component != "admin-api")
            or (api and self.component == "worker")
        ):
            return None
        metric = kind(
            "sentinel_" + name, description, ("service", *labels), registry=self.registry, **kwargs
        )
        self.metrics[name] = metric
        # Initialize only unlabeled observations; absent labeled observations stay absent.
        if not labels:
            metric.labels(service=self.service)
        return metric

    def child(self, name, labels):
        safe = {"service": self.service}
        for key, value in labels.items():
            if key == "route":
                safe[key] = value if value in self.routes else "unmatched"
            else:
                safe[key] = str(value) if str(value) in LABELS[key] else "other"
        return self.metrics[name].labels(**safe)

    def inc(self, name, amount=1, **labels):
        if self.enabled and name in self.metrics:
            self.child(name, labels).inc(amount)

    def set(self, name, value, **labels):
        if self.enabled and name in self.metrics:
            self.child(name, labels).set(value)

    def observe(self, name, value, **labels):
        if self.enabled and name in self.metrics:
            self.child(name, labels).observe(value)

    def dependency(self, name, up, duration):
        self.set("dependency_up", int(up), dependency=name)
        self.set("dependency_checked_timestamp_seconds", time(), dependency=name)
        self.observe("dependency_probe_duration_seconds", duration, dependency=name)

    def http(self, scope, status, duration, completed):
        path = scope.get("path", "")
        if path == "/metrics" or path.startswith("/health/"):
            return
        route = getattr(scope.get("route"), "path", "unmatched")
        method = scope.get("method", "OTHER")
        method = method if method in METHODS else "OTHER"
        self.inc(
            "http_requests",
            method=method,
            route=route,
            status_class=str(status // 100) + "xx" if 100 <= status <= 599 else "other",
        )
        self.inc("http_status", code=str(status))
        if status >= 500:
            self.inc("http_server_errors")
        self.observe("http_duration_seconds", duration, method=method, route=route)
        if not completed:
            self.inc("http_incomplete")


class MetricsEndpoint:
    def __init__(self, metrics, token):
        self.metrics, self.token = metrics, token

    async def __call__(self, scope, receive, send):
        headers = [v for k, v in scope.get("headers", []) if k.lower() == b"authorization"]
        authenticated = (
            len(headers) == 1
            and len(headers[0]) <= 128
            and hmac.compare_digest(headers[0], b"Bearer " + self.token.encode())
        )
        if not authenticated:
            response = Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})
        elif scope["method"] != "GET" or scope["path"] != "/metrics":
            response = Response(status_code=404)
        else:
            body = generate_latest(self.metrics.registry)
            response = Response(
                body,
                media_type="text/plain; version=0.0.4; charset=utf-8",
                headers={"Cache-Control": "no-store"},
            )
        await response(scope, receive, send)


@asynccontextmanager
async def metrics_runtime(metrics, settings, resources):
    """Optional pull listener/probes; scrape failures cannot enter the request/event path."""
    if not settings.metrics_enabled:
        yield
        return
    token = (
        await asyncio.to_thread(Path(settings.metrics_token_file).read_text, encoding="utf-8")
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("Metrics token file must contain a private 256-bit hex secret")
    server = uvicorn.Server(
        uvicorn.Config(
            MetricsEndpoint(metrics, token),
            host="0.0.0.0",  # noqa: S104 - private Docker listener, authenticated and unpublished
            port=settings.metrics_port,
            lifespan="off",
            access_log=False,
            log_config=None,
            limit_concurrency=8,
            timeout_keep_alive=2,
            h11_max_incomplete_event_size=8192,
        )
    )

    # The primary API/worker owns signal handling.
    async def serve():
        await server.serve(sockets=None)

    async def probes():
        while True:
            try:
                await resources.health()
                if settings.dynamic_policies:
                    from time import monotonic

                    from sentinel_security.policy_runtime import load_effective

                    started = monotonic()
                    try:
                        await load_effective(resources.redis)
                    except Exception:
                        metrics.dependency("policy", False, monotonic() - started)
                    else:
                        metrics.dependency("policy", True, monotonic() - started)
            except Exception as error:
                structlog.get_logger().warning(
                    "observability_probe_failed", error_type=type(error).__name__
                )
            await asyncio.sleep(settings.metrics_probe_seconds)

    # The auxiliary server must not replace primary application signal handling.
    from contextlib import nullcontext

    server.capture_signals = nullcontext
    task = asyncio.create_task(serve())
    probe = asyncio.create_task(probes())
    try:
        # Fail deployment explicitly if the private listener cannot bind.
        for _ in range(100):
            if server.started:
                break
            if task.done():
                task.result()
            await asyncio.sleep(0.01)
        if not server.started:
            raise RuntimeError("Metrics listener did not start")
        yield
    finally:
        probe.cancel()
        server.should_exit = True
        try:
            await asyncio.wait_for(task, 3)
        except TimeoutError:
            task.cancel()
        await asyncio.gather(task, probe, return_exceptions=True)
