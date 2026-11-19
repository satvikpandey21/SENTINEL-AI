# ruff: noqa: S101 - controlled local performance comparison, not a production benchmark
"""Alternate instrumentation off/on against real dependencies; report local HTTP and commit cost."""

import asyncio
import json
import logging
import secrets
from contextlib import nullcontext
from datetime import UTC, datetime
from statistics import median
from time import perf_counter
from uuid import uuid4

import httpx2 as httpx
import uvicorn
from pydantic import SecretStr

from sentinel_demo.auth import DemoAuthSettings
from sentinel_demo.main import create_app
from sentinel_security.analysis_storage import AnalysisEngine
from sentinel_security.config import Settings
from sentinel_security.events import SecurityEvent
from sentinel_security.infrastructure import Resources
from sentinel_security.metrics import Metrics
from sentinel_security.storage import EventStore


async def trial(enabled, requests=200, events=100):
    settings = Settings().model_copy(
        update={
            "metrics_enabled": enabled,
            "metrics_port": 9199,
            "monitoring_enabled": True,
            "protection_enabled": True,
            "client_identity_key": SecretStr(secrets.token_hex(32)),
            "dynamic_policies": False,
            "log_level": "ERROR",
        }
    )
    app = create_app(settings, DemoAuthSettings(auth_enabled=False))
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=8199, log_config=None, access_log=False)
    )
    server.capture_signals = nullcontext
    task = asyncio.create_task(server.serve())
    try:
        async with asyncio.timeout(15):
            while not server.started:
                if task.done():
                    task.result()
                await asyncio.sleep(0.01)
        async with httpx.AsyncClient(base_url="http://127.0.0.1:8199", timeout=10) as client:
            for _ in range(20):
                assert (await client.get("/api/demo/ping")).status_code == 200
            latencies = []
            started = perf_counter()
            for _ in range(requests):
                before = perf_counter()
                assert (await client.get("/api/demo/ping")).status_code == 200
                latencies.append((perf_counter() - before) * 1000)
            http_rate = requests / (perf_counter() - started)
    finally:
        server.should_exit = True
        await task
    metrics = Metrics("benchmark-worker", enabled=enabled, component="worker")
    async with Resources(settings) as resources:
        analysis = AnalysisEngine(settings.analysis, metrics)
        store = EventStore(resources.session_factory, analysis, metrics=metrics)
        # Distinct owned pseudonyms avoid lock competition with the running event worker.
        identity = secrets.token_hex(32)

        def event():
            return SecurityEvent(
                schema_version=1,
                event_type="http.request.completed",
                event_id=uuid4(),
                request_id=uuid4().hex,
                occurred_at=datetime.now(UTC),
                service="phase8-benchmark",
                method="GET",
                endpoint="/benchmark",
                status_code=200,
                duration_ms=1,
                client_identifier=identity,
                severity="info",
                authentication_outcome="not_provided",
                response_completed=True,
            )

        for _ in range(10):
            await store.persist(event())
        started = perf_counter()
        for _ in range(events):
            assert await store.persist(event())
        commit_rate = events / (perf_counter() - started)
    return {
        "metrics_enabled": enabled,
        "http_requests": requests,
        "http_median_ms": median(latencies),
        "http_p95_ms": sorted(latencies)[int(0.95 * len(latencies)) - 1],
        "http_requests_per_second": http_rate,
        "analysis_commits": events,
        "analysis_commits_per_second": commit_rate,
    }


async def main():
    logging.getLogger("httpx2").setLevel(logging.WARNING)
    # ABBA ordering reduces a one-sided cache/warm-up bias.
    trials = [await trial(enabled) for enabled in (False, True, True, False)]
    groups = {
        enabled: [t for t in trials if t["metrics_enabled"] == enabled] for enabled in (False, True)
    }
    off, on = groups[False], groups[True]

    def delta(key):
        return (median(t[key] for t in on) / median(t[key] for t in off) - 1) * 100

    print(
        json.dumps(
            {
                "scope": (
                    "Local HTTP, real Redis/AMQP publishing and PostgreSQL analysis commits. "
                    "Two sequential trials per mode; no production claim. "
                    "Commit rate excludes broker consumption and network acknowledgement."
                ),
                "trials": trials,
                "median_http_latency_change_percent": delta("http_median_ms"),
                "median_http_rate_change_percent": delta("http_requests_per_second"),
                "median_commit_rate_change_percent": delta("analysis_commits_per_second"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
