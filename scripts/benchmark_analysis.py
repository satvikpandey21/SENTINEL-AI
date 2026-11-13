"""Bounded real-PostgreSQL analysis benchmark; controlled telemetry, not a load-test SLA."""

import asyncio
import json
import resource
import statistics
from datetime import UTC, datetime
from time import perf_counter
from uuid import uuid4

from sqlalchemy import delete

from sentinel_security.analysis_config import AnalysisPolicy
from sentinel_security.analysis_storage import AnalysisEngine, AnalysisState
from sentinel_security.config import Settings
from sentinel_security.events import SecurityEvent
from sentinel_security.infrastructure import Resources
from sentinel_security.storage import EventStore, SecurityEventRecord


async def main():
    service = "benchmark-" + uuid4().hex
    latencies = []
    async with Resources(Settings()) as resources:
        engine = AnalysisEngine(AnalysisPolicy())
        store = EventStore(resources.session_factory, engine)
        try:
            started = perf_counter()
            timestamp = datetime.now(UTC)
            for _ in range(120):
                event = SecurityEvent(
                    schema_version=1,
                    event_type="http.request.completed",
                    event_id=uuid4(),
                    request_id=uuid4().hex,
                    occurred_at=timestamp,
                    service=service,
                    method="GET",
                    endpoint="/controlled/items",
                    status_code=200,
                    duration_ms=1.0,
                    client_identifier="b" * 64,
                    severity="info",
                    authentication_outcome="not_provided",
                    response_completed=True,
                )
                began = perf_counter()
                await store.persist(event)
                latencies.append((perf_counter() - began) * 1000)
            elapsed = perf_counter() - started
            print(
                json.dumps(
                    {
                        "scope": "120 sequential events, one client, real PostgreSQL commits",
                        "events": len(latencies),
                        "elapsed_seconds": elapsed,
                        "events_per_second": len(latencies) / elapsed,
                        "latency_mean_ms": statistics.mean(latencies),
                        "latency_p95_ms": sorted(latencies)[int(len(latencies) * 0.95) - 1],
                        "latency_max_ms": max(latencies),
                        "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                        "model_load_count": engine.model.load_count,
                        "ml_status": engine.model.status,
                    },
                    indent=2,
                )
            )
        finally:
            async with resources.session_factory() as session, session.begin():
                await session.execute(
                    delete(SecurityEventRecord).where(SecurityEventRecord.service == service)
                )
                await session.execute(delete(AnalysisState).where(AnalysisState.service == service))


if __name__ == "__main__":
    asyncio.run(main())
