# Day 2 verification - November 12, 2026

## Implemented architecture and working behavior

The existing Day 1 foundation was extended without recreating services, replacing volumes, changing service passwords, or adding unused dependencies. The initial repository state was clean at commit `1472953`. The reusable middleware now offers frozen, schema-versioned request/response metadata to a bounded in-memory publisher. A dedicated worker consumes durable RabbitMQ messages and commits typed PostgreSQL audit records before acknowledgement.

Version 1 metadata includes request/event identifiers, UTC time, method, sanitized route template, status, duration, service, a keyed HMAC client identifier, explicit application-provided authentication outcome, response completion, and HTTP-derived severity. The middleware does not consume request/response bodies. Health/docs traffic is excluded. Proxy trust remains conservative. No unauthenticated administrative event API was added.

Confirmed persistent publication, mandatory routing, retry limits, queue capacity/byte limits, bounded worker prefetch, idempotent database insertion, safe quarantine, graceful shutdown, and reconnect supervision are implemented. Invalid/oversized messages produce redacted rejection notices; original bytes are never copied into those notices. Valid storage failures remain replayable through private operator tooling. See the README for exact resource limits and delivery guarantees.

## Final Docker and migration status

| Service | Final status | Host binding |
| --- | --- | --- |
| admin-api | Healthy | 127.0.0.1:8000 |
| demo-api | Healthy | None |
| event-worker | Healthy; heartbeat and DB checked | None; no HTTP server |
| postgres | Healthy | None |
| redis | Healthy | None |
| rabbitmq | Healthy | None |
| migrate | Exited successfully, code 0 | None |

The worker inherits the restricted application container settings: UID/GID 10001, read-only root filesystem, all Linux capabilities dropped, no privilege escalation, and writable temporary storage only. The runtime image declares port 8000 for the API services; that image metadata does not imply the worker listens on a port.

Executed `alembic current`: **0002_security_events (head)**. Executed `alembic check`: **No new upgrade operations detected.** Executed `pip check`: **No broken requirements found.** Named Day 1 volumes were retained through service recreation and both outage exercises.

## Automated tests actually executed

The final complete suite command was:

```sh
docker compose --profile test run --rm --no-deps -e COVERAGE_FILE=/tmp/.coverage tests python -m pytest -p no:cacheprovider --cov=sentinel_security --cov=sentinel_api --cov=sentinel_demo --cov=sentinel_worker --cov-report=term-missing --cov-fail-under=85
```

**Final result: 140 passed, 0 failed, 0 skipped in 3.61 seconds.** This comprises **125 unit tests and 15 integration tests**, including the original Day 1 tests. The only existing test expectation changed for the new migration head; existing behaviors/assertions were retained.

**Combined statement coverage: 94.63%** across the shared package, two API packages, and worker package: 652 statements, 35 missed, with an 85% required floor. Middleware, application/configuration code, consumer logic, storage, and infrastructure each reached 100% statement coverage in that run. The worker CLI entrypoint ran in Docker but was not instrumented by pytest; it remains included as missed lines in the reported coverage. Operator script code is tested but is outside these four package coverage targets.

Earlier independently executed runs also passed: 114 initial unit tests at 93.56% coverage, and 15 integration tests. After adding credential/replay utility tests, the final combined run above supersedes those counts. Targeted host tests for configuration, client identity, event validation, and environment initialization passed **67/67**.

Additional final checks:

- Ruff lint: passed.
- Ruff formatting check: passed.
- Default Compose `config --quiet`: passed.
- Combined default/development Compose `config --quiet`: passed. Optional development host bindings were not started.
- Final application/test image builds: completed successfully using existing hash-locked dependencies and pinned base/service images.
- `docker compose up -d --wait --wait-timeout 180`: completed successfully.
- No remote GitHub Actions execution was claimed; the workflow was updated for the worker and coverage target.

Tests cover successful and failed requests, stream failures, generated request IDs, timing, trusted proxy chains, metadata privacy, explicit authentication outcomes, publisher confirmations, bounded buffering/retries/timeouts, cancellation/shutdown, storage commit ordering, duplicate races/deliveries, RabbitMQ connection failures, PostgreSQL failures, malformed/oversized events, dead-letter confirmation failures, replay safety, concurrency, credential preservation, worker reconnect/health, indexes, and absent event-reading administrative routes.

## Real HTTP-to-database evidence

Executed from PowerShell against the running demo container:

```powershell
Get-Content -Raw scripts/verify_pipeline.py | docker compose exec -T demo-api python -
```

The script made **3 real HTTP requests**, then independently queried PostgreSQL and found **3 matching events**. It reported `sensitive_sentinels_persisted: false`. One actual row was:

```json
{
  "event_id": "bc4f2d61-041c-4f82-a231-027a61da0be2",
  "request_id": "43adf85191eb44249b2fe9308981a603",
  "service": "sentinel-demo-api",
  "endpoint": "/api/demo/ping",
  "status_code": 200,
  "duration_ms": 0.395,
  "occurred_at": "2026-11-12 07:41:20.111575+00:00",
  "ingested_at": "2026-11-12 07:41:20.117756+00:00",
  "schema_version": 1
}
```

These timestamps are UTC; the verification occurred November 12, 2026 in the user's Asia/Calcutta timezone. Random sentinels were sent in the query, body, Authorization header, and cookie. None appeared in stored columns. The spoofed forwarded IP was absent as well. The normal request path publishes through RabbitMQ; it has no event-storage database call. The running worker was observed consuming and persisting corresponding request IDs.

The real integration concurrency test separately sent 25 simultaneous HTTP requests and found all 25 unique events. Duplicate insert races and duplicate acknowledged broker deliveries resulted in one database row per event ID. Running-worker malformed/oversized input tests verified redacted dead-letter notices.

## Live dependency failure and recovery evidence

### PostgreSQL outage

PostgreSQL was stopped with Compose. Demo ping returned **200**, while admin/demo liveness stayed **200** and readiness became **503**. The real request ID was `54e37a2411444f1cb9d10a254c837252`.

After storage retries were exhausted, broker inspection showed 0 ready source messages and **1 dead-letter message**. PostgreSQL was restarted in a `finally` block and all services became healthy again. The operator replay command completed with **Replayed 1 validated events; retained 0 redacted notices**. A subsequent database query confirmed the same request ID persisted with status 200 and endpoint `/api/demo/ping`.

### RabbitMQ outage

RabbitMQ was stopped with Compose. Demo ping returned **200**, liveness stayed **200**, and readiness became **503**. The real request ID was `f400ddcf9c41473d9454bb6d3bfdb158`.

RabbitMQ was restarted in a `finally` block. The publisher retried its buffered event, the worker reconnected, and all services returned healthy. A database query confirmed the same outage request ID persisted with status 200 and endpoint `/api/demo/ping`. This demonstrates recovery within the configured retry window, not a guarantee of lossless telemetry for longer outages.

## Limits and unresolved environment issues

- Unconfirmed telemetry uses process memory. Full buffers, crashes, exhausted publish retries, oversize events, or shutdown drain expiry can lose events. These cases are accounted for and logged with safe loss reasons/counters. There is no durable outbox.
- Quarantined valid events require operator replay after a storage incident; malformed notices remain quarantined. Replay scans are bounded. A full dead queue causes the source delivery to remain unacknowledged and be retried after reconnection/backoff.
- The worker processes sequentially per replica with bounded prefetch. Scaling, retention, replicated broker deployment, and production database/secret-management roles remain future deployment work.
- JWT, authenticated administration, detection, brute-force prevention, distributed enforcement, ML, automated blocking, dashboard, and WebSockets remain deliberately unimplemented. HTTP-derived severity is not a simulated threat result.
- Windows Application Control previously blocked the native `coverage.tracer` and `sqlalchemy.util._collections_cy` extensions. The complete suite therefore ran in Linux containers; only the 67 targeted host tests above are claimed. No operating system policy or installed dependency source was modified.
- No blocker remains for the Docker workflow. Remote CI and optional development host port startup were not executed. No commit or push was made.

## Day 2 checklist

- [x] Request/response monitoring extends existing reusable ASGI middleware.
- [x] Validated versioned metadata and minimal, pseudonymized client identity.
- [x] No sensitive bodies, query values, cookies, tokens, or raw IPs in events.
- [x] Nonblocking bounded ingress, persistent confirmed RabbitMQ publication.
- [x] Dedicated consumer with commit-before-ack, retries, duplicate prevention, safe dead letters.
- [x] Real PostgreSQL audit table, additive migration, and investigation indexes.
- [x] Health/internal exclusions, conservative proxy trust, failure isolation.
- [x] Worker Compose service and operational health checks.
- [x] Complete automated suite and real HTTP/broker/database verification.
- [x] README, architecture, verification, and operator recovery instructions updated.

## Files created and modified

Private `.env` was also updated to add the missing client-identity key; existing service credentials were preserved. It remains ignored by Git. No dependency lock changes were necessary because all implementation uses Day 1 dependencies.

Created (23 files):

- `apps/event-worker/pyproject.toml`
- `apps/event-worker/src/sentinel_worker/__init__.py`
- `apps/event-worker/src/sentinel_worker/__main__.py`
- `apps/event-worker/src/sentinel_worker/consumer.py`
- `apps/event-worker/src/sentinel_worker/healthcheck.py`
- `apps/event-worker/src/sentinel_worker/runtime.py`
- `docs/day-2-verification.md`
- `infra/rabbitmq/20-sentinel.conf`
- `migrations/versions/0002_security_events.py`
- `packages/sentinel-security/src/sentinel_security/events.py`
- `packages/sentinel-security/src/sentinel_security/messaging.py`
- `packages/sentinel-security/src/sentinel_security/publisher.py`
- `packages/sentinel-security/src/sentinel_security/storage.py`
- `scripts/replay_dead_letters.py`
- `scripts/verify_pipeline.py`
- `tests/integration/test_monitoring_pipeline.py`
- `tests/unit/test_consumer.py`
- `tests/unit/test_env_initialization.py`
- `tests/unit/test_events.py`
- `tests/unit/test_monitoring_middleware.py`
- `tests/unit/test_publisher.py`
- `tests/unit/test_replay.py`
- `tests/unit/test_worker_runtime.py`

Modified (15 tracked files):

- `.env.example`
- `.github/workflows/ci.yml`
- `Dockerfile`
- `README.md`
- `compose.yaml`
- `docs/architecture.md`
- `migrations/env.py`
- `packages/sentinel-security/src/sentinel_security/application.py`
- `packages/sentinel-security/src/sentinel_security/config.py`
- `packages/sentinel-security/src/sentinel_security/logging.py`
- `packages/sentinel-security/src/sentinel_security/middleware.py`
- `pyproject.toml`
- `scripts/init_env.py`
- `tests/conftest.py`
- `tests/integration/test_stack.py`
