# SENTINEL AI

Intelligent API Security & Threat Detection Platform. Development window: **November 12-20, 2026**. This repository implements the **Day 1 foundation and Day 2 monitoring pipeline**. Threat detection, authentication, enforcement, and the dashboard follow in later milestones.

## Working functionality

- Independently installable administrative API, isolated demo API, reusable library, and dedicated event worker.
- Reusable `sentinel-security` Python package with validated settings, async PostgreSQL sessions, dependency probes, structured JSON events, and pure ASGI request context middleware.
- PostgreSQL, authenticated Redis, and authenticated RabbitMQ in Docker Compose, with named persistent volumes and startup health gates.
- Alembic baseline and a one-shot migration service. Applications never create schema at startup.
- Liveness, readiness, safe error responses, server-generated request IDs, and conservative proxy trust.
- Versioned request/response metadata, a bounded asynchronous publisher, durable RabbitMQ queues, idempotent PostgreSQL storage, retry handling, and redacted dead letters.
- Digest-pinned service images, locked Python dependencies with artifact hashes, Ruff formatting/linting, Pytest unit/integration coverage, and CI.

**Security scope:** Monitoring records real request metadata. Severity reflects HTTP status, explicit authentication outcomes, and incomplete responses; it is not a threat-detection result. The demo exposes only harmless ping and health routes and remains internal by default. The administrative API exposes only operational endpoints; there is no unauthenticated event-reading API. JWT, blocking, rate limiting, ML, WebSockets, and the frontend are not implemented yet.

## Architecture

```mermaid
flowchart LR
    Local[Local developer] --> Admin[Admin operational API :8000]
    Traffic[Owned test traffic] --> Demo[Internal demo API]
    Demo --> Middleware[Reusable ASGI middleware]
    Middleware --> Buffer[Bounded in-memory publisher buffer]
    Buffer -->|persistent messages and confirms| MQ[Durable RabbitMQ event queue]
    MQ --> Worker[Event worker]
    Worker -->|commit before acknowledgement| PG[(PostgreSQL audit events)]
    Worker -->|confirmed quarantine| Dead[Bounded dead-letter queue]
    Admin -. dependency checks .-> PG
    Middleware -. no enforcement yet .-> Redis[(Redis)]
    Migration[One-shot Alembic service] --> PG
```

The backend network is internal. The admin API also joins an ingress bridge so Docker can publish its loopback port. The development override explicitly adds ingress networking for services whose host ports it publishes.

Middleware only offers validated events to a bounded local buffer. Its request path never awaits RabbitMQ or PostgreSQL. A background task publishes events, and the independent worker commits them before acknowledging delivery. Dependency outages make API readiness return 503 while liveness and demo responses remain available. Future synchronous enforcement must remain independent of event publication. See [the architecture decisions](docs/architecture.md).

## Prerequisites

- Docker Engine/Desktop using **Linux containers**, and Docker Compose v2+.
- Python **3.11** for local development and environment initialization.
- Git. No Node or frontend dependencies are required for this milestone.
- Free localhost port 8000. The optional development override also uses 8001, 5432, 6379, 5672, and 15672.

## Start the complete stack

Run from the repository root (PowerShell, Bash, or another shell):

```sh
python scripts/init_env.py
docker compose config --quiet
docker compose up --build --wait --wait-timeout 180
```

`init_env.py` creates an ignored `.env` containing independently generated 256-bit URL-safe passwords. It refuses to overwrite an existing file. If `.env` already exists, keep it and skip that command. `.env.example` documents settings and deliberately contains no usable passwords. Compose rejects missing passwords.

When upgrading an existing Day 1 checkout, preserve `.env` and run this once before Compose:

```sh
python scripts/init_env.py --add-monitoring-key
```

The command adds only a missing or blank client-identity key and preserves existing service passwords and populated keys. Keep the generated key stable across API instances and restarts.

After startup:

- Admin liveness: http://localhost:8000/health/live
- Admin readiness: http://localhost:8000/health/ready
- Development API documentation: http://localhost:8000/docs
- Demo API, PostgreSQL, Redis, and RabbitMQ have no published host ports by default.

Query the internal demo without publishing its port:

```sh
docker compose exec demo-api python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/demo/ping').read().decode())"
```

Optional localhost development bindings:

```sh
docker compose -f compose.yaml -f compose.dev.yaml up --build --wait --wait-timeout 180
```

The demo is then at http://localhost:8001/api/demo/ping and RabbitMQ management at http://localhost:15672. Use the credentials in your private `.env` for management access. The override is for local development; authentication on application routes is a later milestone.

Useful operations:

```sh
docker compose ps
docker compose logs --tail=100 admin-api demo-api event-worker migrate
docker compose exec admin-api alembic current
docker compose run --rm migrate alembic upgrade head
docker compose down
```

`down` preserves volumes. Do not use `down --volumes` unless intentionally deleting local data. Changing an initialization password in `.env` does not rotate passwords already stored in PostgreSQL or RabbitMQ volumes; rotate them in the service before updating configuration. Treat rendered Compose output and container inspection as sensitive because the local deployment uses environment-based secrets. Prefer `docker compose config --quiet` when validating.

## Tests and code quality

PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip install --no-deps -e packages/sentinel-security -e apps/admin-api -e apps/demo-api -e apps/event-worker
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pytest -m "not integration" --cov=sentinel_security --cov=sentinel_api --cov=sentinel_demo --cov=sentinel_worker --cov-report=term-missing --cov-fail-under=85
```

On Linux/macOS substitute `.venv/bin/python` for `.\.venv\Scripts\python.exe`. Package build isolation downloads pinned setuptools when initially installing the three local packages. Runtime and test dependencies are pinned and hash-checked.

With the stack running, execute real dependency and HTTP checks inside its private network:

```sh
docker compose --profile test run --build --rm tests
```

To run the full unit suite inside Linux (also useful when Windows Application Control blocks native Python extensions):

```sh
docker compose --profile test run --build --rm --no-deps -e COVERAGE_FILE=/tmp/.coverage tests python -m pytest -p no:cacheprovider -m "not integration" --cov=sentinel_security --cov=sentinel_api --cov=sentinel_demo --cov=sentinel_worker --cov-report=term-missing --cov-fail-under=85
```

The integration suite verifies all Day 1 behavior plus real HTTP-to-database persistence, concurrent requests, duplicate insert/delivery handling, redacted malformed messages, PostgreSQL failure quarantine, investigation indexes, and sensitive-data exclusions. Integration tests are explicitly enabled in the container; a bare `pytest` skips them. Host-based unit tests require no running infrastructure. The container unit command uses `--no-deps` and needs only the built test image. GitHub Actions runs lint, unit coverage, Compose startup, and the container integration suite.

Format code with `python -m ruff format .`. Update dependencies intentionally and commit both inputs and lock files:

```sh
python -m piptools compile --allow-unsafe --strip-extras --generate-hashes --output-file=requirements.txt requirements.in
python -m piptools compile --allow-unsafe --strip-extras --generate-hashes --output-file=requirements-dev.txt requirements-dev.in
```

## Local API processes

The Compose workflow is the primary development path. To run a service directly after installing the packages, start the development Compose override and set these variables in the process environment using the private credentials from `.env`:

| Variable | Local value shape |
| --- | --- |
| `SENTINEL_DATABASE_URL` | `postgresql+asyncpg://USER:PASSWORD@localhost:5432/sentinel` |
| `SENTINEL_REDIS_URL` | `redis://:PASSWORD@localhost:6379/0` |
| `SENTINEL_RABBITMQ_URL` | `amqp://USER:PASSWORD@localhost:5672/` |

Settings read the process environment, **not** `.env` automatically. Compose reads `.env` and supplies service URLs. Generated passwords are hex so URL escaping is unnecessary; custom credentials must be percent-encoded in URLs. In a separate process, run either:

```sh
python -m uvicorn sentinel_api.main:create_app --factory --host 127.0.0.1 --port 8010 --reload --no-proxy-headers --no-access-log --log-config uvicorn-log.json
python -m uvicorn sentinel_demo.main:create_app --factory --host 127.0.0.1 --port 8011 --reload --no-proxy-headers --no-access-log --log-config uvicorn-log.json
```

## Migrations

The initial revision establishes the baseline; `0002_security_events` adds the real audit table, idempotency primary key, constraints, and timestamp/service/severity/client/request indexes. ORM metadata is registered in `migrations/env.py`. Generate and review subsequent migrations:

```sh
python -m alembic revision --autogenerate -m "describe schema change"
python -m alembic upgrade head
python -m alembic check
```

A local Alembic command needs the same validated dependency URL variables as an application. Only PostgreSQL is contacted by migrations. Run migrations once per deployment before applications; never run multiple migration jobs concurrently. Test downgrades against disposable data before using them operationally.

## Configuration and operational contracts

| Setting | Default / behavior |
| --- | --- |
| `SENTINEL_ENVIRONMENT` | `development`; only this value exposes OpenAPI/docs |
| `SENTINEL_LOG_LEVEL` | `INFO` |
| `SENTINEL_DEPENDENCY_TIMEOUT_SECONDS` | `3`, bounded to 0.1-30 seconds |
| `SENTINEL_DATABASE_POOL_SIZE` | `5`, per API process |
| `SENTINEL_DATABASE_MAX_OVERFLOW` | `5`, per API process |
| `SENTINEL_TRUSTED_PROXY_CIDRS` | JSON array, empty by default |

- `/health/live`: 200 while the HTTP service is running; never probes dependencies.
- `/health/ready`: concurrent bounded SQL, Redis PING, and authenticated AMQP channel checks. Returns 200 only when all are up, otherwise 503 with dependency names and `up`/`down`; no credentials or raw errors.
- AMQP readiness opens a short-lived authenticated probe. The demo publisher separately reuses a persistent confirmed channel; the worker owns its own connection and database pool.
- Requests get a fresh `X-Request-ID`. Access events record method, registered route template, status, duration, and correlation ID. No raw path, query string, request/response body, cookies, authorization headers, or raw client IP is persisted. Security events use an HMAC-SHA256 client identifier.
- Uvicorn's raw access/error handlers are disabled by the supplied logging config; application errors emit a safe error class and request ID. Use the documented launch commands to keep that policy.
- Uvicorn proxy rewriting is disabled. `X-Forwarded-For` is considered only when the socket peer is inside an explicitly configured trusted proxy CIDR; the chain is traversed from right to left. Do not trust broad public CIDRs. The proxy must overwrite or append forwarding headers correctly.
- A generic 500 response contains a correlation ID and no exception message. Expected HTTP errors keep FastAPI's normal behavior.
- Container runtime processes run as UID 10001 with read-only root filesystems, dropped capabilities, and no privilege escalation. TLS, managed secret storage, dedicated database roles, and deployment network policy are production work beyond this local foundation.

## Repository layout

```text
apps/
  admin-api/                 # independent sentinel_api distribution
  demo-api/                  # independent sentinel_demo distribution
  event-worker/              # independent sentinel_worker distribution
packages/
  sentinel-security/         # reusable sentinel_security distribution
migrations/
  versions/0001_baseline.py
  versions/0002_security_events.py
scripts/                     # credentials, persistence verification, bounded replay
infra/rabbitmq/20-sentinel.conf
tests/
  unit/
  integration/
docs/
  architecture.md
  day-1-verification.md
  day-2-verification.md
.github/workflows/ci.yml
Dockerfile
compose.yaml
compose.dev.yaml
alembic.ini
uvicorn-log.json
pyproject.toml
requirements{,-dev}.{in,txt}
.env.example
```

The frontend, threat engine, enforcement, and Prometheus/Grafana remain future milestones. No fake detections, synthetic production audit rows, or unused machine-learning dependencies are included.

See the historical [Day 1 verification record](docs/day-1-verification.md) and current [Day 2 verification record](docs/day-2-verification.md) for executed checks and the Windows native-extension limitation.

## Monitoring contract and limits

Monitoring is enabled for `demo-api` in Compose and disabled for the admin API by default. `/health`, `/docs`, and `/openapi.json` path prefixes are excluded. Unknown or unsafe route templates become `unmatched`, so a 404 never stores its raw URL. Application code may explicitly call `record_authentication_outcome(request.scope, "succeeded")` or `"failed"`; otherwise the outcome is `not_provided`. No authentication header is inspected by telemetry.

Version 1 events contain only an event UUID, generated request ID, UTC start timestamp, method, safe route template, status, duration, service, HMAC client identifier, severity, explicit authentication outcome, and response completion flag. Duration covers the response stream. A stream failure can retain a transmitted 200 status while recording `response_completed=false` and severity `error`.

| Setting | Default / limit |
| --- | --- |
| `SENTINEL_MONITORING_ENABLED` | False in the library; true for Compose demo |
| `SENTINEL_CLIENT_IDENTITY_KEY` | Required when enabled; 64 lowercase hex characters / 256 bits |
| `SENTINEL_MONITORING_EXCLUDED_PATHS` | JSON array; health/docs/OpenAPI excluded by default |
| `SENTINEL_EVENT_BUFFER_CAPACITY` | 256 queued events per API process, plus one in flight |
| `SENTINEL_EVENT_MAX_BYTES` | 4096 bytes; configurable 1024-12288 |
| `SENTINEL_EVENT_OPERATION_TIMEOUT_SECONDS` | 2 seconds per publish/setup operation |
| `SENTINEL_EVENT_PUBLISH_ATTEMPTS` | 5 attempts with bounded exponential backoff |
| `SENTINEL_EVENT_RETRY_DELAY_SECONDS` | 0.5 seconds initially; backoff capped at 5 seconds |
| `SENTINEL_EVENT_SHUTDOWN_TIMEOUT_SECONDS` | 5 seconds to drain before cancellation/loss accounting |
| `SENTINEL_BROKER_QUEUE_MAX_MESSAGES` | 10000 per event/dead-letter queue |
| `SENTINEL_BROKER_QUEUE_MAX_BYTES` | 16777216 bytes per queue; overflow rejects new publications |
| `SENTINEL_WORKER_PREFETCH` | 16 unacknowledged deliveries; sequential processing per worker |
| `SENTINEL_WORKER_STORAGE_ATTEMPTS` | 4 attempts for transient errors |
| `SENTINEL_WORKER_STORAGE_TIMEOUT_SECONDS` | 3 seconds per storage attempt |

RabbitMQ additionally rejects messages over 16384 bytes. Worker health uses a DB-checked heartbeat file with a 20-second freshness limit and has no public HTTP listener. Queue declaration limits must agree across publishers and workers. Changing arguments of existing queues requires a planned drain/recreation or a new versioned queue name; do not delete queues containing events casually.

### Delivery guarantees and failure behavior

- The ingress buffer is in memory. A crash, full buffer, oversize event, exhausted publish retries, or expired shutdown drain can lose **unconfirmed telemetry**. The API still responds. Safe structured `telemetry_dropped`, `event_publish_failed`, and shutdown counters expose these conditions; this is not a durable outbox.
- Publications are persistent, mandatory, and confirmed. A lost confirmation may cause a resend with the same event ID. PostgreSQL `ON CONFLICT DO NOTHING` prevents duplicate rows.
- The worker acknowledges only after a committed insert, a confirmed duplicate, or a confirmed dead-letter publication. Connection interruption requeues unacknowledged deliveries.
- Transient storage failures retry with bounded backoff. Exhausted/permanent failures send a validated, replayable event envelope to `sentinel.security.events.v1.dead`. Invalid/oversized input sends only a rejection reason, timestamp, and SHA-256 fingerprint; its original bytes and arbitrary headers are omitted.
- If quarantine cannot be confirmed, the original remains unacknowledged. The worker reconnects with backoff, avoiding an immediate nack/requeue hot loop.
- This single-node development broker persists confirmed messages across normal restarts; it does not provide replicated broker availability. Audit retention and production database roles remain deployment work.

### Reproduce end-to-end verification

PowerShell, with the stack running:

```powershell
Get-Content -Raw scripts/verify_pipeline.py | docker compose exec -T demo-api python -
```

Bash:

```sh
docker compose exec -T demo-api python - < scripts/verify_pipeline.py
```

The script sends three real HTTP requests containing randomly generated privacy sentinels, queries PostgreSQL through the private container environment, checks their absence from stored fields, and prints only allowlisted evidence. It does not add an event-reading administrative route.

After resolving a storage incident, an operator with access to the private worker container may replay up to 100 dead-letter deliveries per invocation:

```powershell
Get-Content -Raw scripts/replay_dead_letters.py | docker compose exec -T event-worker python - --limit 25
```

Only validated nested events are republished, retaining their IDs. Dead-letter deliveries are acknowledged after confirmation. Malformed/redacted notices remain quarantined; the scan is bounded, so inspect/manage a large invalid-message backlog through authenticated broker tooling. Replaying duplicates is safe at the database boundary. HMAC identifiers are pseudonyms, not anonymity; rotating the identity key changes future identifiers and breaks historical client continuity.
