# SENTINEL AI

Intelligent API Security & Threat Detection Platform. Development window: **November 12-20, 2026**. This repository implements the **Day 1 foundation**, not the complete threat detection platform.

## Day 1 behavior

- Two independently installable FastAPI services: administrative API and isolated demonstration API.
- Reusable `sentinel-security` Python package with validated settings, async PostgreSQL sessions, dependency probes, structured JSON events, and pure ASGI request context middleware.
- PostgreSQL, authenticated Redis, and authenticated RabbitMQ in Docker Compose, with named persistent volumes and startup health gates.
- Alembic baseline and a one-shot migration service. Applications never create schema at startup.
- Liveness, readiness, safe error responses, server-generated request IDs, and conservative proxy trust.
- Digest-pinned service images, locked Python dependencies with artifact hashes, Ruff formatting/linting, Pytest unit/integration coverage, and CI.

**Security scope:** Day 1 middleware provides observability and client identification. It does not yet detect or block attacks. The demo has only a harmless ping route and is internal in the default deployment. The admin service has only operational endpoints. JWT, protected administrative business routes, rate limiting, threat detection, event workers, audit records, WebSockets, frontend, and monitoring dashboards are later milestones. Do not expose this development stack to the internet.

## Architecture

```mermaid
flowchart LR
    Local[Local developer] --> Admin[Admin API :8000]
    Admin --> Shared[Reusable sentinel-security package]
    Demo[Internal demo API] --> Shared
    Shared --> PG[(PostgreSQL)]
    Shared --> Redis[(Redis)]
    Shared -. readiness handshake .-> MQ[RabbitMQ]
    Migration[One-shot Alembic service] --> PG
```

The backend network is internal. The admin API also joins an ingress bridge so Docker can publish its loopback port. The development override explicitly adds ingress networking for services whose host ports it publishes.

The broker handshake belongs to readiness only. Middleware does not connect to RabbitMQ, Redis, or PostgreSQL. A broker outage makes overall readiness return 503, while liveness and the demo ping remain available. Readiness is an operational signal; future synchronous rate limiting must use Redis independently of asynchronous publication. See [the architecture decisions](docs/architecture.md).

## Prerequisites

- Docker Engine/Desktop using **Linux containers**, and Docker Compose v2+.
- Python **3.11** for local development and environment initialization.
- Git. No Node or frontend dependencies are required for Day 1.
- Free localhost port 8000. The optional development override also uses 8001, 5432, 6379, 5672, and 15672.

## Start the complete stack

Run from the repository root (PowerShell, Bash, or another shell):

```sh
python scripts/init_env.py
docker compose config --quiet
docker compose up --build --wait --wait-timeout 180
```

`init_env.py` creates an ignored `.env` containing independently generated 256-bit URL-safe passwords. It refuses to overwrite an existing file. If `.env` already exists, keep it and skip that command. `.env.example` documents settings and deliberately contains no usable passwords. Compose rejects missing passwords.

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
docker compose logs --tail=100 admin-api demo-api migrate
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
.\.venv\Scripts\python.exe -m pip install --no-deps -e packages/sentinel-security -e apps/admin-api -e apps/demo-api
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pytest -m "not integration" --cov=sentinel_security --cov=sentinel_api --cov=sentinel_demo --cov-report=term-missing --cov-fail-under=85
```

On Linux/macOS substitute `.venv/bin/python` for `.\.venv\Scripts\python.exe`. Package build isolation downloads pinned setuptools when initially installing the three local packages. Runtime and test dependencies are pinned and hash-checked.

With the stack running, execute real dependency and HTTP checks inside its private network:

```sh
docker compose --profile test run --build --rm tests
```

To run the full unit suite inside Linux (also useful when Windows Application Control blocks native Python extensions):

```sh
docker compose --profile test run --build --rm --no-deps -e COVERAGE_FILE=/tmp/.coverage tests python -m pytest -p no:cacheprovider -m "not integration" --cov=sentinel_security --cov=sentinel_api --cov=sentinel_demo --cov-report=term-missing --cov-fail-under=85
```

The integration tests verify the applied migration, SQL execution, Redis write/read/delete, RabbitMQ publish/consume/acknowledge, both APIs' liveness/readiness, and the demo ping. Integration tests are explicitly enabled in the container; a bare `pytest` skips them. Host-based unit tests require no running infrastructure. The container unit command uses `--no-deps` and needs only the built test image. GitHub Actions runs lint, unit coverage, Compose startup, and the container integration suite.

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

The initial revision establishes Alembic's version table without speculative audit or detection tables. Add real domain tables with the feature that uses them, import models in `migrations/env.py`, and generate/review migrations:

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
- AMQP readiness opens a short-lived connection every probe. A durable publisher/worker lifecycle will be introduced alongside actual asynchronous events.
- Requests get a fresh `X-Request-ID`. Access events record method, registered route template, status, duration, and correlation ID. No raw path, query string, request/response body, cookies, authorization headers, or client IP is persisted.
- Uvicorn's raw access/error handlers are disabled by the supplied logging config; application errors emit a safe error class and request ID. Use the documented launch commands to keep that policy.
- Uvicorn proxy rewriting is disabled. `X-Forwarded-For` is considered only when the socket peer is inside an explicitly configured trusted proxy CIDR; the chain is traversed from right to left. Do not trust broad public CIDRs. The proxy must overwrite or append forwarding headers correctly.
- A generic 500 response contains a correlation ID and no exception message. Expected HTTP errors keep FastAPI's normal behavior.
- Container runtime processes run as UID 10001 with read-only root filesystems, dropped capabilities, and no privilege escalation. TLS, managed secret storage, dedicated database roles, and deployment network policy are production work beyond this local foundation.

## Repository layout

```text
apps/
  admin-api/                 # independent sentinel_api distribution
  demo-api/                  # independent sentinel_demo distribution
packages/
  sentinel-security/         # reusable sentinel_security distribution
migrations/
  versions/0001_baseline.py
scripts/init_env.py
tests/
  unit/
  integration/
docs/
  architecture.md
  day-1-verification.md
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

Frontend, workers, and monitoring services are intentionally absent until their milestones; there are no fake detections, placeholder queues, or unused machine-learning dependencies.

See [the Day 1 verification record and checklist](docs/day-1-verification.md) for the checks executed in this workspace and the remaining Windows-specific limitation.
