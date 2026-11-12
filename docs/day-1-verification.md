# Day 1 verification ? November 12, 2026

## Result

The Day 1 foundation is implemented and verified on Docker Desktop's Linux engine. The default stack is left running. This is not a claim that future security detection, enforcement, authentication, or UI features are complete.

## Checks executed

| Check | Result |
| --- | --- |
| Ruff lint (`python -m ruff check .`) | Passed |
| Ruff format (`python -m ruff format --check .`) | Passed |
| Host configuration and client identification unit tests | 20 passed |
| Full unit suite in the Linux test image | 35 passed, 5 integration tests deselected |
| Full unit statement coverage | 94.95% (85% required); coverage includes the two APIs and shared library |
| Real integration suite in Compose | 5 passed, 35 unit tests deselected |
| Default Compose configuration | `docker compose config --quiet` passed |
| Development override configuration | Combined `config --quiet` passed; optional host bindings were not started |
| Digest-pinned runtime and test image builds | Passed; runtime/test dependency artifact hashes checked by pip |
| Initial Compose startup | PostgreSQL/Redis/RabbitMQ and both APIs healthy; migration job exited 0 |
| Alembic applied revision | `0001_baseline (head)` |
| Alembic schema drift check | `No new upgrade operations detected.` |
| Host HTTP access | `http://127.0.0.1:8000/health/ready` returned 200; all three dependencies `up` |
| Broker outage | Both API liveness endpoints stayed 200; readiness became 503 with RabbitMQ down and PostgreSQL/Redis up; demo ping stayed 200 |
| Broker recovery | RabbitMQ restarted; both APIs and all dependencies returned healthy |
| Persistence | Service recreations retained initialized credentials and the applied Alembic revision in named volumes |
| Runtime restrictions | UID 10001, read-only root filesystem, all capabilities dropped, no privilege escalation verified |
| Secret exclusions | `.env` and `.venv/pyvenv.cfg` confirmed ignored by Git |

The final integration suite was rerun after the ingress networking correction and passed. The only test-file edit after the successful unit suite was Ruff's whitespace formatting. CI configuration was added, but a remote GitHub Actions run has not been executed because this is a newly initialized local repository.

## Tests exercise

- Mandatory dependency URLs; invalid schemes, ports, CIDRs, timeouts, pool bounds, and environments; redacted secret representations; immutable settings.
- Spoofed forwarded headers, explicit trusted proxy chains, IPv6, malformed/ambiguous headers, and unknown peers.
- Service lifecycle, live/ready contracts, independently failing dependencies, generated request IDs, safe 500 responses, development-only docs, body streaming, and log redaction.
- Concurrent bounded probes, timeout behavior, Redis acknowledgement, AMQP cleanup on success/failure, and resource shutdown.
- Independent service packaging; PostgreSQL migration/SQL checks; Redis write/read/delete; RabbitMQ publish/get/acknowledge; running-service HTTP checks.

## Remaining setup limitation

The local machine's **Windows Application Control policy blocks downloaded native extensions**:

- `coverage.tracer`: `DLL load failed ... An Application Control policy has blocked this file.`
- `sqlalchemy.util._collections_cy`: the same policy rejection during test collection.

The full host suite could not run, even outside the sandbox. Setting `COVERAGE_CORE=pytrace` bypassed the coverage tracer issue but did not resolve SQLAlchemy's extension rejection. No operating system policy or third-party package files were modified. The complete suite ran successfully in Linux containers. Use the documented container unit command on this machine, or resolve the native-extension policy separately if host-based testing is needed.

Docker access and package downloads initially required leaving the sandbox; both were available through the approved execution path. There is no remaining blocker for the Docker workflow. The development override was validated as configuration, not brought up. The repository has no remote or initial commit; Git was initialized on `main` and files are ready for review.

## Day 1 completion checklist

- [x] 1. Clean project structure with explicit application, package, migration, documentation, and test boundaries.
- [x] 2. Git initialized on `main`; professional ignore and line-ending rules; local secrets excluded.
- [x] 3. FastAPI administrative backend with application factory and lifespan management.
- [x] 4. Independently installable reusable Python package and pure ASGI request context middleware.
- [x] 5. Separate demonstration API, isolated by default; only harmless ping and health routes. Authentication/enforcement follow in later milestones.
- [x] 6. Authenticated PostgreSQL, Redis, and RabbitMQ configured and exercised.
- [x] 7. Multi-stage Dockerfile, non-root runtime, Compose health gates, migration job, private backend network, and persistent volumes.
- [x] 8. Validated environment settings, secret-free `.env.example`, safe random credential initialization.
- [x] 9. Async SQLAlchemy connectivity/session boundary and real Alembic baseline.
- [x] 10. Working application liveness and bounded dependency readiness probes.
- [x] 11. Structured JSON logging, correlation IDs, safe errors, and sensitive-data exclusions.
- [x] 12. Initial unit and real-service integration suites, with unit coverage gate.
- [x] 13. README with architecture, setup, development, testing, operational, and migration commands.
- [x] 14. Ruff lint/format configuration, hash-locked dependencies, and GitHub Actions workflow.
- [x] 15. Implemented functionality verified; environment limitations recorded without claiming host/remote-CI verification.

## Deferred deliberately

No unfinished threat detector, rate limiter, event consumer, audit-log model, JWT system, WebSocket endpoint, frontend, Prometheus/Grafana dashboard, or attack simulator is included. These are full-project requirements for subsequent milestones. In particular, the demo is network-isolated rather than authenticated, and no security enforcement should be inferred from its use of the reusable observability middleware.
