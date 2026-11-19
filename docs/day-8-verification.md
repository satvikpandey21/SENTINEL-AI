# Phase 8 verification — November 19, 2026

## Outcome and recovered workspace

Phase 8 adds private, authenticated operational observability to the existing Phase 1–7
platform. Prometheus, native RabbitMQ metrics, five provisioned Grafana dashboards and nine
operational rules run through the standard Compose workflow. The original Phase 8 Master
Prompt supplied during this session was checked against the delivered behavior. No existing
PostgreSQL/Redis/RabbitMQ volume was deleted, no schema migration was added, and nothing was
committed or pushed. HEAD remains `8028b73`.

The interrupted implementation was resumed, not recreated:

| State on arrival | Inspection finding | Completion in this session |
| --- | --- | --- |
| Existing Phase 1–7 working tree | Extensive tracked changes plus untracked ticket-based realtime backend/frontend, tests, scripts and Phase 7 documentation | Preserved; existing security and browser regressions executed |
| Metrics instrumentation | Per-process registries and wiring already present in APIs, middleware, security engine, publisher, persistence, analysis, worker and WebSockets | Retained; corrected duplicate elapsed-clock read and missing actual ML artifact-status enum values |
| Private collection and Docker | Private ASGI listener, token files, bootstrap identity, native broker plugin, pinned images/networks/volumes/caps already written | Started against existing volumes; confirmed authentication, private ports, health, native queue scrape and least-privilege identity |
| Prometheus/Grafana files | Scrape config, five dashboard JSON files, data source/provider and nine rules present | Validated live; corrected dashboard title placeholders, readable status sizing/colors, context clipping and current-value stat queries |
| Tests and delivery | Metrics unit tests existed; alert fixture covered only the admin-down rule; CI lacked existing-workspace secret initialization | Expanded lifecycle/privacy/failure tests; all-rule pending/firing/recovery/healthy fixtures; real-stack and Grafana browser checks; CI initialization/validation |
| Missing evidence | No Phase 8 verification report, operational inventory, interruption acceptance, controlled overhead comparison or executed deployment evidence | Added and executed; recorded below |

Two deployment problems were found through execution. Observability secrets were missing
from `.dockerignore`; the directory is now excluded. Windows text-mode writes produced CRLF
secrets: Grafana's entrypoint retained the trailing CR, so the generated login was rejected.
The initializer now writes/normalizes LF in place without rotating secret values. The newly
created Grafana account was synchronized to its preserved password using the supported CLI
stdin flow. A regression test covers normalization. Grafana plugin preinstallation/updates
were disabled, its Go memory target was bounded, and optional unused preinstalled apps were
disabled. Its persistent database and existing backend credentials were preserved.

## Architecture, endpoints and privacy

Detailed [architecture](architecture.md#phase-8-private-operational-observability) and the
complete [metrics inventory/runbook](observability.md) document the final implementation.

| Interface | Access |
| --- | --- |
| React dashboard | `http://localhost:5173`; unchanged seven-page security console |
| Admin API | `http://localhost:8000`; existing JWT/session/role checks |
| Grafana | `http://localhost:3000`; separate `sentinel-ops` account, password in `.secrets/observability/grafana_password` |
| Prometheus | `http://prometheus:9090` inside Docker; no host binding; use Grafana Explore |
| App scrapes | `http://admin-api:9100/metrics`, `http://demo-api:9100/metrics`, `http://event-worker:9100/metrics`; private, independent bearer token |
| Broker scrapes | `http://rabbitmq:15692/metrics` and `/metrics/detailed`; native basic-auth monitoring identity |

Only 127.0.0.1:8000 and 127.0.0.1:3000 are published by standard Compose. Resolved-config
assertions confirmed that PostgreSQL, Redis, RabbitMQ, Prometheus, demo and worker have no
host bindings. `rabbitmqctl list_user_permissions sentinel-metrics` returned no vhost
permissions. The monitoring account cannot publish or consume AMQP messages.

All three private listeners reject missing, wrong and duplicated authorization headers;
RabbitMQ rejects unauthenticated scraping. Public API `/metrics` returns 404. Grafana's
unauthenticated search returns 401. The live exported payloads were checked for the metrics
and Grafana passwords, temporary account password, JWT, WebSocket ticket, owned request IDs
and a unique raw-path/query/cookie canary: none appeared. Label keys exclude IPs, HMAC client
identifiers, account/session/request/event IDs and sensitive features. A unit test sends
1,000 distinct raw routes/methods/unknown labels and confirms bounded output below 300 samples.
Repeated registries and listener startup/shutdown are tested. Health/scrape requests do not
inflate application HTTP metrics. No new authentication bypass or metrics access is added
to public API routers.

Scrapes serialize registry/process state; they do not query PostgreSQL. Separate bounded
probes run every 30 seconds. Application scrapes run every 15 seconds; broker/self scrapes
every 30 seconds. Fixed enum values and at most 64 registered route templates bound labels.
Counters reset per process restart. Native queue observation does not consume messages.
Transaction/acknowledgement and bounded-queue behavior remain unchanged.

## Executed automated verification

| Check | Executed result |
| --- | --- |
| Complete backend unit + real integration suite | **380 passed**, 57.43 seconds in the final packaged run (first complete run: 59.91 seconds) |
| Backend statement coverage | **91.56%**, 3,139 statements / 265 missed; required 85% passed |
| Focused backend unit regression | **319 passed** |
| Frontend Vitest | **72 passed** across seven files |
| Frontend coverage | **74.60% statements**, **65.88% branches**, 75.58% lines |
| Existing real-backend Chromium regression | **7 passed**, 1.3 minutes, including authenticated live notifications, cross-tab/logout, restart/reconnect, policies, analyst restrictions and accessibility/navigation |
| Additional Grafana Chromium check | **1 passed**; rendered panels on all five provisioned dashboards; final data-loaded readable-layout rerun passed in 16.6 seconds |
| Frontend contract, Prettier, ESLint, TypeScript and production build | Passed; lint/type/format repeated after adding the Grafana browser check |
| Backend Ruff lint/format using the CI Linux image | Passed; formatting and lint checks clean |
| Administrative OpenAPI and versioned notification contract check | Passed; no contract drift |
| Alembic schema check | Passed: no new upgrade operations |
| Compose resolved configuration and build | Passed; hash-locked dependencies and existing pinned service images |
| Prometheus configuration and rule validation | Passed; six scrape targets and nine rules |
| Alert-rule behavior | All nine rules tested pending, firing and recovered, plus healthy/low-volume suppression |
| Grafana API provisioning | Five dashboards, datasource health `OK`, **47 actual panel expressions** successfully evaluated by Prometheus |

The native Windows `.venv` test attempt could not collect the suite: Windows Application
Control blocked the installed SQLAlchemy extension, and that older environment lacked
`prometheus_client`. Canonical Docker tests above used the hash-locked Linux environment.
An initial sandboxed browser attempt lacked Docker access and was replaced by the successful
run with local-engine access. These environment failures were not counted as successful
verification. The first Docker unit run exposed one actual regression (an extra clock read),
which was fixed before the passing runs. Earlier acceptance failures also exposed the CRLF
Grafana password problem and an acceptance assertion that incorrectly expected `rate_limit`
when the existing default policy actually emits `temporary_block`; enforcement was preserved.

## Real-service correctness evidence

All six Prometheus targets reported `up`: admin-api:9100, demo-api:9100, event-worker:9100,
native rabbitmq:15692 aggregate and queue jobs, and Prometheus self-scrape. The native ready
queue series was present. All nine loaded rules reported evaluation health `ok`. The final rule inspection reported
all nine **inactive**, with no evaluation errors, and all **eight long-running services healthy**.
The migration and broker-monitoring initialization jobs completed successfully (exit 0).

One successful standalone acceptance run recorded:

- Three real `/api/demo/ping` requests: exactly **+3 HTTP requests** and **+3 latency histogram
  observations** for the registered route; Prometheus subsequently contained the new count.
- Twelve requests to the existing limited endpoint: **seven 429 responses** and **+7
  `temporary_block` decisions**. The default policy's action is a temporary restriction;
  configurable `rate_limit` counters are separate.
- Three owned request records confirmed committed in PostgreSQL. Worker delivery, persistence,
  analysis-operation, analysis-duration and committed-assessment metrics increased.
- An actual ANALYST ticket-authenticated network socket changed the active gauge by **+1**,
  delivered a committed-event notification, then returned to baseline after closure. A missing
  ticket increased rejection metrics; connection-lifetime observations increased.
- Exported application samples at that point: admin **187**, demo **203**, worker **174**,
  comfortably below the application scrape sample limit of 20,000. The final standalone run
  observed admin **239**, demo **253**, worker **210** samples and Prometheus HTTP count 126.
  These are observed counts,
  not a promised maximum under every supported route/method combination.

Prometheus/Grafana interruption was tested by stopping both services. Both API readiness
responses stayed **200**, three additional owned requests committed, and the existing
network acceptance exercised **three ADMIN/ANALYST clients**, **43 controlled requests** and
**47 unique notifications**. Duplicate broker-delivery suppression and privacy checks passed;
server logout closed the socket with **4401**. Median post-commit receipt was **2.026 ms**
(141 observed receipts). Both observability services recovered in `finally`.

The final `verify_admin.py` network acceptance also passed: unauthenticated events returned
401; ADMIN login returned 200; ANALYST policy mutation returned 403; stored event/assessment
and SQL-matched analytics agreed; a reviewed live policy returned 200 then 429; audit actions
were present; logout returned 204 and the revoked access token returned 401. Temporary
verification accounts were removed and policy state restored.

The inherited dependency-failure drill was also executed sequentially:

- Denied only Redis `PUBLISH`: eight owned HTTP events committed and restrictions still
  returned 429; the permission was restored.
- Redis outage: managed-policy protection failed closed with 503; recovery succeeded.
- RabbitMQ outage: independent Redis restrictions continued returning 429; recovery succeeded.
- PostgreSQL plus worker interruption: five confirmed queued requests reconciled after recovery.
- New owned requests persisted after every recovery; the script restored stopped services.

These checks preserve commit-before-acknowledgement, idempotent insert/assessment behavior,
existing dead-letter guarantees, safe ML boundaries and ticket/session/Origin authentication.
Notification hints remain best effort and REST remains authoritative.

## Resource and performance observations

The hard limits resolve to **512 MiB and one CPU each** for Prometheus/Grafana, plus
**128 MiB / 0.25 CPU** for one-shot broker provisioning. Grafana uses `GOMEMLIMIT=320MiB`.
Prometheus keeps metric blocks for **7 days or 1 GiB**, with 4 concurrent queries, 10-second
query timeout, 500,000 maximum query samples and 32 HTTP connections. WAL/head overhead is
additional; this is not a disk quota. No heavyweight DB exporter or Alertmanager was added.

An idle/verification snapshot before the final fault drill observed Prometheus **93.64 MiB**,
Grafana **259.1 MiB**, admin **75.14 MiB**, demo **71.37 MiB**, worker **64.89 MiB**, RabbitMQ
**101.9 MiB**, PostgreSQL **70.96 MiB**, Redis **13.15 MiB** (about **750 MiB** total). Snapshot
CPU values ranged 0.04–4.44% per container. Grafana's earlier startup/plugin activity reached
491.2 MiB before the plugin/memory adjustments; no OOM was observed. These snapshots are not
peak-load guarantees, but leave substantial room within the reported 7.55 GiB Docker budget.
Final snapshot after recovery and the packaged verification: Grafana **272.3 MiB / 1.52% CPU**,
Prometheus **37.57 MiB / 0.45%**, worker **64.63 MiB / 0.42%**, demo **103 MiB / 0.25%**,
admin **73.8 MiB / 0.31%**, RabbitMQ **108.7 MiB / 0.23%**, PostgreSQL **47.88 MiB / 0.21%**,
Redis **5.332 MiB / 0.35%**: about **713 MiB** for all eight running services. Inspection
confirmed both observability containers had `OOMKilled=false`, restart count zero, the
512 MiB / 1 CPU hard caps and 10 MiB ? 3-file log rotation.

The final controlled benchmark ran after browser work completed, in off/on/on/off order,
with 200 real loopback HTTP requests and 100 real PostgreSQL analysis commits per trial,
plus warm-ups. APIs used real Redis enforcement and an AMQP publisher. Commit throughput
measures the analysis/persistence stage, excluding broker consumption and network ack cost;
the benchmark listeners are not extra configured Prometheus scrape targets.

| Instrumentation | HTTP median ms, trials | HTTP p95 ms, trials | HTTP requests/s, trials | Analysis commits/s, trials |
| --- | --- | --- | --- | --- |
| Disabled | 2.673 / 2.401 | 4.224 / 3.508 | 355.65 / 399.78 | 104.29 / 74.69 |
| Enabled | 2.650 / 2.426 | 3.787 / 3.394 | 363.16 / 402.29 | 82.82 / 93.74 |

Median HTTP latency changed **+0.04%**, HTTP throughput **+1.33%**, and analysis commit
throughput **−1.35%**. Variability is larger than these differences. This small local sequential
comparison shows no measured material latency regression; it does not establish production
overhead, maximum sustained throughput or an instrumentation-driven speed improvement.

## File inventory

Existing Phase 8 work retained includes `metrics.py`, private runtime wiring in
`application.py`, `config.py`, `infrastructure.py`, `middleware.py`, `protection.py`,
`management.py`, `publisher.py`, `storage.py`, `analysis_storage.py`, worker runtime/consumer,
admin/reusable realtime modules, `observability_bootstrap.py`, RabbitMQ plugin/config files,
Compose/Docker/dependency changes, and all provisioning/scrape/dashboard files.

This resume added:

- `docs/observability.md` and this `docs/day-8-verification.md`.
- `scripts/verify_observability.py`, `scripts/verify_observability_failures.py`,
  `scripts/benchmark_observability.py`.
- `tests/integration/test_observability.py` and
  `apps/dashboard/e2e/observability.spec.ts`.
- Empty optional Grafana provisioning directory placeholders.

This resume modified existing work in:

- `.dockerignore`, `.env.example`, `.github/workflows/ci.yml`, `compose.yaml`, `README.md`,
  `docs/architecture.md`.
- `scripts/init_observability.py`, `tests/unit/test_metrics.py`, shared `metrics.py` and
  `middleware.py`.
- All five Grafana dashboard JSON files, Prometheus `alerts.yml` and `alerts.test.yml`.

Generated secrets remain ignored. Existing Phase 7 untracked files were kept; the React
product implementation was not redesigned or replaced. CI now initializes observability,
validates Prometheus/rule behavior, verifies live provisioning and runs the additional
Grafana browser check alongside the existing browser suite.

## Reproduction

From the repository root, with the existing `.env`:

```powershell
python scripts/init_observability.py
docker compose up --build -d --wait --wait-timeout 180
# Optional only if no Sentinel admin has been provisioned:
docker compose exec admin-api python -m sentinel_api.bootstrap --username your-admin-name
```

In another terminal:

```powershell
cd apps/dashboard
npm.cmd run dev
```

Open React at http://localhost:5173 and Grafana at http://localhost:3000. Read the generated
Grafana password locally from `.secrets/observability/grafana_password`. Prometheus remains
internal at http://prometheus:9090; use Grafana Explore. No database port binding or
`compose.dev.yaml` is required. No existing frontend needs to be stopped.

To reproduce verification sequentially from the root:

```powershell
docker compose --profile test build tests
docker compose exec -T prometheus promtool check config /etc/prometheus/prometheus.yml
docker compose exec -T -w /etc/prometheus prometheus promtool test rules alerts.test.yml
docker compose exec -T admin-api alembic check
docker compose --profile test run --rm tests
docker compose --profile test run --rm tests python scripts/verify_admin.py
docker compose --profile test run --rm tests python scripts/verify_realtime.py
docker compose --profile test run --rm tests python scripts/verify_observability.py
docker compose --profile test run --rm tests python scripts/benchmark_observability.py
python scripts/verify_observability_failures.py
python scripts/verify_realtime_failures.py
cd apps/dashboard
npm.cmd run verify
npm.cmd run test:integration
```

Fresh checkouts first require the existing README `.env`/demo/admin-key initialization and
`npm.cmd ci`; `npx.cmd playwright install chromium` installs the browser if absent. Do not run
policy-changing browser/backend checks concurrently. Fault scripts are reversible local
acceptance exercises; do not use them against a production deployment.

## Known limits

This is a single-host deployment using bearer/basic authentication over private Docker HTTP
networks; cross-host TLS and metrics-volume encryption are not implemented. Docker/host
access remains privileged. Grafana admin accounts are separate from Sentinel roles.
Prometheus evaluates rules but does not deliver external notifications. Dependency availability
is a bounded observation, not a full infrastructure exporter. A fresh/restarted collector
has missing or reset samples, and low-traffic histogram/rate panels need observations.

Use one Uvicorn worker per container. Scaling requires distinct process scrape targets;
shared multiprocess aggregation is not implemented. Browser reconnect identity is not
invented from new server attempts. Socket sends are not client acknowledgements. ML is
experimental and disabled by default in the deployed worker; enabled-model inference paths
are covered by existing model/backend tests, not claimed as validated live attack detection.

Verification retains owned audit/demo/benchmark events and assessments, while temporary
accounts/sessions and changed policies are cleaned up/restored. Baseline local data was not
purged. If an operator intentionally changes the persisted Grafana password, update the
private verification credential separately; ordinary initialization never resets it. The
runbook includes recovery for the interrupted implementation's CRLF-specific initial login.
Native Windows Python remains subject to the observed Application Control restriction;
Docker is the verified backend path.
