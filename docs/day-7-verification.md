# Phase 7 verification — November 14, 2026

## Delivered behavior

Phase 7 adds authenticated near-real-time hints to the existing platform. The worker still
commits each event, behavioral profile and assessment in one PostgreSQL transaction before
acknowledging RabbitMQ. A nonblocking, bounded post-commit offer feeds an asynchronous Redis
publisher. Each administrative API has one Pub/Sub subscriber and bounded WebSocket fan-out.
No subscriber competes with the worker queue. Duplicate event inserts produce no notification.
The event pipeline, deterministic enforcement, model safety boundaries and seven dashboard
pages remain intact. No migration, additional infrastructure service, paid service, external
AI API, Prometheus or Grafana was introduced. Nothing was committed or pushed.

Detailed design: [architecture](architecture.md#phase-7-committed-security-activity-streaming),
[HTTP/WebSocket contract](admin-api-contract.md#phase-7-real-time-contract), and the
[version 1 notification JSON schema](security-notification-v1.schema.json).

## Authentication and lifecycle

The existing in-memory bearer JWT authorizes `POST /api/admin/ws/v1/ticket`. The request must
pass the current PostgreSQL account/session checks, exact Origin validation and CSRF intent.
A random 256-bit ticket expires in 20 seconds. Redis stores its SHA-256 key and
account/session/role/Origin binding. `GET /api/admin/ws/v1/security` offers
`sentinel.security.v1` and a secret-bearing `sentinel.ticket.<ticket>` subprotocol; the server
selects only the fixed protocol. GETDEL makes redemption atomic and one-time. URLs cannot
contain query parameters. Refresh credentials are never used for the WebSocket handshake.

Both ADMIN and ANALYST can read. PostgreSQL authorization is rechecked every 15 seconds with
a three-second query deadline; inactive accounts, revoked/expired sessions, logout and role
changes close an open stream. The session's absolute expiry governs an established stream,
not the minting access token's expiry. New tickets always require current bearer authorization.
Client sign-out, including BroadcastChannel sign-out, closes the local stream immediately.
The initiating tab waits for server logout to finish before navigation, avoiding reload races.

Queues, payloads, connection caps, leases, heartbeat timeouts, cancellation and retry limits
are configurable/bounded. Defaults: 128 clients/process; 8/account and 4/session across
instances; 32 queued frames/client; 256 worker hints; 4096-byte notification limit; 512-byte
inbound WebSocket messages; heartbeat 20 seconds; idle threshold 60 seconds. Tickets are
limited to 12/session/minute and 24/account/minute; peer handshake limit is 120/minute.
Redis lease remnants expire after 60 seconds following a crash.

## Delivery and frontend reconciliation

Redis Pub/Sub notifications are **best-effort delivery hints**. They are not a durable log,
lossless stream or exactly-once delivery guarantee. PostgreSQL is authoritative. A worker
crash after commit, publication failure/timeout, a full buffer, no subscriber, a slow client,
network interruption or shutdown may lose a hint. These do not undo commits or weaken broker
acknowledgement/quarantine requirements. Existing pre-confirmation telemetry loss windows
remain the Phase 2 contract. PostgreSQL failure still follows bounded retry/quarantine/replay.

One activity envelope per event contains its stable event UUID, service, sanitized endpoint,
HTTP status/action, time, allowlisted rule/classification IDs and optional persisted assessment
reference/risk/severity. High/Critical activity uses the configured persisted severity.
Experimental ML evidence stays explicitly labeled and never causes blocking or increases risk.
Connection ready/heartbeat frames carry version and timestamp metadata. No raw IP, client
pseudonym, credential, cookie, request body/header/query value or unbounded DB object is sent.

React manages one connection per authenticated visible online tab, with cleanup and account
generation checks. Retries use exponential backoff, jitter, a 30-second cap and eight failures,
then manual retry. Confirmed authorization failure stops reconnection. Hidden/offline tabs
suspend; return/online events reacquire tickets. Every ready, including first connection,
reconciles mounted REST resources. Overview invalidations are batched at 1.5 seconds; existing
manual refresh and 60-second fallback polling remain. Totals are never independently incremented.

Events and Threat Intelligence show new-activity indicators and preserve filters, pagination,
custom windows and selected detail IDs. Relative windows advance on refresh/reconciliation.
The notification bell has actual connection status, timestamps, severity, event/assessment
links, unread counts, mark-read/clear controls and optional informational activity. Its
50-item history and read state are local tab memory. Matching alert categories are grouped
for 30 seconds; ordinary activity does not generate disruptive popups. Stable-ID deduplication
is bounded to 2048 browser IDs and 4096 server IDs. No server notification inbox or read-state
acknowledgement is claimed.

## Executed verification

All results below were executed locally against this working tree.

| Check | Result |
| --- | --- |
| Backend complete unit/integration suite | 359 passed (36 more than the supplied Phase 6 baseline) |
| Backend statement coverage | 92.33% (2,752 statements; 211 missed) |
| Frontend Vitest | 72 passed |
| Frontend statement / branch coverage | 74.60% / 65.88% |
| Real-backend Chromium tests | 7 passed |
| TypeScript, ESLint, Prettier, contract type check | Passed |
| Production Vite build | Passed; largest application entry 306.53 kB, gzip 97.55 kB |
| Ruff lint / formatting | Passed; 99 Python files formatted |
| Alembic schema check / exported contracts | Passed; no new upgrade operations, HTTP and notification contracts match |
| Standard Compose services | All six runtime services healthy; migration completed; event and dead-letter queues both 0 ready / 0 unacknowledged |

Backend tests cover accepted ADMIN/ANALYST upgrades, unauthenticated/invalid/expired/reused
credentials, bad Origin and query rejection, concurrent ticket redemption, ticket issuance
quotas, distributed connection caps/release, disabled accounts, direct role changes, expired
and revoked sessions, live logout, schema/privacy checks, post-commit ordering, duplicates,
publisher/DB/Redis failures, queue backpressure, heartbeat/idle handling and cleanup/shutdown.
Cross-instance tests create two independent administrative application lifespans sharing real
Redis and PostgreSQL, rather than two consumers of RabbitMQ. Original consumer retry,
acknowledgement uncertainty, quarantine, rollback and real broker redelivery tests remain.

Frontend tests cover ticket acquisition, no credential storage, connection/control frames,
bounded exponential reconnect, silent restarts, authorization failures, stale account callbacks,
visibility suspension, deduplication, grouped alerts, bounded history, read/clear controls,
REST fallback, batching, retained event filters/offset/detail and threat severity/ML labeling.
Browser tests exercise the built application against the real stack: authentication/refresh/
reload/logout, seven routes, roles, cross-tab session coordination, notification fan-out,
local history, network offline/online, admin restart and retained investigation context.
Existing Axe checks and overflow assertions pass at 1440, 1024, 768, 390 and 320 pixels.

A browser run caught and fixed an initiating-tab logout/reload race. The API restart check
waits for authoritative detail content rather than capturing a transient loading dialog.
The existing in-process distributed protection atomicity test uses a one-second test-only
Redis deadline under instrumentation; the production 200 ms default and separate failure-policy
checks remain unchanged. Local Windows native-module execution was blocked by Application
Control, so backend tests were executed in the existing Linux test image.

## Real worker streaming and duplicate evidence

`scripts/verify_realtime.py` creates temporary ADMIN/ANALYST accounts, opens three actual
network WebSockets (two ADMIN, one ANALYST), sends 43 owned demo requests (five invalid demo
logins, eight limited-route requests and thirty pings), waits for real worker persistence,
checks the authenticated event/detail APIs, republishes an actual persisted broker event and
checks one assessment/frame for that UUID. Accounts and sessions are removed in `finally`;
real monitored traffic remains auditable. No artificial score or fabricated attack is inserted.

An initial measured run delivered 47 unique notifications per client, including 35 High-risk
notifications. The extra records were actual independent security decisions. All three clients
received matching IDs. Duplicate publication left one assessment and one visible frame.
A fresh ticket/reconnect plus authoritative event read succeeded; server logout closed the
ANALYST socket with 4401. Passwords, JWTs and the controlled sensitive query marker were absent
from notification JSON. The browser verified empty localStorage/sessionStorage and the
existing HttpOnly/SameSite refresh-cookie behavior. A recent application-log scan also found
no ticket-subprotocol credentials, bearer strings, access/refresh-token fields or the controlled
sensitive-query marker; matching values were never printed by the scan.

## Failure recovery

Executed sequentially with `scripts/verify_realtime_failures.py`; all temporary permissions
and stopped services were restored in `finally`:

| Failure | Observed behavior |
| --- | --- |
| Redis `PUBLISH` denied while other Redis commands remain enabled | Eight controlled HTTP events persisted; real rate restrictions still returned 429. Optional notification failures did not break the worker. |
| Redis service stopped | The existing managed-policy loader failed closed with 503 on the owned login route; recovery persisted a new request. |
| RabbitMQ stopped | Redis restrictions still returned 429; recovery persisted a fresh request. Existing pre-confirmation loss/retry semantics apply to outage traffic. |
| PostgreSQL stopped with worker held | Five requests were accepted/queued by the existing broker path; after PostgreSQL and worker recovery, all five HTTP records reconciled. |
| Worker restart | Queued records drained and assessments persisted after restart. |
| Admin API restart | Browser reacquired a fresh ticket, reconnected and refetched REST while retaining the selected event and service filter. |
| Browser offline/online | Connected status changed, existing metrics remained visible, then ready triggered reconciliation. |
| Slow subscriber / full queue | Unit checks close the affected client with 1013 while another client continues. |

The PostgreSQL outage run deliberately held the worker to demonstrate queued durability;
live-worker storage failure, retry exhaustion and quarantine are separately tested by the
existing consumer/transaction tests. It does not claim a lossless notification during DB outage.
Denying only `PUBLISH` demonstrates transport isolation; a total Redis outage necessarily also
affects the pre-existing Redis enforcement dependency and follows its configured failure policy.

## Measured environment and performance

Windows host, Docker Desktop Linux containers, Python 3.11.14 in images, host Python 3.11.9,
Node 24.20.0, current pinned dependencies, Chromium, standard internal Compose networking.
Docker reports 8,106,291,200 bytes (approximately 7.55 GiB) memory. No extra service port was
published. Only admin API port 8000 is host-bound; the dashboard uses the Vite port 5173 proxy.

Initial three-client run: 141 frame receipts, sampled post-commit timestamp to receipt
**44.680 ms median, 0.977 ms minimum, 119.100 ms maximum**. Fresh ticket, reconnect and
one authoritative REST read: **24.332 ms**. `committed_at` is sampled after transaction
completion, not a PostgreSQL WAL commit timestamp. Same-machine container clocks are assumed.
These are actual local measurements, not production throughput/SLA evidence.

An idle/recovered snapshot reported: admin 72.04 MiB / 0.27% CPU; worker 57.88 MiB / 0%;
demo 82.37 MiB / 0.24%; PostgreSQL 29.55 MiB / 0.06%; Redis 5.105 MiB / 0.41%; RabbitMQ
99.26 MiB / 0.25%. Docker percentages are snapshots, not long-term utilization or a capacity
forecast. A final sampled run and fan-out receipt spread are recorded below.

Final sampled run (`scripts/benchmark_realtime.py`):

- Three connected network clients; 43 owned demo requests; 47 unique event hints/client.
- 37 hints carried High/Critical persisted severity; all clients received matching IDs.
- 141 frame receipts: 45.399 ms median, 1.061 ms minimum, 90.530 ms maximum post-commit-to-receipt.
- Per-event receipt spread across three clients (47 samples): 0.089 ms median, 0.406 ms maximum.
- Fresh ticket/reconnect plus REST read: 34.008 ms. Server logout closed with 4401.
- Duplicate broker publication still produced one assessment and one visible frame.

Nine Docker resource snapshots per service during the verification, including setup and logout:

| Service | Maximum sampled CPU | Maximum sampled container memory |
| --- | ---: | ---: |
| admin-api | 23.58% | 135.900 MiB |
| demo-api | 22.05% | 99.050 MiB |
| event-worker | 0.44% | 58.930 MiB |
| postgres | 5.59% | 40.420 MiB |
| rabbitmq | 1.07% | 100.700 MiB |
| redis | 3.92% | 6.172 MiB |

Sampling can miss short CPU spikes; these maxima are sampled observations, not continuous
peak measurements. The workload includes authentication memory costs. Raw local output is in
`.artifacts/day7-benchmark.json` (ignored by Git). Repeated runs use real existing behavioral
state and time windows, so severity counts and timings can differ. No production-scale
capacity, endurance, WAN latency or delivery SLA is inferred.

## Exact local reproduction

Use the existing private `.env` and administrative account; do not regenerate populated keys.
For first-time setup only, follow the README environment/demo/bootstrap commands. Standard
local stack (no `compose.dev.yaml` or infrastructure host bindings):

```powershell
docker compose up --build -d --wait --wait-timeout 180
cd apps/dashboard
npm.cmd ci
npm.cmd run dev
```

Open **http://localhost:5173**. Local HTTP requires the existing explicit development
Origin/cookie settings; production requires same-site HTTPS/WSS and Secure cookies.

From the repository root, run backend commands sequentially:

```powershell
docker compose --profile test build tests
docker compose --profile test run --rm tests
docker compose exec -T admin-api alembic check
docker compose --profile test run --rm tests python scripts/verify_admin.py
docker compose --profile test run --rm tests python scripts/verify_realtime.py
# This intentionally interrupts the local services; run separately from all other tests:
.\.venv\Scripts\python.exe scripts/verify_realtime_failures.py
# Three-client verification plus sampled Docker resource data:
.\.venv\Scripts\python.exe scripts/benchmark_realtime.py
```

Contract/style checks on a Windows host whose native modules are restricted:

```powershell
docker compose --profile test run --rm --no-deps -v "${PWD}:/workspace:ro" -w /workspace tests python scripts/export_admin_openapi.py --check
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
```

Frontend checks from `apps/dashboard` (Playwright starts Vite preview when needed):

```powershell
npm.cmd run verify
npx.cmd playwright install chromium
npm.cmd run test:integration
```

To regenerate contracts after an intentional API/schema change, mount the workspace writable
for `scripts/export_admin_openapi.py` without `--check`, then run `npm.cmd run api:generate`.
CI now runs the real-service streaming verifier in addition to existing checks. Hosted GitHub
Actions has not been executed for this uncommitted working tree.

## Remaining limits

Best-effort hints have the documented loss windows; historical events are available through
REST. Local notification history is neither durable nor a server inbox. Authorization changes
are observed within the documented polling/deadline bound, not instantaneously across servers.
An opaque pre-upgrade browser failure cannot distinguish revoked credentials from network
failure; retries remain bounded. Redis leases can temporarily occupy capacity after a crash.
Multi-instance authorization requires consistent settings/shared signing keys and Redis.
The test proves two independent app instances and three network clients, not production scale
or Redis/PostgreSQL/RabbitMQ high availability. Production HTTPS termination and proxy logging
must be configured by deployment. Non-Chromium browsers and a full manual accessibility audit
are outside the executed evidence. No production alert-delivery SLA is claimed.

## Files created and modified

- Modified: [.env.example](../.env.example)
- Modified: [.github/workflows/ci.yml](../.github/workflows/ci.yml)
- Modified: [Dockerfile](../Dockerfile)
- Modified: [README.md](../README.md)
- Modified: [apps/admin-api/pyproject.toml](../apps/admin-api/pyproject.toml)
- Modified: [apps/admin-api/src/sentinel_api/main.py](../apps/admin-api/src/sentinel_api/main.py)
- Created: [apps/admin-api/src/sentinel_api/realtime.py](../apps/admin-api/src/sentinel_api/realtime.py)
- Modified: [apps/admin-api/src/sentinel_api/settings.py](../apps/admin-api/src/sentinel_api/settings.py)
- Created: [apps/dashboard/e2e/realtime.spec.ts](../apps/dashboard/e2e/realtime.spec.ts)
- Modified: [apps/dashboard/src/api/generated.ts](../apps/dashboard/src/api/generated.ts)
- Modified: [apps/dashboard/src/auth/AuthProvider.tsx](../apps/dashboard/src/auth/AuthProvider.tsx)
- Modified: [apps/dashboard/src/auth/session.ts](../apps/dashboard/src/auth/session.ts)
- Modified: [apps/dashboard/src/layouts/AppLayout.tsx](../apps/dashboard/src/layouts/AppLayout.tsx)
- Modified: [apps/dashboard/src/pages/EventsPage.tsx](../apps/dashboard/src/pages/EventsPage.tsx)
- Modified: [apps/dashboard/src/pages/OverviewPage.tsx](../apps/dashboard/src/pages/OverviewPage.tsx)
- Modified: [apps/dashboard/src/pages/ThreatsPage.tsx](../apps/dashboard/src/pages/ThreatsPage.tsx)
- Created: [apps/dashboard/src/realtime/LiveActivity.tsx](../apps/dashboard/src/realtime/LiveActivity.tsx)
- Created: [apps/dashboard/src/realtime/NotificationCenter.tsx](../apps/dashboard/src/realtime/NotificationCenter.tsx)
- Created: [apps/dashboard/src/realtime/RealtimeProvider.tsx](../apps/dashboard/src/realtime/RealtimeProvider.tsx)
- Created: [apps/dashboard/src/realtime/stream.test.ts](../apps/dashboard/src/realtime/stream.test.ts)
- Created: [apps/dashboard/src/realtime/stream.ts](../apps/dashboard/src/realtime/stream.ts)
- Created: [apps/dashboard/src/realtime/types.ts](../apps/dashboard/src/realtime/types.ts)
- Modified: [apps/dashboard/src/styles/components.css](../apps/dashboard/src/styles/components.css)
- Created: [apps/dashboard/src/tests/live.ts](../apps/dashboard/src/tests/live.ts)
- Modified: [apps/dashboard/src/tests/pages.test.tsx](../apps/dashboard/src/tests/pages.test.tsx)
- Modified: [apps/dashboard/src/utils/format.ts](../apps/dashboard/src/utils/format.ts)
- Modified: [apps/dashboard/vite.config.ts](../apps/dashboard/vite.config.ts)
- Modified: [apps/event-worker/src/sentinel_worker/runtime.py](../apps/event-worker/src/sentinel_worker/runtime.py)
- Modified: [compose.yaml](../compose.yaml)
- Modified: [docs/admin-api-contract.md](../docs/admin-api-contract.md)
- Modified: [docs/admin-openapi.json](../docs/admin-openapi.json)
- Modified: [docs/architecture.md](../docs/architecture.md)
- Created: [docs/day-7-verification.md](../docs/day-7-verification.md)
- Created: [docs/security-notification-v1.schema.json](../docs/security-notification-v1.schema.json)
- Modified: [packages/sentinel-security/src/sentinel_security/analysis_storage.py](../packages/sentinel-security/src/sentinel_security/analysis_storage.py)
- Modified: [packages/sentinel-security/src/sentinel_security/config.py](../packages/sentinel-security/src/sentinel_security/config.py)
- Created: [packages/sentinel-security/src/sentinel_security/realtime.py](../packages/sentinel-security/src/sentinel_security/realtime.py)
- Modified: [packages/sentinel-security/src/sentinel_security/storage.py](../packages/sentinel-security/src/sentinel_security/storage.py)
- Modified: [requirements-dev.txt](../requirements-dev.txt)
- Modified: [requirements.in](../requirements.in)
- Modified: [requirements.txt](../requirements.txt)
- Created: [scripts/benchmark_realtime.py](../scripts/benchmark_realtime.py)
- Modified: [scripts/export_admin_openapi.py](../scripts/export_admin_openapi.py)
- Created: [scripts/verify_realtime.py](../scripts/verify_realtime.py)
- Created: [scripts/verify_realtime_failures.py](../scripts/verify_realtime_failures.py)
- Modified: [tests/conftest.py](../tests/conftest.py)
- Modified: [tests/integration/test_distributed_protection.py](../tests/integration/test_distributed_protection.py)
- Created: [tests/integration/test_realtime_pipeline.py](../tests/integration/test_realtime_pipeline.py)
- Created: [tests/unit/test_realtime.py](../tests/unit/test_realtime.py)
