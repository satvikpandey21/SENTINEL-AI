# Phase 8 observability operations

Start from the existing repository root and keep the existing `.env` and data volumes:

```powershell
python scripts/init_observability.py
docker compose up --build -d --wait --wait-timeout 180
```

For a fresh checkout only, first follow the README environment, demo-authentication and
administrative-account initialization steps. The observability initializer is idempotent:
it retains existing generated secret values and normalizes secret files to LF on Windows.
It refreshes only the private copy of the existing RabbitMQ management password.

Grafana is **http://localhost:3000**, username **sentinel-ops**. Its generated password is in
`.secrets/observability/grafana_password`; read that file locally to sign in. Grafana's own
accounts are independent of Sentinel ADMIN/ANALYST accounts. Anonymous access, account
sign-up, organization creation, telemetry, plugin preinstallation/automatic updates and
plugin administration are disabled. Grafana Live is disabled; Sentinel's separate secure
WebSocket implementation is unaffected. A Go runtime memory target helps keep Grafana
within its container limit. Use HTTPS and `SENTINEL_GRAFANA_COOKIE_SECURE=true` if placing
Grafana behind a trusted production proxy. Never publish it on an unrestricted host binding.

Prometheus is **http://prometheus:9090 inside Docker only**, with no host port. Use Grafana
Explore with the provisioned `Sentinel Prometheus` data source. The standard workflow does
not use `compose.dev.yaml`, and exposes no PostgreSQL, Redis or RabbitMQ protocol/management
ports to Windows. Keep React on http://localhost:5173 using `npm.cmd run dev` in
`apps/dashboard`; its seven pages, authentication and live reconciliation are unchanged.

## Architecture and access

Each API and the event worker owns a separate `CollectorRegistry` and an optional private
ASGI listener on **9100**. Public API port 8000 has no `/metrics` export. The private endpoint
requires exactly one `Authorization: Bearer` header with the independent 256-bit metrics
secret. Duplicate/missing/incorrect headers are rejected. Secrets are mounted read-only and
excluded from Git and Docker build context. Listener concurrency is 8, keep-alive 2 seconds,
and incomplete HTTP headers are limited to 8192 bytes. Metrics are enabled by default in
Compose and disabled by default for standalone Python application construction/tests.

The internal `telemetry` network connects Prometheus, application processes and RabbitMQ.
The internal `observability` network connects Prometheus and Grafana. Grafana has the
loopback ingress binding and cannot reach the backend/telemetry networks directly.
Application authentication, enforcement and event guarantees still use their existing
paths; successful metrics authentication grants no administrative API access.

`rabbitmq_prometheus` provides native authenticated metrics on 15692. A short one-shot job
idempotently creates `sentinel-metrics` with the `monitoring` tag and **no AMQP vhost
permissions**. It uses separate management and monitoring password files. The aggregate
scrape removes object labels. The detailed scrape observes ready/unacknowledged message
counts for only `sentinel.security.events.v1` and its `.dead` queue. No messages are consumed
to observe queue depth. The existing message caps, durable queues, publication confirms,
commit-before-acknowledgement and confirmed-quarantine-before-acknowledgement remain intact.

Scrapes only serialize in-memory metric state (and process information). Dependency probes
run separately every 30 seconds with the existing bounded PostgreSQL/Redis/AMQP health
checks; policy probes read the effective policy with the existing timeout. No scrape runs a
DB query. Dependency timestamps show observation age, not an assurance about the future.

## Metrics inventory

Every application family starts with `sentinel_`, uses a constant process `service` label,
and is exported only by its owning component where applicable. Counters have `_total`;
histograms expose `_bucket`, `_count` and `_sum`. Prometheus client creation timestamps
may also appear. The inventory below omits those conventional suffixes.

| Area | Families |
| --- | --- |
| HTTP | `http_requests`, `http_status`, `http_server_errors`, `http_incomplete`, `http_duration_seconds` |
| Security | `security_actions`, `security_decisions`, `security_authentication`, `enforcement_errors`, `enforcement_redis_duration_seconds`, `policy_operations` |
| Publisher | `publisher_accepted`, `publisher_published`, `publisher_dropped`, `publisher_failures`, `publisher_retries`, `publisher_buffer`, `publisher_connected` |
| Worker | `worker_deliveries`, `worker_storage_errors`, `worker_reconnects`, `worker_connected`, `worker_ready`, `worker_duration_seconds`, `dead_letter_published` |
| Persistence | `persistence_events`, `persistence_errors`, `persistence_duration_seconds` |
| Analysis | `assessments_committed`, `analysis_operations`, `analysis_duration_seconds`, `statistical_results`, `ml_results`, `ml_enabled`, `ml_model_available`, `ml_inference_duration_seconds` |
| WebSocket | `ws_attempts`, `ws_connections`, `ws_active`, `ws_revalidation_failures`, `ws_slow_consumers`, `ws_lifetime_seconds` |
| Notification | `notification_published`, `notification_publish_errors`, `notification_buffer`, `notification_enqueued`, `notification_sent`, `notification_dropped`, `notification_duplicates`, `notification_subscription_up`, `notification_subscription_errors`, `notification_fanout_duration_seconds` |
| Dependencies | `dependency_up`, `dependency_checked_timestamp_seconds`, `dependency_probe_duration_seconds` |
| Instrumentation/process | `build_info`, standard `process_*` collectors where supported |
| Broker | Native `rabbitmq_*` aggregate families and allowlisted `rabbitmq_detailed_queue_messages_ready` / `rabbitmq_detailed_queue_messages_unacked` |
| Scraper | Standard Prometheus self metrics and `up` / scrape observations |

HTTP latency covers request handling through response completion, including enforcement;
incomplete requests have a separate counter. Health paths and `/metrics` are excluded from
application traffic metrics. Registered route templates are captured at application startup
(up to 64); unmatched/unrouted or rejected-before-routing requests use `unmatched`. Methods
are a fixed allowlist plus `OTHER`; unusual HTTP status codes collapse to `other` in the
exact-code counter but retain their status class. Actions, outcomes, reasons, dependency
names and ML/statistical statuses use fixed allowlists. No raw path, query, IP, HMAC client
identifier, account/session/request/event ID, credential, exception text, feature vector or
request body is used as a label. Client-controlled event `service` fields do not become the
process `service` label. The worker and socket queues remain bounded independently of metrics.

Counters describe their actual stage. Publisher accepted is an in-memory offer; published
means broker confirmation. Worker outcomes follow completed acknowledgement/quarantine.
Persistence success and assessment counts follow transaction commit; analysis-operation
success describes execution and can precede commit. Security actions count decision checks,
including authentication-stage checks, rather than distinct users or uniquely blocked
clients. The default limited endpoint returns 429 for `temporary_block` decisions. Separate
`rate_limit` actions are reported when configured. A WebSocket accepted connection is not
identified as a browser reconnect; new attempts/acceptances/rejections and subscription
reconnections are the server-observable facts. Notifications are best-effort hints, with
separate enqueue, transport-publish, socket-send, duplicate and drop metrics. Socket send is
not a browser acknowledgement. ML is experimental and disabled by default; status/latency
metrics neither validate detection accuracy nor cause enforcement.

## Scraping, storage and dashboards

`infra/observability/prometheus/prometheus.yml` uses 15-second application scrapes,
30-second native broker/self scrapes and a 5-second timeout. Application scrapes have a
20,000-sample/4 MB cap; aggregate broker scrapes have a 3,000-sample/2 MB cap; the queue scrape
has a 100-sample/2 MB cap. Unknown queue labels are dropped. Prometheus evaluates rules every
30 seconds. Storage in `prometheus_data` retains at most 7 days or 1 GiB of blocks, whichever
limit removes older data first. WAL/head/temporary blocks add disk overhead; 1 GiB is not a
hard filesystem quota. Query concurrency is 4, query timeout 10 seconds, maximum samples
500,000, and HTTP connections 32. Prometheus and Grafana each have a **512 MiB / 1 CPU** hard
container limit; the one-shot initialization job has **128 MiB / 0.25 CPU**. Existing backend
services retain their earlier resource configuration. Containers have read-only roots,
temporary `/tmp`, dropped capabilities and no-new-privileges. Each service has a readiness
health check. Observability JSON logs rotate at 10 MiB with three files per service.
Existing PostgreSQL, Redis and RabbitMQ volumes are never recreated/deleted.

Grafana stores its database/settings in `grafana_data`. The read-only file provider creates
five dashboards in `Sentinel AI Operations`, and the fixed `sentinel-prometheus` data source
uses `http://prometheus:9090`. Dashboards use actual rates, histograms, dependency gauges,
native queue depth and stage counters. They display **No samples** when unavailable; no
zero-fill or fabricated traffic is used. Low-volume rates/histograms need at least two
scrapes and can remain absent. Provisioned dashboards are not editable in the UI; change
JSON in Git and wait 30 seconds for provisioning. Authentication credentials are never
embedded in dashboard exports. The React security UI remains separate.

## Operational rules and response

Prometheus rules describe operational availability/performance, independently of Phase 7
security notifications. No Alertmanager or external delivery service is installed. View
rules/alerts via the internal Prometheus API; firing rules do not send email or browser
security notices.

| Alert | Condition | Hold | First operator check |
| --- | --- | --- | --- |
| `SentinelAdminUnavailable` | Admin scrape down | 2 min | API liveness/readiness, metrics listener, token/mount |
| `SentinelWorkerUnavailable` | Worker scrape down, disconnected or database-unready | 2 min | Worker health/logs and broker/DB readiness |
| `SentinelDependencyUnavailable` | Completed dependency probe reports down | 3 min | Named dependency and current probe timestamp |
| `SentinelEventBacklog` | Ready events >1,000 | 5 min | Worker throughput/errors and DB saturation |
| `SentinelWorkerFailures` | Error/quarantine fraction >5%, >20 deliveries/5 min | 5 min | Storage errors and dead-letter reasons |
| `SentinelApiErrors` | Per-service HTTP 5xx >5%, >100 requests/5 min | 5 min | Readiness, errors, downstream failures |
| `SentinelApiLatency` | Per-service p95 >500 ms, >100 requests/5 min | 10 min | Redis duration, dependency probes, CPU/memory |
| `SentinelNotificationDrops` | >20 drops/5 min | 5 min | Slow consumers, bounded buffers, Redis transport |
| `SentinelDeadLetters` | Ready dead letters >0 | 5 min | Existing inspect/replay procedure; never purge blindly |

Validate configuration and all nine rules' pending, firing, recovered and healthy/low-volume
cases without waiting for wall-clock alert windows:

```powershell
docker compose exec -T prometheus promtool check config /etc/prometheus/prometheus.yml
docker compose exec -T -w /etc/prometheus prometheus promtool test rules alerts.test.yml
docker compose exec -T prometheus wget -qO- http://127.0.0.1:9090/api/v1/alerts
```

## Verification and recovery

Run tests sequentially. Backend/browser/acceptance tests edit owned temporary accounts and
policies, restore policy state, and retain audit/test traffic. Do not run independent policy
editing checks concurrently.

```powershell
docker compose --profile test build tests
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

Failure checks temporarily stop owned local services and restore them in `finally` blocks.
An observability outage must leave application enforcement, commit/acknowledgement and
WebSockets functional; metrics history simply has a gap. The database outage check stops the
worker first to retain confirmed messages for replay. These commands are for the owned local
stack, not a production fault drill. The performance comparison alternates instrumentation
off/on/on/off with actual loopback HTTP, Redis/AMQP publishing and PostgreSQL analysis
commits; commit throughput excludes broker consumption/network acknowledgement. Treat its
small sequential sample as a local observation, not a capacity or production claim.

If upgrading from the interrupted Windows implementation, run the initializer before
starting. Older CRLF secret files could have created a Grafana password with a trailing CR.
To synchronize that newly provisioned Grafana account to the preserved LF password file,
use the CLI without exposing the password in arguments/history:

```powershell
docker compose exec -T grafana sh -c 'cat /run/secrets/grafana_password | grafana cli --homepath /usr/share/grafana --configOverrides cfg:default.paths.data=/var/lib/grafana admin reset-admin-password --password-from-stdin'
```

Grafana initial admin settings apply only to a new database; intentional later password
changes persist in its volume. Do not reset an existing operator's changed password during
routine startup. Generated observability secrets can be rotated explicitly with a planned
restart, but the normal initializer preserves them. This single-host Compose setup uses
HTTP plus bearer/basic authentication on private Docker networks; it does not implement
cross-host TLS or encrypt metrics volumes. Restrict Docker engine/host access. Do not mount
Docker's socket into observability containers. Metrics are per-process and reset on restart;
use one Uvicorn worker per container and scale with distinct scrape targets if needed.

Executed evidence and limitations: [day-8-verification.md](day-8-verification.md).
Configuration reference: [Grafana settings](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/).


## Phase 9 deployment integration

Production keeps the same six Prometheus targets, five provisioned dashboards and nine
operational rules. Application/Grafana/Prometheus ports are not routed through the public
Caddy ingress. Grafana is loopback/SSH-only on a Linux deployment; the isolated local TLS
acceptance stack removes its host binding entirely. The deployment guide includes the
required independent production secret paths and resource ceilings.

Background online tabs now retain their bounded authenticated WebSocket, so `ws_active`
can remain positive for a hidden tab. This is an actual connection, not an inferred browser
reconnect metric. Offline/revoked clients still close; REST reconciliation and best-effort
notification semantics remain. Proxy error-log request/header fields are removed in addition
to the existing API/library redaction. Observability is not on the enforcement/commit path.
See [Phase 9 evidence](day-9-verification.md) and [deployment operations](deployment-guide.md).
