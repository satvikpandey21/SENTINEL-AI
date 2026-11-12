# Architecture decisions and boundaries

## Foundation implemented November 12, 2026

The monorepo now contains four Python distributions, including the Day 2 event worker. `sentinel-security` owns reusable configuration, request context, dependency lifecycle, database session creation, and operational endpoints. It imports neither API service. The admin and demo distributions depend on it independently and expose application factories. This lets future middleware be attached to another ASGI API without importing Sentinel's administrative application.

`RequestContextMiddleware` is pure ASGI: it forwards the request receive stream and response send stream without reading or buffering bodies. It handles only HTTP and passes other scopes through. Structured events use registered route templates to avoid path token leakage. Client identity uses the socket address by default; trusted-proxy configuration is explicit and validated. Day 2 extends this middleware with an injectable event sink; it remains a foundation for detection, not an enforcement claim.

Resources belong to each application's lifespan. PostgreSQL and Redis pools initialize lazily; liveness can start during dependency outages. Readiness probes each dependency concurrently with an overall per-probe deadline. Shutdown closes pools. PostgreSQL transactions belong to the caller of `get_session`; the dependency never commits implicitly.

Alembic owns schema history. The initial revision deliberately has no speculative tables. A one-shot job runs before APIs start, guarded only by PostgreSQL health. Redis and RabbitMQ health gate initial API startup, but the APIs do not terminate because a broker later fails. The backend Docker network is internal. The admin API also joins an ingress bridge to support its loopback-only published port; Docker Engine 29 does not publish ports for internal-only containers. The demo ping is not authenticated in Day 1 and has no default host binding.

## Component boundaries (detection, enforcement, UI, and authentication remain future work)

| Component | Responsibility | Must not own |
| --- | --- | --- |
| Security engine (Phase 3 rules) | Validated policies and Redis decisions; ML/scoring remains future work | HTTP transport, broker availability |
| Reusable middleware | Safe request metadata and synchronous enforcement adapter | Administrative UI, asynchronous persistence |
| Redis enforcement adapter (Phase 3) | Atomic distributed counters, expiry, bounded failure policy | Audit durability |
| Demo API | Controlled API workload behind middleware and later authentication | Security administration |
| Administrative API | JWT authorization, policy management, audit queries | Demo business behavior |
| Event publisher (Day 2) | Bounded publication, explicit retry/delivery semantics | Synchronous allow/deny decisions |
| Asynchronous worker (Day 2) | Event consumption and durable audit writes; analysis is future work | Request-path rate-limit decisions |
| React dashboard | Authenticated operational view and real-time notifications | Access tokens in logs or security decisions |
| Monitoring | Prometheus service metrics and Grafana dashboards | Sensitive request payload collection |

A RabbitMQ outage must not automatically bypass Redis rate limiting. Publication failure and enforcement failure need independent configuration, metrics, and tests. Redis failure policy must be explicit per protected route or deployment rather than silently allowing everything. Readiness may report degraded dependencies while the request path still enforces available controls; a future deployment should decide whether a degraded broker removes an instance from routing.

Phase 3 provides typed threshold/expiry/observation policies and false-positive safeguards for deterministic rules. Sampling, richer identity, allowlists, and advanced actions remain future policy work. Authentication and traffic simulation must be scoped to the owned demo. Passwords, tokens, bodies, and secrets are outside the telemetry contract. Future audit records should contain allowlisted metadata, with retention and access policies.

## Operational tradeoffs

- The development database uses the initialization role. A production rollout should separate migration ownership from restricted application privileges.
- Redis AOF, PostgreSQL, and RabbitMQ all use named volumes. Persistence is not a substitute for backups, and volume contents are not committed.
- Service images and the Python base are pinned to verified release digests. Review upstream security updates and refresh pins intentionally; digest locking does not replace vulnerability monitoring.
- Dependency readiness handshakes prioritize real authentication checks over lightweight TCP checks. If probe volume grows, tune frequency or introduce short-lived cached readiness without caching enforcement decisions.
- Third-party connection errors are suppressed in favor of allowlisted dependency status/error-class events to avoid credentials leaking through exception messages.
- No CORS policy, permissive JWT defaults, unused RabbitMQ consumer, or fake ML model is added in this milestone. Each will arrive with the feature that needs it and corresponding tests.

## Day 2: monitoring and persistence

The middleware builds a frozen, extra-forbidding version 1 `SecurityEvent`. It uses only registered route templates, maps unknown methods to `OTHER`, and generates timestamps/identifiers on the server. Application-owned authentication code may explicitly annotate the ASGI scope; telemetry never parses credentials. Raw client IPs remain request-local and are converted to keyed HMAC identifiers before event publication. Stable keys support correlation across instances without keeping raw addresses.

An injected `EventSink` keeps the ASGI adapter reusable. Its `offer` method is synchronous and bounded: serialization and `put_nowait` only. The concrete publisher runs in an independent lifespan task, reuses an AMQP channel, and performs no database work. API startup does not await the publisher's connection. The overall Day 1 readiness contract still checks dependencies, while normal routes keep responding if telemetry fails.

The fixed queues `sentinel.security.events.v1` and `.dead` are durable and bounded by both count and body bytes. Overflow rejects new publications instead of silently evicting older events. Persistent messages, publisher confirmations, and mandatory routing make the broker handoff explicit. This follows RabbitMQ's [publisher reliability contract](https://www.rabbitmq.com/docs/reliability) and [queue overflow behavior](https://www.rabbitmq.com/docs/maxlength). An in-memory ingress buffer deliberately provides best-effort availability before confirmation; telemetry loss is possible and observable. There is no durable outbox or claim of exactly-once transport.

The separately packaged `sentinel_worker` owns a long-lived connection and a PostgreSQL pool. Bounded prefetch limits received but unacknowledged messages. Each delivery is validated before storage, and each transaction uses an idempotent PostgreSQL insert on the event UUID primary key. Commit precedes acknowledgement. If a connection is lost after commit and before acknowledgement, redelivery is harmless at the database boundary.

Transient SQL connection/resource/transaction failures have bounded retries with capped exponential backoff. Permanent failures or exhausted retries are quarantined with publisher confirmation before the source is acknowledged. Valid events remain replayable. Malformed messages create only a redacted notice with a fingerprint, not a copy of attacker-controlled input. A full/unavailable dead queue leaves the source unacknowledged; closing the channel and reconnecting after a delay avoids hot-loop requeues. Operator replay retains event IDs and requires private container/broker access; it adds no HTTP event endpoint.

`0002_security_events` stores explicit typed columns rather than an unbounded JSON payload. It adds timestamp, service/time, severity/time, client/time, and request-ID indexes, as well as schema/status/duration/severity/authentication constraints. No API request opens a database connection for event persistence. A separate worker heartbeat probes the pooled database connection and records connection supervision health without exposing audit data.

Default resource limits, failure semantics, verification, and replay commands are documented in the README. The worker is sequential per replica; additional replicas can share the queue. Long storage retries can cause head-of-line delay within one worker, which intentionally reduces pressure on a failing database. Production scaling should follow workload measurement.

## Phase 3: Redis-only synchronous protection

`policies.py` defines immutable validated endpoint groups, rate rules, and verified-authentication rules. Selection uses the most-specific full path-segment prefix and optional method set; group count and identifiers are bounded. The policy fingerprint is part of Redis state identity, so all API instances must deploy the same configuration and HMAC key. This avoids per-URL key creation and isolates services/groups while allowing intentional policy changes to start fresh state.

`SecurityEngine` depends only on a Redis store and typed policy definitions. It imports no worker, broker, demo authentication, or database module. Two cached Lua scripts perform atomic server-time sliding-window admission and verified-failure tracking. Each group/client has at most rate, failure, and temporary-block keys, with validated finite TTLs and capped sorted-set membership. Script registration uses cached SHA execution and automatically reloads after Redis restart. Atomicity follows Redis's [Lua execution guarantee](https://redis.io/docs/latest/develop/interact/programmability/eval-intro/).

The existing request-context/monitoring middleware is outermost around an optional protection adapter. It establishes the trusted peer, HMAC identity, request ID, and timing first. Pre-routing Redis checks can return generic 429/Retry-After or fail-closed 503. The outer middleware still observes those responses and emits HTTP metadata. Endpoint labels for pre-routing rejections come from the static selected policy prefix, never the submitted raw path.

The inner adapter runs the application after admission. A trusted demo authenticator explicitly marks verified success/failure in request-local scope state. Before forwarding response headers, the adapter atomically updates authentication state. Generic 401s and ordinary authentication outcome annotations do not enter this counter. If a required Redis write fails after credentials were checked, the adapter can replace the response with a generic 503 and suppress the original success body. Existing streaming responses otherwise pass through untouched.

The test-only authenticator is owned by `sentinel_demo`, not the reusable engine. It has bounded JSON parsing, generic errors, salted fixed-cost scrypt verification in a bounded thread workload, constant-time comparisons, and hash-only environment configuration. It issues no token/session and is rejected in production mode. A separate host initializer prompts for a password or creates a random discarded-password hash; neither raw passwords nor login bodies are persisted.

Actions are allow, observe/record, rate-limit, and finite group-scoped block. A separate deny action describes fail-closed infrastructure unavailability. Shared-IP false positives are addressed with endpoint-specific quotas, observation policies, login-only restrictions, explicit thresholds, and optional successful-login reset. Client-wide attribution beyond the existing IP pseudonym is intentionally not claimed. A newly created block applies to future admission checks; already admitted in-flight requests are not retroactively cancelled.

HTTP events retain schema version 1. Independently identified version 2 decision events contain rule/action, bounded counter and threshold, window, restriction expiry/retry, and degradation metadata. `0003_security_decisions` adds nullable columns and version-aware constraints, preserving all existing v1 records; the worker and replay/quarantine parsing use a discriminated union. Duplicate prevention remains the event UUID primary key. No scores or unprotected event-query routes are introduced.

Redis failures are explicit per policy, with a bounded operation deadline. Ordinary groups fail open and emit/log degradation; the default login group fails closed. RabbitMQ publication and PostgreSQL writes remain outside this decision path. Confirmed delivery, retries, quarantine, replay, and unconfirmed-event loss semantics retain the Day 2 contract. Production replicas require shared policy/key deployment and appropriately secured Redis permissions; this local single-node service is not a highly available cluster.

A host verification command temporarily configures the actual demo with short policies and hash-only credentials, uses two genuine network peer identities, checks real PostgreSQL events, then restores the service in finally. This is controlled owned-API traffic and real enforcement, not a mock response or synthetic threat score. It must run separately from concurrent demo deployment changes.
