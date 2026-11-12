# Architecture decisions and boundaries

## Foundation implemented November 12, 2026

The monorepo contains three Python distributions. `sentinel-security` owns reusable configuration, request context, dependency lifecycle, database session creation, and operational endpoints. It imports neither API service. The admin and demo distributions depend on it independently and expose application factories. This lets future middleware be attached to another ASGI API without importing Sentinel's administrative application.

`RequestContextMiddleware` is pure ASGI: it forwards the request receive stream and response send stream without reading or buffering bodies. It handles only HTTP and passes other scopes through. Structured events use registered route templates to avoid path token leakage. Client identity uses the socket address by default; trusted-proxy configuration is explicit and validated. This is a foundation for detection, not an enforcement claim.

Resources belong to each application's lifespan. PostgreSQL and Redis pools initialize lazily; liveness can start during dependency outages. Readiness probes each dependency concurrently with an overall per-probe deadline. Shutdown closes pools. PostgreSQL transactions belong to the caller of `get_session`; the dependency never commits implicitly.

Alembic owns schema history. The initial revision deliberately has no speculative tables. A one-shot job runs before APIs start, guarded only by PostgreSQL health. Redis and RabbitMQ health gate initial API startup, but the APIs do not terminate because a broker later fails. The backend Docker network is internal. The admin API also joins an ingress bridge to support its loopback-only published port; Docker Engine 29 does not publish ports for internal-only containers. The demo ping is not authenticated in Day 1 and has no default host binding.

## Boundaries for the next milestones (not implemented)

| Component | Responsibility | Must not own |
| --- | --- | --- |
| Security engine | Configurable rules, explainable scores, statistical/ML inference | HTTP transport, broker availability |
| Reusable middleware | Safe request metadata and synchronous enforcement adapter | Administrative UI, asynchronous persistence |
| Redis enforcement adapter | Atomic distributed counters, expiry, bounded failure policy | Audit durability |
| Demo API | Controlled API workload behind middleware and later authentication | Security administration |
| Administrative API | JWT authorization, policy management, audit queries | Demo business behavior |
| Event publisher | Bounded publication, explicit retry/delivery semantics | Synchronous allow/deny decisions |
| Asynchronous worker | Event consumption, durable audit writes, asynchronous analysis | Request-path rate-limit decisions |
| React dashboard | Authenticated operational view and real-time notifications | Access tokens in logs or security decisions |
| Monitoring | Prometheus service metrics and Grafana dashboards | Sensitive request payload collection |

A RabbitMQ outage must not automatically bypass Redis rate limiting. Publication failure and enforcement failure need independent configuration, metrics, and tests. Redis failure policy must be explicit per protected route or deployment rather than silently allowing everything. Readiness may report degraded dependencies while the request path still enforces available controls; a future deployment should decide whether a degraded broker removes an instance from routing.

Detection thresholds, sampling, lockout TTLs, allowlists, observation mode, and escalating actions need typed policy models and false-positive tests before enforcement is enabled. Authentication and traffic simulation must be scoped to the owned demo. Passwords, tokens, bodies, and secrets are outside the telemetry contract. Future audit records should contain allowlisted metadata, with retention and access policies.

## Operational tradeoffs

- The development database uses the initialization role. A production rollout should separate migration ownership from restricted application privileges.
- Redis AOF, PostgreSQL, and RabbitMQ all use named volumes. Persistence is not a substitute for backups, and volume contents are not committed.
- Service images and the Python base are pinned to verified release digests. Review upstream security updates and refresh pins intentionally; digest locking does not replace vulnerability monitoring.
- Dependency readiness handshakes prioritize real authentication checks over lightweight TCP checks. If probe volume grows, tune frequency or introduce short-lived cached readiness without caching enforcement decisions.
- Third-party connection errors are suppressed in favor of allowlisted dependency status/error-class events to avoid credentials leaking through exception messages.
- No CORS policy, permissive JWT defaults, unused RabbitMQ consumer, or fake ML model is added in this milestone. Each will arrive with the feature that needs it and corresponding tests.
