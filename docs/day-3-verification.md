# Phase 3 / Day 3 verification - November 12, 2026

## Result and architecture

Phase 3 is implemented on top of the unchanged Day 1/2 platform boundaries. The starting repository was clean at commit `9b7a321`. No dashboard, monitoring dashboard, advanced ML, or fabricated score was added.

```text
HTTP -> request context / monitoring -> Redis policy enforcement -> demo application
                |                              |
                +--- v1 HTTP / v2 decisions ----+
                                |
                     bounded publisher buffer
                                |
                             RabbitMQ
                                |
                          event worker
                                |
                     PostgreSQL audit events
```

The synchronous engine depends only on Redis and typed policies. Broker publication and audit persistence cannot become admission-control dependencies. Health endpoints remain excluded. Normal/streaming responses and existing event recovery functionality remain intact.

Implemented protection includes atomic server-time sliding windows, most-specific endpoint groups, verified-authentication failure tracking, allow/record/rate-limit/temporary-block actions, fixed finite block expiration, per-policy Redis failure behavior, generic HTTP 429/503 responses, conservative Retry-After values, and HMAC client identification under the original proxy trust rules.

No raw IP, username, password, login body, header, cookie, query value, or arbitrary submitted URL is stored by protection. A hash-only test authenticator lives in the demo package and issues no tokens/sessions. Generic 401s do not count as verified password failures. High read quotas, group-scoped restrictions, successful-login reset, and observation mode provide explicit false-positive safeguards.

## Real rate-limiting and brute-force demonstration

Executed successfully against the actual Compose demo service:

```sh
python scripts/verify_protection.py
```

The host script temporarily configures short validated policies and a randomly generated credential, passing the plaintext only in memory/stdin. Its override file contains a salted scrypt hash, not the password. The actual service is recreated for verification and restored in `finally`. The final output confirmed **Normal demo credentials and policies restored.** Temporary override files were removed.

| Live scenario | Actual result |
| --- | --- |
| Requests below verification quota | 200, 200, 200 |
| Next request | 429; Retry-After 2 seconds |
| Request during temporary restriction | 429 |
| After expiry | 200 |
| Unrelated network client during restriction | 200 |
| Initial correct login | 200 |
| Three verified wrong-password attempts | 401, 401, 401 |
| Correct login while restricted | 429 |
| Correct login after expiry | 200 |
| Correct login from unrelated network client | 200 |
| Different client identities in PostgreSQL | Confirmed |
| Sensitive verification sentinels persisted | False |

The two clients use real loopback and bridge source addresses of the owned demo, with the same ignored spoofed forwarding header. This does not simulate client isolation by trusting arbitrary headers. Verification policies use 3 requests/1 second with a 2-second block, and 3 verified login failures/10 seconds with a 2-second block. Normal defaults are restored: read 600/60s, demonstration limited route 5/3s with a 3-second block, login 30/60s plus 5 verified failures/60s and a 60-second group block.

Two actual persisted decision events from the final successful invocation:

```json
{
  "rate": {
    "event_id": "aa7a76f4-49d7-4583-9a0a-2ae305f7ad9d",
    "request_id": "508823832c7a427793aaf0dc45319a24",
    "schema_version": 2,
    "rule_id": "verify-rate-a0b7522f0dc4.rate",
    "security_action": "temporary_block",
    "threshold": 3,
    "counter_value": 4,
    "restriction_expires_at": "2026-11-12 10:34:59.058000+00:00"
  },
  "authentication": {
    "event_id": "02be4d55-d5ea-42da-baaa-6c96b65f3836",
    "request_id": "a4016f8d1c814fe9ae3e1753a72b9931",
    "schema_version": 2,
    "rule_id": "verify-login-a0b7522f0dc4.auth_failures",
    "security_action": "temporary_block",
    "threshold": 3,
    "counter_value": 3,
    "restriction_expires_at": "2026-11-12 10:35:01.390000+00:00"
  }
}
```

Timestamps above are UTC; both were recorded November 12, 2026 in the user's Asia/Calcutta timezone as well. The script queried PostgreSQL independently after HTTP calls. Decisions travelled through the existing bounded publisher, RabbitMQ, and upgraded worker; request handling has no audit-insert call.

## Actual dependency outage exercises

Each dependency was stopped separately using Compose and restored in `finally`; all services recovered.

| Outage | Actual synchronous result | Persistence evidence |
| --- | --- | --- |
| Redis | Ordinary read 200; designated login 503 | Two degraded v2 events with actions record/deny persisted |
| RabbitMQ | 200, 200, 200, 200, 200, 429, 429 | Rejection decision persisted after reconnection |
| PostgreSQL | 200, 200, 200, 200, 200, 429, 429 | Rejection decision persisted after database recovery |

Redis outage request IDs: `cc12ddc22f4047d192e5365af7f54c86` (fail-open) and `4da6721ae51f40949f04c7f366166797` (fail-closed). Both were found with `degraded=true`.

Broker-outage rejection request ID: `84b5443212e94e26ba27f20a1f7faa31`, persisted with rule `demo-limited.rate` and action `temporary_block`.

Database-outage rejection request ID: `a479c5c79e1a41c188abafbd818394d8`, persisted with the same rule/action after recovery. These exercises demonstrate continued enforcement, not a lossless guarantee for arbitrarily long telemetry outages. The Day 2 retry, quarantine, replay, and unconfirmed-buffer loss contracts remain documented.

## Automated verification

Final complete command:

```sh
docker compose --profile test run --rm --no-deps -e COVERAGE_FILE=/tmp/.coverage tests python -m pytest -p no:cacheprovider --cov=sentinel_security --cov=sentinel_api --cov=sentinel_demo --cov=sentinel_worker --cov-report=term-missing --cov-fail-under=85
```

**Final result: 201 passed, 0 failed, 0 skipped in 9.63 seconds.** Composition: **175 unit tests and 26 integration tests**. Existing Day 1/2 tests remain; the migration-head expectation was advanced to the actual new head.

**Statement coverage: 96.04%** across the shared package, demo/admin APIs, and worker: 986 statements, 39 missed; required floor 85%. Protection engine, policies, enforcement middleware, request middleware, configuration, storage, and consumer logic each reached 100% statement coverage. This is package statement coverage, not a branch-coverage claim or a measurement of separate live container processes. The worker CLI remains in the measured target despite not being instrumented when executed by Docker.

The tests cover two independent Redis connections, two independent demo ASGI instances, concurrent quota admission, independent clients, spoofed headers, bounded ZSET membership/TTLs, no block extension, expiry, observation mode, successful-login reset settings, verified failures versus generic 401s, fail-open/closed connection failures, broker/DB independence, response replacement, streaming, body/credential limits, hash-only credential setup, v1/v2 parsing/persistence/deduplication, and all retained event-pipeline failure cases.

Targeted host command also executed:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_config.py tests/unit/test_client_identity.py tests/unit/test_events.py tests/unit/test_env_initialization.py tests/unit/test_policies.py tests/unit/test_protection.py -q
```

**Host result: 95 passed in 0.69 seconds.** The complete suite used Linux containers because of the previously recorded Windows Application Control restriction on native SQLAlchemy/coverage extensions. No OS policy was changed.

Additional executed checks:

- Ruff lint and formatting: passed.
- Git whitespace check: passed.
- Default Compose and combined development override `config --quiet`: passed.
- Runtime/test image builds and `compose up --wait`: completed successfully.
- Alembic current: **0003_security_decisions (head)**.
- Alembic check: **No new upgrade operations detected.**
- Runtime `pip check`: **No broken requirements found.**
- Migration container exit: **0**.
- Redis server version: **7.4.12**.

The Redis image was intentionally updated from 7.4.5 within its existing 7.4 line before enabling Lua, because the older pin predates documented [Lua security fixes](https://redis.io/docs/latest/operate/oss_and_stack/stack-with-enterprise/release-notes/redisce/redisce-7.4-release-notes/). The verified digest is `sha256:2e3eb11462c4e3759e6972678dd051d150ff54b1e60714b3c33b701260172a90`. The existing volume and credentials were retained. No unnecessary dependency or other service image changes were made.

## Docker health and schema compatibility

Final health: admin-api, demo-api, event-worker, PostgreSQL, Redis, and RabbitMQ are healthy. Only the admin API is published by the default stack, at `127.0.0.1:8000`; the worker does not run an HTTP server despite inherited image port metadata. The migration job exited 0. Runtime non-root/read-only/capability restrictions remain inherited from Day 1.

`0003_security_decisions` adds optional typed decision columns, a rule/time index, and version-aware constraints without rewriting v1 HTTP records. The worker, quarantine model, and operator replay accept both versions. A downgrade refuses to discard existing v2 security history. For a rolling deployment, migrate and upgrade consumers before enabling v2 producers; the compatible queue transport name is unchanged.

## Exact setup and reproduction commands

For an existing Day 2 checkout:

```sh
python scripts/configure_demo_auth.py --initialize
docker compose config --quiet
docker compose up --build --wait --wait-timeout 180
python scripts/verify_protection.py
docker compose --profile test run --build --rm tests
```

For a fresh checkout, run `python scripts/init_env.py` first. For a Day 1 checkout, also add the monitoring key using `python scripts/init_env.py --add-monitoring-key`. To choose a known password instead of a random discarded-password hash, run `python scripts/configure_demo_auth.py` interactively, then recreate the demo. Never pass a password in CLI arguments or commit `.env`.

The complete all-tests/coverage command is above. The repeatable protection script briefly replaces the local demo service and must not overlap another deployment operation. It restores normal credentials/policies and removes its hash-only override file on completion, including failed verification.

## Known limitations and deliberate scope

- Shared IP/NAT users share a privacy-preserving client identifier. Group-specific thresholds, generous read limits, observation mode, and verified-success reset mitigate false positives; they do not provide per-account/device/botnet attribution.
- Already admitted concurrent requests can complete while a new block is being established. Blocks apply to future checks; they do not cancel existing application work.
- State is shared only when replicas use identical policies, HMAC key, and Redis. Policy/key changes create new namespaces and reset that state. TTLs bound idle retention, and ZSETs bound per-client membership, but distinct active client cardinality is not globally capped.
- The test-only login is not an administrative authentication system and creates no JWT/session. Production startup rejects that flow when enabled.
- Before broker confirmation, telemetry is memory-buffered and can be lost under the documented conditions. Confirmed messages retain Day 2 persistence/retry/quarantine semantics. This single-node stack is not a highly available deployment.
- Windows native-extension limitations remain; the complete Linux suite passed. Optional development host bindings were configuration-validated, not started. Remote GitHub Actions was updated but not executed.
- No dashboard, Grafana, Prometheus, advanced ML, fabricated scores, commit, push, or unrelated feature work was added.

## Completion checklist

- [x] Distributed atomic Redis rate limiting with endpoint groups, finite TTLs, and bounded membership.
- [x] Verified-login failure detection, successful-login behavior, and temporary group restrictions.
- [x] Validated policy defaults, observation mode, enable/disable, and false-positive safeguards.
- [x] Existing HMAC identity and conservative proxy trust retained.
- [x] Generic 429/Retry-After and explicit fail-open/fail-closed degradation.
- [x] Enforcement independent of RabbitMQ/PostgreSQL, demonstrated during real outages.
- [x] Rejected/streaming/normal requests monitored; health traffic excluded.
- [x] Real v2 decision persistence with migration and v1 compatibility.
- [x] Complete tests, coverage, lint, configuration, schema, and live protection verification.
- [x] Repeatable verification, operator setup, architecture, and limitations documented.

## File manifest

Private `.env` was updated with the demo username and salted hash. It remains ignored; existing infrastructure credentials and the identity key were preserved. No raw demo password was written. No dependency lock updates were needed.

Created (18 files):

- `apps/demo-api/src/sentinel_demo/auth.py`
- `apps/demo-api/src/sentinel_demo/credentials.py`
- `docs/day-3-verification.md`
- `migrations/versions/0003_security_decisions.py`
- `packages/sentinel-security/src/sentinel_security/auth_failures.lua`
- `packages/sentinel-security/src/sentinel_security/policies.py`
- `packages/sentinel-security/src/sentinel_security/protection.py`
- `packages/sentinel-security/src/sentinel_security/protection_middleware.py`
- `packages/sentinel-security/src/sentinel_security/rate_limit.lua`
- `scripts/configure_demo_auth.py`
- `scripts/verify_protection.py`
- `scripts/verify_protection_runtime.py`
- `tests/integration/test_distributed_protection.py`
- `tests/unit/test_demo_auth.py`
- `tests/unit/test_demo_credential_setup.py`
- `tests/unit/test_policies.py`
- `tests/unit/test_protection.py`
- `tests/unit/test_protection_middleware.py`

Modified (17 tracked files):

- `.env.example`
- `.github/workflows/ci.yml`
- `README.md`
- `apps/demo-api/src/sentinel_demo/main.py`
- `apps/event-worker/src/sentinel_worker/consumer.py`
- `compose.yaml`
- `docs/architecture.md`
- `packages/sentinel-security/pyproject.toml`
- `packages/sentinel-security/src/sentinel_security/application.py`
- `packages/sentinel-security/src/sentinel_security/config.py`
- `packages/sentinel-security/src/sentinel_security/events.py`
- `packages/sentinel-security/src/sentinel_security/middleware.py`
- `packages/sentinel-security/src/sentinel_security/publisher.py`
- `packages/sentinel-security/src/sentinel_security/storage.py`
- `scripts/replay_dead_letters.py`
- `tests/conftest.py`
- `tests/integration/test_stack.py`
