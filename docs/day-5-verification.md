# Phase 5 implementation and executed verification

Verified on **November 13, 2026 (Asia/Kolkata)**, before the November 20 deadline. This report records local execution, not an unexecuted GitHub Actions result. No commit or push was made.

## 1. Implemented functionality

Phase 5 adds private administrative accounts; interactive first-account bootstrap; Argon2id password verification; strict short-lived JWTs; rotating, hashed refresh credentials; server-side session revocation and replay detection; ADMIN/ANALYST authorization; event/assessment/client APIs; PostgreSQL dashboard analytics; shared Redis policy activation; account management; and persistent administrative audit records. Existing demo authentication remains isolated. Historical Phase 1–4 event and assessment schemas/data are preserved.

## 2. Files created and modified

Created:

| File | Purpose |
|---|---|
| `apps/admin-api/src/sentinel_api/auth.py` | Password verification, JWT validation, authorization, Redis authentication budgets, refresh locking |
| `apps/admin-api/src/sentinel_api/auth_routes.py` | Login, CSRF preparation, refresh, logout, current account |
| `apps/admin-api/src/sentinel_api/bootstrap.py` | Interactive first-account provisioning CLI |
| `apps/admin-api/src/sentinel_api/models.py` | Private account/session/token tables |
| `apps/admin-api/src/sentinel_api/settings.py` | Independent signing/cookie/origin settings |
| `apps/admin-api/src/sentinel_api/schemas.py` | Public response fields, filters, pagination, errors |
| `apps/admin-api/src/sentinel_api/queries.py` | Bounded SQL lists/aggregations/investigation queries |
| `apps/admin-api/src/sentinel_api/routes.py` | Data, analytics, client, policy, account, and audit endpoints |
| `packages/sentinel-security/src/sentinel_security/management.py` | Versioned policy coordinator and audit models |
| `packages/sentinel-security/src/sentinel_security/policy_runtime.py` | Redis-only effective policy reads |
| `migrations/versions/0005_administration.py` | Tables, constraints, dashboard/query indexes |
| `scripts/export_admin_openapi.py` | Reproducible OpenAPI export/drift check |
| `scripts/verify_admin.py` | Real HTTP acceptance verification with ephemeral accounts |
| `tests/unit/test_admin_security.py` | JWT, hashing, configuration, filtering, policy availability checks |
| `tests/integration/test_admin_api.py` | Real database/Redis/HTTP security and analytics tests |
| `docs/admin-api-contract.md` | Exact frontend/security contract |
| `docs/admin-openapi.json` | Generated implementation contract |
| `docs/day-5-verification.md` | This report |

Modified: `.env.example`, `.github/workflows/ci.yml`, `README.md`, `compose.yaml`, `docs/architecture.md`, `migrations/env.py`, `packages/sentinel-security/pyproject.toml`, the shared library's `application.py`, `config.py`, `protection.py`, `storage.py`, `analysis_storage.py`, `requirements.in`, `requirements.txt`, `requirements-dev.txt`, `scripts/init_env.py`, `scripts/verify_protection.py`, `tests/integration/test_stack.py`, `tests/unit/test_env_initialization.py`, and `tests/unit/test_services.py`.

The ignored local `.env` received an independently generated signing key and explicit local HTTP administrative cookie/origin settings. Existing service passwords, identity key, and demo password hash were preserved. Ignored `.artifacts/day-5-tests.txt`, `.artifacts/day-5-http-verification.txt`, and `.artifacts/day-5-legacy-protection.txt` hold executed output without passwords/tokens.

## 3. Authentication architecture

Argon2id uses 64 MiB, three iterations, one lane, independent random salts, generic login failures, dummy verification for unknown accounts, and bounded password work. Accounts are provisioned through the interactive CLI only while no accounts exist; subsequent creation requires an ADMIN. There are no default credentials or public registration. The local verification scripts used random temporary accounts and removed them; provision your own persistent account with:

```sh
docker compose exec admin-api python -m sentinel_api.bootstrap --username your-admin-name
```

No credentials enter argv, documentation examples, OpenAPI examples, telemetry, or audit summaries. Login limits run atomically in Redis before password verification. Separate HMAC account/peer budgets avoid raw identity data in limiter keys. The administrative signing key is supplied only to the administrative container.

## 4. JWT and refresh behavior

Access tokens default to five minutes. Fixed HS256 validation checks signature, issuer, audience, expiry, not-before/issued-at types and values, maximum lifetime, UUID subject/session, JTI, and access token type/header. PostgreSQL account/session checks make revocation immediate for subsequent requests.

Refresh tokens have 256 random bits, rotate on use, and are stored only as SHA-256 digests. Families expire absolutely after eight hours by default. Used generations remain as replay tombstones. Family row locks serialize refresh/logout/replay. Two concurrent uses of one generation yield one 200 and one 401; replay revokes the family, including the token returned by the winning response. Logout expires the cookie and revokes the family. Account password/role/activation changes revoke all target sessions.

Frontend access and CSRF tokens stay in memory. Refresh cookies are HttpOnly, host only, path scoped, SameSite=Strict, and Secure in production. Exact Origin, custom intent header, and per-generation CSRF nonce checks are documented in [the contract](admin-api-contract.md). Local HTTP cookie behavior is an explicit development configuration.

## 5. Permission verification

Executed tests verify unauthenticated data access returns 401; both roles can read events, assessments, analytics, clients, and policies; analysts receive 403 for policy writes, account operations, and audit reads; administrators can perform these operations; deactivation, role/password changes, logout, and expiration revoke access. The last active ADMIN cannot be disabled/demoted. All checks execute on the server.

## 6. Working security event examples

The final HTTP run created an actual `/api/demo/ping` request and retrieved its worker-persisted event:

```http
GET /api/admin/events?request_id=fc39c47726b449118bba102349f4b169
Authorization: Bearer <in-memory-access-token>

GET /api/admin/events/a80a16b1-7c0a-48e0-8d4c-1d4220fe48ed
Authorization: Bearer <in-memory-access-token>
```

Observed fields: schema 1, service `sentinel-demo-api`, sanitized endpoint `/api/demo/ping`, status 200. Event filtering tests cover type, severity, service, action, endpoint template, request correlation, timestamps, client ID, and bounded pagination; detail 404s and invalid parameters are exercised. Version 2 rate/block decisions remain queryable alongside schema 1 without exposing credential or request payload fields.

## 7. Working assessment examples

The same actual request produced assessment `da68e138-e4bc-42fc-9403-cf10bc653433`, event-linked risk 0.0, severity low, rule version `risk-v1`, and null ML model version:

```http
GET /api/admin/assessments?event_id=a80a16b1-7c0a-48e0-8d4c-1d4220fe48ed
Authorization: Bearer <in-memory-access-token>

GET /api/admin/assessments/da68e138-e4bc-42fc-9403-cf10bc653433
Authorization: Bearer <in-memory-access-token>
```

A normal request having zero risk is expected. Controlled integration records also exercised deterministic authentication/policy threats and statistical/experimental Phase 4 evidence. Public schemas retain the detection-method/model distinction and discard unexpected private JSON extensions. No assessment is fabricated by an API handler.

## 8. Real analytics evidence

For `2026-11-13T11:31:40.465407Z` through `2026-11-13T11:31:42.493126Z` (exclusive end), the final actual HTTP run queried `GET /api/admin/analytics?service=sentinel-demo-api&start=...&end=...`. It returned **1 monitored request, 0 decision events**, matching independent PostgreSQL COUNT queries over exactly that window.

Controlled real PostgreSQL integration fixtures separately verified **2 HTTP requests + 2 decision events** produce request total 2, decision total 2, one rate-limit decision, one temporary-block decision, two timeline/status observations, and three threat-bearing assessments. Request and decision rows sharing a request ID are not added together. Empty services produce zeros and empty arrays. Threat severity, classification, risk buckets, sanitized routes, recent alerts, and suspicious service/client aggregates all use stored records. See the [metric semantics](admin-api-contract.md#analytics-semantics).

## 9. Policy management results

The final HTTP demonstration activated revision **15** through the ADMIN API. The running demo endpoint changed from 200 on its first request to 429 on the second under the new threshold, then the script restored the previous configuration in a subsequent revision. Tests also verify two independent engine instances read the same Redis configuration, a second writer with a stale version gets 409, unsafe scope/overlap/disable/removal changes get 422, and a Redis fence returns 503.

An injected activation interruption after the real PostgreSQL commit left a newer persisted revision and a Redis fence; policy reads reported unsynchronized state, enforcement closed, and authenticated reconciliation repaired it. Managed policies are not a PostgreSQL-only save operation. Redis snapshots are loaded per protected request; middleware never queries PostgreSQL. The legacy Phase 3 verifier explicitly uses static mode only during its temporary override, then restores managed enforcement without altering managed policy history.

## 10. Audit evidence

The final read-only database check found **287 retained audit records**, **zero leftover verification accounts**, and restored policy revision **16** matching Redis. The final administrator's persisted audit actions included `account.bootstrap`, `account.create`, `auth.login`, and `policy.update`. The suite additionally verifies failed logins, throttling, role denials, refresh rotation/replay, logout, invalid/unsafe writes, version conflicts, account changes, and reconciliation records. Audit rows retain actor UUID, action, timestamp, resource target, success/rejected outcome, and allowlisted summaries. Passwords, hashes, JWTs, refresh values, raw IPs, and cookies are excluded from API output/audit summaries.

## 11. Test and quality results

| Executed check | Result |
|---|---|
| Complete packaged unit + integration suite | **322 passed in 28.82 seconds** |
| Statement coverage, all four distributions | **92.18%** (85% gate passed) |
| Prior Phase 1–4 baseline | Existing 269 tests retained; 53 additional tests |
| Ruff check in final Linux test image | Passed |
| Ruff format check | Passed for repository Python files |
| OpenAPI drift check | Passed |
| Docker Compose config validation | Passed |
| Alembic upgrade head | Passed |
| Alembic schema drift check | No new upgrade operations detected |
| Final real HTTP A–J acceptance script | Passed |
| Original live rate/brute-force demonstration | Passed, credentials/policies restored |
| Python compilation and Git whitespace checks | Passed |

The Windows sandbox prevented native SQLAlchemy/Argon2 DLL imports during an initial local test attempt. Full verification subsequently ran successfully in the project's Linux image with real PostgreSQL, Redis, RabbitMQ, protected demo HTTP service, and event worker. No tests were represented as passing based solely on mocks, skipped integrations, or lint results. CI configuration now performs OpenAPI drift and the real HTTP acceptance demonstration; remote GitHub Actions has not been run by this session.

## 12. Docker services and resources

The admin API, demo API, event worker, PostgreSQL, Redis, and RabbitMQ were healthy after the final packaged startup. The one-shot migrate service completed successfully. Data volumes were retained; no new service was added. The administrative port remains loopback-only at `127.0.0.1:8000`.

A Docker point-in-time snapshot observed about 405 MiB across the six persistent services: administrative API 71.68 MiB, demo API 64.43 MiB, worker 57.36 MiB, PostgreSQL 61.8 MiB, Redis 13.16 MiB, RabbitMQ 137 MiB. The simultaneously running test container used 158.5 MiB. These values are a snapshot rather than a peak/load benchmark; the Docker memory limit was 7.55 GiB.

## 13. Migration status

`alembic current` returned **0005_administration (head)**. `alembic check` returned **No new upgrade operations detected**. The migration adds account/session/token, policy revision, and administrative audit tables plus constraints and relevant event/assessment indexes. It does not recreate or delete historical events or assessments. Downgrade refuses to erase populated administrative history.

## 14. Frontend readiness

The [OpenAPI artifact](admin-openapi.json) and [frontend contract](admin-api-contract.md) specify all endpoint schemas, role requirements, token/cookie behavior, reload/CSRF/refresh flow, pagination/filtering, safe error formats, analytics meanings, policy version conflicts, and recovery. A same-site React + TypeScript dashboard can consume these APIs. No React code was added.

## 15. Known limitations

- Production requires an operator-managed HTTPS ingress, explicit trusted origins/proxies, secret distribution/rotation, and database/Redis permissions. This local Compose stack is not a high-availability production deployment.
- PostgreSQL and Redis do not share a distributed transaction. Fenced/missing snapshots close enforcement; after an independent Redis restore, reconcile the latest PostgreSQL revision before admitting traffic. Successful requests already in flight may finish with their selected snapshot.
- Strict refresh replay revocation requires the frontend to serialize refresh across tabs. There is no grace window. SameSite=Strict intentionally excludes unrelated-domain browser deployments.
- Policy edits start fresh fingerprinted counters. Active restriction inspection reports current fingerprints, bounded to 20 observed services; expired/history-only restrictions remain clearly historical.
- Lists use bounded offset pagination, and ingestion is asynchronous. New/late records can move later pages; fix investigation windows. Long-term archival exports are outside this API.
- Audit and policy history are retained; expired refresh/session rows are invalid but currently require operator-scheduled retention cleanup. Database owners can alter audit rows; external immutable archival, MFA, and recovery workflows are not included.
- Experimental ML retains Phase 4 limitations and cannot raise risk or block traffic. No production classifier claims are made.
- No persistent administrator was left with a generated/discarded test password. Run the interactive bootstrap command to establish your own account. No changes were committed or pushed.

## 16. Exact reproduction commands

For an existing checkout, preserve `.env`, service data, identity key, and demo credential hash. Add a missing signing key, then explicitly configure local HTTP origins/cookies as described in [the contract](admin-api-contract.md#provisioning-and-deployment). A fresh `.env` generated from the example already contains the local development settings.

```sh
# Fresh checkout only (both initializers preserve/refuse existing credentials):
python scripts/init_env.py
python scripts/configure_demo_auth.py --initialize
# Upgrade existing checkout:
python scripts/init_env.py --add-admin-key

docker compose config --quiet
docker compose --profile test build
docker compose up --wait --wait-timeout 180
docker compose exec -T admin-api alembic upgrade head
docker compose exec -T admin-api alembic check
docker compose exec -T admin-api alembic current

docker run --rm -v "$PWD:/workspace:ro" -w /workspace sentinel-ai-tests python -m ruff check --no-cache .
docker run --rm -v "$PWD:/workspace:ro" -w /workspace sentinel-ai-tests python -m ruff format --no-cache --check .
docker run --rm -v "$PWD:/workspace:ro" -w /workspace sentinel-ai-tests python scripts/export_admin_openapi.py --check

docker compose --profile test run --rm tests
docker compose --profile test run --rm tests python scripts/verify_admin.py
python scripts/verify_protection.py
docker compose ps --all
docker stats --no-stream

# Create your lasting first administrator after ephemeral verification accounts are removed:
docker compose exec admin-api python -m sentinel_api.bootstrap --username your-admin-name
```

The Docker bind-mount examples above use Bash `$PWD`. In PowerShell, use `"${PWD}:/workspace:ro"` to delimit the path before the colon. To regenerate the contract, run the exporter in a Linux test container with `docs` mounted writable and pass `--output /output/admin-openapi.json`. Never use `docker compose down --volumes` during verification. Run policy-editing verification scripts sequentially.
