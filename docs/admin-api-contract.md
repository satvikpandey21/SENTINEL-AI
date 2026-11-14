# Administrative API contract (Phase 5)

The versioned backend contract is [admin-openapi.json](admin-openapi.json). Generate TypeScript types from that file; the development service also serves `/openapi.json` and `/docs`. Production disables these public documentation routes. The base path is `/api/admin`. The Phase 6 React dashboard consumes this contract; WebSockets and Grafana remain outside its scope.

## Provisioning and deployment

```sh
python scripts/init_env.py --add-admin-key
# For existing local HTTP installations, add these explicit settings to the private .env:
# SENTINEL_ADMIN_DEPLOYMENT=development
# SENTINEL_ADMIN_COOKIE_SECURE=false
# SENTINEL_ADMIN_ALLOWED_ORIGINS=["http://localhost:5173","http://localhost:8000"]
docker compose --profile test build
docker compose up --wait --wait-timeout 180
docker compose exec admin-api python -m sentinel_api.bootstrap --username your-admin-name
```

The last command prompts twice without echo. Passwords must be 15–128 characters; account names are 3–64 lowercase ASCII letters, digits, dots, underscores, or hyphens, starting with a letter or digit. Bootstrap uses a PostgreSQL advisory lock and works only while the account table is empty. It creates an active ADMIN and an audit record. Subsequent provisioning requires an authenticated ADMIN. There is no public registration, seeded administrator, default password, password argument, or coupling to demo authentication. Do not bootstrap through a shared terminal recording.

`SENTINEL_ADMIN_SIGNING_KEY` is an independent 32-byte random value encoded as 64 lowercase hexadecimal characters. The initializer preserves existing service credentials and populated keys. Only the administrative service receives this key in Compose. Keep it stable across administrative replicas. Rotating it invalidates access tokens; revoke existing PostgreSQL sessions as well when responding to a compromise. Issuer/audience defaults are `sentinel-admin` / `sentinel-dashboard`. Optional settings use the `SENTINEL_ADMIN_` prefix: `ACCESS_SECONDS` (60–900; default 300), `SESSION_SECONDS` (300–86400; default 28800), `ISSUER`, `AUDIENCE`, `LOGIN_ATTEMPTS`, and `LOGIN_WINDOW_SECONDS`.

For production, set both `SENTINEL_ENVIRONMENT=production` and `SENTINEL_ADMIN_DEPLOYMENT=production`, `SENTINEL_ADMIN_COOKIE_SECURE=true`, and explicit HTTPS frontend origins. Terminate TLS at your ingress and configure only its real trusted proxy CIDRs. The default deployment is production with Secure cookies. HTTP cookies require an explicit development setting; the example `.env` is local development configuration. No CORS wildcard or arbitrary Origin reflection is used.

The supported browser topology is **same site**: for example `https://dashboard.example.com` and `https://api.example.com`, or a single reverse-proxied origin. A frontend on an unrelated registrable domain is intentionally unsupported with `SameSite=Strict`. In local development use `localhost` for both the frontend and API, rather than mixing `127.0.0.1` and `localhost`.

## Browser authentication flow

All authentication POST requests require an exact configured `Origin` and `X-CSRF-Intent: sentinel-admin`. Browser fetch supplies Origin automatically. CLI clients must explicitly supply it. Use `credentials: "include"` for login, CSRF preparation, refresh, and logout.

| Method and path | Input | Output / behavior |
|---|---|---|
| `POST /auth/login` | JSON `{username, password}` | 200 token envelope; sets refresh cookie |
| `POST /auth/csrf` | Refresh cookie and Origin/intent headers | 200 `{csrf_token}`; replaces the current unused token's CSRF digest |
| `POST /auth/refresh` | Refresh cookie, Origin/intent, `X-CSRF-Token` | 200 new token envelope and rotated refresh cookie |
| `POST /auth/logout` | Refresh cookie, Origin/intent, `X-CSRF-Token` | 204; revokes the session family and expires its cookie |
| `GET /auth/me` | Bearer access token | 200 public account fields |

The token envelope has `access_token`, `token_type: "Bearer"`, `expires_in` (seconds), `csrf_token`, and `account: {id, username, role, active, created_at}`. The refresh token never appears in JSON. Store access and CSRF tokens **only in memory**, and send access tokens in `Authorization: Bearer <access_token>`. Never use localStorage, sessionStorage, URLs, or analytics/logging instrumentation for either token. Authentication responses and all administrative responses use `Cache-Control: no-store`.

On page reload, call `POST /auth/csrf` with the refresh cookie, then refresh with the returned nonce. On access expiration, serialize one refresh operation, update both in-memory tokens, and retry the original request once. Serialize refresh across tabs using a browser lock and communicate completion through BroadcastChannel. The strict replay policy intentionally revokes the entire family if two requests use the same refresh generation: one receives 200, the other receives 401, and even the first response's access token becomes invalid. There is no replay grace period. A concurrent CSRF preparation can invalidate another tab's old nonce; prepare again after coordinating the tabs. Clear in-memory authentication and return to login after 401.

In production the cookie is `__Secure-sentinel-refresh`, HttpOnly, Secure, SameSite=Strict, host only, and scoped to `/api/admin/auth`. Development without Secure uses `sentinel-refresh`. Its Max-Age is the remaining absolute session lifetime. Rotation does not extend the eight-hour default lifetime. The cookie is not an access credential for event APIs. CSRF values are independent random nonces, stored only as digests alongside the refresh digest. Origin validation and the custom intent header protect login and reload preparation; refresh/logout additionally require the nonce. CORS explicitly allows only configured origins and the necessary headers/methods.

Access tokens use a fixed HS256 algorithm and `typ: at+jwt`. Validation requires signature, exact issuer and audience, integer `iat`/`nbf`/`exp`, bounded lifetime, UUID subject/session, random JTI, and `token_type: access`. Role claims are not trusted: every privileged request joins the active account to its unrevoked, unexpired PostgreSQL session. Logout, account deactivation, password change, and role changes invalidate sessions immediately for subsequent requests. Already executing requests may finish. Tokens carry no client IP or password data.

Refresh tokens contain 256 random bits. PostgreSQL retains SHA-256 digests, used-token tombstones, CSRF digests, and session expiration/revocation timestamps. It stores no recoverable refresh secrets. A family row lock serializes refresh, replay, and logout operations. Replay revocation commits before the 401 response. Database failure prevents authentication; Redis failure prevents login/session authentication operations. Login uses atomic Redis limits per HMAC account name and pseudonymous peer (10 attempts/account/5 minutes; peer budget 50 by default). Session endpoints have a separate 120-operation peer budget per five minutes. Successful attempts count toward these budgets. Limits apply before password work; at most two Argon2 operations run concurrently per process.

## Authorization

| Operation | Unauthenticated | ANALYST | ADMIN |
|---|---|---|---|
| Health endpoints | Allowed | Allowed | Allowed |
| Events, assessments, analytics, client investigations | 401 | Read | Read |
| Policy reads | 401 | Read | Read |
| Policy updates / reconciliation | 401 | 403 | Allowed |
| Account list/create/update | 401 | 403 | Allowed |
| Administrative audit reads | 401 | 403 | Allowed |

All account and policy writes additionally require the Origin/intent headers. Account creation accepts `{username,password,role}`; role is ADMIN or ANALYST and the new account is active. `PATCH /accounts/{id}` accepts optional `active`, `role`, and `password`. Password/role/activation operations revoke every session for the target account. The last active ADMIN cannot be disabled or demoted. `GET /accounts` returns the standard page envelope. No password hash is ever returned.

## Query and pagination rules

List responses are `{items: [...], total, limit, offset}`. `limit` defaults to 50 and is bounded to 1–100; `offset` defaults to 0 and is bounded to 0–10000. Ordering is newest timestamp first, then UUID descending, providing deterministic ties. Counts use the same filters as items. Offset pages are suitable for the bounded dashboard; new or late-ingested rows can shift later pages. Use a fixed `start`/`end` while investigating. Deep archival export is outside this API.

Monitoring, assessment, analytics, client, and audit queries default to the last 24 hours. `start` and `end` must be timezone-aware ISO 8601 timestamps. The interval is **[start, end)** and must be positive and no longer than 31 days. UTC timestamps are returned. Monitoring metrics/filtering use event `occurred_at`; assessment metrics/filtering use `analyzed_at`. Ingestion and analysis are asynchronous, so recent windows can gain rows after a request completes. Unknown query fields, unrecognized enums, invalid route templates, and unbounded pagination are rejected with 422.

| Endpoint | Additional filters / purpose |
|---|---|
| `GET /events` | `service`, `event_type`, `severity`, `security_action`, `endpoint`, `request_id`, `client_identifier`, `start`, `end`, pagination |
| `GET /events/{event_id}` | UUID lookup; 404 if missing |
| `GET /assessments` | `service`, `severity`, `classification`, `detection_method`, `event_id`, `client_identifier`, `min_risk` (0–100), `start`, `end`, pagination |
| `GET /assessments/{assessment_id}` | UUID lookup; 404 if missing |
| `GET /analytics` | `service`, `start`, `end`, `bucket=hour\|day` |
| `GET /clients/{client_identifier}/activity` | `service`, `start`, `end`; bounded investigation result |
| `GET /audit` | ADMIN; `actor_id`, `action`, `outcome`, `start`, `end`, pagination; no service filter |

Event types are `http.request.completed` (schema 1) and `security.decision` (schema 2). Event severities are `info`, `warning`, `error`. Actions are `record`, `rate_limit`, `temporary_block`, `deny`. Endpoints must be exact sanitized registered templates (e.g. `/api/demo/items/{item_id}`), or `unmatched`; query strings are rejected. Client IDs are 64 lowercase hexadecimal HMAC identifiers and request IDs are 32 lowercase hexadecimal characters.

Event output explicitly permits correlation IDs, schema/type, UTC time, service, HTTP method, sanitized endpoint, status, duration, pseudonymous client identifier, severity, authentication outcome, response completion, and nullable decision fields (`rule_id`, action, counter/threshold/window, retry time, restriction expiration, degraded). It never contains raw IP, request bodies, arbitrary paths, headers, query values, credentials, cookies, or tokens.

Assessment output contains assessment/event IDs, service, pseudonymous client identifier, risk score, severity, rule/model/feature versions, analysis time, and an allowlisted evidence schema. Evidence includes threats with classification/method/rule IDs, numeric deterministic/statistical evidence, grouped contributions, statistical availability/flags, and explicit experimental ML status/score/model version. It omits private behavioral profiles and unknown JSON extensions. Assessment severities are `low`, `moderate`, `high`, `critical`. Methods are `deterministic`, `robust_statistics`, `isolation_forest`. Classification enums and complete field shapes are in OpenAPI. ML is supporting evidence only; it neither raises risk scores nor triggers enforcement.

Client investigations return window-bounded first/last event times, at most 50 recent requests, 50 related assessments, 50 policy violations, and 50 historical temporary restriction events. `active_restrictions` checks live Redis TTLs for the client's first 20 observed service names (alphabetical) across at most 32 managed policies, in one bounded pipeline. Each result has service, policy ID, remaining seconds, and observation time. Historical expiration fields are not asserted to be currently active. A client identifier can represent a shared NAT, proxy, or changing network context; it does not uniquely identify a person. Unknown identifiers have meaningful empty activity arrays and null timestamps.

## Analytics semantics

`GET /analytics` runs PostgreSQL aggregates in one repeatable-read transaction with a five-second statement timeout. Empty databases produce zero counters and empty arrays. No mock fallback is used. Response fields:

| Field | Meaning |
|---|---|
| `start`, `end`, `bucket` | Applied window and UTC hour/day grouping |
| `monitored_requests` | Count of schema 1 HTTP completion records only |
| `security_decisions` | Count of schema 2 decision records only |
| `rate_limit_violations` | Schema 2 events with action `rate_limit` |
| `temporary_blocks` | Schema 2 events with action `temporary_block`; includes repeated decisions during a restriction, not distinct block episodes |
| `requests_over_time` | `{timestamp,count}` for populated UTC buckets, schema 1 only; frontend can fill missing buckets with zero |
| `status_distribution` | `{key,count}` with HTTP status string keys; schema 1 only |
| `threats_by_severity` | Counts of assessments containing at least one threat, grouped by assessment severity |
| `threats_by_classification` | Distinct assessment count per persisted threat category; one assessment can belong to multiple categories |
| `risk_distribution` | All assessments grouped into `[0,25)`, `[25,50)`, `[50,75)`, `[75,100]` |
| `targeted_routes` | Top 20 sanitized routes by schema 1 traffic, ties alphabetical; includes benign traffic |
| `recent_alerts` | Latest 20 nonzero-risk assessments, deterministic timestamp/ID ordering |
| `suspicious_clients` | Latest 20 service/client groups with nonzero-risk assessments: count, maximum risk, latest analysis time |

Requests and decisions are never added together. One request can emit multiple decisions and multiple per-event assessments. Threat/assessment counts describe analysis records, not unique incidents or people. Zero-risk experimental evidence remains available in assessment queries even if it is absent from the nonzero-risk alert list.

## Policies and audit records

`GET /policies` returns `{version,created_at,policies,enforcement_synchronized}`. `GET /policies/{policy_id}` returns the individual configuration. `PUT /policies` replaces the bounded policy set with `{expected_version,policies}` and returns the resulting document. The full EndpointPolicy schema and nested rate/authentication rule bounds are in OpenAPI. A stale expected version returns 409. Invalid or unsafe configurations return 422.

Managed changes preserve existing protected IDs, prefixes, method scopes, existing rate/authentication rules, and closed failure modes. Policies cannot be disabled, emptied, or left without a rule through this API. Existing threshold/action/window configuration remains editable, and new non-overlapping policy groups can be added up to 32. Block actions must cover the relevant window. Use a reviewed deployment/migration if a protected scope must be retired. Policy IDs and fingerprints are not secrets.

The PostgreSQL advisory lock serializes writers. A Redis fence closes enforcement before the revision and successful change audit commit together. Activation is compare-and-set against that fence; an older writer cannot overwrite a newer revision. Every protected request loads the shared Redis snapshot without a per-process policy cache. All replicas must use the same PostgreSQL database, Redis database, HMAC identity key, and `SENTINEL_DYNAMIC_POLICIES=true`. Compose configures this for both APIs. The first initializer seeds environment policies once; subsequent environment edits do not override persisted revisions.

A successful 200 update means Redis activation completed. 503 can mean a revision committed but activation is pending: reload the policy document before retrying, rather than blindly resubmitting an old version. During a fence, a missing snapshot, or unavailable Redis, managed enforcement returns 503 even if an individual policy previously permitted failure-open behavior. Requests already in flight retain their selected policy until completion. Rule edits change fingerprints and start new counter windows; old counters/restrictions expire under their original TTLs. Active restriction inspection covers current fingerprints.

`POST /policies/reconcile` (ADMIN, Origin/intent) reactivates the latest PostgreSQL revision after an interrupted update or Redis restore. Service startup also reconciles. Redis persistence/failover is not a distributed transaction with PostgreSQL: after restoring Redis independently, reconcile before admitting traffic; readiness detects a missing/fenced snapshot. The admin API itself remains available for recovery because its authentication limiter is independent of demo protection rules.

Audit records contain ID, actor ID (null for unknown/system actors), action, UTC time, target template/ID, outcome (`success`/`rejected`), and an allowlisted change summary. Account provisioning/changes, login success/failure, throttling, refresh/replay/logout, policy revisions, reconciliation, invalid authenticated writes, and role denials are audited. Unknown-login account names and credential values are never recorded. Historical actor IDs are retained without a cascading account foreign key. Audit storage is durable PostgreSQL history, not an immutable external ledger. The application has no audit editing/deletion endpoint.

## Errors and examples

Errors have `{"detail":"fixed safe message"}`; validation adds `errors: [{location: ["body","password"],type:"too_short"}]` without input values or Pydantic context. Unexpected errors have a fixed detail and request ID. `X-Request-ID` correlates requests. Authentication failures use the same generic 401 detail and `WWW-Authenticate: Bearer`; 403 means insufficient role, Origin, or CSRF; 404 missing resource; 409 version/account conflict; 422 invalid input; 429 throttling with Retry-After; 503 unavailable security dependency or pending activation. The OpenAPI error model permits these fields.

After interactive authentication, these are the actual resource requests (supply your in-memory bearer value):

```http
GET /api/admin/events?service=sentinel-demo-api&event_type=http.request.completed&limit=20&offset=0
Authorization: Bearer <access_token>

GET /api/admin/events?request_id=<32-character-request-id>
Authorization: Bearer <access_token>

GET /api/admin/assessments?event_id=<event-uuid>
Authorization: Bearer <access_token>

GET /api/admin/assessments?severity=high&detection_method=deterministic&limit=20
Authorization: Bearer <access_token>

GET /api/admin/analytics?service=sentinel-demo-api&bucket=hour
Authorization: Bearer <access_token>

GET /api/admin/clients/<64-character-hmac>/activity?service=sentinel-demo-api
Authorization: Bearer <access_token>
```

For a repeatable real HTTP demonstration with ephemeral random credentials and SQL-checked analytics:

```sh
docker compose --profile test run --rm tests python scripts/verify_admin.py
```

It preserves existing accounts, restores original policies, removes its temporary accounts/sessions, retains audit evidence, and prints no tokens or passwords. It intentionally produces monitored demo traffic, which remains in the historical event store. Use `--origin`/`--base-url` for a different configured deployment. See [executed verification](day-5-verification.md).

Design references: [Argon2 password hasher](https://argon2-cffi.readthedocs.io/en/stable/api.html), [PyJWT validation](https://pyjwt.readthedocs.io/en/stable/api.html), [OWASP CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html). Local implementation and test evidence remain the source of truth for this contract.
