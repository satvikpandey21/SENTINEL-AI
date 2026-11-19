# Phase 9 final verification — November 19, 2026

## Completion status

Repository-side Phase 9 implementation is complete and locally verified. The two reported
notification defects are fixed, an additional keyboard-focus defect is fixed, existing
Phase 1–8 behavior remains intact, and the complete production HTTPS/WSS topology is
implemented and tested locally. **No public deployment occurred.** No VM, domain or hosting
account was available, and no external deployment/tunnel was authorized or started.

Nothing was reset, stashed, committed or pushed. HEAD remains `8028b73`. Existing uncommitted
Phase 7/8 files were preserved. No database volume was deleted, no schema migration was
added, and no core enforcement/risk/ML algorithm was replaced. Phase 9 did not change the
existing Python dependency locks or backend Dockerfile; those already-modified files match
the saved Phase 9 starting hashes.

| Category | Final state |
| --- | --- |
| Implemented and verified | Notification fixes, all seven pages, actual event/analysis/socket pipeline, role/session security, full regressions, private observability, local production TLS/WSS, deployment validation, redacted proxy errors, restart persistence and backup restore |
| Implemented but not publicly verified | Public ACME/DNS configuration, temporary-tunnel configuration, ARM64-compatible image indexes; actual external HTTPS/WSS, public CA issuance and ARM execution were not performed |
| Incomplete/blocked externally | An always-on public endpoint: no user-owned infrastructure/account/domain was available |
| External prerequisites | Obtain an eligible Linux VM and DNS hostname, or explicitly authorize a temporary tunnel; provision the first real administrator and verify the public endpoint from outside the local network |

Detailed commands, environment contract, hosting limits, backup/restore and rollback:
[deployment-guide.md](deployment-guide.md). Current architecture:
[architecture.md](architecture.md#phase-9-final-integration-and-production-ingress).

## Inspection and root causes

The continuation inspected the actual working tree, existing reports/code, both running
stacks, partial deployment files and test artifacts. Existing mobile/background fixes were
retained. Remaining work was final proxy hardening/verification, packaging/backup helpers,
CI wiring, regression completion and documentation. The original Phase 9 Master Prompt and
final-continuation requirements were used as the acceptance checklist.

**Mobile controls:** `.topbar-account > div` hid the notification center's wrapper below
680px. Descendant `.button` and `.badge` rules also affected controls inside its dialog.
Selectors now target the explicit `.account-details` element and direct shell controls.
Header titles can shrink/ellipsis at 320px while navigation, bell, avatar and logout remain
available. Notification buttons, unread badge, severity badges and panel layout retain their
own rules; no essential navigation was removed.

**Empty history despite Connected:** the stream disconnected whenever the document became
hidden. Running traffic from another application could therefore persist genuine events
while no socket was subscribed for that tab. Returning reconnected and reconciled REST,
which updated Events without replaying bell history. Enabling information afterward only
affected future frames. This gap was reproduced with real backend traffic before changing
behavior. Authenticated online background tabs now keep one bounded socket. Visibility return
reconciles REST without needless reconnect; offline/logout/revocation still close access.

The worker commit → Redis Pub/Sub → admin subscriber → socket → runtime parser → eligibility,
classification/grouping/deduplication → React state path was reviewed. Foreground real-service
delivery and valid schema frames worked; no fictional notifications or new threat rules were
introduced. The UI now explains best-effort delivery, background receipt, informational opt-in
and the absence of historical replay. Last activity tracks a valid received notification even
when informational display is disabled. History is bounded to 50, deduplication to 2,048 IDs,
and the 30-second grouping key includes service, endpoint, action, severity and classifications.
Different severities/categories can legitimately create separate alerts.

**Additional confirmed defect:** the strengthened keyboard test found Shift+Tab could move
focus outside the native notification dialog. The shared Modal now wraps first/last enabled,
visible focusable controls for Tab/Shift+Tab, retains Escape close behavior and restores
focus to the trigger. The failing test was fixed, not skipped. The complete viewport/page
matrix then passed. Documentation encoding/newline issues introduced during editing were
corrected; the final text source scan and whitespace checks are clean.

**Deployment gaps completed:** added same-origin static/API ingress, non-root/read-only
sandbox and caps, exact trusted proxy /32, secure production flags, private endpoint routing,
production/tunnel/local-test overrides, generated independent credentials, configuration
validation, backup/release tooling, safe log filtering and reproducible instructions.
A 263 MB build-context observation exposed nested frontend dependencies being included;
`.dockerignore` now excludes nested node_modules, build/test artifacts and environment files.
The final cached source upload was about 622 KB; cache conditions differ, so no throughput
speed-up is inferred from that comparison.

## Executed automated results

These are executed results for the Phase 9 working implementation, not the old Phase 8 totals.

| Check | Result |
| --- | --- |
| Final packaged backend unit + real integration coverage suite | **396 passed in 52.71 seconds** |
| Backend statement coverage | **91.59%**; 3,139 statements, 264 missed; existing 85% gate passed |
| New deployment security unit cases | 16 included in the full suite: unsafe origins, credential preservation, partial initialization, private ports, Secure cookies, proxy trust, root ingress, Grafana and demo-login regressions |
| Frontend Vitest | **72 passed** |
| Frontend statement / branch coverage | **73.09% / 64.77%**; browser execution is not included in these percentages |
| TypeScript, ESLint, Prettier, frontend API contract and production build | Passed |
| Final full development-topology Chromium suite | **10 passed**, 1 production-mode-only scenario skipped here and executed in the dedicated production run; 2.0 minutes |
| Final production-topology Chromium suite | **6 passed**, 1.1 minutes; includes the shared five functional/security scenarios plus explicit HTTPS/WSS/session-revocation acceptance |
| Strengthened mobile/background check after focus fix | **2 passed**, 34.9 seconds; also included in the final 10-pass suite |
| Ruff lint and formatting | Passed; no threshold/test suppression introduced |
| CI and Compose YAML parsing | Passed using the installed YAML parser; all resolved Compose modes validate |
| Alembic drift check | Passed: no new upgrade operations |
| OpenAPI/notification contract | No payload/API schema changes; generated frontend contract checks passed |
| Prometheus config/rules | Configuration valid; all nine rules' pending/firing/recovery/healthy fixtures pass |
| Current advisory audit artifacts | **0 reported npm vulnerabilities** (423 dependencies), **0 reported Python vulnerabilities** (61 packages); locks unchanged since that Phase 9 audit |
| Image architecture metadata | All eight pinned base/service indexes advertise AMD64 and ARM64; runtime tests were AMD64 |
| Git-visible credential scan | No actual local/production-test password, signing/identity key or observability secret found in Git-visible source |

Initial tests deliberately reproduced the mobile/background failures. A later full browser
run found the keyboard defect (9 passed, 1 failed); that failure was corrected before the
final successful runs above. No failing test was disabled. The dedicated production scenario
is selected only when `SENTINEL_E2E_PRODUCTION=1`, because it requires the isolated HTTPS
stack. Existing backend/frontend coverage settings were not lowered.

## Mobile and notification acceptance

Real-service browser tests exercised **320, 375, 390, 400, 768 and 1440 pixels across all
seven authenticated pages** (42 page/viewport combinations). They verify bell visibility,
unread badge boundaries, dialog fit, no document-level horizontal overflow, clear-history
control availability, keyboard focus containment, Escape close and return of focus to the
bell. Existing desktop/mobile navigation and automated accessibility checks also passed.
A rendered 400px notification-panel capture was visually inspected; it shows actual 429
restriction notifications, timestamps, risk/severity, unread state, read/clear controls and
links without clipping.

The live browser acceptance logs ADMIN in through the real API, waits for an authenticated
socket, enables information, sends a real `/api/demo/ping` and 12 limited-endpoint requests
while simulating the browser's hidden-state event, then returns to the page. It verifies the
persisted API notification, genuine restriction notifications, updated last activity/unread
count, mark-read, clear-history and reload without fabricated historical notices. Production
acceptance also queries authenticated event/assessment REST APIs and verifies actual
persisted decision/assessment data alongside received WSS frames.

Backend integration tests and the existing real-time network verifier cover commit-before-
acknowledgement, duplicates, bounded retries/quarantine, rate restrictions/brute-force/expiry,
statistical/ML safety, one-time tickets, Origin checks, distributed leases and revoked
sessions. The final browser suite verifies reconnect and REST reconciliation after an admin
API restart while retaining event investigation state. Cross-tab refresh/logout and ANALYST
restrictions are exercised through actual pages and services.

## Production HTTPS/WSS acceptance

The separate `sentinel-production-test` project uses independent credentials and named
volumes. It adds one Caddy ingress and removes admin/Grafana host bindings. Its only published
ports are **127.0.0.1:8080 and 127.0.0.1:8443**. The original development project remains
separate and unchanged in its network behavior.

The production browser run verified:

- Built React static assets and direct SPA navigation behind the proxy.
- Same-origin HTTPS login and real protected API queries.
- `__Secure-sentinel-refresh` with Secure, HttpOnly, SameSite=Strict and `/api/admin/auth`
  scope; reload rotates its value and restores the session.
- Cross-tab coordination, logout, ADMIN policy/account/audit workflows and ANALYST restrictions.
- Wrong-Origin CSRF preparation rejected with 403.
- Authenticated **wss://localhost:8443** sockets, real restriction frames and unread UI updates.
- Offline reconnect with fresh authorization and REST reconciliation.
- Server-side logout performed without notifying React, followed by periodic WSS authorization
  closing access and routing to login; the former access token then returned 401.
- No credentials in localStorage/sessionStorage or WebSocket query strings.
- Public metrics/demo/private-health requests rejected with 404.

The browser's dedicated localhost test mode accepts Caddy's untrusted private test CA.
Separately, `verify_deployment.py` loads that exported public CA certificate and performs
normal certificate/hostname verification using Python SSL. This proves encrypted local TLS
and the production authentication topology; it is **not proof of publicly trusted HTTPS**.
No CA was installed in the user's host trust store. Public ACME issuance remains NOT VERIFIED.

Additional deployment acceptance passed:

- Production and tunnel Compose modes validate without publishing an endpoint.
- Both proxy config variants parse; the fixed ingress is non-root/read-only and the private
  edge network is internal.
- Real compiled static assets contain none of the generated deployment credentials.
- A stopped isolated admin API caused a 502; canary URL/header/ticket/cookie values did not
  appear in Caddy error logs after whole request/header objects were filtered.
- Restarting isolated PostgreSQL, Redis, RabbitMQ, worker and admin preserved **44 events**
  and the sampled original event ID.
- A binary-safe custom-format backup restored **44 events** into a newly created disposable
  database. The original database was untouched; only the explicitly created restore-test
  database was removed. No volume was deleted.

## Security review and limits

No unresolved critical application defect was identified in this scoped review. JWT
signature/issuer/audience/expiry validation, rotating hashed refresh secrets, family locks,
revocation, CSRF/Origin, server-authoritative roles, safe validation/errors and parameterized
queries remain unchanged. Access/CSRF credentials stay in memory; refresh secrets stay in
HttpOnly cookies. WebSocket tickets remain random, short-lived, one-use, session/role/Origin
bound, and absent from URLs/logs. Background connection retention does not relax these checks.

Public production networking exposes only the application ingress; Grafana is loopback/SSH-
only, Prometheus and data/broker services remain private. The development-only login is
forced off. The fixed trusted proxy address replaces incoming forwarded peer chains.
Root capabilities, writable filesystems and unbounded proxy request sizes are not required.
Operational credentials remain independent and ignored; no Docker socket is mounted.

Dependency advisory results cover Python/npm packages, not every operating-system package
or future vulnerability. Base-image OS CVE scanning, a complete external penetration test,
ARM execution, public CA issuance and external-network acceptance are **NOT VERIFIED**.
Pinned multi-architecture images and sandbox/configuration checks are implemented, but do
not substitute for those separate checks. Experimental ML remains disabled by default,
non-authoritative and dependent on trusted artifacts; no live production detection accuracy
or new algorithm performance is claimed.

## Performance, resources and observability

Backend detection/storage algorithms and query plans were preserved. Existing bounded
pagination, indexed queries, operation deadlines, publisher/worker queues and WebSocket
caps remain. The focus and background fixes add no dependency or unbounded per-client
state. Background tabs can retain one authenticated socket until offline/logout/revocation;
browser freezing can still interrupt best-effort delivery. REST remains authoritative.

Final frontend main bundle: **307.34 KB / 97.88 KB gzip**, versus the Phase 8 report's
306.53 KB / 97.55 KB gzip. CSS is **36.09 KB / 8.78 KB gzip**, versus 35.73 KB / 8.73 KB.
The chart chunk remains 195.51 KB. These are build-size observations, not latency benchmarks.
No speculative database/Redis/React rewrite was made.

Production limits: PostgreSQL 768 MiB, Redis 128 MiB, RabbitMQ 512 MiB, admin 512 MiB,
demo 256 MiB, worker 512 MiB, ingress 256 MiB, plus the existing 512 MiB each for Prometheus
and Grafana. Long-running ceilings sum to 3,968 MiB, excluding short-lived build/test/init
processes and Docker/OS overhead. CPU caps are ceilings rather than guaranteed reservations.
The proxy uses a 128 MiB Go memory target, 16 KB header limit, 64 KB body limit and read/idle
bounds; logs rotate at 10 MiB × 3. Existing metrics retention/cardinality/query limits remain.

Final health, resource snapshots, live scrape results and recovery evidence are recorded in
the final-state section below. Observability and dependency failures are exercised after
browser tests, so the intentional interruptions do not invalidate their integration evidence.

## Files created and changed

New production assets:

- `compose.production.yaml`, `compose.production-test.yaml`, `compose.tunnel.yaml`.
- `infra/deploy/Dockerfile`, `Caddyfile`, `Caddyfile.local-test`, `Caddyfile.tunnel`,
  `common.caddy`, `production.env.example`.
- `scripts/init_production.py`, `deploy.py`, `verify_deployment.py`,
  `backup_deployment.py`, `package_release.py`.
- `tests/unit/test_deployment.py`, `apps/dashboard/e2e/phase9.spec.ts`,
  `apps/dashboard/e2e/production.spec.ts`.
- This report and `docs/deployment-guide.md`.

Focused existing-file changes: `AppLayout.tsx`, shared `Modal.tsx`, notification center,
stream and stream tests, layout/components/responsive CSS, browser fixtures/configuration,
`.dockerignore`, CI, README, architecture/API/observability docs. Existing Phase 7/8 backend
and realtime implementation files remain intact. Private environments/secrets, screenshots,
backups, logs, dependency-audit output and release artifacts remain ignored. No runtime
library was added or existing coverage threshold changed.

CI now builds and verifies the normal stack, then an independent local-CA production stack,
checks proxy/persistence behavior and runs production browser acceptance. It uploads only
intended coverage/build/screenshots/model-evaluation artifacts, not secrets or backups.
Hosted CI itself was not executed from this local session; local equivalent checks were run.

## Exact commands and release decision

From the existing workspace root:

```powershell
python scripts/init_observability.py
docker compose up --build -d --wait --wait-timeout 180
cd apps/dashboard
npm.cmd run dev
```

For the isolated production acceptance stack:

```powershell
python scripts/init_production.py --origin https://localhost:8443 --local-test
python scripts/deploy.py up --env-file .env.production-test --project sentinel-production-test --mode local-test
python scripts/verify_deployment.py --fault-check
cd apps/dashboard
$env:SENTINEL_E2E_PRODUCTION='1'
npm.cmd run test:integration
Remove-Item Env:SENTINEL_E2E_PRODUCTION
```

On an authorized Linux VM after configuring a DNS name you control:

```sh
python scripts/init_production.py --origin https://sentinel.your-domain.example
python scripts/deploy.py validate
python scripts/deploy.py up
```

All commands run from the repository root unless `cd` is shown. See the deployment guide
for independent admin bootstrap, backup/restore/rollback, normal verification commands and
temporary tunnel setup. No cloud credential, account signup or public tunnel was attempted.

**Go:** the tested local demonstration and repository-side production deployment preparation.
**No-go for claiming public deployment:** obtain user-owned hosting/DNS or explicit temporary-
tunnel authorization, then verify publicly trusted HTTPS login/rotation and authenticated
WSS from outside the local network. A temporary tunnel is not permanent hosting. The source
release includes the current uncommitted implementation; nothing was committed or pushed.


## Final state and recovery evidence

At the final check, all **eight development services** and all **nine isolated production-
topology services** were running and healthy. Migration and monitoring-bootstrap jobs
completed successfully. No user/frontend process was stopped to perform deployment tests;
only test-owned preview/browser processes and explicitly isolated service faults were used.

All **six canonical Prometheus targets** reported up: admin, demo, worker, native broker
aggregate, native broker queue scrape and Prometheus self-scrape. Grafana's five provisioned
dashboards and **47 real panel queries** passed, and its data source health was OK. The nine
operational rules all reported health `ok` and state `inactive`. Authenticated private app
scrapes worked while missing/incorrect/duplicate credentials were rejected; unauthenticated
Grafana/broker scraping and public API metrics access were rejected as designed.

The final live metric acceptance recorded exactly **+3 HTTP request counter** and **+3
latency histogram observations** for three owned ping requests, seven real 429s / temporary-
block decisions, committed events/assessments and an active socket gauge increasing by one
then returning to baseline. Exported payload/privacy/cardinality checks passed. Final sample
counts: 237 admin, 243 demo, 192 worker; Prometheus subsequently
contained HTTP route count 45.0. These are observations after process restarts, not
permanent totals or a theoretical cardinality bound.

Sequential dependency recovery passed: denying only Redis notification PUBLISH preserved
eight committed HTTP events and 429 enforcement; total Redis loss failed managed policy
protection closed with 503; RabbitMQ loss preserved Redis restrictions; five confirmed
queued requests reconciled after PostgreSQL/worker recovery. New owned events persisted
after each recovery and all stopped services/permissions were restored.

Stopping Prometheus and Grafana preserved both API readiness responses at 200 and three
additional committed requests. Three ADMIN/ANALYST socket clients received 47 unique
notifications from 43 controlled requests, with duplicate-delivery suppression, privacy
checks and revoked-session close code 4401. Observability recovered afterward. There were
141 observed post-commit receipts: median 14.286 ms, maximum 41.789 ms; median fan-out spread
0.077 ms, and ticket/reconnect/REST reconciliation took 47.313 ms. This is a small local
verification sample, not a production latency objective or a controlled comparison to
Phase 8's measurements.

A post-acceptance snapshot measured approximately **779 MiB for development** and
**750 MiB for the isolated production topology**, **1.49 GiB combined** within the available
7.55 GiB Docker budget. Caddy used 12.25 MiB, production Prometheus 38.71 MiB and production
Grafana 340.2 MiB. One development RabbitMQ sample briefly reported 199.11% CPU after the
acceptance activity; a quiet follow-up measured 3.69% (production broker 3.52%). No sustained
broker CPU fault was observed. These snapshots are not peak-load or capacity guarantees.
Production ingress/data/application caps and the observability caps were retained.

The current source, including uncommitted Phase 7?9 files, is packaged using the release
helper in the ignored `.artifacts` directory. Private environments/secrets, database backup,
TLS state and test logs are excluded from that source package. The final source/secret,
UTF-8, whitespace, lint/format and configuration checks passed. The archive is a local
handoff artifact, not a commit, upload or deployment.
