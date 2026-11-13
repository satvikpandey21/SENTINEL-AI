# Phase 4 verification — explainable threat analysis

Verification date: November 13, 2026 (Asia/Calcutta). Manual frontend/visual acceptance remains deferred. This record concerns automated backend and real-service verification.

## Implemented architecture and privacy

The existing ASGI → bounded publisher → durable RabbitMQ → independent worker pipeline is preserved. The worker injects `AnalysisEngine` into `EventStore`. A new audit insert, a row-locked client profile update, and an event-linked assessment commit together before broker acknowledgement. Duplicate UUIDs mutate nothing. A transaction failure rolls back every analysis effect; the existing retry/dead-letter/replay path applies unchanged. Different workers serialize the same service/HMAC profile through PostgreSQL row locks. No analysis event is republished, so there is no processing loop. Version 1 HTTP and version 2 decision wire schemas are unchanged.

Features and evidence contain registered route templates, generated request IDs, HMAC client identifiers, counters, outcomes, timestamps, and numeric summaries. They never inspect credentials, bodies, query strings, cookies, headers, or raw IPs. There is no new public data endpoint. `AssessmentRepository` supplies a bounded internal read boundary for a future authenticated dashboard. Existing Redis protection does not import or depend on analysis or ML.

## Scoring methodology (`risk-v1`)

Assessments use observed unique requests in a UTC tumbling window (60 seconds by default). Strengths are in [0,1]; multiply by configurable weights, combine the groups below, round to two decimals, then clamp to [0,100]. The score prioritizes investigation; it is not an attack probability.

| Group | Default weight | Strength |
| --- | ---: | --- |
| Volume | 25 | Zero through half the configured request threshold; above that, `min(1, requests / request_threshold)`; threshold defaults to 600 |
| Authentication | 40 | `min(1, min(1, failures/5) * (1 + 0.25*sensitive_fraction))` |
| Policy | 40 | Maximum of `min(1, rate_violations/3)` and `min(1, max(0, restriction_episodes-1)/2)` |
| Behavior | 20 | Statistical endpoint-entropy/timing deviation, or supported residual error deviation; high residual error fraction contributes only with minimum traffic |

The combined score is **authentication + max(volume, policy) + behavior**, capped at 100. Volume and rate violations share a cause and are not added. Request/auth statistical flags provide context without another contribution. Error-rate behavior first subtracts authentication-failure and rate-violation fractions, conservatively avoiding duplicate contributions for those errors. Repeated checks of one existing restriction expiry count as one episode. Sensitivity does not score a normal sensitive visit. Infrastructure-degraded decision events do not count as rate violations or new restrictions.

Severity thresholds are low <20, moderate 20–<50, high 50–<80, and critical ≥80 by default. Categories include possible brute force only when the configured observed failure threshold is reached; excessive requests; repeated authentication failures; repeated policy restrictions; statistical behavioral deviation; and explicitly experimental ML anomaly evidence. Each stored classification includes severity, score, evidence, rule identifiers, method, timestamp, and model version when applicable. Scores and contributions remain available for normal traffic even when no threat category applies.

The effective scoring weights/thresholds and a canonical configuration digest accompany evidence. All replicas must use the same analysis configuration; changes reset the affected behavioral profile. Scores do not introduce a second blocking mechanism. Phase 3 rules retain sole authority over rate limiting and temporary blocks.

## Aggregation and statistical detection

The default profile holds at most 2,048 request entries and 32 completed numeric window summaries. v1/v2 events sharing one server request ID merge instead of increasing request count twice, irrespective of arrival order. Current-window route distribution, Shannon entropy, error/auth/rate fractions, distinct restriction episodes, mean inter-request gap, population timing coefficient of variation, and sensitive-route fraction are extracted. Baselines omit route dictionaries to bound storage. Windows are aligned to the UTC epoch and never overlap.

A window becomes a baseline only when completed, unsaturated, and containing at least ten requests. There must be at least eight valid completed windows. Missing/malformed baseline records are ignored; low traffic and warm-up return explicit insufficient-data statuses rather than anomaly flags. Idle profiles older than state retention discard their baseline. Late prior-window events remain auditable but cannot rewrite a finalized baseline; expired or >5-second future observations are excluded. Saturation exposes capped counts as lower bounds, disables statistical/ML claims for that window, and preserves deterministic threshold evidence. A single exact-boundary request belongs to the new window; this is a tumbling-window limitation relative to Phase 3 sliding limits.

For each supported feature, the robust deviation is `(x - median) / max(1.4826*MAD, floor)`. Entropy/timing use absolute deviations. Count, error rate, and authentication-failure rate use upper-tail deviations. Default threshold: 3.5. Floors are count=5 requests, error/auth rates=0.05, and entropy/timing-CV=0.25. These finite floors handle zero MAD and prevent tiny numerical changes from becoming enormous scores. Evidence stores feature, observation, median, effective scale, robust z-score, and rule ID. Current partial windows can support upper-tail count/rate evidence, while ML uses completed windows only.

Assumptions: a client pseudonym's recent completed windows are a useful comparison; baselines may contain attacks; shared NAT clients, seasonality, legitimate releases, quiet windows, and route changes can defeat this assumption. There is no global reputation or validated attack signature. A statistical deviation is not proof of malice.

## ML training, artifact safety, and inference

The experimental detector is Scikit-learn **1.8.0 IsolationForest**, 32 trees, `max_samples=128`, all eight features, `random_state=41`, `n_jobs=1`, `contamination='auto'`. Isolation Forest is a bounded, inexpensive unsupervised starting point when representative labels are absent; it provides anomaly evidence rather than a supervised security classification.

Feature schema `behavior-v1`, ordered: request count, error rate, auth-failure rate, rate-violation rate, endpoint entropy, mean interval, timing CV, sensitive fraction. Count and interval use `log1p`; all inputs are finite and bounded, and tree evaluation uses float32 values matching Scikit-learn. Axis-aligned trees do not require standard scaling. Export parity against `-score_samples` is checked on every controlled evaluation row. The anomaly score is a path-length statistic, not a calibrated probability.

Training is offline. The runtime image excludes NumPy/SciPy/Scikit-learn; it interprets only a narrowly versioned, data-only JSON tree export. It never loads pickle/joblib or arbitrary Python objects. Deployment supplies an independently trusted SHA-256 pin. Loading is once per worker startup, with a regular-file check, no-follow/nonblocking open where supported, a 2 MB read/size ceiling, strict exporter/trainer/model/schema/window compatibility, finite thresholds, 32 trees, ≤255 nodes/tree, depth ≤7, and validated acyclic topology. Models mounted read-only are not auto-reloaded. Changing a model requires a deliberate worker deployment.

Inference happens only on rotation of a completed eligible window; the evidence carries that window's features/end time. Each traversal checks the default 10 ms budget and has at most 256 node steps. This is a bounded algorithm and cooperative deadline in the worker, not a hard real-time operating-system guarantee. Artifact reading is bounded local-file I/O. Disabled, untrusted, missing, invalid, incompatible, insufficient-traffic, timeout, and inference-error outcomes are explicit. Unexpected ML errors are contained. Deterministic assessment and Redis enforcement continue. ML contributes **zero** risk points and never blocks.

Primary references: [Scikit-learn IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html) and [model persistence risks](https://scikit-learn.org/stable/model_persistence.html).

## Controlled dataset and evaluation protocol

No representative production corpus or trustworthy attack labels exist in this repository. `model_training.controlled_windows` generates **synthetic owned development telemetry windows**, derives their aggregates through the shared extraction layer, and keeps them out of production event queues/tables. There are no external datasets, paid services, or API keys.

- Training: 512 normal windows, seed 4101; 30–90 requests/window, three controlled endpoints, low independent error/auth-failure probabilities, uniform request times.
- Calibration: 128 separate normal windows, seed 4102; threshold is the greater of 0.5 and the 99th percentile of their anomaly scores.
- Held-out normal evaluation: 256 windows, seed 4103.
- Held-out controlled anomalies: 64 bursts (500–1,000 requests, seed 4200), 64 concentrated authentication patterns (25 failures, seed 4201), 64 high-error/high-route-diversity patterns (seed 4202).
- Benign distribution-shift challenge: 128 windows with 100–180 requests, seed 4301.

Seeds, labels, and the calibration method are fixed before evaluation. There is no fit on evaluation records and no tuning against their labels. Pairwise record hashes reject overlap across training, calibration, and evaluation partitions; the report includes partition SHA-256 digests. Training reproducibility compares complete canonical artifact bytes, not just predictions. Normal and anomalous cohorts are evaluated separately with confusion counts, plus a benign-shift false-positive count.

The first executed benchmark produced TN=256, FP=0, TP=66, FN=126, and 0/128 benign-shift flags. Threshold=0.66071370038221; export-vs-Scikit-learn score difference was zero. A normal example scored 0.445305364778008; one missed burst scored 0.46291503604807627, below threshold. The burst was intentionally retained as a miss. The model was not tuned to make the evaluation look stronger.

**This is an experimental anomaly detector with substantial false negatives, not a validated attack classifier.** Zero false positives in a small toy cohort provides no production guarantee. The distributions are deliberately simple, incomplete, and not representative of real clients. Reviewed representative traffic, tenant/endpoint-specific baselines, drift monitoring, and independent validation would be required before security-classifier claims or any ML enforcement policy.

`models/evaluation.json` contains the final machine-readable report; `models/experimental-iforest-v1.json` is the reproducible development artifact. It is not enabled by default.

## Configuration, retention, and deployment

Set worker-only `SENTINEL_ANALYSIS` to a JSON `AnalysisPolicy`. Supported settings include `enabled`, `window_seconds`, `max_requests`, `baseline_windows`, `baseline_min_windows`, `min_requests`, `z_threshold`, `request_threshold`, `auth_threshold`, all four `weights`, `severity_thresholds`, `sensitive_endpoints`, `state_retention_days`, `assessment_retention_days`, `cleanup_batch`, `ml_enabled`, `model_path`, `model_version`, `model_sha256`, and `inference_budget_ms`. Unknown keys, invalid finite ranges, missing/unknown weight groups, contradictory baseline capacity, unobservable request thresholds, and unordered severity thresholds fail validation.

Default state retention is seven days; assessment retention is thirty days. Every minute the worker deletes at most 500 expired rows per table with indexed predicates and `SKIP LOCKED`. Original audit retention is unchanged. Per-profile memory is bounded, and inactive state is removed in finite batches; total database growth still depends on traffic and cleanup capacity. Operators should schedule extra bounded cleanup invocations if expiry backlog grows faster than this budget. This is not an automatic audit-archive or partitioning system.

To enable the reviewed development artifact, retain the existing private `.env` and add one line using the digest from `models/evaluation.json`:

```dotenv
SENTINEL_ANALYSIS={"ml_enabled":true,"model_version":"experimental-iforest-v1","model_sha256":"eb60fa1453ffdc183e226dfd72f41ca84be36ec524947d27af1ac3d1b561eef8"}
```

The Compose worker mounts `./models` read-only at `/app/models`. Default model path and artifact window are 60 seconds. Recreate only the worker after a reviewed artifact/config change:

```sh
docker compose up -d --no-deps --force-recreate event-worker
docker compose logs --tail=20 event-worker
```

Check `analysis_model_status` for `ready`/load_count=1. To disable, set `ml_enabled:false` and recreate the worker. Never accept a digest supplied by the same untrusted source as an artifact as sufficient provenance.

## Verification commands and evidence

Run from the repository root with the existing private `.env`; do not reinitialize credentials or delete volumes. All automated tests and scientific training run inside Docker.

```sh
docker compose config --quiet
docker compose --profile test build
docker run --rm -v "${PWD}:/workspace:ro" -w /workspace sentinel-ai-tests python -m ruff check --no-cache .
docker run --rm -v "${PWD}:/workspace:ro" -w /workspace sentinel-ai-tests python -m ruff format --no-cache --check .
docker compose up --wait --wait-timeout 180
docker compose exec -T admin-api alembic current
docker compose exec -T admin-api alembic check
docker compose --profile test run --rm tests
docker compose --profile test run --rm --no-deps -v ./models:/output tests python -m sentinel_security.model_training --output /output
docker compose --profile test run --rm --no-deps tests python -m pytest -p no:cacheprovider tests/integration/test_analysis_pipeline.py -s -q
docker compose --profile test run --rm --no-deps tests python scripts/benchmark_analysis.py
docker compose exec -T rabbitmq rabbitmqctl list_queues name messages_ready messages_unacknowledged
docker stats --no-stream
docker compose ps
```

`${PWD}` works in Bash and PowerShell; use one line per command. The complete Compose test command includes unit and integration tests, statement coverage, and the existing ≥85% gate. GitHub Actions uses the same Docker checks plus offline training and uploads its evaluation report. No commit or push is performed.

The real-service suite covers normal scoring, increasing verified-failure risk, rate-rule evidence, persisted controlled statistical windows, actual trained-model inference, ML disabled/missing/error fallback, concurrent processing, duplicate delivery, real RabbitMQ disconnect after commit, transaction rollback, retention, and absence of private markers in profiles/evidence. Existing suites cover PostgreSQL connection failure/retries/quarantine, Redis failure policies, broker connection failures, real HTTP publication, brute-force blocks, shared rate limiting, expiry, and v1/v2 compatibility. Controlled events are explicitly test traffic and cleaned up after each scenario.

## Remaining limits

- The model has substantial measured false negatives and synthetic-only evidence. It remains optional and experimental.
- Per-client baselines can be contaminated, sparse, shared by NAT users, or invalidated by legitimate changes. Cross-window delayed events are auditable but excluded; very long in-flight requests may complete after a window is finalized.
- Cleanup throughput and the existing in-memory publisher's loss window are finite. Queue backlog, retention backlog, and database sizing need operational monitoring.
- Inference uses cooperative deadlines and bounded work, not a hard real-time process sandbox. Training is offline and single-threaded; production never launches training.
- The existing local single-node services, development database role, and dashboard/JWT/production-authentication gaps remain unchanged. No frontend or Grafana was added. Manual visual/end-to-end acceptance remains deferred to the frontend milestone; automated backend and real-service checks are mandatory and recorded here.

## Final executed results

The final packaged Docker run completed **269 tests in 24.95 seconds**, all passing, with **96.25% statement coverage** (1,466 statements, 55 uncovered). All pre-existing tests passed, including real Phase 3 distributed limits, verified-login restrictions, block expiry, Redis interruption/failure policies, PostgreSQL interruption/retry handling, RabbitMQ durability/redelivery, and sensitive-data exclusion. Ruff lint and formatting checks passed inside Docker; Compose validation passed. No production protection deadline or fail-open/fail-closed policy was relaxed.

The migration service successfully upgraded the existing database from `0003_security_decisions` to **`0004_threat_analysis` (head)**. `alembic check` returned **“No new upgrade operations detected.”** All six long-running services were healthy; the one-shot migration container completed successfully. Existing volumes and private credentials were preserved. No downgrade was attempted against populated audit history.

Executed controlled risk examples (from PostgreSQL, not display fixtures):

| Observations in the window | Risk | Severity |
| --- | ---: | --- |
| Normal request, no failure/violation | 0 | low |
| One failure on the configured sensitive login route | 10 | low |
| Two failures on that route | 20 | moderate |
| Three failures on that route | 30 | moderate |
| Four/five failures on that route | 40 | moderate |
| Five failures plus one rate-rule violation | 53.33 | high |
| Five failures plus two rate-rule violations | 66.67 | high |
| Five failures plus three rate-rule violations | 80 | critical |

These are explicitly controlled test observations, removed after verification. The score increments reflect the documented policy, including sensitivity and overlapping-group maximum. They are not real attacker findings.

The persisted statistical scenario used eight completed ten-request baseline windows. The controlled final window contained 80 requests with error rate 1.0. Stored evidence showed request-count median=10, scale=5, robust z=14; error-rate median=0, scale=0.05, robust z=20. Both were flagged with their statistical rule identifiers.

The separately isolated **real `run_worker` pipeline** used actual RabbitMQ publication, worker consumption, transaction commit, and acknowledgement with a trusted model enabled. It persisted 31 assessments and one completed-window ML result: 30 observed failures on the controlled login route, anomaly score **0.7526078254159259**, threshold **0.66071370038221**, experimental anomaly=true, model=`experimental-iforest-v1`. The closed window's true start/end and features were persisted. A regression also confirms that a subsequent low-volume window cannot reuse an older eligible profile or mislabel an idle-gap boundary. Production Compose remains ML-disabled by default.

The final offline evaluation reproduced identical model bytes and exact Scikit-learn/export scores. Pattern breakdown: **0/64 bursts**, **64/64 concentrated authentication patterns**, and **2/64 high-error/diversity patterns** were flagged. Combined results remain TP=66, FN=126, TN=256, FP=0; benign-shift FP=0/128. These substantial misses are retained and explicitly reported. Artifact SHA-256: `eb60fa1453ffdc183e226dfd72f41ca84be36ec524947d27af1ac3d1b561eef8`.

Real PostgreSQL benchmark, 120 sequential controlled events for one client, including audit/profile/assessment commits:

| Measure | Observation |
| --- | ---: |
| Elapsed | 1.1943 s |
| Committed events/second | 100.47 |
| Mean full-persist latency | 9.87 ms |
| p95 full-persist latency | 13.13 ms |
| Maximum latency | 43.47 ms |
| Benchmark process peak RSS | 74,272 KiB (72.53 MiB) |
| Model load count | 0 (explicitly disabled in this benchmark) |

This is a small local benchmark, not a sustained throughput SLA or an ML-enabled load benchmark. The verified ML-enabled worker loads its artifact once. In a Docker snapshot after tests, the worker used approximately 57.5 MiB, APIs approximately 65–66 MiB each, Redis 14 MiB, RabbitMQ 216 MiB, and PostgreSQL 59 MiB (about 478 MiB total against the available 7.55 GiB, excluding transient test/build processes). RabbitMQ CLI/management snapshots showed high transient CPU, so these observations do not establish idle CPU or peak-stack guarantees. Both durable queues reported **0 ready and 0 unacknowledged messages**, including the dead-letter queue.

Local ignored evidence files: `.artifacts/phase4-final-tests.txt`, `.artifacts/phase4-execution-evidence.txt`, and `.artifacts/phase4-benchmark.txt`. The source-controlled model/evaluation files provide reproducible scientific evidence without committing private environment data.

## File inventory

Created:

- `packages/sentinel-security/src/sentinel_security/analysis_config.py` — validated analysis policy.
- `features.py`, `risk.py`, `anomaly_model.py`, `model_training.py`, `analysis_storage.py` in that package — bounded extraction, statistics/scoring, safe inference, offline training, transactional models/repository/retention.
- `migrations/versions/0004_threat_analysis.py`.
- `tests/unit/test_analysis.py` and `tests/integration/test_analysis_pipeline.py`.
- `scripts/benchmark_analysis.py` and `requirements-ml.in`.
- `models/experimental-iforest-v1.json`, `models/evaluation.json`, and this verification record.

Modified:

- Shared `config.py` and `storage.py`; worker `runtime.py`; migration metadata registration in `migrations/env.py`; expected revision in `tests/integration/test_stack.py`.
- `requirements-dev.in`/`.txt` (hash-locked offline training dependencies), `Dockerfile` (dependency download cache), `compose.yaml` (worker policy/model mount and complete Docker test command), and `.env.example`.
- `.github/workflows/ci.yml`, `README.md`, and `docs/architecture.md`.

All work is left uncommitted for review. No frontend, Grafana, public assessment API, cloud service, or paid external AI dependency was added.

A later quiet snapshot showed approximately **398.7 MiB total** across the six services (worker 58.5, admin 64.64, demo 65.15, Redis 13.27, RabbitMQ 137, PostgreSQL 60.14 MiB), each below 1% sampled CPU. The earlier RabbitMQ CPU spike subsided. Runtime inspection confirmed `sklearn` and `numpy` are absent, analysis is enabled, and ML is explicitly disabled. These are sampled development observations, not peak-capacity guarantees.
