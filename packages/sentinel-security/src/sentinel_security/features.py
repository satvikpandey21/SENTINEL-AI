"""Bounded event-time tumbling windows. v1/v2 for one request merge, never add twice."""

import math
from statistics import mean, pstdev

from pydantic import BaseModel, ConfigDict, Field

from sentinel_security.analysis_config import AnalysisPolicy
from sentinel_security.events import DetectionEvent, SecurityEvent

FEATURE_SCHEMA = "behavior-v1"
ML_FEATURES = (
    "request_count",
    "error_rate",
    "auth_failure_rate",
    "rate_violation_rate",
    "endpoint_entropy",
    "mean_interval",
    "timing_cv",
    "sensitive_fraction",
)


class Features(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    request_count: int = Field(ge=0, le=10000)
    error_rate: float = Field(ge=0, le=1)
    auth_failures: int = Field(ge=0, le=10000)
    auth_failure_rate: float = Field(ge=0, le=1)
    rate_violations: int = Field(ge=0, le=10000)
    rate_violation_rate: float = Field(ge=0, le=1)
    restriction_episodes: int = Field(ge=0, le=10000)
    endpoint_distribution: dict[str, int]
    endpoint_entropy: float = Field(ge=0, le=14)
    mean_interval: float = Field(ge=0, le=3600)
    timing_cv: float = Field(ge=0, le=100)
    sensitive_fraction: float = Field(ge=0, le=1)
    saturated: bool = False

    def vector(self) -> list[float]:
        return [float(getattr(self, key)) for key in ML_FEATURES]


def extract(entries: dict, policy: AnalysisPolicy, saturated: bool = False) -> Features:
    rows = list(entries.values())
    count = len(rows)
    endpoints: dict[str, int] = {}
    for row in rows:
        endpoints[row["endpoint"]] = endpoints.get(row["endpoint"], 0) + 1
    times = sorted(row["time"] for row in rows)
    intervals = [b - a for a, b in zip(times, times[1:], strict=False)]
    average = mean(intervals) if intervals else 0.0
    auth = sum(row["auth"] for row in rows)
    rate = sum(row["rate"] for row in rows)
    return Features(
        request_count=count,
        error_rate=sum(row["error"] for row in rows) / max(1, count),
        auth_failures=auth,
        auth_failure_rate=auth / max(1, count),
        rate_violations=rate,
        rate_violation_rate=rate / max(1, count),
        restriction_episodes=len({episode for row in rows for episode in row["episodes"]}),
        endpoint_distribution=endpoints,
        endpoint_entropy=-sum((n / count) * math.log2(n / count) for n in endpoints.values())
        if count
        else 0,
        mean_interval=average,
        timing_cv=min(100, pstdev(intervals) / average) if average else 0,
        sensitive_fraction=sum(row["endpoint"] in policy.sensitive_endpoints for row in rows)
        / max(1, count),
        saturated=saturated,
    )


def observe(
    state: dict, event: SecurityEvent, policy: AnalysisPolicy
) -> tuple[dict, Features, str]:
    bucket = int(event.occurred_at.timestamp()) // policy.window_seconds * policy.window_seconds
    if not state:
        state = {"bucket": bucket, "entries": {}, "baseline": [], "saturated": False}
    if bucket < state["bucket"]:
        return state, extract(state["entries"], policy, state["saturated"]), "late_event"
    if bucket > state["bucket"]:
        previous = extract(state["entries"], policy, state["saturated"])
        history = state["baseline"]
        # Non-overlapping completed windows only; no partial-window baseline contamination.
        if previous.request_count >= policy.min_requests and not previous.saturated:
            profile = previous.model_dump()
            profile["endpoint_distribution"] = {}  # Baselines retain numeric summaries only.
            history = (history + [profile])[-policy.baseline_windows :]
        # Old profiles expire even when the client was idle (prevents stale baseline reuse).
        if bucket - state["bucket"] > policy.state_retention_days * 86400:
            history = []
        state = {"bucket": bucket, "entries": {}, "baseline": history, "saturated": False}
    entries = state["entries"]
    if event.request_id not in entries:
        if len(entries) >= policy.max_requests:
            state["saturated"] = True
            return state, extract(entries, policy, True), "capacity_reached"
        entries[event.request_id] = {
            "time": event.occurred_at.timestamp(),
            "endpoint": event.endpoint,
            "auth": False,
            "error": False,
            "rate": False,
            "episodes": [],
        }
    row = entries[event.request_id]
    row["auth"] |= event.authentication_outcome == "failed"
    row["error"] |= event.status_code >= 400 or not event.response_completed
    if isinstance(event, DetectionEvent) and not event.degraded:
        row["rate"] |= event.rule_id.endswith(".rate")
        if event.security_action == "temporary_block" and event.restriction_expires_at:
            # Redis returns the same expiry for an existing block; retries aren't new episodes.
            episode = event.rule_id + ":" + event.restriction_expires_at.isoformat()
            if episode not in row["episodes"] and len(row["episodes"]) < 4:
                row["episodes"].append(episode)
    return state, extract(entries, policy, state["saturated"]), "observed"
