"""Explicit public schemas and bounded dashboard query contracts."""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

Service = Annotated[
    str, Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
]
ClientID = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
RequestID = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Endpoint = Annotated[str, Field(max_length=256, pattern=r"^(unmatched|/[a-zA-Z0-9_./{}:~-]*)$")]
EventSeverity = Literal["info", "warning", "error"]
RiskSeverity = Literal["low", "moderate", "high", "critical"]
Action = Literal["record", "rate_limit", "temporary_block", "deny"]
Classification = Literal[
    "possible_brute_force",
    "repeated_authentication_failures",
    "excessive_api_requests",
    "repeated_policy_violations",
    "suspicious_behavioral_deviation",
    "experimental_behavioral_anomaly",
]
Detection = Literal["deterministic", "robust_statistics", "isolation_forest"]


class PublicModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore", allow_inf_nan=False)


class Window(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC) - timedelta(hours=24))
    end: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))
    service: Service | None = None

    @model_validator(mode="after")
    def bounded_window(self):
        if not timedelta(0) < self.end - self.start <= timedelta(days=31):
            raise ValueError("time window must be positive and at most 31 days")
        return self


class Pagination(BaseModel):
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=10000)


class EventFilter(Window, Pagination):
    event_type: Literal["http.request.completed", "security.decision"] | None = None
    severity: EventSeverity | None = None
    security_action: Action | None = None
    endpoint: Endpoint | None = None
    request_id: RequestID | None = None
    client_identifier: ClientID | None = None


class AssessmentFilter(Window, Pagination):
    severity: RiskSeverity | None = None
    classification: Classification | None = None
    detection_method: Detection | None = None
    event_id: UUID | None = None
    client_identifier: ClientID | None = None
    min_risk: float = Field(default=0, ge=0, le=100, allow_inf_nan=False)


class EventOut(PublicModel):
    event_id: UUID
    schema_version: Literal[1, 2]
    event_type: Literal["http.request.completed", "security.decision"]
    request_id: RequestID
    occurred_at: AwareDatetime
    service: Service
    method: str
    endpoint: Endpoint
    status_code: int
    duration_ms: float
    client_identifier: ClientID
    severity: EventSeverity
    authentication_outcome: Literal["not_provided", "succeeded", "failed"]
    response_completed: bool
    rule_id: str | None
    security_action: Action | None
    counter_value: int | None
    threshold: int | None
    window_seconds: float | None
    retry_after_seconds: int | None
    restriction_expires_at: AwareDatetime | None
    degraded: bool | None


class StatisticalFlag(PublicModel):
    rule_id: str
    feature: Literal[
        "request_count", "error_rate", "auth_failure_rate", "endpoint_entropy", "timing_cv"
    ]
    observed: float
    median: float
    scale: float
    robust_z: float


class Statistics(PublicModel):
    status: str
    baseline_windows: int | None = None
    flags: list[StatisticalFlag] = Field(default_factory=list)


class ML(PublicModel):
    status: str
    experimental: bool = True
    anomaly_score: float | None = None
    anomalous: bool | None = None
    threshold: float | None = None
    model_version: str | None = None
    window_end: int | None = None


class ThreatEvidence(PublicModel):
    failures: int | None = None
    requests: int | None = None
    rate_violations: int | None = None
    restriction_episodes: int | None = None
    flags: list[StatisticalFlag] | None = None
    anomaly_score: float | None = None
    anomalous: bool | None = None
    threshold: float | None = None
    experimental: bool | None = None


class Threat(PublicModel):
    category: Classification
    severity: RiskSeverity
    risk_score: float
    detection_method: Detection
    rule_ids: list[str]
    evidence: ThreatEvidence
    timestamp: AwareDatetime
    model_version: str | None = None


class Contributions(PublicModel):
    volume: float = 0
    authentication: float = 0
    policy: float = 0
    behavior: float = 0


class Evidence(PublicModel):
    threats: list[Threat] = Field(default_factory=list)
    contributions: Contributions = Field(default_factory=Contributions)
    statistics: Statistics
    ml: ML
    aggregation_status: str
    window_start: int | None = None
    window_seconds: int


class AssessmentOut(PublicModel):
    assessment_id: UUID
    event_id: UUID
    service: Service
    client_identifier: ClientID
    risk_score: float
    severity: RiskSeverity
    rule_version: str
    model_version: str | None
    feature_schema: str
    evidence: Evidence
    analyzed_at: AwareDatetime


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class Count(PublicModel):
    key: str
    count: int


class Timeline(PublicModel):
    timestamp: AwareDatetime
    count: int


class SuspiciousClient(PublicModel):
    client_identifier: ClientID
    service: Service
    assessment_count: int
    max_risk: float
    last_seen: AwareDatetime


class AnalyticsOut(BaseModel):
    start: AwareDatetime
    end: AwareDatetime
    bucket: Literal["hour", "day"]
    monitored_requests: int
    security_decisions: int
    rate_limit_violations: int
    temporary_blocks: int
    requests_over_time: list[Timeline]
    status_distribution: list[Count]
    threats_by_severity: list[Count]
    threats_by_classification: list[Count]
    risk_distribution: list[Count]
    targeted_routes: list[Count]
    recent_alerts: list[AssessmentOut]
    suspicious_clients: list[SuspiciousClient]


class ActiveRestriction(PublicModel):
    service: Service
    policy_id: str
    remaining_seconds: int
    observed_at: AwareDatetime


class ClientActivity(BaseModel):
    client_identifier: ClientID
    start: AwareDatetime
    end: AwareDatetime
    first_seen: AwareDatetime | None
    last_seen: AwareDatetime | None
    recent_requests: list[EventOut]
    assessments: list[AssessmentOut]
    violations: list[EventOut]
    temporary_restrictions: list[EventOut]
    active_restrictions: list[ActiveRestriction] = Field(default_factory=list)


class ValidationIssue(BaseModel):
    location: list[str | int]
    type: str


class ErrorOut(BaseModel):
    detail: str
    errors: list[ValidationIssue] | None = None
    request_id: str | None = None
