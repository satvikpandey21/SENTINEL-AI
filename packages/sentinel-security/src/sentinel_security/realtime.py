"""Small post-commit hints. PostgreSQL remains authoritative; Pub/Sub is lossy."""

import asyncio
import re
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

import structlog
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

CHANNEL = "sentinel:security:notifications:v1"
MAX_BYTES = 4096
Classification = Literal[
    "possible_brute_force",
    "repeated_authentication_failures",
    "excessive_api_requests",
    "repeated_policy_violations",
    "suspicious_behavioral_deviation",
    "experimental_behavioral_anomaly",
]


class SecurityNotification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    notification_id: UUID  # Event UUID: one hint combines the event and its assessment.
    type: Literal["security.event.created", "security.decision.created"]
    event_id: UUID
    occurred_at: AwareDatetime
    committed_at: AwareDatetime
    service: str = Field(max_length=64, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
    endpoint: str = Field(max_length=256, pattern=r"^(unmatched|/[a-zA-Z0-9_./{}:~-]*)$")
    status_code: int = Field(ge=100, le=599)
    security_action: Literal["record", "rate_limit", "temporary_block", "deny"] | None = None
    rule_ids: list[Annotated[str, Field(max_length=96, pattern=r"^[a-zA-Z0-9_.-]+$")]] = Field(
        default_factory=list, max_length=16
    )
    assessment_id: UUID | None = None
    risk_score: float | None = Field(default=None, ge=0, le=100, allow_inf_nan=False)
    severity: Literal["low", "moderate", "high", "critical"] | None = None
    classifications: list[Classification] = Field(default_factory=list, max_length=6)
    experimental: bool = False
    degraded: bool = False

    @model_validator(mode="after")
    def references(self):
        if self.notification_id != self.event_id:
            raise ValueError("notification identifier must equal event identifier")
        if (
            self.assessment_id is None
            and (self.risk_score is not None or self.severity is not None)
        ) or (
            self.assessment_id is not None and (self.risk_score is None or self.severity is None)
        ):
            raise ValueError("assessment references require score and severity")
        return self


def notification_for(event, assessment=None):
    evidence = assessment.evidence if assessment is not None else {}
    threats = evidence.get("threats", [])
    rules = {rule for threat in threats for rule in threat.get("rule_ids", [])}
    if getattr(event, "rule_id", None):
        rules.add(event.rule_id)
    # Rule identifiers come from application configuration, never request values.
    return SecurityNotification(
        notification_id=event.event_id,
        event_id=event.event_id,
        type="security.decision.created"
        if event.event_type == "security.decision"
        else "security.event.created",
        occurred_at=event.occurred_at,
        committed_at=datetime.now(UTC),
        service=event.service,
        endpoint=event.endpoint,
        status_code=event.status_code,
        security_action=getattr(event, "security_action", None),
        degraded=getattr(event, "degraded", False),
        rule_ids=sorted(r for r in rules if re.fullmatch(r"[a-zA-Z0-9_.-]{1,96}", r))[:16],
        assessment_id=assessment.assessment_id if assessment is not None else None,
        risk_score=assessment.risk_score if assessment is not None else None,
        severity=assessment.severity if assessment is not None else None,
        classifications=sorted({t["category"] for t in threats}),
        experimental=any(t["detection_method"] == "isolation_forest" for t in threats),
    )


class NotificationPublisher:
    """Nonblocking bounded ingress; failures never escape into event persistence/ack."""

    def __init__(self, redis, capacity=256, timeout=0.2, metrics=None):
        self.redis, self.timeout = redis, timeout
        self.metrics = metrics
        self.queue = asyncio.Queue(maxsize=capacity)
        self.task = None
        self.dropped = 0

    def offer(self, notification):
        try:
            body = notification.model_dump_json()
            if len(body.encode()) > MAX_BYTES:
                raise ValueError("oversized notification")
            self.queue.put_nowait(body)
            if self.metrics is not None:
                self.metrics.set("notification_buffer", self.queue.qsize())
        except (ValueError, asyncio.QueueFull):
            self.dropped += 1
            if self.metrics is not None:
                self.metrics.inc("notification_dropped", component="worker", reason="queue_full")
            structlog.get_logger().warning("notification_dropped", dropped=self.dropped)

    async def __aenter__(self):
        self.task = asyncio.create_task(self.run())
        return self

    async def __aexit__(self, *exc):
        self.task.cancel()
        await asyncio.gather(self.task, return_exceptions=True)

    async def run(self):
        while True:
            body = await self.queue.get()
            if self.metrics is not None:
                self.metrics.set("notification_buffer", self.queue.qsize())
            try:
                async with asyncio.timeout(self.timeout):
                    await self.redis.publish(CHANNEL, body)
                if self.metrics is not None:
                    self.metrics.inc("notification_published")
            except Exception as error:
                self.dropped += 1
                if self.metrics is not None:
                    self.metrics.inc("notification_publish_errors")
                    self.metrics.inc("notification_dropped", component="worker", reason="transport")
                structlog.get_logger().warning(
                    "notification_publish_failed", error_type=type(error).__name__
                )
            finally:
                self.queue.task_done()
