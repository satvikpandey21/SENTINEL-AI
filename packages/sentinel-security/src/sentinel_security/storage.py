"""Allowlisted audit schema and idempotent PostgreSQL persistence."""

from datetime import datetime
from time import monotonic
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    Index,
    Integer,
    SmallInteger,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column

from sentinel_security.database import Base
from sentinel_security.events import MonitoringEvent
from sentinel_security.realtime import notification_for


class SecurityEventRecord(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint("schema_version IN (1, 2)", name="ck_security_events_version"),
        CheckConstraint(
            "(schema_version = 1 AND event_type = 'http.request.completed' "
            "AND rule_id IS NULL AND security_action IS NULL AND degraded IS NULL) OR "
            "(schema_version = 2 AND event_type = 'security.decision' AND rule_id IS NOT NULL "
            "AND security_action IN ('record','rate_limit','temporary_block','deny') "
            "AND degraded IS NOT NULL)",
            name="ck_security_events_type",
        ),
        CheckConstraint("counter_value BETWEEN 0 AND 10001", name="ck_security_events_counter"),
        CheckConstraint("threshold BETWEEN 1 AND 10000", name="ck_security_events_threshold"),
        CheckConstraint("window_seconds BETWEEN 0.1 AND 3600", name="ck_security_events_window"),
        CheckConstraint("retry_after_seconds BETWEEN 1 AND 3600", name="ck_security_events_retry"),
        CheckConstraint("status_code BETWEEN 100 AND 599", name="ck_security_events_status"),
        CheckConstraint("duration_ms BETWEEN 0 AND 86400000", name="ck_security_events_duration"),
        CheckConstraint(
            "severity IN ('info', 'warning', 'error')", name="ck_security_events_severity"
        ),
        CheckConstraint(
            "authentication_outcome IN ('not_provided', 'succeeded', 'failed')",
            name="ck_security_events_auth",
        ),
        CheckConstraint("request_id ~ '^[0-9a-f]{32}$'", name="ck_security_events_request_id"),
        CheckConstraint("client_identifier ~ '^[0-9a-f]{64}$'", name="ck_security_events_client"),
        Index("ix_security_events_time", "occurred_at"),
        Index("ix_security_events_type_time_id", "event_type", "occurred_at", "event_id"),
        Index("ix_security_events_endpoint_time", "endpoint", "occurred_at"),
        Index("ix_security_events_service_time", "service", "occurred_at"),
        Index("ix_security_events_severity_time", "severity", "occurred_at"),
        Index("ix_security_events_client_time", "client_identifier", "occurred_at"),
        Index("ix_security_events_request_id", "request_id"),
        Index("ix_security_events_rule_time", "rule_id", "occurred_at"),
    )

    event_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    schema_version: Mapped[int] = mapped_column(SmallInteger)
    event_type: Mapped[str] = mapped_column(String(32))
    request_id: Mapped[str] = mapped_column(String(32))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    service: Mapped[str] = mapped_column(String(64))
    method: Mapped[str] = mapped_column(String(16))
    endpoint: Mapped[str] = mapped_column(String(256))
    status_code: Mapped[int] = mapped_column(SmallInteger)
    duration_ms: Mapped[float] = mapped_column(Float)
    client_identifier: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(10))
    authentication_outcome: Mapped[str] = mapped_column(String(16))
    response_completed: Mapped[bool] = mapped_column(Boolean)
    rule_id: Mapped[str | None] = mapped_column(String(96), nullable=True)
    security_action: Mapped[str | None] = mapped_column(String(20), nullable=True)
    counter_value: Mapped[int | None] = mapped_column(Integer, nullable=True)
    threshold: Mapped[int | None] = mapped_column(Integer, nullable=True)
    window_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    retry_after_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    restriction_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    degraded: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class EventStore:
    def __init__(
        self, sessions: async_sessionmaker[AsyncSession], analysis=None, notifier=None, metrics=None
    ):
        self.sessions = sessions
        self.analysis = analysis
        self.notifier = notifier
        self.metrics = metrics

    async def persist(self, event: MonitoringEvent) -> bool:
        started = monotonic()
        try:
            inserted = await self._persist(event)
        except Exception:
            if self.metrics is not None:
                self.metrics.inc("persistence_errors")
            raise
        else:
            if self.metrics is not None:
                self.metrics.inc(
                    "persistence_events", outcome="persisted" if inserted else "duplicate"
                )
            return inserted
        finally:
            if self.metrics is not None:
                self.metrics.observe("persistence_duration_seconds", monotonic() - started)

    async def _persist(self, event: MonitoringEvent) -> bool:
        statement = (
            insert(SecurityEventRecord)
            .values(**event.model_dump())
            .on_conflict_do_nothing(index_elements=[SecurityEventRecord.event_id])
            .returning(SecurityEventRecord.event_id)
        )
        assessment = None
        async with self.sessions() as session, session.begin():
            result = await session.execute(statement)
            inserted = result.scalar_one_or_none() is not None
            if inserted and self.analysis is not None and self.analysis.policy.enabled:
                assessment = await self.analysis.analyze(session, event)
        # The transaction has committed before the caller can acknowledge the broker message.
        if inserted and assessment is not None and self.metrics is not None:
            self.metrics.inc("assessments_committed", severity=assessment.severity)
        if inserted and self.notifier is not None:
            try:
                self.notifier.offer(notification_for(event, assessment))
            except Exception:
                # Even a schema/serialization fault must not turn a committed event into a DLQ.
                import structlog

                structlog.get_logger().warning("notification_offer_failed")
        return inserted
