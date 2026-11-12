"""Allowlisted audit schema and idempotent PostgreSQL persistence."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, Index, SmallInteger, String, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column

from sentinel_security.database import Base
from sentinel_security.events import SecurityEvent


class SecurityEventRecord(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint("schema_version = 1", name="ck_security_events_version"),
        CheckConstraint("event_type = 'http.request.completed'", name="ck_security_events_type"),
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
        Index("ix_security_events_service_time", "service", "occurred_at"),
        Index("ix_security_events_severity_time", "severity", "occurred_at"),
        Index("ix_security_events_client_time", "client_identifier", "occurred_at"),
        Index("ix_security_events_request_id", "request_id"),
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
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class EventStore:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    async def persist(self, event: SecurityEvent) -> bool:
        statement = (
            insert(SecurityEventRecord)
            .values(**event.model_dump())
            .on_conflict_do_nothing(index_elements=[SecurityEventRecord.event_id])
            .returning(SecurityEventRecord.event_id)
        )
        async with self.sessions() as session, session.begin():
            result = await session.execute(statement)
            inserted = result.scalar_one_or_none() is not None
        # The transaction has committed before the caller can acknowledge the broker message.
        return inserted
