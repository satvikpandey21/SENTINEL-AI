"""Transactional analysis state and results; accessed only by the asynchronous worker."""

import hashlib
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from time import monotonic
from uuid import UUID, uuid4

import structlog
from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Index, String, delete, select
from sqlalchemy.dialects.postgresql import JSONB, insert
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from sentinel_security.analysis_config import AnalysisPolicy
from sentinel_security.anomaly_model import AnomalyModel, canonical_bytes
from sentinel_security.database import Base
from sentinel_security.events import SecurityEvent
from sentinel_security.features import FEATURE_SCHEMA, extract, observe
from sentinel_security.risk import RULE_VERSION, score, statistical


class AnalysisState(Base):
    __tablename__ = "analysis_states"
    __table_args__ = (Index("ix_analysis_states_updated", "updated_at"),)
    service: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_identifier: Mapped[str] = mapped_column(String(64), primary_key=True)
    policy_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[dict] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    __table_args__ = (
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_risk_score"),
        CheckConstraint(
            "severity IN ('low','moderate','high','critical')", name="ck_risk_severity"
        ),
        Index(
            "ix_risk_assessments_service_client_time", "service", "client_identifier", "analyzed_at"
        ),
        Index("ix_risk_assessments_severity_time", "severity", "analyzed_at"),
        Index("ix_risk_assessments_time", "analyzed_at"),
        Index("ix_risk_assessments_client_time", "client_identifier", "analyzed_at"),
        Index(
            "ix_risk_assessments_evidence",
            "evidence",
            postgresql_using="gin",
            postgresql_ops={"evidence": "jsonb_path_ops"},
        ),
    )
    assessment_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    event_id: Mapped[UUID] = mapped_column(
        ForeignKey("security_events.event_id", ondelete="CASCADE"), unique=True
    )
    service: Mapped[str] = mapped_column(String(64))
    client_identifier: Mapped[str] = mapped_column(String(64))
    risk_score: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(10))
    rule_version: Mapped[str] = mapped_column(String(32))
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    feature_schema: Mapped[str] = mapped_column(String(32))
    evidence: Mapped[dict] = mapped_column(JSONB)
    analyzed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AnalysisEngine:
    def __init__(self, policy: AnalysisPolicy):
        self.policy = policy
        self.policy_hash = hashlib.sha256(canonical_bytes(policy.model_dump())).hexdigest()
        self.model = AnomalyModel(policy)
        structlog.get_logger().info(
            "analysis_model_status", status=self.model.status, load_count=self.model.load_count
        )

    async def analyze(self, session, event: SecurityEvent) -> None:
        started = monotonic()
        now = datetime.now(UTC)
        policy = self.policy
        identity = {"service": event.service, "client_identifier": event.client_identifier}
        # Preserve stale/future audit events without admitting them to aggregation.
        eligible = (
            now - timedelta(days=policy.state_retention_days)
            <= event.occurred_at
            <= now + timedelta(seconds=5)
        )
        await session.execute(
            insert(AnalysisState)
            .values(**identity, policy_hash=self.policy_hash, state={}, updated_at=now)
            .on_conflict_do_nothing()
        )
        record = await session.scalar(select(AnalysisState).filter_by(**identity).with_for_update())
        state = deepcopy(record.state) if record.policy_hash == self.policy_hash else {}
        previous_bucket = state.get("bucket")
        incoming_bucket = (
            int(event.occurred_at.timestamp()) // policy.window_seconds * policy.window_seconds
        )
        completed = None
        if (
            eligible
            and previous_bucket is not None
            and incoming_bucket > previous_bucket
            and incoming_bucket - previous_bucket <= policy.state_retention_days * 86400
        ):
            completed = extract(state["entries"], policy, state["saturated"])
        # JSON is replaced wholesale, so SQLAlchemy always observes the mutation.
        if eligible:
            state, features, status = observe(state, event, policy)
        else:
            features, status = extract({}, policy), "outside_retention"
        statistics = statistical(features, state.get("baseline", []), policy)
        # Evaluate only completed windows against a complete-window training distribution.
        # The preceding completed profile is independent of the newly opened window.
        ml = {
            "status": "awaiting_completed_window"
            if self.model.status == "ready"
            else self.model.status
        }
        if status == "observed" and completed is not None:
            try:
                ml = self.model.infer(completed, complete_window=True)
            except Exception as error:
                structlog.get_logger().warning(
                    "analysis_ml_failed", error_type=type(error).__name__
                )
                ml = {"status": "inference_error"}
            ml["window_start"] = previous_bucket
            ml["window_end"] = previous_bucket + policy.window_seconds
            ml["features"] = completed.model_dump()
        result = score(features, statistics, ml, policy)
        if status in ("late_event", "outside_retention"):
            # Do not attribute the current client's activity to an unrelated late event.
            result = score(extract({}, policy), {"flags": []}, {"status": "not_applicable"}, policy)
            statistics, ml = {"status": status, "flags": []}, {"status": "not_applicable"}
        evidence = {
            **result,
            "features": features.model_dump() if eligible and status != "late_event" else {},
            "statistics": statistics,
            "ml": ml,
            "aggregation_status": status,
            "window_start": state.get("bucket"),
            "window_seconds": policy.window_seconds,
            "policy_hash": self.policy_hash,
            "scoring_policy": {
                "weights": policy.weights,
                "severity_thresholds": policy.severity_thresholds,
                "request_threshold": policy.request_threshold,
                "auth_threshold": policy.auth_threshold,
            },
        }
        for threat in evidence["threats"]:
            threat["timestamp"] = now.isoformat()
            threat["model_version"] = (
                ml.get("model_version")
                if threat["detection_method"] == "isolation_forest"
                else None
            )
        session.add(
            RiskAssessment(
                assessment_id=uuid4(),
                event_id=event.event_id,
                **identity,
                risk_score=result["risk_score"],
                severity=result["severity"],
                rule_version=RULE_VERSION,
                model_version=ml.get("model_version"),
                feature_schema=FEATURE_SCHEMA,
                evidence=evidence,
                analyzed_at=now,
            )
        )
        record.state, record.policy_hash, record.updated_at = dict(state), self.policy_hash, now
        structlog.get_logger().info(
            "risk_analyzed",
            event_id=str(event.event_id),
            latency_ms=round((monotonic() - started) * 1000, 3),
            risk_score=result["risk_score"],
            ml_status=ml["status"],
        )


class AssessmentRepository:
    """Internal query boundary for future authenticated APIs; exposes no HTTP route."""

    def __init__(self, sessions):
        self.sessions = sessions

    async def for_client(self, service: str, client_identifier: str, limit: int = 50):
        if not 1 <= limit <= 200:
            raise ValueError("limit must be in 1..200")
        async with self.sessions() as session:
            return list(
                await session.scalars(
                    select(RiskAssessment)
                    .filter_by(service=service, client_identifier=client_identifier)
                    .order_by(RiskAssessment.analyzed_at.desc())
                    .limit(limit)
                )
            )


async def cleanup_analysis(sessions, policy: AnalysisPolicy) -> int:
    """Bounded indexed batches; skip locked rows and never delete original audit history."""
    deleted = 0
    async with sessions() as session, session.begin():
        for model, column, days, key in (
            (
                RiskAssessment,
                RiskAssessment.analyzed_at,
                policy.assessment_retention_days,
                RiskAssessment.assessment_id,
            ),
            (
                AnalysisState,
                AnalysisState.updated_at,
                policy.state_retention_days,
                AnalysisState.service,
            ),
        ):
            cutoff = datetime.now(UTC) - timedelta(days=days)
            if model is AnalysisState:
                rows = (
                    await session.scalars(
                        select(model)
                        .where(column < cutoff)
                        .limit(policy.cleanup_batch)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
                for row in rows:
                    await session.delete(row)
                deleted += len(rows)
            else:
                ids = (
                    select(key)
                    .where(column < cutoff)
                    .limit(policy.cleanup_batch)
                    .with_for_update(skip_locked=True)
                )
                result = await session.execute(delete(model).where(key.in_(ids)))
                deleted += result.rowcount
    return deleted
