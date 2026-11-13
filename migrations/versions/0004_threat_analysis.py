"""Transactional, private behavioral profiles and explainable assessments.

Revision ID: 0004_threat_analysis
Revises: 0003_security_decisions
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004_threat_analysis"
down_revision = "0003_security_decisions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analysis_states",
        sa.Column("service", sa.String(64), primary_key=True),
        sa.Column("client_identifier", sa.String(64), primary_key=True),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("state", postgresql.JSONB(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_analysis_states_updated", "analysis_states", ["updated_at"])
    op.create_table(
        "risk_assessments",
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "event_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("security_events.event_id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("service", sa.String(64), nullable=False),
        sa.Column("client_identifier", sa.String(64), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("rule_version", sa.String(32), nullable=False),
        sa.Column("model_version", sa.String(64), nullable=True),
        sa.Column("feature_schema", sa.String(32), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_risk_score"),
        sa.CheckConstraint(
            "severity IN ('low','moderate','high','critical')", name="ck_risk_severity"
        ),
    )
    op.create_index(
        "ix_risk_assessments_service_client_time",
        "risk_assessments",
        ["service", "client_identifier", "analyzed_at"],
    )
    op.create_index(
        "ix_risk_assessments_severity_time", "risk_assessments", ["severity", "analyzed_at"]
    )
    op.create_index("ix_risk_assessments_time", "risk_assessments", ["analyzed_at"])


def downgrade() -> None:
    connection = op.get_bind()
    if connection.scalar(
        sa.text("SELECT EXISTS (SELECT 1 FROM risk_assessments)")
    ) or connection.scalar(sa.text("SELECT EXISTS (SELECT 1 FROM analysis_states)")):
        raise RuntimeError("Archive analysis history before downgrading this schema")
    op.drop_table("risk_assessments")
    op.drop_table("analysis_states")
