"""Persist versioned request events with idempotency and investigation indexes.

Revision ID: 0002_security_events
Revises: 0001_baseline
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_security_events"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("schema_version", sa.SmallInteger(), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("request_id", sa.String(32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("service", sa.String(64), nullable=False),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("endpoint", sa.String(256), nullable=False),
        sa.Column("status_code", sa.SmallInteger(), nullable=False),
        sa.Column("duration_ms", sa.Float(), nullable=False),
        sa.Column("client_identifier", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("authentication_outcome", sa.String(16), nullable=False),
        sa.Column("response_completed", sa.Boolean(), nullable=False),
        sa.Column(
            "ingested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("event_id"),
        sa.CheckConstraint("schema_version = 1", name="ck_security_events_version"),
        sa.CheckConstraint("event_type = 'http.request.completed'", name="ck_security_events_type"),
        sa.CheckConstraint("status_code BETWEEN 100 AND 599", name="ck_security_events_status"),
        sa.CheckConstraint(
            "duration_ms BETWEEN 0 AND 86400000", name="ck_security_events_duration"
        ),
        sa.CheckConstraint(
            "severity IN ('info', 'warning', 'error')", name="ck_security_events_severity"
        ),
        sa.CheckConstraint(
            "authentication_outcome IN ('not_provided', 'succeeded', 'failed')",
            name="ck_security_events_auth",
        ),
        sa.CheckConstraint("request_id ~ '^[0-9a-f]{32}$'", name="ck_security_events_request_id"),
        sa.CheckConstraint(
            "client_identifier ~ '^[0-9a-f]{64}$'", name="ck_security_events_client"
        ),
    )
    op.create_index("ix_security_events_time", "security_events", ["occurred_at"])
    op.create_index(
        "ix_security_events_service_time", "security_events", ["service", "occurred_at"]
    )
    op.create_index(
        "ix_security_events_severity_time", "security_events", ["severity", "occurred_at"]
    )
    op.create_index(
        "ix_security_events_client_time", "security_events", ["client_identifier", "occurred_at"]
    )
    op.create_index("ix_security_events_request_id", "security_events", ["request_id"])


def downgrade() -> None:
    op.drop_table("security_events")
