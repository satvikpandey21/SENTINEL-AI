"""Add version 2 decision metadata while retaining version 1 HTTP events.

Revision ID: 0003_security_decisions
Revises: 0002_security_events
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_security_decisions"
down_revision = "0002_security_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for column in (
        sa.Column("rule_id", sa.String(96), nullable=True),
        sa.Column("security_action", sa.String(20), nullable=True),
        sa.Column("counter_value", sa.Integer(), nullable=True),
        sa.Column("threshold", sa.Integer(), nullable=True),
        sa.Column("window_seconds", sa.Float(), nullable=True),
        sa.Column("retry_after_seconds", sa.Integer(), nullable=True),
        sa.Column("restriction_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("degraded", sa.Boolean(), nullable=True),
    ):
        op.add_column("security_events", column)
    op.drop_constraint("ck_security_events_version", "security_events", type_="check")
    op.drop_constraint("ck_security_events_type", "security_events", type_="check")
    op.create_check_constraint(
        "ck_security_events_version", "security_events", "schema_version IN (1, 2)"
    )
    op.create_check_constraint(
        "ck_security_events_type",
        "security_events",
        "(schema_version = 1 AND event_type = 'http.request.completed' "
        "AND rule_id IS NULL AND security_action IS NULL AND degraded IS NULL) OR "
        "(schema_version = 2 AND event_type = 'security.decision' AND rule_id IS NOT NULL "
        "AND security_action IN ('record','rate_limit','temporary_block','deny') "
        "AND degraded IS NOT NULL)",
    )
    for name, clause in (
        ("counter", "counter_value BETWEEN 0 AND 10001"),
        ("threshold", "threshold BETWEEN 1 AND 10000"),
        ("window", "window_seconds BETWEEN 0.1 AND 3600"),
        ("retry", "retry_after_seconds BETWEEN 1 AND 3600"),
    ):
        op.create_check_constraint(f"ck_security_events_{name}", "security_events", clause)
    op.create_index("ix_security_events_rule_time", "security_events", ["rule_id", "occurred_at"])


def downgrade() -> None:
    # Refuse to erase security history; remove/rearchive v2 rows deliberately before downgrade.
    connection = op.get_bind()
    if connection.scalar(
        sa.text("SELECT EXISTS (SELECT 1 FROM security_events WHERE schema_version = 2)")
    ):
        raise RuntimeError("Archive version 2 events before downgrading this schema")
    op.drop_index("ix_security_events_rule_time", table_name="security_events")
    for name in ("counter", "threshold", "window", "retry", "version", "type"):
        op.drop_constraint(f"ck_security_events_{name}", "security_events", type_="check")
    for name in (
        "rule_id",
        "security_action",
        "counter_value",
        "threshold",
        "window_seconds",
        "retry_after_seconds",
        "restriction_expires_at",
        "degraded",
    ):
        op.drop_column("security_events", name)
    op.create_check_constraint(
        "ck_security_events_version", "security_events", "schema_version = 1"
    )
    op.create_check_constraint(
        "ck_security_events_type", "security_events", "event_type = 'http.request.completed'"
    )
