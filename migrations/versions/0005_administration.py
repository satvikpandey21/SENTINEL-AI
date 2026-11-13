"""Administrative accounts, revocable sessions, policy versions and audit history.

Revision ID: 0005_administration
Revises: 0004_threat_analysis
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0005_administration"
down_revision = "0004_threat_analysis"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "admin_accounts",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(256), nullable=False),
        sa.Column("role", sa.String(10), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('ADMIN','ANALYST')", name="ck_admin_role"),
        sa.CheckConstraint("username ~ '^[a-z0-9][a-z0-9_.-]{2,63}$'", name="ck_admin_username"),
    )
    op.create_table(
        "admin_sessions",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "account_id", pg.UUID(as_uuid=True), sa.ForeignKey("admin_accounts.id"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("expires_at > created_at", name="ck_admin_session_expiry"),
    )
    op.create_index("ix_admin_sessions_account", "admin_sessions", ["account_id", "expires_at"])
    op.create_table(
        "admin_refresh_tokens",
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column(
            "session_id", pg.UUID(as_uuid=True), sa.ForeignKey("admin_sessions.id"), nullable=False
        ),
        sa.Column("csrf_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "digest ~ '^[0-9a-f]{64}$' AND csrf_digest ~ '^[0-9a-f]{64}$'",
            name="ck_admin_token_digests",
        ),
    )
    op.create_index("ix_admin_refresh_session", "admin_refresh_tokens", ["session_id"])
    op.create_table(
        "admin_audit",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("actor_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("target", sa.String(128), nullable=False),
        sa.Column("outcome", sa.String(10), nullable=False),
        sa.Column("summary", pg.JSONB(), nullable=False),
        sa.CheckConstraint("outcome IN ('success','rejected')", name="ck_admin_audit_outcome"),
    )
    op.create_index("ix_admin_audit_time", "admin_audit", ["occurred_at", "id"])
    op.create_index("ix_admin_audit_actor_time", "admin_audit", ["actor_id", "occurred_at"])
    op.create_table(
        "policy_revisions",
        sa.Column("version", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("policies", pg.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", pg.UUID(as_uuid=True), nullable=True),
        sa.CheckConstraint("version > 0", name="ck_policy_version"),
    )
    op.create_index(
        "ix_security_events_type_time_id",
        "security_events",
        ["event_type", "occurred_at", "event_id"],
    )
    op.create_index(
        "ix_security_events_endpoint_time", "security_events", ["endpoint", "occurred_at"]
    )
    op.create_index(
        "ix_risk_assessments_client_time", "risk_assessments", ["client_identifier", "analyzed_at"]
    )
    op.create_index(
        "ix_risk_assessments_evidence",
        "risk_assessments",
        ["evidence"],
        postgresql_using="gin",
        postgresql_ops={"evidence": "jsonb_path_ops"},
    )


def downgrade():
    connection = op.get_bind()
    for table in ("admin_accounts", "admin_audit", "policy_revisions"):
        # Static migration-owned table names only.
        if connection.scalar(sa.select(sa.exists().select_from(sa.table(table)))):
            raise RuntimeError("Archive administrative history before downgrading")
    op.drop_index("ix_risk_assessments_evidence", table_name="risk_assessments")
    op.drop_index("ix_risk_assessments_client_time", table_name="risk_assessments")
    op.drop_index("ix_security_events_endpoint_time", table_name="security_events")
    op.drop_index("ix_security_events_type_time_id", table_name="security_events")
    for table in (
        "admin_refresh_tokens",
        "admin_sessions",
        "admin_accounts",
        "admin_audit",
        "policy_revisions",
    ):
        op.drop_table(table)
