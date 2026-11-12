"""Establish the migration baseline without speculative domain tables.

Revision ID: 0001_baseline
Revises: None
"""

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Alembic creates and maintains alembic_version. Domain schema arrives with its feature.
    pass


def downgrade() -> None:
    pass
