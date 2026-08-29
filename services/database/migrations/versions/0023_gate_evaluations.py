"""CI gate evaluation records (blocked-deployments tracking).

Revision ID: 0023
Revises: 0022
Create Date: 2026-08-29
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "gate_evaluations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), nullable=False, index=True),
        sa.Column("target_location", sa.String(500), nullable=True),
        sa.Column("profile", sa.String(20), nullable=False, server_default="standard"),
        sa.Column("decision", sa.String(10), nullable=False),
        sa.Column("blocking_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("warning_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("actor", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("gate_evaluations")
