"""24/7 continuous monitoring: watch-list targets + event feed.

Revision ID: 0028
Revises: 0027
Create Date: 2026-08-29
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "monitor_targets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("target_type", sa.String(20), nullable=False, index=True),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING", index=True),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_scan_at", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("last_summary", sa.JSON(), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_table(
        "monitor_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("monitor_targets.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("target_name", sa.String(200), nullable=False),
        sa.Column("event_type", sa.String(30), nullable=False, index=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("monitor_events")
    op.drop_table("monitor_targets")
