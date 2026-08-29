"""Scheduled compliance reports + immutable snapshots (W55-56 items 7-8).

Revision ID: 0027
Revises: 0026
Create Date: 2026-08-29
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "report_schedules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("template_id", sa.String(60), nullable=False),
        sa.Column("requirements", sa.JSON(), nullable=True),
        sa.Column("frequency", sa.String(20), nullable=False, server_default="quarterly"),
        sa.Column("scan_target", sa.String(500), nullable=False),
        sa.Column("recipients", sa.JSON(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "report_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("schedule_id", sa.String(36), sa.ForeignKey("report_schedules.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("schedule_name", sa.String(200), nullable=True),
        sa.Column("scan_id", sa.String(36), nullable=False, index=True),
        sa.Column("template_id", sa.String(60), nullable=False),
        sa.Column("report_hash", sa.String(64), nullable=False, index=True),
        sa.Column("report", sa.JSON(), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("emailed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("email_status", sa.String(20), nullable=True),
        sa.Column("email_detail", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )



def downgrade() -> None:
    op.drop_table("report_snapshots")
    op.drop_table("report_schedules")
