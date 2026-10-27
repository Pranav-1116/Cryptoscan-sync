"""OT/ICS maintenance windows for deterministic active-scan safety gating.

Revision ID: 0048
Revises: 0047
Create Date: 2026-09-03

Adds the ot_maintenance_windows table: approved, time-bounded authorizations
for active/intrusive operations against operational equipment. Passive scanning
never needs a window. No AI/ML — pure policy-as-code safety control.
"""
import sqlalchemy as sa
from alembic import op

revision = "0048"
down_revision = "0047"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ot_maintenance_windows",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_ref", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("device_ids", sa.Text(), nullable=True),
        sa.Column("zones", sa.Text(), nullable=True),
        sa.Column("sites", sa.Text(), nullable=True),
        sa.Column("allowed_action_class", sa.String(length=20), nullable=False,
                  server_default="interact"),
        sa.Column("approved_by", sa.String(length=100), nullable=False, server_default=""),
        sa.Column("change_ticket", sa.String(length=60), nullable=False, server_default=""),
        sa.Column("requested_by", sa.String(length=100), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="APPROVED"),
        sa.Column("operations", sa.Text(), nullable=True),
        sa.Column("is_cancelled", sa.Boolean(), nullable=False, server_default="0"),
    )
    op.create_index("ix_ot_mw_window_ref", "ot_maintenance_windows", ["window_ref"], unique=True)
    op.create_index("ix_ot_mw_starts_at", "ot_maintenance_windows", ["starts_at"])
    op.create_index("ix_ot_mw_ends_at", "ot_maintenance_windows", ["ends_at"])
    op.create_index("ix_ot_mw_status", "ot_maintenance_windows", ["status"])


def downgrade() -> None:
    op.drop_index("ix_ot_mw_status", table_name="ot_maintenance_windows")
    op.drop_index("ix_ot_mw_ends_at", table_name="ot_maintenance_windows")
    op.drop_index("ix_ot_mw_starts_at", table_name="ot_maintenance_windows")
    op.drop_index("ix_ot_mw_window_ref", table_name="ot_maintenance_windows")
    op.drop_table("ot_maintenance_windows")
