"""
Create network_scan_runs table (persisted scan results for scan-to-scan drift).

Revision ID: 0021
Revises: 0020
Create Date: 2026-08-27
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "network_scan_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(100), nullable=True),
        sa.Column("target_kind", sa.String(30), nullable=False, server_default="hosts"),
        sa.Column("verdict", sa.String(20), nullable=True),
        sa.Column("probed", sa.Integer(), nullable=True),
        sa.Column("ok", sa.Integer(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_network_scan_runs_created_at", "network_scan_runs", ["created_at"])
    op.create_index("ix_network_scan_runs_target_kind", "network_scan_runs", ["target_kind"])


def downgrade() -> None:
    op.drop_index("ix_network_scan_runs_target_kind", table_name="network_scan_runs")
    op.drop_index("ix_network_scan_runs_created_at", table_name="network_scan_runs")
    op.drop_table("network_scan_runs")
