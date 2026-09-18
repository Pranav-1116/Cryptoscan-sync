"""OT/ICS Enhanced — passive-only TAP safety, deterministic risk.

Revision ID: 0061
Revises: 0060
"""

import sqlalchemy as sa
from alembic import op

revision = "0061"
down_revision = "0060"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ot_enhanced_scans",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("target_type", sa.String(20), nullable=False),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("purdue_level", sa.String(10), nullable=True),
        sa.Column("safety_mode", sa.String(20), nullable=False, server_default="passive_only"),
        sa.Column("environment", sa.String(100), nullable=False, server_default="production"),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_table(
        "ot_enhanced_devices",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("ot_enhanced_scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("protocol", sa.String(20), nullable=False),
        sa.Column("ip", sa.String(50), nullable=True),
        sa.Column("vendor", sa.String(100), nullable=True),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column("firmware", sa.String(50), nullable=True),
        sa.Column("purdue_level", sa.String(10), nullable=True),
        sa.Column("zone", sa.String(50), nullable=True),
    )
    op.create_table(
        "ot_enhanced_findings",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("ot_enhanced_scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("ot_enhanced_devices.id", ondelete="SET NULL"), nullable=True),
        sa.Column("protocol", sa.String(20), nullable=False),
        sa.Column("type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("purdue_level", sa.String(10), nullable=True),
    )
    op.create_index("ix_ot_enhanced_findings_scan_id", "ot_enhanced_findings", ["scan_id"])
    op.create_index("ix_ot_enhanced_findings_severity", "ot_enhanced_findings", ["severity"])


def downgrade() -> None:
    op.drop_index("ix_ot_enhanced_findings_severity", table_name="ot_enhanced_findings")
    op.drop_index("ix_ot_enhanced_findings_scan_id", table_name="ot_enhanced_findings")
    op.drop_table("ot_enhanced_findings")
    op.drop_table("ot_enhanced_devices")
    op.drop_table("ot_enhanced_scans")
