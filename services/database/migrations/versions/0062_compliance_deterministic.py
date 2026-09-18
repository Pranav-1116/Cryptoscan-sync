"""Compliance Deterministic — policy-as-code, HMAC-signed, chain verified.

Revision ID: 0062
Revises: 0061
"""

import sqlalchemy as sa
from alembic import op

revision = "0062"
down_revision = "0061"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "compliance_deterministic_evaluations",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("pack_id", sa.String(50), nullable=False),
        sa.Column("pack_name", sa.String(200), nullable=True),
        sa.Column("system_id", sa.String(100), nullable=False),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("passed", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("total_controls", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("passed_controls", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_controls", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("manifest", sa.JSON(), nullable=True),
        sa.Column("chain_head", sa.String(64), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
        sa.Column("worm_stored", sa.Boolean(), nullable=False, server_default="1"),
    )
    op.create_index("ix_compliance_det_pack_id", "compliance_deterministic_evaluations", ["pack_id"])
    op.create_index("ix_compliance_det_system_id", "compliance_deterministic_evaluations", ["system_id"])


def downgrade() -> None:
    op.drop_index("ix_compliance_det_system_id", table_name="compliance_deterministic_evaluations")
    op.drop_index("ix_compliance_det_pack_id", table_name="compliance_deterministic_evaluations")
    op.drop_table("compliance_deterministic_evaluations")
