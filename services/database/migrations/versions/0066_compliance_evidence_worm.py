"""Compliance evidence WORM store — 7y retention, chain verification.

Revision ID: 0066
Revises: 0065
"""

import sqlalchemy as sa
from alembic import op

revision = "0066"
down_revision = "0065"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "compliance_worm_manifests",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("evaluation_id", sa.String(36), nullable=True),
        sa.Column("pack_id", sa.String(50), nullable=False),
        sa.Column("system_id", sa.String(100), nullable=False),
        sa.Column("chain_head", sa.String(64), nullable=False),
        sa.Column("content_hashes", sa.JSON(), nullable=True),
        sa.Column("chain_hashes", sa.JSON(), nullable=True),
        sa.Column("hmac_signature", sa.String(128), nullable=True),
        sa.Column("worm_path", sa.String(500), nullable=True),
        sa.Column("retention_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_worm_manifests_pack_id", "compliance_worm_manifests", ["pack_id"])
    op.create_index("ix_worm_manifests_system_id", "compliance_worm_manifests", ["system_id"])


def downgrade() -> None:
    op.drop_index("ix_worm_manifests_system_id", table_name="compliance_worm_manifests")
    op.drop_index("ix_worm_manifests_pack_id", table_name="compliance_worm_manifests")
    op.drop_table("compliance_worm_manifests")
