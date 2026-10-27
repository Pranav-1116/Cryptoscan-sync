"""Retired-asset registry + crypto-asset lifecycle (audits 69/54, GAP-023).

1. ``retired_assets`` — registry of deliberately retired weak crypto. Scans
   are checked against it (``POST /retirements/check/{scan_id}``) so a retired
   algorithm reappearing is a detected, severity-rated reintroduction instead
   of a silently "new" finding.
2. ``crypto_assets.lifecycle_state`` — DISCOVERED -> VERIFIED -> ACTIVE ->
   DEPRECATED -> RETIRED (audit 54's missing state machine). Existing rows
   default to DISCOVERED — the only state the pipeline writes on its own;
   later states are human judgments with an audit trail.

Revision ID: 0073
Revises: 0072
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0073"
down_revision = "0072"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "retired_assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("algorithm", sa.String(80), nullable=False),
        sa.Column("scope", sa.String(20), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("asset_id", sa.String(36), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("source_task_id", sa.String(36), nullable=True),
        sa.Column("retired_by", sa.String(100), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("lifted_reason", sa.Text(), nullable=True),
    )
    op.create_index("ix_retired_assets_tenant", "retired_assets", ["tenant_id"])
    op.create_index("ix_retired_assets_algorithm", "retired_assets", ["algorithm"])
    op.create_index("ix_retired_assets_active", "retired_assets", ["active"])
    op.create_index("ix_retired_assets_asset", "retired_assets", ["asset_id"])

    op.add_column(
        "crypto_assets",
        sa.Column("lifecycle_state", sa.String(20), nullable=False,
                  server_default="DISCOVERED"),
    )


def downgrade() -> None:
    op.drop_column("crypto_assets", "lifecycle_state")
    op.drop_index("ix_retired_assets_asset", table_name="retired_assets")
    op.drop_index("ix_retired_assets_active", table_name="retired_assets")
    op.drop_index("ix_retired_assets_algorithm", table_name="retired_assets")
    op.drop_index("ix_retired_assets_tenant", table_name="retired_assets")
    op.drop_table("retired_assets")
