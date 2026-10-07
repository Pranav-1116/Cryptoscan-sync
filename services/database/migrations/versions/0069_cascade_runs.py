"""Persist cross-BOM cascade runs (unified cascade audit trail).

Revision ID: 0069
Revises: 0068
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0069"
down_revision = "0068"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cascade_runs",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("target_kind", sa.String(30), nullable=True),
        sa.Column("max_depth", sa.Integer(), nullable=False),
        sa.Column("verdict", sa.String(30), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_cascade_runs_tenant_id", "cascade_runs", ["tenant_id"])
    op.create_index("ix_cascade_runs_created_at", "cascade_runs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_cascade_runs_created_at", table_name="cascade_runs")
    op.drop_index("ix_cascade_runs_tenant_id", table_name="cascade_runs")
    op.drop_table("cascade_runs")
