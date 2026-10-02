"""Persist tenant-scoped network inventory revisions.

Revision ID: 0068
Revises: 0067
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0068"
down_revision = "0067"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "network_inventory_revisions",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("inventory_id", sa.String(160), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="DRAFT"),
        sa.Column("source", sa.String(80), nullable=False, server_default="MANUAL"),
        sa.Column("inventory_json", sa.JSON(), nullable=False),
        sa.Column("completeness_json", sa.JSON(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(160), nullable=True),
        sa.Column("reviewed_by", sa.String(160), nullable=True),
        sa.Column("review_notes", sa.Text(), nullable=True),
        sa.UniqueConstraint("tenant_id", "inventory_id", "revision", name="uq_network_inventory_revision"),
    )
    op.create_index("ix_network_inventory_revisions_tenant_id", "network_inventory_revisions", ["tenant_id"])
    op.create_index("ix_network_inventory_revisions_inventory_id", "network_inventory_revisions", ["inventory_id"])
    op.create_index("ix_network_inventory_revisions_status", "network_inventory_revisions", ["status"])
    op.create_index("ix_network_inventory_revisions_content_sha256", "network_inventory_revisions", ["content_sha256"])


def downgrade() -> None:
    op.drop_index("ix_network_inventory_revisions_content_sha256", table_name="network_inventory_revisions")
    op.drop_index("ix_network_inventory_revisions_status", table_name="network_inventory_revisions")
    op.drop_index("ix_network_inventory_revisions_inventory_id", table_name="network_inventory_revisions")
    op.drop_index("ix_network_inventory_revisions_tenant_id", table_name="network_inventory_revisions")
    op.drop_table("network_inventory_revisions")
