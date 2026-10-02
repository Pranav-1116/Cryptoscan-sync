"""Versioned vendor due-diligence profiles.

Revision ID: 0066
Revises: 0065
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0066"
down_revision = "0065"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vendor_profile_revisions",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("vendor_id", sa.String(36), sa.ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(80), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="DRAFT"),
        sa.Column("source", sa.String(120), nullable=False, server_default="operator"),
        sa.Column("profile_json", sa.JSON(), nullable=False),
        sa.Column("completeness_json", sa.JSON(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_by", sa.String(160), nullable=True),
        sa.Column("review_notes", sa.Text(), nullable=True),
        sa.UniqueConstraint("vendor_id", "revision", name="uq_vendor_profile_revision"),
    )
    op.create_index("ix_vendor_profile_revisions_tenant_id", "vendor_profile_revisions", ["tenant_id"])
    op.create_index("ix_vendor_profile_revisions_vendor_id", "vendor_profile_revisions", ["vendor_id"])
    op.create_index("ix_vendor_profile_revisions_status", "vendor_profile_revisions", ["status"])
    op.create_index("ix_vendor_profile_revisions_content_sha256", "vendor_profile_revisions", ["content_sha256"])


def downgrade() -> None:
    op.drop_index("ix_vendor_profile_revisions_content_sha256", table_name="vendor_profile_revisions")
    op.drop_index("ix_vendor_profile_revisions_status", table_name="vendor_profile_revisions")
    op.drop_index("ix_vendor_profile_revisions_vendor_id", table_name="vendor_profile_revisions")
    op.drop_index("ix_vendor_profile_revisions_tenant_id", table_name="vendor_profile_revisions")
    op.drop_table("vendor_profile_revisions")
