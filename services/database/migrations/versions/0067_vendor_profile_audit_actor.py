"""Record the authenticated actor that created each profile revision.

Revision ID: 0067
Revises: 0066
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0067"
down_revision = "0066"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vendor_profile_revisions",
        sa.Column("created_by", sa.String(160), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vendor_profile_revisions", "created_by")
