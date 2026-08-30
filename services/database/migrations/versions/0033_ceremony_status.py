"""Ceremony scheduling: status column on key ceremonies (PLANNED/HELD/ABANDONED).

Revision ID: 0033
Revises: 0032
Create Date: 2026-08-30
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # existing rows are historical records -> HELD; new planned ceremonies set PLANNED
    op.add_column(
        "key_ceremonies",
        sa.Column("status", sa.String(20), server_default="HELD", nullable=True),
    )


def downgrade() -> None:
    op.drop_column("key_ceremonies", "status")
