"""Leader lease for multi-AZ monitor daemons (exactly-one-scans).

Revision ID: 0031
Revises: 0030
Create Date: 2026-08-30
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "monitor_leases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(50), nullable=False, unique=True, index=True),
        sa.Column("holder", sa.String(200), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("monitor_leases")
