"""Certificate renewal tracking: status, ticket reference, notes on certificates.

Revision ID: 0034
Revises: 0033
Create Date: 2026-08-30
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("certificates", sa.Column("renewal_status", sa.String(20), server_default="NONE", nullable=True))
    op.add_column("certificates", sa.Column("renewal_ticket", sa.String(100), nullable=True))
    op.add_column("certificates", sa.Column("renewal_note", sa.Text(), nullable=True))
    op.add_column("certificates", sa.Column("renewed_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("certificates", "renewed_at")
    op.drop_column("certificates", "renewal_note")
    op.drop_column("certificates", "renewal_ticket")
    op.drop_column("certificates", "renewal_status")
