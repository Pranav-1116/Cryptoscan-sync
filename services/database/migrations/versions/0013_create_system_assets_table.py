"""Create system_assets table.

Revision ID: 0013
Revises: 0012
"""
from alembic import op
import sqlalchemy as sa

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "system_assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("system_id", sa.String(36), sa.ForeignKey("systems.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("crypto_assets.id", ondelete="CASCADE"), nullable=False),
        sa.UniqueConstraint("system_id", "asset_id", name="uq_system_asset"),
    )


def downgrade() -> None:
    op.drop_table("system_assets")
