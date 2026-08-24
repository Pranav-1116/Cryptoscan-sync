"""Create crypto_asset_evidence link table.

Revision ID: 0011
Revises: 0010
"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "crypto_asset_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("crypto_assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("evidence_id", sa.String(36), sa.ForeignKey("evidence_records.id", ondelete="CASCADE"), nullable=False),
        sa.UniqueConstraint("asset_id", "evidence_id", name="uq_asset_evidence"),
    )
    op.create_index("ix_crypto_asset_evidence_asset_id", "crypto_asset_evidence", ["asset_id"])
    op.create_index("ix_crypto_asset_evidence_evidence_id", "crypto_asset_evidence", ["evidence_id"])


def downgrade() -> None:
    op.drop_index("ix_crypto_asset_evidence_evidence_id", table_name="crypto_asset_evidence")
    op.drop_index("ix_crypto_asset_evidence_asset_id", table_name="crypto_asset_evidence")
    op.drop_table("crypto_asset_evidence")
