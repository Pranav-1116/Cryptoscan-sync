"""Create crypto_assets table (SQLite-safe JSON).

Revision ID: 0010
Revises: 0009
"""
from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "crypto_assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("algorithm", sa.String(80), nullable=False),
        sa.Column("purpose", sa.String(50), nullable=True),
        sa.Column("mode", sa.String(50), nullable=True),
        sa.Column("key_size", sa.Integer, nullable=True),
        sa.Column("file_path", sa.Text, nullable=False),
        sa.Column("line_number", sa.Integer, nullable=False, server_default="0"),
        sa.Column("source_language", sa.String(40), nullable=True),
        sa.Column("confidence", sa.String(20), nullable=False, server_default="LOW"),
        sa.Column("is_hardcoded_key", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("occurrence_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("scanner_ids", sa.JSON, nullable=True),
        sa.Column("libraries", sa.JSON, nullable=True),
        sa.Column("extra", sa.JSON, nullable=True),
    )
    op.create_index("ix_crypto_assets_algorithm", "crypto_assets", ["algorithm"])
    op.create_index("ix_crypto_assets_purpose", "crypto_assets", ["purpose"])


def downgrade() -> None:
    op.drop_index("ix_crypto_assets_purpose", table_name="crypto_assets")
    op.drop_index("ix_crypto_assets_algorithm", table_name="crypto_assets")
    op.drop_table("crypto_assets")
