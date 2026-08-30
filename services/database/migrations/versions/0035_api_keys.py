"""Machine API keys for CI/SIEM integration (real-time / enterprise API).

Revision ID: 0035
Revises: 0034
Create Date: 2026-08-30
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, index=True),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("key_prefix", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(100), nullable=False),
        sa.Column("roles", sa.String(200), nullable=False, server_default="viewer"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("api_keys")
