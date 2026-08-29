"""Add MFA (TOTP) support: users.mfa_secret/mfa_enabled + recovery codes.

Revision ID: 0022
Revises: 0021
Create Date: 2026-08-28
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_secret", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False, index=True),
        # only the hash is stored — a leaked DB cannot mint valid codes
        sa.Column("code_hash", sa.String(500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("mfa_recovery_codes")
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "mfa_secret")
