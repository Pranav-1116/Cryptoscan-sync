"""Exception Enhanced — CISO HMAC signature, WORM, chain hash.

Revision ID: 0064
Revises: 0063
"""

import sqlalchemy as sa
from alembic import op

revision = "0064"
down_revision = "0063"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "exceptions_enhanced",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("asset_id", sa.String(100), nullable=True),
        sa.Column("system_id", sa.String(100), nullable=True),
        sa.Column("policy_rule_id", sa.String(100), nullable=True),
        sa.Column("exception_type", sa.String(50), nullable=False, server_default="RISK_ACCEPTANCE"),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("risk_statement", sa.Text(), nullable=False),
        sa.Column("compensating_controls", sa.Text(), nullable=True),
        sa.Column("business_justification", sa.Text(), nullable=True),
        sa.Column("compliance_impact", sa.Text(), nullable=True),
        sa.Column("expiration_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_frequency", sa.String(20), nullable=False, server_default="QUARTERLY"),
        sa.Column("status", sa.String(20), nullable=False, server_default="REQUESTED"),
        sa.Column("requested_by", sa.String(100), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ciso_signature", sa.String(128), nullable=True),
        sa.Column("ciso_approved_by", sa.String(100), nullable=True),
        sa.Column("ciso_approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("chain_hash", sa.String(64), nullable=True),
        sa.Column("previous_chain_hash", sa.String(64), nullable=True),
        sa.Column("worm_stored", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_exceptions_enhanced_status", "exceptions_enhanced", ["status"])
    op.create_index("ix_exceptions_enhanced_system_id", "exceptions_enhanced", ["system_id"])

    op.create_table(
        "exception_reviews_enhanced",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("exception_id", sa.String(36), sa.ForeignKey("exceptions_enhanced.id", ondelete="CASCADE"), nullable=False),
        sa.Column("reviewer", sa.String(100), nullable=True),
        sa.Column("still_valid", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("action_taken", sa.String(20), nullable=False, server_default="RENEWED"),
        sa.Column("ciso_signature", sa.String(128), nullable=True),
    )
    op.create_index("ix_exception_reviews_exc_id", "exception_reviews_enhanced", ["exception_id"])


def downgrade() -> None:
    op.drop_index("ix_exception_reviews_exc_id", table_name="exception_reviews_enhanced")
    op.drop_table("exception_reviews_enhanced")
    op.drop_index("ix_exceptions_enhanced_system_id", table_name="exceptions_enhanced")
    op.drop_index("ix_exceptions_enhanced_status", table_name="exceptions_enhanced")
    op.drop_table("exceptions_enhanced")
