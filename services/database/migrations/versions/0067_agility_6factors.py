"""Agility 6 factors — deterministic scoring, weighted, no AI.

Revision ID: 0067
Revises: 0066
"""

import sqlalchemy as sa
from alembic import op

revision = "0067"
down_revision = "0066"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agility_scores_enhanced",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("system_id", sa.String(100), nullable=False),
        sa.Column("agility_score", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(20), nullable=False),
        sa.Column("factor_scores", sa.JSON(), nullable=True),
        sa.Column("weighted_sum", sa.Float(), nullable=True),
        sa.Column("calculation_version", sa.String(20), nullable=False, server_default="6factors-v1"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_agility_enhanced_system_id", "agility_scores_enhanced", ["system_id"])
    op.create_index("ix_agility_enhanced_score", "agility_scores_enhanced", ["agility_score"])

    op.create_table(
        "agility_factors_def",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("factor", sa.String(50), nullable=False),
        sa.Column("weight", sa.Float(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
    )
    # Seed 6 factors deterministic
    from sqlalchemy import table, column
    factors_table = table(
        "agility_factors_def",
        column("id", sa.String),
        column("factor", sa.String),
        column("weight", sa.Float),
        column("description", sa.Text),
    )
    op.bulk_insert(
        factors_table,
        [
            {"id": "f1", "factor": "crypto_diversity", "weight": 0.20, "description": "Number of distinct crypto libraries/algorithms — higher diversity = lower agility"},
            {"id": "f2", "factor": "abstraction_layer", "weight": 0.25, "description": "Presence of crypto abstraction layer (EVP, JCA, wrapper) — improves agility"},
            {"id": "f3", "factor": "key_management", "weight": 0.20, "description": "Centralized KMS/HSM vs scattered keys"},
            {"id": "f4", "factor": "protocol_support", "weight": 0.15, "description": "Protocol agility TLS 1.3 hybrid negotiation"},
            {"id": "f5", "factor": "testing_coverage", "weight": 0.10, "description": "Automated crypto tests CI/CD maturity"},
            {"id": "f6", "factor": "vendor_lockin", "weight": 0.10, "description": "Vendor lock-in open standards vs proprietary"},
        ],
    )


def downgrade() -> None:
    op.drop_table("agility_factors_def")
    op.drop_index("ix_agility_enhanced_score", table_name="agility_scores_enhanced")
    op.drop_index("ix_agility_enhanced_system_id", table_name="agility_scores_enhanced")
    op.drop_table("agility_scores_enhanced")
