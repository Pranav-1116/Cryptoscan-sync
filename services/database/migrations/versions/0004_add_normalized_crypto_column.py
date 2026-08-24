"""Add normalized_crypto column to evidence_records

Revision ID: 0004
Revises: 0003
Create Date: 2024-01-15 00:04:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add normalized_crypto JSONB column
    op.add_column(
        "evidence_records",
        sa.Column("normalized_crypto", JSONB, nullable=True),
    )

    # Add normalization metadata columns for fast filtering
    op.add_column(
        "evidence_records",
        sa.Column("normalized_algorithm", sa.VARCHAR(50), nullable=True),
    )
    op.add_column(
        "evidence_records",
        sa.Column("algorithm_family", sa.VARCHAR(50), nullable=True),
    )
    op.add_column(
        "evidence_records",
        sa.Column("nist_designation", sa.VARCHAR(50), nullable=True),
    )
    op.add_column(
        "evidence_records",
        sa.Column("normalization_status", sa.VARCHAR(20), nullable=True, server_default="PENDING"),
    )
    op.add_column(
        "evidence_records",
        sa.Column("normalization_version", sa.VARCHAR(20), nullable=True),
    )
    op.add_column(
        "evidence_records",
        sa.Column("normalization_confidence", sa.VARCHAR(20), nullable=True),
    )
    op.add_column(
        "evidence_records",
        sa.Column("requires_review", sa.Boolean, nullable=False, server_default=sa.text("false")),
    )

    # Indexes for normalized data queries
    op.create_index(
        "idx_evidence_normalized_algorithm",
        "evidence_records",
        ["normalized_algorithm"],
    )
    op.create_index(
        "idx_evidence_nist_designation",
        "evidence_records",
        ["nist_designation"],
    )
    op.create_index(
        "idx_evidence_normalization_status",
        "evidence_records",
        ["normalization_status"],
    )
    op.create_index(
        "idx_evidence_requires_review",
        "evidence_records",
        ["requires_review"],
        postgresql_where=sa.text("requires_review = true"),
    )
    op.create_index(
        "idx_evidence_normalized_crypto_gin",
        "evidence_records",
        ["normalized_crypto"],
        postgresql_using="gin",
    )

    # Add CHECK constraint for normalization_status
    op.create_check_constraint(
        "ck_normalization_status",
        "evidence_records",
        "normalization_status IN ('PENDING', 'NORMALIZED', 'UNKNOWN', 'FAILED')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_normalization_status", "evidence_records")
    op.drop_index("idx_evidence_normalized_crypto_gin", table_name="evidence_records")
    op.drop_index("idx_evidence_requires_review", table_name="evidence_records")
    op.drop_index("idx_evidence_normalization_status", table_name="evidence_records")
    op.drop_index("idx_evidence_nist_designation", table_name="evidence_records")
    op.drop_index("idx_evidence_normalized_algorithm", table_name="evidence_records")
    op.drop_column("evidence_records", "requires_review")
    op.drop_column("evidence_records", "normalization_confidence")
    op.drop_column("evidence_records", "normalization_version")
    op.drop_column("evidence_records", "normalization_status")
    op.drop_column("evidence_records", "nist_designation")
    op.drop_column("evidence_records", "algorithm_family")
    op.drop_column("evidence_records", "normalized_algorithm")
    op.drop_column("evidence_records", "normalized_crypto")