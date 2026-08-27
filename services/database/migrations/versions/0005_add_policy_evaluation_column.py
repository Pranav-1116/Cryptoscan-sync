"""Add policy_evaluation column to evidence_records

Revision ID: 0005
Revises: 0004
Create Date: 2024-01-15 00:05:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add policy evaluation columns
    op.add_column(
        "evidence_records",
        sa.Column("policy_evaluation", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=True),
    )
    op.add_column(
        "evidence_records",
        sa.Column(
            "compliance_status",
            sa.VARCHAR(20),
            nullable=True,
            server_default="PENDING",
        ),
    )
    op.add_column(
        "evidence_records",
        sa.Column("policy_version", sa.VARCHAR(20), nullable=True),
    )
    op.add_column(
        "evidence_records",
        sa.Column(
            "policy_evaluated_at",
            sa.TIMESTAMP(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "evidence_records",
        sa.Column("rules_failed_count", sa.Integer, nullable=True, server_default="0"),
    )
    op.add_column(
        "evidence_records",
        sa.Column("rules_passed_count", sa.Integer, nullable=True, server_default="0"),
    )
    op.add_column(
        "evidence_records",
        sa.Column("highest_severity_failed", sa.VARCHAR(20), nullable=True),
    )

    # Indexes for policy queries
    op.create_index(
        "idx_evidence_compliance_status",
        "evidence_records",
        ["compliance_status"],
    )
    if op.get_bind().dialect.name == "postgresql":
        op.create_index(
            "idx_evidence_policy_fail",
            "evidence_records",
            ["compliance_status"],
            postgresql_where=sa.text("compliance_status = 'FAIL'"),
        )
    if op.get_bind().dialect.name == "postgresql":
        op.create_index(
            "idx_evidence_policy_evaluation_gin",
            "evidence_records",
            ["policy_evaluation"],
            postgresql_using="gin",
        )
    op.create_index(
        "idx_evidence_highest_severity",
        "evidence_records",
        ["highest_severity_failed"],
    )

    # CHECK constraint for compliance_status
    if op.get_bind().dialect.name == "postgresql":
        op.create_check_constraint(
            "ck_compliance_status",
            "evidence_records",
            "compliance_status IN ('PENDING', 'PASS', 'WARN', 'FAIL')",
        )


def downgrade() -> None:
    op.drop_constraint("ck_compliance_status", "evidence_records")
    op.drop_index("idx_evidence_highest_severity", table_name="evidence_records")
    op.drop_index("idx_evidence_policy_evaluation_gin", table_name="evidence_records")
    op.drop_index("idx_evidence_policy_fail", table_name="evidence_records")
    op.drop_index("idx_evidence_compliance_status", table_name="evidence_records")
    op.drop_column("evidence_records", "highest_severity_failed")
    op.drop_column("evidence_records", "rules_passed_count")
    op.drop_column("evidence_records", "rules_failed_count")
    op.drop_column("evidence_records", "policy_evaluated_at")
    op.drop_column("evidence_records", "policy_version")
    op.drop_column("evidence_records", "compliance_status")
    op.drop_column("evidence_records", "policy_evaluation")