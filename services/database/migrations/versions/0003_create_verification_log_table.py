"""Create verification_log table

Revision ID: 0003
Revises: 0002
Create Date: 2024-01-15 00:03:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "verification_log",
        sa.Column(
            "verification_id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            UUID(as_uuid=True),
            sa.ForeignKey("scans.scan_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("verified_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("verified_by", sa.VARCHAR(100), nullable=False),
        sa.Column("result", sa.VARCHAR(20), nullable=False),
        sa.Column("details", JSONB, nullable=True, server_default=sa.text("'{}'")),
        sa.Column("chain_valid", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("content_hashes_valid", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("manifest_valid", sa.Boolean, nullable=True),
        sa.Column("findings_count_verified", sa.Integer, nullable=True),
        sa.Column("errors", JSONB, nullable=True, server_default=sa.text("'[]'")),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint("result IN ('PASS', 'FAIL', 'PARTIAL')", name="ck_verification_result"),
    )

    op.create_index("idx_verification_log_scan_id", "verification_log", ["scan_id"])
    op.create_index(
        "idx_verification_log_scan_verified_at",
        "verification_log",
        ["scan_id", sa.text("verified_at DESC")],
    )
    op.create_index(
        "idx_verification_log_result",
        "verification_log",
        ["result"],
        postgresql_where=sa.text("result = 'FAIL'"),
    )


def downgrade() -> None:
    op.drop_index("idx_verification_log_result", table_name="verification_log")
    op.drop_index("idx_verification_log_scan_verified_at", table_name="verification_log")
    op.drop_index("idx_verification_log_scan_id", table_name="verification_log")
    op.drop_table("verification_log")