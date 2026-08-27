"""
Create runtime_findings table (runtime TLS tap + process library observations).

Revision ID: 0020
Revises: 0019
Create Date: 2026-08-27
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runtime_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scanner_id", sa.String(120), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False, server_default="session"),
        sa.Column("hostname", sa.String(300), nullable=True),
        sa.Column("process_name", sa.String(300), nullable=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("tls_version", sa.String(20), nullable=True),
        sa.Column("cipher_suite", sa.String(200), nullable=True),
        sa.Column("algorithm", sa.String(120), nullable=True),
        sa.Column("key_size", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(20), nullable=True),
        sa.Column("quantum_impact", sa.String(10), nullable=True),
        sa.Column("weak_tls", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("dedup_key", sa.String(400), nullable=False),
        sa.Column("extra", sa.JSON(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_runtime_findings_scanner_id", "runtime_findings", ["scanner_id"])
    op.create_index("ix_runtime_findings_hostname", "runtime_findings", ["hostname"])
    op.create_index("ix_runtime_findings_algorithm", "runtime_findings", ["algorithm"])
    op.create_index("ix_runtime_findings_dedup_key", "runtime_findings", ["dedup_key"])
    op.create_index("ix_runtime_findings_last_seen", "runtime_findings", ["last_seen_at"])
    op.create_index("ix_runtime_findings_weak", "runtime_findings", ["weak_tls"])


def downgrade() -> None:
    op.drop_index("ix_runtime_findings_weak", table_name="runtime_findings")
    op.drop_index("ix_runtime_findings_last_seen", table_name="runtime_findings")
    op.drop_index("ix_runtime_findings_dedup_key", table_name="runtime_findings")
    op.drop_index("ix_runtime_findings_algorithm", table_name="runtime_findings")
    op.drop_index("ix_runtime_findings_hostname", table_name="runtime_findings")
    op.drop_index("ix_runtime_findings_scanner_id", table_name="runtime_findings")
    op.drop_table("runtime_findings")
