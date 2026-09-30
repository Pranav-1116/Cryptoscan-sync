"""Add durable binary scan and per-observation query indexes.

The artifact store remains the signed source of truth for exported BOMs. These
small tenant-scoped tables are a read model for the binary console/API: scan
summaries and bounded parser observations can be filtered without opening large
artifact JSON files.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0063"
down_revision = "0062"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "binary_scan_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=True),
        sa.Column("artifact_id", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=True),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("format", sa.String(length=32), nullable=False, server_default="cyclonedx"),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="COMPLETED"),
        sa.Column("created_by", sa.String(length=200), nullable=False, server_default="system"),
        sa.Column("files_walked", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("binaries_scanned", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("observations_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("observations_truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("summary", sa.JSON(), nullable=True),
        sa.Column("coverage", sa.JSON(), nullable=True),
        sa.Column("limits", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "artifact_id", name="uq_binary_scan_records_tenant_artifact"),
    )
    op.create_index("ix_binary_scan_records_tenant_id", "binary_scan_records", ["tenant_id"])
    op.create_index("ix_binary_scan_records_artifact_id", "binary_scan_records", ["artifact_id"])
    op.create_index("ix_binary_scan_records_job_id", "binary_scan_records", ["job_id"])
    op.create_index("ix_binary_scan_records_sha256", "binary_scan_records", ["sha256"])
    op.create_index("ix_binary_scan_records_created_at", "binary_scan_records", ["created_at"])

    op.create_table(
        "binary_scan_observations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=True),
        sa.Column("scan_record_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_id", sa.String(length=64), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("format", sa.String(length=32), nullable=False, server_default="raw"),
        sa.Column("arch", sa.String(length=100), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("parsed", sa.Boolean(), nullable=True),
        sa.Column("evidence_state", sa.String(length=32), nullable=False, server_default="unknown"),
        sa.Column("derived_from", sa.Text(), nullable=True),
        sa.Column("depth", sa.Integer(), nullable=True),
        sa.Column("crypto", sa.JSON(), nullable=True),
        sa.Column("hardening", sa.JSON(), nullable=True),
        sa.Column("signature", sa.JSON(), nullable=True),
        sa.Column("coverage", sa.JSON(), nullable=True),
        sa.Column("findings", sa.JSON(), nullable=True),
        sa.Column("parser_metadata", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_binary_scan_observations_tenant_id", "binary_scan_observations", ["tenant_id"])
    op.create_index("ix_binary_scan_observations_scan_record_id", "binary_scan_observations", ["scan_record_id"])
    op.create_index("ix_binary_scan_observations_artifact_id", "binary_scan_observations", ["artifact_id"])
    op.create_index("ix_binary_scan_observations_sha256", "binary_scan_observations", ["sha256"])
    op.create_index("ix_binary_scan_observations_format", "binary_scan_observations", ["format"])


def downgrade() -> None:
    op.drop_index("ix_binary_scan_observations_format", table_name="binary_scan_observations")
    op.drop_index("ix_binary_scan_observations_sha256", table_name="binary_scan_observations")
    op.drop_index("ix_binary_scan_observations_artifact_id", table_name="binary_scan_observations")
    op.drop_index("ix_binary_scan_observations_scan_record_id", table_name="binary_scan_observations")
    op.drop_index("ix_binary_scan_observations_tenant_id", table_name="binary_scan_observations")
    op.drop_table("binary_scan_observations")

    op.drop_index("ix_binary_scan_records_created_at", table_name="binary_scan_records")
    op.drop_index("ix_binary_scan_records_sha256", table_name="binary_scan_records")
    op.drop_index("ix_binary_scan_records_job_id", table_name="binary_scan_records")
    op.drop_index("ix_binary_scan_records_artifact_id", table_name="binary_scan_records")
    op.drop_index("ix_binary_scan_records_tenant_id", table_name="binary_scan_records")
    op.drop_table("binary_scan_records")
