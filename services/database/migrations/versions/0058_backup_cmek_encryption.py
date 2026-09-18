""":class:`backup_jobs` / `backup_cmek_bindings`.

Revision ID: 0058
Revises: 0057
Create Date: 2026-09-17

Adds backup encryption with CMEK (customer-managed encryption keys):
- backup_jobs: scheduled backup definitions with CMEK provider/key binding.
- backup_runs: immutable backup execution records with content hash + encryption metadata.
- backup_cmek_bindings: per-backup CMEK key version binding for rotation tracking.

Supports WORM + CMEK + data residency for enterprise backup compliance
(SOC 2, GDPR Article 32, FedRAMP SC-13, 3GPP SEC).
"""

import sqlalchemy as sa
from alembic import op

revision = "0058"
down_revision = "0057"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "backup_jobs",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("frequency", sa.String(32), nullable=False, server_default="daily"),
        sa.Column("scope", sa.String(32), nullable=False, server_default="full"),
        sa.Column("include_tables", sa.JSON(), nullable=True),
        sa.Column("exclude_tables", sa.JSON(), nullable=True),
        sa.Column("retention_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("retention_years", sa.Integer(), nullable=True),
        sa.Column("cmek_provider", sa.String(20), nullable=True),
        sa.Column("cmek_key_id", sa.String(500), nullable=True),
        sa.Column("cmek_enforced", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("worm_enforced", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("residency_regions", sa.JSON(), nullable=True),
        sa.Column("destination", sa.String(500), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_backup_jobs_name", "backup_jobs", ["name"], unique=True)

    op.create_table(
        "backup_runs",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("job_id", sa.String(36), sa.ForeignKey("backup_jobs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("job_name", sa.String(200), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="completed"),
        sa.Column("scope", sa.String(32), nullable=False, server_default="full"),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("content_sha256", sa.String(64), nullable=True),
        sa.Column("encryption_algo", sa.String(32), nullable=True),
        sa.Column("cmek_provider", sa.String(20), nullable=True),
        sa.Column("cmek_key_id", sa.String(500), nullable=True),
        sa.Column("cmek_key_version", sa.Integer(), nullable=True),
        sa.Column("destination", sa.String(500), nullable=True),
        sa.Column("worm_object_id", sa.String(500), nullable=True),
        sa.Column("audit_event_id", sa.String(36), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index("ix_backup_runs_job_id", "backup_runs", ["job_id"])
    op.create_index("ix_backup_runs_created_at", "backup_runs", ["created_at"])

    op.create_table(
        "backup_cmek_bindings",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("backup_run_id", sa.String(36), sa.ForeignKey("backup_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cmek_key_version_id", sa.String(36), sa.ForeignKey("cmek_key_versions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("key_id", sa.String(500), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("wrapped_dek_b64", sa.Text(), nullable=True),
        sa.Column("rotation_due_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_backup_cmek_bindings_backup_run_id", "backup_cmek_bindings", ["backup_run_id"])


def downgrade() -> None:
    op.drop_index("ix_backup_cmek_bindings_backup_run_id", table_name="backup_cmek_bindings")
    op.drop_table("backup_cmek_bindings")
    op.drop_index("ix_backup_runs_created_at", table_name="backup_runs")
    op.drop_index("ix_backup_runs_job_id", table_name="backup_runs")
    op.drop_table("backup_runs")
    op.drop_index("ix_backup_jobs_name", table_name="backup_jobs")
    op.drop_table("backup_jobs")
