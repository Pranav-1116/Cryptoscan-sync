""":class:`technology_bom_export_schedules` / `technology_bom_export_runs`.

Revision ID: 0056
Revises: 0055
Create Date: 2026-09-09

Adds scheduled Technology BOM exports (daily/weekly/monthly/after scan/after
major change) and their immutable runs. Each run stores the downloadable
artifact with a content hash + HMAC signature + audit event id so the artifact
an auditor received never changes underneath them.

Mirrors the ``TechnologyBomExportSchedule`` / ``TechnologyBomExportRun`` ORM
models exactly (see schema-parity test).
"""
import sqlalchemy as sa
from alembic import op

revision = "0056"
down_revision = "0055"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "technology_bom_export_schedules",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("frequency", sa.String(32), nullable=False, server_default="weekly"),
        sa.Column("fmt", sa.String(32), nullable=False, server_default="json"),
        sa.Column("layer", sa.String(32), nullable=False, server_default="all"),
        sa.Column("filters", sa.JSON(), nullable=True),
        sa.Column("environment", sa.String(100), nullable=False, server_default="default"),
        sa.Column("recipients", sa.JSON(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_snapshot_id", sa.String(32), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index(
        "ix_technology_bom_export_schedules_name", "technology_bom_export_schedules", ["name"], unique=True
    )

    op.create_table(
        "technology_bom_export_runs",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("schedule_id", sa.String(36), sa.ForeignKey(
            "technology_bom_export_schedules.id", ondelete="SET NULL"), nullable=True),
        sa.Column("schedule_name", sa.String(200), nullable=True),
        sa.Column("version", sa.Integer(), nullable=True),
        sa.Column("snapshot_id", sa.String(32), nullable=False),
        sa.Column("environment", sa.String(100), nullable=False, server_default="default"),
        sa.Column("fmt", sa.String(32), nullable=False),
        sa.Column("layer", sa.String(32), nullable=False, server_default="all"),
        sa.Column("filters", sa.JSON(), nullable=True),
        sa.Column("total_components", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("signature_hmac", sa.String(64), nullable=True),
        sa.Column("artifact_b64", sa.Text(), nullable=True),
        sa.Column("mime_type", sa.String(80), nullable=True),
        sa.Column("audit_event_id", sa.String(36), nullable=True),
        sa.Column("trigger", sa.String(32), nullable=True),
    )
    op.create_index("ix_technology_bom_export_runs_schedule_id", "technology_bom_export_runs", ["schedule_id"])
    op.create_index("ix_technology_bom_export_runs_snapshot_id", "technology_bom_export_runs", ["snapshot_id"])


def downgrade() -> None:
    op.drop_index("ix_technology_bom_export_runs_snapshot_id", table_name="technology_bom_export_runs")
    op.drop_index("ix_technology_bom_export_runs_schedule_id", table_name="technology_bom_export_runs")
    op.drop_table("technology_bom_export_runs")
    op.drop_index("ix_technology_bom_export_schedules_name", table_name="technology_bom_export_schedules")
    op.drop_table("technology_bom_export_schedules")
