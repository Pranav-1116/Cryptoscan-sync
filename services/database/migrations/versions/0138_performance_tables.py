"""Performance engine tables (docs/performance/01_PRODUCT_SPEC.md §5).

Revision ID: 0138
Revises: 0137
Create Date: 2026-11-07

performance_metrics            — the §5 measurement field table
performance_metric_definitions — the taxonomy registry
performance_collector_health   — stale collectors named, never zero-filled

The remaining §5 tables (aggregates, baselines, alerts, incidents,
slo_policies, capacity_forecasts, benchmark_runs) arrive with the
phases that use them — a table without a consumer is a claim.
"""

import sqlalchemy as sa
from alembic import op

revision = "0138"
down_revision = "0137"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "performance_metrics",
        sa.Column("metric_id", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(120), nullable=True),
        sa.Column("asset_id", sa.String(120), nullable=False),
        sa.Column("metric_name", sa.String(120), nullable=False),
        sa.Column("metric_type", sa.String(20), nullable=False),
        sa.Column("metric_value", sa.Float(), nullable=True),
        sa.Column("unit", sa.String(32), nullable=False),
        sa.Column("source_id", sa.String(120), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("interval_seconds", sa.Float(), nullable=True),
        sa.Column("labels", sa.JSON(), nullable=True),
        sa.Column("evidence_id", sa.String(120), nullable=True),
        sa.Column("quality_status", sa.String(20), nullable=False),
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_performance_metrics_metric_id",
                    "performance_metrics", ["metric_id"], unique=True)
    op.create_index("ix_performance_metrics_asset_id",
                    "performance_metrics", ["asset_id"])
    op.create_index("ix_performance_metrics_metric_name",
                    "performance_metrics", ["metric_name"])
    op.create_index("ix_performance_metrics_source_id",
                    "performance_metrics", ["source_id"])
    op.create_index("ix_performance_metrics_observed_at",
                    "performance_metrics", ["observed_at"])
    op.create_index("ix_performance_metrics_tenant_name_observed",
                    "performance_metrics",
                    ["tenant_id", "metric_name", "observed_at"])

    op.create_table(
        "performance_metric_definitions",
        sa.Column("metric_name", sa.String(120), nullable=False),
        sa.Column("domain", sa.String(40), nullable=False),
        sa.Column("unit", sa.String(32), nullable=False),
        sa.Column("metric_type", sa.String(20), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.String(120), nullable=True),
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_performance_metric_definitions_metric_name",
                    "performance_metric_definitions", ["metric_name"])
    op.create_index("ix_performance_metric_definitions_tenant_name",
                    "performance_metric_definitions",
                    ["tenant_id", "metric_name"], unique=True)

    op.create_table(
        "performance_collector_health",
        sa.Column("collector_id", sa.String(120), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("last_report_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("tenant_id", sa.String(120), nullable=True),
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_performance_collector_health_collector_id",
                    "performance_collector_health", ["collector_id"])
    op.create_index("ix_performance_collector_health_tenant_collector",
                    "performance_collector_health",
                    ["tenant_id", "collector_id"], unique=True)


def downgrade() -> None:
    op.drop_table("performance_collector_health")
    op.drop_table("performance_metric_definitions")
    op.drop_table("performance_metrics")
