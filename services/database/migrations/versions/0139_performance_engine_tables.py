"""Performance engine tables (docs/performance/01_PRODUCT_SPEC.md §5).

Revision ID: 0139
Revises: 0138
Create Date: 2026-11-08

performance_assets             — Digital Twin asset references (never a
                                 second asset registry)
performance_aggregates         — stored aggregates with their coverage
performance_baselines          — named method over a named window
performance_alerts             — proven AND not-proven, computed severity
performance_incidents          — grouped alert state
performance_slo_policies       — SLO objectives per metric
performance_capacity_forecasts — forecast, not fact (disclaimer stored)
performance_benchmark_runs     — controlled benchmark results, kept
                                 separate from observed production metrics
"""

import sqlalchemy as sa
from alembic import op

revision = "0139"
down_revision = "0138"
branch_labels = None
depends_on = None

_COMMON = (
    sa.Column("tenant_id", sa.String(120), nullable=True),
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)


def _table(name, *columns):
    op.create_table(name, *columns, *_COMMON)


def upgrade() -> None:
    _table(
        "performance_assets",
        sa.Column("asset_id", sa.String(120), nullable=False),
        sa.Column("identity_source", sa.String(40), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_performance_assets_asset_id",
                    "performance_assets", ["asset_id"])
    op.create_index("ix_performance_assets_tenant_asset",
                    "performance_assets", ["tenant_id", "asset_id"],
                    unique=True)

    _table(
        "performance_aggregates",
        sa.Column("metric_name", sa.String(120), nullable=False),
        sa.Column("asset_id", sa.String(120), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("value_count", sa.Integer(), nullable=False),
        sa.Column("unknown_count", sa.Integer(), nullable=False),
        sa.Column("average", sa.Float(), nullable=True),
        sa.Column("p95", sa.Float(), nullable=True),
    )
    op.create_index("ix_performance_aggregates_metric_name",
                    "performance_aggregates", ["metric_name"])
    op.create_index("ix_performance_aggregates_tenant_name_window",
                    "performance_aggregates",
                    ["tenant_id", "metric_name", "window_start"])

    _table(
        "performance_baselines",
        sa.Column("metric_name", sa.String(120), nullable=False),
        sa.Column("asset_id", sa.String(120), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("method", sa.String(80), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("median", sa.Float(), nullable=True),
        sa.Column("p95", sa.Float(), nullable=True),
        sa.Column("mad", sa.Float(), nullable=True),
    )
    op.create_index("ix_performance_baselines_metric_name",
                    "performance_baselines", ["metric_name"])
    op.create_index("ix_performance_baselines_tenant_name_window",
                    "performance_baselines",
                    ["tenant_id", "metric_name", "window_start"])

    _table(
        "performance_alerts",
        sa.Column("metric_name", sa.String(120), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("severity_factors", sa.JSON(), nullable=True),
        sa.Column("proven", sa.JSON(), nullable=True),
        sa.Column("not_proven", sa.JSON(), nullable=True),
        sa.Column("supporting_measurements", sa.JSON(), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raised_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_performance_alerts_metric_name",
                    "performance_alerts", ["metric_name"])
    op.create_index("ix_performance_alerts_tenant_name_raised",
                    "performance_alerts",
                    ["tenant_id", "metric_name", "raised_at"])

    _table(
        "performance_incidents",
        sa.Column("incident_key", sa.String(160), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("alert_ids", sa.JSON(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False),
    )
    op.create_index("ix_performance_incidents_incident_key",
                    "performance_incidents", ["incident_key"])
    op.create_index("ix_performance_incidents_tenant_key",
                    "performance_incidents", ["tenant_id", "incident_key"],
                    unique=True)

    _table(
        "performance_slo_policies",
        sa.Column("policy_key", sa.String(160), nullable=False),
        sa.Column("metric_name", sa.String(120), nullable=False),
        sa.Column("objective", sa.Float(), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("comparator", sa.String(8), nullable=False),
    )
    op.create_index("ix_performance_slo_policies_policy_key",
                    "performance_slo_policies", ["policy_key"])
    op.create_index("ix_performance_slo_policies_tenant_key",
                    "performance_slo_policies", ["tenant_id", "policy_key"],
                    unique=True)

    _table(
        "performance_capacity_forecasts",
        sa.Column("metric_name", sa.String(120), nullable=False),
        sa.Column("method", sa.String(80), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("growth_per_second", sa.Float(), nullable=True),
        sa.Column("estimated_seconds_to_exhaustion", sa.Float(), nullable=True),
        sa.Column("disclaimer", sa.Text(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_performance_capacity_forecasts_metric_name",
                    "performance_capacity_forecasts", ["metric_name"])
    op.create_index("ix_performance_capacity_forecasts_tenant_name",
                    "performance_capacity_forecasts",
                    ["tenant_id", "metric_name"])

    _table(
        "performance_benchmark_runs",
        sa.Column("run_id", sa.String(64), nullable=False),
        sa.Column("measurement_kind", sa.String(40), nullable=False),
        sa.Column("approved", sa.Integer(), nullable=False),
        sa.Column("method", sa.JSON(), nullable=False),
        sa.Column("results", sa.JSON(), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_performance_benchmark_runs_tenant_run",
                    "performance_benchmark_runs", ["tenant_id", "run_id"],
                    unique=True)
    op.create_index("ix_performance_benchmark_runs_run_id",
                    "performance_benchmark_runs", ["run_id"], unique=True)


def downgrade() -> None:
    op.drop_table("performance_benchmark_runs")
    op.drop_table("performance_capacity_forecasts")
    op.drop_table("performance_slo_policies")
    op.drop_table("performance_incidents")
    op.drop_table("performance_alerts")
    op.drop_table("performance_baselines")
    op.drop_table("performance_aggregates")
    op.drop_table("performance_assets")
