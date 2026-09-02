"""ZELNX Control Plane (P0): tenancy, ABAC grants, credential vault refs,
agent fleet, safe-scan policies, asset identity, durable event queue, and
detection benchmarking.

Revision ID: 0043
Revises: 0042
Create Date: 2026-09-06
"""
import sqlalchemy as sa
from alembic import op

revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None


def _base(table, cols):
    op.create_table(
        table,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        *cols,
    )


def upgrade() -> None:
    _base("cp_tenants", [
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("data_residency_region", sa.String(40), nullable=False, server_default="us"),
        sa.Column("processing_regions", sa.JSON(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("extra_info", sa.JSON(), nullable=True),
    ])
    _base("cp_scope_grants", [
        sa.Column("tenant_id", sa.String(36), nullable=True, index=True),
        sa.Column("subject", sa.String(200), nullable=False, index=True),
        sa.Column("subject_type", sa.String(20), nullable=False, server_default="user"),
        sa.Column("actions", sa.JSON(), nullable=False),
        sa.Column("region", sa.String(80), nullable=True, index=True),
        sa.Column("business_unit", sa.String(120), nullable=True, index=True),
        sa.Column("environment", sa.String(120), nullable=True, index=True),
        sa.Column("asset_id", sa.String(36), nullable=True, index=True),
        sa.Column("effect", sa.String(10), nullable=False, server_default="allow"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
    ])
    _base("cp_credentials", [
        sa.Column("tenant_id", sa.String(36), nullable=True, index=True),
        sa.Column("name", sa.String(200), nullable=False, index=True),
        sa.Column("kind", sa.String(30), nullable=False, server_default="other"),
        sa.Column("vault_provider", sa.String(40), nullable=False, server_default="manual_out_of_band"),
        sa.Column("secret_ref", sa.Text(), nullable=False),
        sa.Column("least_privilege_scope", sa.Text(), nullable=True),
        sa.Column("region", sa.String(80), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending", index=True),
        sa.Column("rotation_policy_days", sa.Integer(), nullable=False, server_default="90"),
        sa.Column("last_rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_health_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("health_ok", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("access_count", sa.Integer(), nullable=False, server_default="0"),
    ])
    _base("cp_agents", [
        sa.Column("tenant_id", sa.String(36), nullable=True, index=True),
        sa.Column("name", sa.String(200), nullable=False, index=True),
        sa.Column("region", sa.String(80), nullable=True, index=True),
        sa.Column("environment", sa.String(120), nullable=True),
        sa.Column("platform", sa.String(20), nullable=False, server_default="linux"),
        sa.Column("enrollment_token_fingerprint", sa.String(128), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="enrolled", index=True),
        sa.Column("version", sa.String(40), nullable=True),
        sa.Column("target_version", sa.String(40), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_ip", sa.String(64), nullable=True),
        sa.Column("healthy", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("link", sa.String(20), nullable=False, server_default="disconnected"),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("resource_limits", sa.JSON(), nullable=True),
        sa.Column("offline_events_buffered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cert_serial", sa.String(128), nullable=True),
    ])
    _base("cp_safe_scan_policies", [
        sa.Column("tenant_id", sa.String(36), nullable=True, index=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("scope_region", sa.String(80), nullable=True, index=True),
        sa.Column("scope_environment", sa.String(120), nullable=True),
        sa.Column("mode", sa.String(20), nullable=False, server_default="standard"),
        sa.Column("rate_limit_qps", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("max_connections", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("concurrent_scans", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("scan_budget_minutes", sa.Integer(), nullable=False, server_default="240"),
        sa.Column("excluded_assets", sa.JSON(), nullable=False),
        sa.Column("excluded_ports", sa.JSON(), nullable=False),
        sa.Column("excluded_protocols", sa.JSON(), nullable=False),
        sa.Column("maintenance_windows", sa.JSON(), nullable=False),
        sa.Column("maintenance_timezone", sa.String(64), nullable=True),
        sa.Column("auto_stop_conditions", sa.JSON(), nullable=False),
        sa.Column("emergency_stop", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
    ])
    _base("cp_asset_identities", [
        sa.Column("tenant_id", sa.String(36), nullable=True, index=True),
        sa.Column("canonical_id", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("asset_type", sa.String(40), nullable=True),
        sa.Column("name", sa.String(200), nullable=True),
        sa.Column("region", sa.String(80), nullable=True, index=True),
        sa.Column("business_unit", sa.String(120), nullable=True, index=True),
        sa.Column("environment", sa.String(120), nullable=True, index=True),
        sa.Column("owner", sa.String(200), nullable=True),
        sa.Column("maintainer", sa.String(200), nullable=True),
        sa.Column("application", sa.String(200), nullable=True),
        sa.Column("service", sa.String(200), nullable=True),
        sa.Column("data_classification", sa.String(40), nullable=True),
        sa.Column("criticality", sa.String(20), nullable=True, index=True),
        sa.Column("confidence", sa.String(20), nullable=False, server_default="UNKNOWN", index=True),
        sa.Column("evidence_sources", sa.JSON(), nullable=False),
        sa.Column("source_refs", sa.JSON(), nullable=False),
    ])
    _base("cp_queued_events", [
        sa.Column("event_type", sa.String(80), nullable=False, index=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(60), nullable=False, server_default="control_plane"),
        sa.Column("priority", sa.String(20), nullable=False, server_default="normal", index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued", index=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("leased_by", sa.String(120), nullable=True, index=True),
        sa.Column("leased_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
    ])
    _base("cp_benchmark_datasets", [
        sa.Column("name", sa.String(200), nullable=False, unique=True, index=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("sector", sa.String(50), nullable=True),
        sa.Column("case_count", sa.Integer(), nullable=False, server_default="0"),
    ])
    _base("cp_benchmark_cases", [
        sa.Column("dataset_id", sa.String(36), nullable=False, index=True),
        sa.Column("case_ref", sa.String(200), nullable=False, index=True),
        sa.Column("ground_truth", sa.String(120), nullable=False),
        sa.Column("expected_detection", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("extra_info", sa.JSON(), nullable=True),
    ])
    _base("cp_benchmark_runs", [
        sa.Column("dataset_id", sa.String(36), nullable=False, index=True),
        sa.Column("scanner_id", sa.String(120), nullable=False, server_default="universal"),
        sa.Column("scanner_version", sa.String(60), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="created"),
        sa.Column("true_positive", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("false_positive", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("true_negative", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("false_negative", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("precision", sa.Float(), nullable=True),
        sa.Column("recall", sa.Float(), nullable=True),
        sa.Column("f1", sa.Float(), nullable=True),
        sa.Column("false_positive_rate", sa.Float(), nullable=True),
        sa.Column("accuracy", sa.Float(), nullable=True),
        sa.Column("scored_by", sa.String(120), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
    ])


def downgrade() -> None:
    for table in ("cp_benchmark_runs", "cp_benchmark_cases", "cp_benchmark_datasets",
                  "cp_queued_events", "cp_asset_identities", "cp_safe_scan_policies",
                  "cp_agents", "cp_credentials", "cp_scope_grants", "cp_tenants"):
        op.drop_table(table)
