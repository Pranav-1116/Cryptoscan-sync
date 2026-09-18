""":class:`materialized_stats` / production hardening tables.

Revision ID: 0057
Revises: 0056
Create Date: 2026-09-17

Adds production hardening tables required for enterprise readiness:
- materialized_stats: pre-aggregated counts for /stats/materialized (assets/certs/systems/algorithms/risk) refreshed every 60s via Redis cache.
- cache_metrics: observability for Redis shared cache hit/miss rates (techbom/stats/analytics).
- worm_audit_log: immutable WORM storage audit trail for compliance (SEC 17a-4, FINRA).
- cmek_key_versions: customer-managed encryption key versioning with rotation/escrow tracking.
- mtls_certificates: mTLS cert inventory for zero-trust posture.
- waf_events: WAF blocked/logged request events.
- data_residency_policies: data residency routing enforcement.
"""

import sqlalchemy as sa
from alembic import op

revision = "0057"
down_revision = "0056"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Materialized stats — pre-aggregated view for /stats/materialized
    op.create_table(
        "materialized_stats",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("total_assets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_certificates", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_systems", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_scans", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("algorithms_breakdown", sa.JSON(), nullable=True),
        sa.Column("risk_breakdown", sa.JSON(), nullable=True),
        sa.Column("compliance_score", sa.Float(), nullable=True),
        sa.Column("cache_ttl_seconds", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("source", sa.String(32), nullable=False, server_default="live"),
    )
    op.create_index("ix_materialized_stats_computed_at", "materialized_stats", ["computed_at"])

    # Cache metrics — hit/miss observability for Redis shared cache
    op.create_table(
        "cache_metrics",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("cache_name", sa.String(100), nullable=False),
        sa.Column("key", sa.String(500), nullable=False),
        sa.Column("hit", sa.Boolean(), nullable=False),
        sa.Column("ttl_seconds", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("tenant_id", sa.String(100), nullable=True),
    )
    op.create_index("ix_cache_metrics_cache_name", "cache_metrics", ["cache_name"])
    op.create_index("ix_cache_metrics_created_at", "cache_metrics", ["created_at"])

    # WORM audit log — immutable storage access trail
    op.create_table(
        "worm_audit_log",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("object_id", sa.String(500), nullable=False),
        sa.Column("object_type", sa.String(50), nullable=False, server_default="cbom"),
        sa.Column("actor", sa.String(100), nullable=True),
        sa.Column("retention_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("region", sa.String(50), nullable=True),
        sa.Column("compliance_pack", sa.String(50), nullable=True),
    )
    op.create_index("ix_worm_audit_log_object_id", "worm_audit_log", ["object_id"])
    op.create_index("ix_worm_audit_log_created_at", "worm_audit_log", ["created_at"])

    # CMEK key versions — customer-managed encryption key rotation tracking
    op.create_table(
        "cmek_key_versions",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("key_id", sa.String(500), nullable=False),
        sa.Column("provider", sa.String(20), nullable=False, server_default="aws"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
        sa.Column("escrow_id", sa.String(36), nullable=True),
        sa.Column("dual_control_approved_by", sa.JSON(), nullable=True),
    )
    op.create_index("ix_cmek_key_versions_key_id", "cmek_key_versions", ["key_id"])
    op.create_index("ix_cmek_key_versions_status", "cmek_key_versions", ["status"])

    # mTLS certificates inventory — zero-trust posture
    op.create_table(
        "mtls_certificates",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("common_name", sa.String(200), nullable=False),
        sa.Column("san", sa.String(500), nullable=True),
        sa.Column("spiffe_id", sa.String(500), nullable=True),
        sa.Column("issuer", sa.String(200), nullable=True),
        sa.Column("serial_number", sa.String(100), nullable=True),
        sa.Column("fingerprint_sha256", sa.String(64), nullable=True),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("service", sa.String(50), nullable=True),
        sa.Column("region", sa.String(50), nullable=True),
    )
    op.create_index("ix_mtls_certificates_spiffe_id", "mtls_certificates", ["spiffe_id"])
    op.create_index("ix_mtls_certificates_status", "mtls_certificates", ["status"])

    # WAF events — blocked/logged requests
    op.create_table(
        "waf_events",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("rule_id", sa.String(100), nullable=False),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("method", sa.String(10), nullable=True),
        sa.Column("path", sa.String(500), nullable=True),
        sa.Column("source_ip", sa.String(50), nullable=True),
        sa.Column("user_agent", sa.String(500), nullable=True),
        sa.Column("payload_snippet", sa.Text(), nullable=True),
        sa.Column("tenant_id", sa.String(100), nullable=True),
    )
    op.create_index("ix_waf_events_rule_id", "waf_events", ["rule_id"])
    op.create_index("ix_waf_events_created_at", "waf_events", ["created_at"])

    # Data residency policies — routing enforcement
    op.create_table(
        "data_residency_policies",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("allowed_regions", sa.JSON(), nullable=False),
        sa.Column("sovereign", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("enforced", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("tenant_id", sa.String(100), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_data_residency_policies_name", "data_residency_policies", ["name"], unique=True)

    # Materialized view SQL — create or replace views for fast stats
    # These are advisory; the API uses Redis cache + live queries as fallback.
    op.execute(
        """
        CREATE OR REPLACE VIEW v_materialized_asset_counts AS
        SELECT
            COUNT(*) AS total_assets,
            COUNT(*) FILTER (WHERE deleted_at IS NULL) AS active_assets
        FROM systems;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE VIEW v_materialized_cert_counts AS
        SELECT COUNT(*) AS total_certificates
        FROM certificates;
        """
    )


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS v_materialized_cert_counts;")
    op.execute("DROP VIEW IF EXISTS v_materialized_asset_counts;")
    op.drop_index("ix_data_residency_policies_name", table_name="data_residency_policies")
    op.drop_table("data_residency_policies")
    op.drop_index("ix_waf_events_created_at", table_name="waf_events")
    op.drop_index("ix_waf_events_rule_id", table_name="waf_events")
    op.drop_table("waf_events")
    op.drop_index("ix_mtls_certificates_status", table_name="mtls_certificates")
    op.drop_index("ix_mtls_certificates_spiffe_id", table_name="mtls_certificates")
    op.drop_table("mtls_certificates")
    op.drop_index("ix_cmek_key_versions_status", table_name="cmek_key_versions")
    op.drop_index("ix_cmek_key_versions_key_id", table_name="cmek_key_versions")
    op.drop_table("cmek_key_versions")
    op.drop_index("ix_worm_audit_log_created_at", table_name="worm_audit_log")
    op.drop_index("ix_worm_audit_log_object_id", table_name="worm_audit_log")
    op.drop_table("worm_audit_log")
    op.drop_index("ix_cache_metrics_created_at", table_name="cache_metrics")
    op.drop_index("ix_cache_metrics_cache_name", table_name="cache_metrics")
    op.drop_table("cache_metrics")
    op.drop_index("ix_materialized_stats_computed_at", table_name="materialized_stats")
    op.drop_table("materialized_stats")
