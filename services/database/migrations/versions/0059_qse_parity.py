""":class:`casb_*` / `hbom_*` / `entropy_*` / `sovereign_*` / `hsm_*` / `qsim_*` / `collaboration_*` / `compliance_cert_*`.

Revision ID: 0059
Revises: 0058
Create Date: 2026-09-17

QSE parity production hardening — without AI:
- CASB: saas_apps, access_policies, dlp_policies, shadow_it_discoveries, devices, cis_benchmark_runs
- HBOM: hbom_components, hbom_boms
- Entropy Core: entropy_sources, entropy_pools, entropy_audit_log
- Sovereign Storage: storage_buckets, storage_objects
- HSM Fabric: hsm_inventory, hsm_partitions, hsm_keys
- QSim: qsim_simulations, qsim_roadmaps
- Collaboration: collab_assessments, collab_risk_items, collab_comments
- Compliance Cert: compliance_cert_assessments, compliance_cert_controls
"""

import sqlalchemy as sa
from alembic import op

revision = "0059"
down_revision = "0058"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # CASB — SaaS apps
    op.create_table(
        "casb_saas_apps",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("app_type", sa.String(50), nullable=False),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("display_name", sa.String(200), nullable=True),
        sa.Column("domain", sa.String(200), nullable=True),
        sa.Column("admin_email", sa.String(200), nullable=True),
        sa.Column("credentials_configured", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending_credentials"),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_casb_saas_apps_app_type", "casb_saas_apps", ["app_type"])
    op.create_index("ix_casb_saas_apps_tenant_id", "casb_saas_apps", ["tenant_id"])

    op.create_table(
        "casb_access_policies",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("app_type", sa.String(50), nullable=True),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("ip_whitelist", sa.JSON(), nullable=True),
        sa.Column("ip_blacklist", sa.JSON(), nullable=True),
        sa.Column("browser_whitelist", sa.JSON(), nullable=True),
        sa.Column("device_mac_whitelist", sa.JSON(), nullable=True),
        sa.Column("geo_fence_countries", sa.JSON(), nullable=True),
        sa.Column("geo_fence_cities", sa.JSON(), nullable=True),
        sa.Column("geo_mode", sa.String(20), nullable=False, server_default="whitelist"),
        sa.Column("time_restriction", sa.JSON(), nullable=True),
        sa.Column("session_timeout_minutes", sa.Integer(), nullable=True),
        sa.Column("session_max_duration_minutes", sa.Integer(), nullable=True),
        sa.Column("third_party_app_whitelist", sa.JSON(), nullable=True),
        sa.Column("domain_whitelist", sa.JSON(), nullable=True),
        sa.Column("enforced", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_casb_access_policies_tenant_id", "casb_access_policies", ["tenant_id"])

    op.create_table(
        "casb_dlp_policies",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("app_type", sa.String(50), nullable=True),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("rules", sa.JSON(), nullable=True),
        sa.Column("scan_attachments", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("scan_shared_drives", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("enforced", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )

    op.create_table(
        "casb_shadow_it",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("apps", sa.JSON(), nullable=True),
        sa.Column("total_unsanctioned", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high_risk_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )

    op.create_table(
        "casb_devices",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("mac_address", sa.String(20), nullable=False),
        sa.Column("hostname", sa.String(200), nullable=True),
        sa.Column("os", sa.String(20), nullable=True),
        sa.Column("owner", sa.String(100), nullable=True),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("trusted", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_casb_devices_mac_address", "casb_devices", ["mac_address"])

    op.create_table(
        "casb_cis_benchmarks",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("provider", sa.String(20), nullable=False, server_default="aws"),
        sa.Column("total_controls", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("passed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("results", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )

    # HBOM
    op.create_table(
        "hbom_components",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("component_type", sa.String(30), nullable=False),
        sa.Column("manufacturer", sa.String(200), nullable=True),
        sa.Column("model", sa.String(200), nullable=True),
        sa.Column("serial_number", sa.String(200), nullable=True),
        sa.Column("firmware_version", sa.String(100), nullable=True),
        sa.Column("firmware_supplier", sa.String(200), nullable=True),
        sa.Column("supplier", sa.String(200), nullable=True),
        sa.Column("supplier_country", sa.String(50), nullable=True),
        sa.Column("supplier_trust_level", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("location", sa.String(200), nullable=True),
        sa.Column("environment", sa.String(100), nullable=False, server_default="production"),
        sa.Column("crypto_algorithms", sa.JSON(), nullable=True),
        sa.Column("certificates", sa.JSON(), nullable=True),
        sa.Column("keys", sa.JSON(), nullable=True),
        sa.Column("parent_id", sa.String(36), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_factors", sa.JSON(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_hbom_components_component_type", "hbom_components", ["component_type"])
    op.create_index("ix_hbom_components_supplier", "hbom_components", ["supplier"])

    op.create_table(
        "hbom_boms",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("version", sa.String(50), nullable=False, server_default="1.0.0"),
        sa.Column("environment", sa.String(100), nullable=False, server_default="default"),
        sa.Column("component_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("content_hash", sa.String(64), nullable=True),
        sa.Column("bom", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )

    # Entropy Core
    op.create_table(
        "entropy_sources",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("source_type", sa.String(30), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False, server_default="software"),
        sa.Column("total_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("health_checks_passed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("health_checks_failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("compliance", sa.JSON(), nullable=True),
    )

    op.create_table(
        "entropy_pools",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("total_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("requests", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_request", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_entropy_pools_tenant_id", "entropy_pools", ["tenant_id"])

    # Sovereign Storage
    op.create_table(
        "storage_buckets",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("tier", sa.String(20), nullable=False, server_default="basic"),
        sa.Column("region", sa.String(50), nullable=False, server_default="us-east-1"),
        sa.Column("sovereign", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("encryption", sa.String(50), nullable=False, server_default="AES-256-GCM+QRNG"),
        sa.Column("replication_factor", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("bucket_key_fingerprint", sa.String(16), nullable=True),
        sa.Column("cid_prefix", sa.String(50), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_storage_buckets_name", "storage_buckets", ["name"], unique=True)
    op.create_index("ix_storage_buckets_tenant_id", "storage_buckets", ["tenant_id"])

    op.create_table(
        "storage_objects",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("bucket_id", sa.String(36), sa.ForeignKey("storage_buckets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key", sa.String(500), nullable=False),
        sa.Column("cid", sa.String(100), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("encrypted_size_bytes", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("encryption", sa.String(50), nullable=True),
        sa.Column("replication", sa.Integer(), nullable=True),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_storage_objects_bucket_id", "storage_objects", ["bucket_id"])
    op.create_index("ix_storage_objects_cid", "storage_objects", ["cid"])

    # HSM Fabric
    op.create_table(
        "hsm_inventory",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("vendor", sa.String(30), nullable=False),
        sa.Column("model", sa.String(200), nullable=True),
        sa.Column("firmware_version", sa.String(100), nullable=True),
        sa.Column("serial_number", sa.String(200), nullable=True),
        sa.Column("location", sa.String(200), nullable=True),
        sa.Column("environment", sa.String(100), nullable=False, server_default="production"),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("pkcs11_library", sa.String(500), nullable=True),
        sa.Column("kmip_endpoint", sa.String(500), nullable=True),
        sa.Column("partition_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(30), nullable=False, server_default="registered_simulated"),
        sa.Column("crypto_capabilities", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_hsm_inventory_vendor", "hsm_inventory", ["vendor"])

    op.create_table(
        "hsm_partitions",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("hsm_id", sa.String(36), sa.ForeignKey("hsm_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slot_id", sa.Integer(), nullable=True),
        sa.Column("label", sa.String(200), nullable=True),
        sa.Column("key_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
    )
    op.create_index("ix_hsm_partitions_hsm_id", "hsm_partitions", ["hsm_id"])

    op.create_table(
        "hsm_keys",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("hsm_id", sa.String(36), sa.ForeignKey("hsm_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("partition_id", sa.String(36), sa.ForeignKey("hsm_partitions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("key_type", sa.String(30), nullable=False),
        sa.Column("label", sa.String(200), nullable=True),
        sa.Column("fingerprint", sa.String(16), nullable=True),
        sa.Column("fingerprint_full", sa.String(64), nullable=True),
        sa.Column("extractable", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("entropy_source", sa.String(50), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_hsm_keys_hsm_id", "hsm_keys", ["hsm_id"])

    # QSim
    op.create_table(
        "qsim_simulations",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("environment", sa.String(100), nullable=False, server_default="default"),
        sa.Column("total_assets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_cost_usd", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_effort_days", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_effort_months", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("avg_risk_reduction", sa.Float(), nullable=True),
        sa.Column("prioritized_actions", sa.JSON(), nullable=True),
        sa.Column("phases", sa.JSON(), nullable=True),
        sa.Column("mosca", sa.JSON(), nullable=True),
        sa.Column("budget", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )

    op.create_table(
        "qsim_roadmaps",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("simulation_id", sa.String(36), sa.ForeignKey("qsim_simulations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("environment", sa.String(100), nullable=False, server_default="default"),
        sa.Column("executive_summary", sa.Text(), nullable=True),
        sa.Column("phases", sa.JSON(), nullable=True),
        sa.Column("top_20", sa.JSON(), nullable=True),
        sa.Column("total_cost", sa.Integer(), nullable=True),
        sa.Column("total_months", sa.Integer(), nullable=True),
        sa.Column("board_metrics", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_qsim_roadmaps_simulation_id", "qsim_roadmaps", ["simulation_id"])

    # Collaboration
    op.create_table(
        "collab_assessments",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("environment", sa.String(100), nullable=False, server_default="default"),
        sa.Column("quarter", sa.String(10), nullable=False, server_default="Q1-2026"),
        sa.Column("posture_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("categories", sa.JSON(), nullable=True),
        sa.Column("category_analysis", sa.JSON(), nullable=True),
        sa.Column("risk_items_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("comments_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_collab_assessments_quarter", "collab_assessments", ["quarter"])

    op.create_table(
        "collab_risk_items",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("collab_assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("category", sa.String(30), nullable=False, server_default="inventory"),
        sa.Column("assigned_team", sa.String(20), nullable=False, server_default="security"),
        sa.Column("assigned_to", sa.String(100), nullable=True),
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("comments_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_collab_risk_items_assessment_id", "collab_risk_items", ["assessment_id"])
    op.create_index("ix_collab_risk_items_assigned_team", "collab_risk_items", ["assigned_team"])

    op.create_table(
        "collab_comments",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("risk_item_id", sa.String(36), sa.ForeignKey("collab_risk_items.id", ondelete="CASCADE"), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("author", sa.String(100), nullable=True),
        sa.Column("author_team", sa.String(20), nullable=True),
    )
    op.create_index("ix_collab_comments_risk_item_id", "collab_comments", ["risk_item_id"])

    # Compliance Cert
    op.create_table(
        "compliance_cert_assessments",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("framework", sa.String(50), nullable=False),
        sa.Column("framework_name", sa.String(200), nullable=True),
        sa.Column("standard", sa.String(200), nullable=True),
        sa.Column("environment", sa.String(100), nullable=False, server_default="default"),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("total_controls", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("passed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("partial", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("compliant", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("controls", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_compliance_cert_assessments_framework", "compliance_cert_assessments", ["framework"])
    op.create_index("ix_compliance_cert_assessments_tenant_id", "compliance_cert_assessments", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_compliance_cert_assessments_tenant_id", table_name="compliance_cert_assessments")
    op.drop_index("ix_compliance_cert_assessments_framework", table_name="compliance_cert_assessments")
    op.drop_table("compliance_cert_assessments")
    op.drop_index("ix_collab_comments_risk_item_id", table_name="collab_comments")
    op.drop_table("collab_comments")
    op.drop_index("ix_collab_risk_items_assigned_team", table_name="collab_risk_items")
    op.drop_index("ix_collab_risk_items_assessment_id", table_name="collab_risk_items")
    op.drop_table("collab_risk_items")
    op.drop_index("ix_collab_assessments_quarter", table_name="collab_assessments")
    op.drop_table("collab_assessments")
    op.drop_index("ix_qsim_roadmaps_simulation_id", table_name="qsim_roadmaps")
    op.drop_table("qsim_roadmaps")
    op.drop_table("qsim_simulations")
    op.drop_index("ix_hsm_keys_hsm_id", table_name="hsm_keys")
    op.drop_table("hsm_keys")
    op.drop_index("ix_hsm_partitions_hsm_id", table_name="hsm_partitions")
    op.drop_table("hsm_partitions")
    op.drop_index("ix_hsm_inventory_vendor", table_name="hsm_inventory")
    op.drop_table("hsm_inventory")
    op.drop_index("ix_storage_objects_cid", table_name="storage_objects")
    op.drop_index("ix_storage_objects_bucket_id", table_name="storage_objects")
    op.drop_table("storage_objects")
    op.drop_index("ix_storage_buckets_tenant_id", table_name="storage_buckets")
    op.drop_index("ix_storage_buckets_name", table_name="storage_buckets")
    op.drop_table("storage_buckets")
    op.drop_index("ix_entropy_pools_tenant_id", table_name="entropy_pools")
    op.drop_table("entropy_pools")
    op.drop_table("entropy_sources")
    op.drop_index("ix_hbom_components_supplier", table_name="hbom_components")
    op.drop_index("ix_hbom_components_component_type", table_name="hbom_components")
    op.drop_table("hbom_components")
    op.drop_table("hbom_boms")
    op.drop_table("casb_cis_benchmarks")
    op.drop_index("ix_casb_devices_mac_address", table_name="casb_devices")
    op.drop_table("casb_devices")
    op.drop_table("casb_shadow_it")
    op.drop_table("casb_dlp_policies")
    op.drop_index("ix_casb_access_policies_tenant_id", table_name="casb_access_policies")
    op.drop_table("casb_access_policies")
    op.drop_index("ix_casb_saas_apps_tenant_id", table_name="casb_saas_apps")
    op.drop_index("ix_casb_saas_apps_app_type", table_name="casb_saas_apps")
    op.drop_table("casb_saas_apps")
