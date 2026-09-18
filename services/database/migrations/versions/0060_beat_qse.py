""":class:`living_cbom` / `api_scanner` / `network_device` / `ca_hierarchy` / `key_lifecycle` / `streaming_backbone` / `attack_detection` / `telecom_enhanced`.

Revision ID: 0060
Revises: 0059
Create Date: 2026-09-17

Improvement plan to beat QSE Corp — production-grade, no AI:
- Living CBOM Service: current CBOM Redis + version history PostgreSQL cbom_versions_enhanced + diff engine + freshness monitor + webhook subscriptions + WS connections
- API & Protocol Scanner: api_scans, api_endpoints — OpenAPI/GraphQL/gRPC/SOAP/JWT/OAuth2/OIDC/Webhooks/WebSockets/MQTT/AMQP
- Network Device Scanner: network_devices, network_device_scans — SNMPv3/SSH/NETCONF/RESTCONF/IPsec/MACsec/802.1X
- CA Hierarchy Mapping: ca_hierarchy, ca_certificates — Root/Intermediate/Issuing, X.509 parsing, CT logs, risks
- Key Lifecycle: key_lifecycle_keys, key_lifecycle_destruction_certs — state machine CREATED/ACTIVE/ROTATING/RETIRED/DESTROYED/COMPROMISED, rotation monitor, WORM destruction certs
- Streaming Backbone: streaming_topics, streaming_flink_jobs — Kafka 3 brokers 3 AZs 32/16/8/4 partitions, Flink 7 jobs normalization/dedup/policy/attack/cbom/graph/audit, S3 WORM 7y
- Attack Detection: attack_baselines, attack_known_endpoints, attack_key_systems, attack_alerts — 13 deterministic rules
- Telecom Enhanced: telecom_enhanced_scans, telecom_enhanced_findings — SS7/Diameter/SIP_IMS/GTP/5G_SBA/IPsec/MACsec/PFCP, 3GPP TS 33.501/210/102/203/401, safety guardrails
"""

import sqlalchemy as sa
from alembic import op

revision = "0060"
down_revision = "0059"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Living CBOM Enhanced
    op.create_table(
        "cbom_versions_enhanced",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("system_id", sa.String(100), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("cbom_json", sa.JSON(), nullable=True),
        sa.Column("cbom_hash", sa.String(64), nullable=True),
        sa.Column("previous_version_id", sa.String(36), nullable=True),
        sa.Column("jws_signature", sa.String(500), nullable=True),
        sa.Column("change_type", sa.String(20), nullable=True),
        sa.Column("actor", sa.String(100), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_cbom_versions_enhanced_system_id", "cbom_versions_enhanced", ["system_id"])
    op.create_index("ix_cbom_versions_enhanced_version_number", "cbom_versions_enhanced", ["version_number"])

    op.create_table(
        "cbom_subscriptions",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("system_id", sa.String(100), nullable=False),
        sa.Column("webhook_url", sa.String(500), nullable=False),
        sa.Column("events", sa.JSON(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )

    # API Scanner
    op.create_table(
        "api_scans",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("target_url", sa.String(500), nullable=False),
        sa.Column("protocol", sa.String(20), nullable=False, server_default="REST"),
        sa.Column("spec_url", sa.String(500), nullable=True),
        sa.Column("environment", sa.String(100), nullable=False, server_default="default"),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("tls_version", sa.String(10), nullable=True),
        sa.Column("cipher_suite", sa.String(100), nullable=True),
        sa.Column("endpoints_discovered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_api_scans_protocol", "api_scans", ["protocol"])

    op.create_table(
        "api_endpoints",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("api_scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("path", sa.String(500), nullable=False),
        sa.Column("method", sa.String(10), nullable=False, server_default="GET"),
        sa.Column("protocol", sa.String(20), nullable=False, server_default="REST"),
        sa.Column("tls_version", sa.String(10), nullable=True),
        sa.Column("cipher_suite", sa.String(100), nullable=True),
        sa.Column("auth_type", sa.String(50), nullable=True),
        sa.Column("auth_algorithm", sa.String(50), nullable=True),
        sa.Column("key_size", sa.Integer(), nullable=True),
        sa.Column("finding", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_api_endpoints_scan_id", "api_endpoints", ["scan_id"])

    # Network Device Scanner
    op.create_table(
        "network_devices",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("device_type", sa.String(30), nullable=False),
        sa.Column("vendor", sa.String(100), nullable=True),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column("ip_address", sa.String(50), nullable=False),
        sa.Column("environment", sa.String(100), nullable=False, server_default="production"),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("snmp_version", sa.String(10), nullable=True),
        sa.Column("crypto", sa.JSON(), nullable=True),
        sa.Column("risk", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_network_devices_device_type", "network_devices", ["device_type"])
    op.create_index("ix_network_devices_ip_address", "network_devices", ["ip_address"])

    op.create_table(
        "network_device_scans",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("network_devices.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ip_address", sa.String(50), nullable=True),
        sa.Column("scan_type", sa.String(20), nullable=False, server_default="full"),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("findings", sa.JSON(), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )

    # CA Hierarchy
    op.create_table(
        "ca_hierarchy",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("ca_type", sa.String(20), nullable=False),
        sa.Column("subject", sa.String(500), nullable=False),
        sa.Column("issuer", sa.String(500), nullable=True),
        sa.Column("key_algorithm", sa.String(30), nullable=True),
        sa.Column("signature_algorithm", sa.String(30), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_ca", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("path_length", sa.Integer(), nullable=True),
        sa.Column("crl_url", sa.String(500), nullable=True),
        sa.Column("ocsp_url", sa.String(500), nullable=True),
        sa.Column("parent_ca_id", sa.String(36), sa.ForeignKey("ca_hierarchy.id", ondelete="SET NULL"), nullable=True),
        sa.Column("environment", sa.String(100), nullable=False, server_default="production"),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("risks", sa.JSON(), nullable=True),
        sa.Column("risk_level", sa.String(20), nullable=False, server_default="low"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_ca_hierarchy_ca_type", "ca_hierarchy", ["ca_type"])
    op.create_index("ix_ca_hierarchy_parent_ca_id", "ca_hierarchy", ["parent_ca_id"])

    op.create_table(
        "ca_certificates",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("common_name", sa.String(200), nullable=False),
        sa.Column("subject", sa.String(500), nullable=False),
        sa.Column("issuer", sa.String(500), nullable=False),
        sa.Column("ca_id", sa.String(36), sa.ForeignKey("ca_hierarchy.id", ondelete="SET NULL"), nullable=True),
        sa.Column("key_algorithm", sa.String(30), nullable=True),
        sa.Column("signature_algorithm", sa.String(30), nullable=True),
        sa.Column("san", sa.JSON(), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )

    # Key Lifecycle Enhanced
    op.create_table(
        "key_lifecycle_keys",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("key_id", sa.String(100), nullable=False),
        sa.Column("algorithm", sa.String(30), nullable=False),
        sa.Column("key_size", sa.Integer(), nullable=True),
        sa.Column("owner", sa.String(100), nullable=False),
        sa.Column("system", sa.String(100), nullable=True),
        sa.Column("purpose", sa.String(50), nullable=False, server_default="ENCRYPTION"),
        sa.Column("location", sa.String(20), nullable=False, server_default="KMS"),
        sa.Column("state", sa.String(20), nullable=False, server_default="CREATED"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotation_policy", sa.JSON(), nullable=True),
        sa.Column("last_rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_rotation_due", sa.DateTime(timezone=True), nullable=True),
        sa.Column("usage_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("escrow_status", sa.String(20), nullable=False, server_default="not_escrowed"),
        sa.Column("destruction_status", sa.String(20), nullable=False, server_default="not_destroyed"),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("state_history", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_key_lifecycle_keys_state", "key_lifecycle_keys", ["state"])
    op.create_index("ix_key_lifecycle_keys_algorithm", "key_lifecycle_keys", ["algorithm"])

    op.create_table(
        "key_lifecycle_destruction_certs",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("key_id", sa.String(36), sa.ForeignKey("key_lifecycle_keys.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key_algorithm", sa.String(30), nullable=True),
        sa.Column("owner", sa.String(100), nullable=True),
        sa.Column("destroyed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("destroyed_by", sa.String(100), nullable=True),
        sa.Column("verification", sa.JSON(), nullable=True),
        sa.Column("certificate_hash", sa.String(64), nullable=True),
        sa.Column("signature", sa.String(128), nullable=True),
        sa.Column("worm_stored", sa.Boolean(), nullable=False, server_default="0"),
    )

    # Streaming Backbone
    op.create_table(
        "streaming_topics",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("partitions", sa.Integer(), nullable=False),
        sa.Column("retention_hours", sa.Integer(), nullable=False),
        sa.Column("messages", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_streaming_topics_name", "streaming_topics", ["name"], unique=True)

    op.create_table(
        "streaming_flink_jobs",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="running"),
        sa.Column("parallelism", sa.Integer(), nullable=False, server_default="4"),
        sa.Column("processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("errors", sa.Integer(), nullable=False, server_default="0"),
    )

    # Attack Detection
    op.create_table(
        "attack_baselines",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("system_id", sa.String(100), nullable=False),
        sa.Column("tls_version", sa.String(10), nullable=True),
        sa.Column("algorithm", sa.String(30), nullable=True),
        sa.Column("key_size", sa.Integer(), nullable=True),
        sa.Column("cipher_suite", sa.String(100), nullable=True),
        sa.Column("cert_fingerprint", sa.String(64), nullable=True),
        sa.Column("trusted_cas", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_attack_baselines_system_id", "attack_baselines", ["system_id"])

    op.create_table(
        "attack_alerts",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("system_id", sa.String(100), nullable=False),
        sa.Column("rule_id", sa.String(20), nullable=False),
        sa.Column("rule_name", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("channels", sa.JSON(), nullable=True),
    )
    op.create_index("ix_attack_alerts_system_id", "attack_alerts", ["system_id"])
    op.create_index("ix_attack_alerts_rule_id", "attack_alerts", ["rule_id"])
    op.create_index("ix_attack_alerts_severity", "attack_alerts", ["severity"])

    # Telecom Enhanced
    op.create_table(
        "telecom_enhanced_scans",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("target_type", sa.String(20), nullable=False),
        sa.Column("target", sa.String(200), nullable=False),
        sa.Column("environment", sa.String(100), nullable=False, server_default="production"),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("safety_mode", sa.String(20), nullable=False, server_default="passive_only"),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(100), nullable=True),
    )

    op.create_table(
        "telecom_enhanced_findings",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("telecom_enhanced_scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("protocol", sa.String(20), nullable=False),
        sa.Column("nf_type", sa.String(20), nullable=True),
        sa.Column("crypto", sa.JSON(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="low"),
        sa.Column("3gpp", sa.String(20), nullable=True),
    )
    op.create_index("ix_telecom_enhanced_findings_scan_id", "telecom_enhanced_findings", ["scan_id"])
    op.create_index("ix_telecom_enhanced_findings_protocol", "telecom_enhanced_findings", ["protocol"])


def downgrade() -> None:
    op.drop_index("ix_telecom_enhanced_findings_protocol", table_name="telecom_enhanced_findings")
    op.drop_index("ix_telecom_enhanced_findings_scan_id", table_name="telecom_enhanced_findings")
    op.drop_table("telecom_enhanced_findings")
    op.drop_table("telecom_enhanced_scans")
    op.drop_index("ix_attack_alerts_severity", table_name="attack_alerts")
    op.drop_index("ix_attack_alerts_rule_id", table_name="attack_alerts")
    op.drop_index("ix_attack_alerts_system_id", table_name="attack_alerts")
    op.drop_table("attack_alerts")
    op.drop_index("ix_attack_baselines_system_id", table_name="attack_baselines")
    op.drop_table("attack_baselines")
    op.drop_table("streaming_flink_jobs")
    op.drop_index("ix_streaming_topics_name", table_name="streaming_topics")
    op.drop_table("streaming_topics")
    op.drop_table("key_lifecycle_destruction_certs")
    op.drop_index("ix_key_lifecycle_keys_algorithm", table_name="key_lifecycle_keys")
    op.drop_index("ix_key_lifecycle_keys_state", table_name="key_lifecycle_keys")
    op.drop_table("key_lifecycle_keys")
    op.drop_table("ca_certificates")
    op.drop_index("ix_ca_hierarchy_parent_ca_id", table_name="ca_hierarchy")
    op.drop_index("ix_ca_hierarchy_ca_type", table_name="ca_hierarchy")
    op.drop_table("ca_hierarchy")
    op.drop_table("network_device_scans")
    op.drop_index("ix_network_devices_ip_address", table_name="network_devices")
    op.drop_index("ix_network_devices_device_type", table_name="network_devices")
    op.drop_table("network_devices")
    op.drop_index("ix_api_endpoints_scan_id", table_name="api_endpoints")
    op.drop_table("api_endpoints")
    op.drop_index("ix_api_scans_protocol", table_name="api_scans")
    op.drop_table("api_scans")
    op.drop_table("cbom_subscriptions")
    op.drop_index("ix_cbom_versions_enhanced_version_number", table_name="cbom_versions_enhanced")
    op.drop_index("ix_cbom_versions_enhanced_system_id", table_name="cbom_versions_enhanced")
    op.drop_table("cbom_versions_enhanced")
