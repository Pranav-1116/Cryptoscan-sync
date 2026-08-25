"""Part 4 maturity tables: agility, exceptions, OT, vendor crypto, cert usages.

Revision ID: 0018
Revises: 0017
"""
from alembic import op
import sqlalchemy as sa

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("certificates", sa.Column("revocation_status", sa.String(30), nullable=True))
    op.add_column("certificates", sa.Column("revocation_method", sa.String(20), nullable=True))
    op.add_column("certificates", sa.Column("revocation_checked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("certificates", sa.Column("ocsp_url", sa.Text, nullable=True))
    op.add_column("certificates", sa.Column("crl_url", sa.Text, nullable=True))
    op.add_column("network_scan_targets", sa.Column("next_scan_time", sa.DateTime(timezone=True), nullable=True))
    op.add_column("systems", sa.Column("current_agility_score", sa.Integer, nullable=True))
    op.add_column("systems", sa.Column("agility_category", sa.String(20), nullable=True))
    op.add_column("systems", sa.Column("migration_readiness_score", sa.Integer, nullable=True))
    op.add_column("systems", sa.Column("migration_readiness_category", sa.String(50), nullable=True))
    op.add_column("systems", sa.Column("extra", sa.JSON, nullable=True))
    op.add_column("vendors", sa.Column("vendor_type", sa.String(50), nullable=True))
    op.add_column("vendors", sa.Column("contract_end_date", sa.DateTime(timezone=True), nullable=True))
    op.add_column("vendors", sa.Column("data_classifications", sa.JSON, nullable=True))
    op.add_column("vendors", sa.Column("integration_type", sa.String(50), nullable=True))
    op.add_column("vendors", sa.Column("primary_contact", sa.String(200), nullable=True))
    op.add_column("vendors", sa.Column("security_contact", sa.String(200), nullable=True))
    op.add_column("vendors", sa.Column("last_assessment_date", sa.DateTime(timezone=True), nullable=True))
    op.add_column("vendors", sa.Column("extra_json", sa.JSON, nullable=True))

    op.create_table(
        "certificate_usages",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(64), nullable=False),
        sa.Column("usage_type", sa.String(40), nullable=False),
        sa.Column("location", sa.String(400), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("fingerprint_sha256", "location", name="uq_cert_usage_location"),
    )
    op.create_index("ix_certificate_usages_fp", "certificate_usages", ["fingerprint_sha256"])

    op.create_table(
        "system_agility_scores",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("system_id", sa.String(36), sa.ForeignKey("systems.id", ondelete="CASCADE"), nullable=False),
        sa.Column("agility_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("category", sa.String(20), nullable=False, server_default="CRITICAL"),
        sa.Column("factor_scores", sa.JSON, nullable=True),
        sa.Column("recommendations", sa.JSON, nullable=True),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("calculation_version", sa.String(20), nullable=False, server_default="agility-v1.0"),
        sa.Column("readiness_score", sa.Integer, nullable=True),
        sa.Column("readiness_category", sa.String(30), nullable=True),
        sa.Column("readiness", sa.JSON, nullable=True),
    )
    op.create_index("ix_system_agility_scores_system", "system_agility_scores", ["system_id"])

    op.create_table(
        "policy_exceptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=True),
        sa.Column("system_id", sa.String(36), nullable=True),
        sa.Column("policy_rule_id", sa.String(50), nullable=True),
        sa.Column("exception_type", sa.String(50), nullable=False, server_default="RISK_ACCEPTANCE"),
        sa.Column("justification", sa.Text, nullable=True),
        sa.Column("risk_statement", sa.Text, nullable=True),
        sa.Column("compensating_controls", sa.Text, nullable=True),
        sa.Column("requested_by", sa.String(100), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.String(100), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approval_signature", sa.Text, nullable=True),
        sa.Column("expiration_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_frequency", sa.String(50), nullable=False, server_default="QUARTERLY"),
        sa.Column("last_reviewed", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="PENDING"),
        sa.Column("notes", sa.Text, nullable=True),
    )
    op.create_index("ix_policy_exceptions_status", "policy_exceptions", ["status"])

    op.create_table(
        "exception_reviews",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("exception_id", sa.String(36), sa.ForeignKey("policy_exceptions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("review_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewer", sa.String(100), nullable=True),
        sa.Column("still_valid", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("action_taken", sa.String(50), nullable=True),
    )

    op.create_table(
        "vendor_crypto_inventory",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("vendor_id", sa.String(36), sa.ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("crypto_use_case", sa.String(100), nullable=True),
        sa.Column("algorithm", sa.String(50), nullable=True),
        sa.Column("key_size", sa.Integer, nullable=True),
        sa.Column("mode", sa.String(50), nullable=True),
        sa.Column("key_management", sa.String(100), nullable=True),
        sa.Column("pqc_ready", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("discovery_method", sa.String(50), nullable=True),
        sa.Column("confidence", sa.String(20), nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_document", sa.Text, nullable=True),
    )

    op.create_table(
        "ot_devices",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("mac_address", sa.String(32), nullable=True),
        sa.Column("vendor", sa.String(100), nullable=True),
        sa.Column("device_type", sa.String(50), nullable=True),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column("firmware_version", sa.String(50), nullable=True),
        sa.Column("protocols_observed", sa.JSON, nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("location", sa.String(200), nullable=True),
        sa.Column("criticality", sa.String(20), nullable=True),
    )
    op.create_index("ix_ot_devices_ip", "ot_devices", ["ip_address"])

    op.create_table(
        "ot_crypto_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("ot_devices.id", ondelete="CASCADE"), nullable=True),
        sa.Column("protocol", sa.String(50), nullable=True),
        sa.Column("crypto_config", sa.JSON, nullable=True),
        sa.Column("has_crypto", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("security_level", sa.String(50), nullable=True),
        sa.Column("vulnerabilities", sa.JSON, nullable=True),
        sa.Column("confidence", sa.String(20), nullable=False, server_default="MEDIUM"),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observation_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("compliance_issue", sa.String(80), nullable=True),
        sa.Column("note", sa.Text, nullable=True),
    )


def downgrade() -> None:
    for table in (
        "ot_crypto_findings",
        "ot_devices",
        "vendor_crypto_inventory",
        "exception_reviews",
        "policy_exceptions",
        "system_agility_scores",
        "certificate_usages",
    ):
        op.drop_table(table)
    for table, cols in (
        ("certificates", ("revocation_status", "revocation_method", "revocation_checked_at", "ocsp_url", "crl_url")),
        ("network_scan_targets", ("next_scan_time",)),
        ("systems", ("current_agility_score", "agility_category", "migration_readiness_score", "migration_readiness_category", "extra")),
        (
            "vendors",
            (
                "vendor_type",
                "contract_end_date",
                "data_classifications",
                "integration_type",
                "primary_contact",
                "security_contact",
                "last_assessment_date",
                "extra_json",
            ),
        ),
    ):
        for col in cols:
            op.drop_column(table, col)
