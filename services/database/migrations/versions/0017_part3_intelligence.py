"""Part 3 intelligence tables.

Revision ID: 0017
Revises: 0016
"""
from alembic import op
import sqlalchemy as sa

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "certificates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(64), nullable=False),
        sa.Column("subject", sa.Text, nullable=True),
        sa.Column("issuer", sa.Text, nullable=True),
        sa.Column("serial_number", sa.String(128), nullable=True),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("public_key_algorithm", sa.String(40), nullable=True),
        sa.Column("public_key_size", sa.Integer, nullable=True),
        sa.Column("expiry_status", sa.String(30), nullable=True),
        sa.Column("days_until_expiry", sa.Integer, nullable=True),
        sa.Column("is_self_signed", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("san", sa.JSON, nullable=True),
        sa.Column("usages", sa.JSON, nullable=True),
        sa.Column("extra", sa.JSON, nullable=True),
    )
    op.create_index("ix_certificates_fingerprint", "certificates", ["fingerprint_sha256"], unique=True)

    op.create_table(
        "network_scan_targets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("endpoint", sa.String(300), nullable=False),
        sa.Column("system_id", sa.String(36), nullable=True),
        sa.Column("scan_frequency", sa.String(20), nullable=False, server_default="daily"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_scan_time", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_network_scan_targets_endpoint", "network_scan_targets", ["endpoint"], unique=True)

    op.create_table(
        "cloud_accounts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cloud_provider", sa.String(20), nullable=False),
        sa.Column("account_identifier", sa.String(200), nullable=False),
        sa.Column("role_arn", sa.Text, nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("regions", sa.JSON, nullable=True),
        sa.Column("extra", sa.JSON, nullable=True),
    )

    op.create_table(
        "business_processes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("process_type", sa.String(50), nullable=True),
        sa.Column("revenue_daily", sa.Float, nullable=False, server_default="0"),
        sa.Column("customer_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("sla_uptime", sa.Float, nullable=True),
        sa.Column("executive_sponsor", sa.String(100), nullable=True),
        sa.Column("data_classifications", sa.JSON, nullable=True),
        sa.Column("extra", sa.JSON, nullable=True),
    )
    op.create_index("ix_business_processes_name", "business_processes", ["name"], unique=True)

    op.create_table(
        "business_owners",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("email", sa.String(200), nullable=True),
        sa.Column("role", sa.String(100), nullable=True),
        sa.Column("department", sa.String(100), nullable=True),
        sa.Column("escalation_contact", sa.String(200), nullable=True),
    )

    op.create_table(
        "system_business_process_map",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("system_id", sa.String(36), sa.ForeignKey("systems.id", ondelete="CASCADE"), nullable=False),
        sa.Column("process_id", sa.String(36), sa.ForeignKey("business_processes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(40), nullable=True),
    )

    op.create_table(
        "vendors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("criticality", sa.String(20), nullable=True),
        sa.Column("extra", sa.String(400), nullable=True),
    )
    op.create_table(
        "system_vendors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("system_id", sa.String(36), sa.ForeignKey("systems.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vendor_id", sa.String(36), sa.ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("dependency_type", sa.String(40), nullable=True),
    )
    op.create_table(
        "migration_projects",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("system_id", sa.String(36), nullable=True),
        sa.Column("algorithm_from", sa.String(80), nullable=True),
        sa.Column("algorithm_to", sa.String(80), nullable=True),
        sa.Column("status", sa.String(30), nullable=False, server_default="PLANNED"),
        sa.Column("progress", sa.Float, nullable=False, server_default="0"),
        sa.Column("owner", sa.String(200), nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("extra", sa.JSON, nullable=True),
    )


def downgrade() -> None:
    for table in (
        "migration_projects",
        "system_vendors",
        "vendors",
        "system_business_process_map",
        "business_owners",
        "business_processes",
        "cloud_accounts",
        "network_scan_targets",
        "certificates",
    ):
        op.drop_table(table)
