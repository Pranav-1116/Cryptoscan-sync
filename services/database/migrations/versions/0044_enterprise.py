"""P1 enterprise layer: policy-as-code (versioned), compliance intelligence,
ITSM tickets, CMDB/ITS/SIEM integrations, regions/DR, crypto knowledge base.

Revision ID: 0044
Revises: 0043
Create Date: 2026-09-06
"""
import sqlalchemy as sa
from alembic import op

revision = "0044"
down_revision = "0043"
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
    _base("ent_policies", [
        sa.Column("name", sa.String(200), nullable=False, index=True),
        sa.Column("layer", sa.String(20), nullable=False, server_default="organization", index=True),
        sa.Column("sector", sa.String(50), nullable=True, index=True),
        sa.Column("region", sa.String(40), nullable=True, index=True),
        sa.Column("tenant_id", sa.String(36), nullable=True, index=True),
        sa.Column("version", sa.String(32), nullable=False, server_default="v0"),
        sa.Column("rules", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(120), nullable=True),
    ])
    _base("ent_policy_evaluations", [
        sa.Column("policy_version", sa.String(32), nullable=False, index=True),
        sa.Column("target_type", sa.String(40), nullable=False),
        sa.Column("target_id", sa.String(64), nullable=True, index=True),
        sa.Column("verdict", sa.String(20), nullable=False, index=True),
        sa.Column("results", sa.JSON(), nullable=False),
    ])
    _base("ent_compliance_controls", [
        sa.Column("framework", sa.String(60), nullable=False, index=True),
        sa.Column("control_id", sa.String(60), nullable=False, index=True),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("sector", sa.String(50), nullable=True, index=True),
        sa.Column("assets", sa.JSON(), nullable=False),
    ])
    _base("ent_compliance_status", [
        sa.Column("framework", sa.String(60), nullable=False, index=True),
        sa.Column("control_id", sa.String(60), nullable=False, index=True),
        sa.Column("status", sa.String(20), nullable=False, index=True),
        sa.Column("open_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("compliance_pct", sa.Float(), nullable=True),
        sa.Column("coverage_pct", sa.Float(), nullable=True),
    ])
    _base("ent_tickets", [
        sa.Column("provider", sa.String(30), nullable=False, server_default="manual"),
        sa.Column("external_ref", sa.String(120), nullable=True, index=True),
        sa.Column("finding_id", sa.String(64), nullable=True, index=True),
        sa.Column("asset_id", sa.String(64), nullable=True, index=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("assignee", sa.String(120), nullable=True),
        sa.Column("state", sa.String(20), nullable=False, server_default="open", index=True),
        sa.Column("history", sa.JSON(), nullable=False),
    ])
    _base("ent_integrations", [
        sa.Column("kind", sa.String(20), nullable=False, index=True),
        sa.Column("provider", sa.String(40), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("endpoint", sa.Text(), nullable=True),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("credential_id", sa.String(36), nullable=True),
        sa.Column("last_sync_at", sa.String(40), nullable=True),
        sa.Column("last_sync_status", sa.String(20), nullable=True),
    ])
    _base("ent_regions", [
        sa.Column("code", sa.String(20), nullable=False, unique=True, index=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("healthy", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("rpo_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("rto_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("last_backup_at", sa.String(40), nullable=True),
    ])
    _base("ent_crypto_kb", [
        sa.Column("algorithm", sa.String(120), nullable=False, unique=True, index=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("category", sa.String(40), nullable=True),
        sa.Column("pqc", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("migration_candidate", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
    ])


def downgrade() -> None:
    for table in ("ent_crypto_kb", "ent_regions", "ent_integrations", "ent_tickets",
                  "ent_compliance_status", "ent_compliance_controls",
                  "ent_policy_evaluations", "ent_policies"):
        op.drop_table(table)
