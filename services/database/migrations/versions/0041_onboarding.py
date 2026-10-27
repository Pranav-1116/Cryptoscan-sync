"""Enterprise onboarding aggregate: organizations, environments, authorized
scope entries, connectors, and discovery runs.

These tables model the customer setup journey before the universal engine
takes over (org -> sector -> environment -> scope -> connections -> discovery).

Revision ID: 0041
Revises: 0040
Create Date: 2026-09-02
"""
import sqlalchemy as sa
from alembic import op

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("sector", sa.String(50), nullable=False, server_default="generic"),
        sa.Column("industry", sa.String(100), nullable=True),
        sa.Column("regions", sa.JSON(), nullable=True),
        sa.Column("business_units", sa.JSON(), nullable=True),
        sa.Column("onboarding_stage", sa.String(40), nullable=False, server_default="organization"),
        sa.Column("onboarding_complete", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "environments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False, index=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("env_type", sa.String(40), nullable=False, server_default="production"),
        sa.Column("region", sa.String(120), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("scan_mode", sa.String(20), nullable=False, server_default="standard"),
        sa.Column("active_probing", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "scope_entries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False, index=True),
        sa.Column("env_id", sa.String(36), nullable=True, index=True),
        sa.Column("kind", sa.String(20), nullable=False, index=True),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "connectors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False, index=True),
        sa.Column("env_id", sa.String(36), nullable=True, index=True),
        sa.Column("kind", sa.String(30), nullable=False, index=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("method", sa.String(30), nullable=False, server_default="api"),
        sa.Column("mode", sa.String(20), nullable=False, server_default="passive"),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("last_tested_at", sa.String(40), nullable=True),
        sa.Column("test_result", sa.JSON(), nullable=True),
        sa.Column("agent_id", sa.String(80), nullable=True, index=True),
        sa.Column("agent_healthy", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "discovery_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False, index=True),
        sa.Column("run_type", sa.String(20), nullable=False, server_default="initial"),
        sa.Column("status", sa.String(20), nullable=False, server_default="planned"),
        sa.Column("summary", sa.JSON(), nullable=True),
        sa.Column("assets_discovered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("triggered_by", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("discovery_runs")
    op.drop_table("connectors")
    op.drop_table("scope_entries")
    op.drop_table("environments")
    op.drop_table("organizations")
