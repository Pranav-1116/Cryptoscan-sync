"""Deterministic automation engine: configured rules + run records.

Revision ID: 0050
Revises: 0049
Create Date: 2026-09-03

Adds automation_rules (declarative WHEN/IF/THEN) and automation_runs (the plan
produced per event). No AI/ML — rule-based orchestration records.
"""
import sqlalchemy as sa
from alembic import op

revision = "0050"
down_revision = "0049"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "automation_rules",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rule_id", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("when", sa.String(length=60), nullable=False),
        sa.Column("conditions", sa.JSON(), nullable=True),
        sa.Column("actions", sa.JSON(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="MEDIUM"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("created_by", sa.String(length=100), nullable=False, server_default=""),
    )
    op.create_index("ix_ar_rule_id", "automation_rules", ["rule_id"], unique=True)
    op.create_index("ix_ar_when", "automation_rules", ["when"])

    op.create_table(
        "automation_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("event_kind", sa.String(length=60), nullable=False),
        sa.Column("asset_id", sa.String(length=120), nullable=True),
        sa.Column("scanners", sa.JSON(), nullable=True),
        sa.Column("auto_actions", sa.JSON(), nullable=True),
        sa.Column("gated_actions", sa.JSON(), nullable=True),
        sa.Column("matched_rules", sa.JSON(), nullable=True),
        sa.Column("playbook", sa.String(length=80), nullable=True),
        sa.Column("needs_human", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("recommended_tier", sa.String(length=16), nullable=False, server_default="LOW"),
        sa.Column("triggered_by", sa.String(length=100), nullable=False, server_default="system"),
        sa.Column("governance_ref", sa.String(length=120), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_aru_event_kind", "automation_runs", ["event_kind"])
    op.create_index("ix_aru_asset_id", "automation_runs", ["asset_id"])


def downgrade() -> None:
    op.drop_index("ix_aru_asset_id", table_name="automation_runs")
    op.drop_index("ix_aru_event_kind", table_name="automation_runs")
    op.drop_table("automation_runs")
    op.drop_index("ix_ar_when", table_name="automation_rules")
    op.drop_index("ix_ar_rule_id", table_name="automation_rules")
    op.drop_table("automation_rules")
