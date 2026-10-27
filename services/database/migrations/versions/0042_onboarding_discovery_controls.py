"""Onboarding: maintenance-window controls, agent heartbeat, discovery progress.

Adds OT maintenance-window fields to environments, agent check-in fields to
connectors, and plan/progress/timing columns to discovery runs.

Revision ID: 0042
Revises: 0041
Create Date: 2026-09-02
"""
import sqlalchemy as sa
from alembic import op

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # environments — maintenance window controls (OT/ICS safety)
    op.add_column("environments", sa.Column("maintenance_window_enabled", sa.Boolean(),
                                            nullable=False, server_default=sa.false()))
    op.add_column("environments", sa.Column("maintenance_timezone", sa.String(64), nullable=True))
    op.add_column("environments", sa.Column("maintenance_windows", sa.JSON(), nullable=True))

    # connectors — agent heartbeat / encrypted link
    op.add_column("connectors", sa.Column("agent_last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("connectors", sa.Column("agent_version", sa.String(40), nullable=True))
    op.add_column("connectors", sa.Column("agent_link", sa.String(20),
                                          nullable=False, server_default="disconnected"))

    # discovery runs — plan + execution progress
    op.add_column("discovery_runs", sa.Column("plan", sa.JSON(), nullable=True))
    op.add_column("discovery_runs", sa.Column("targets_registered", sa.Integer(),
                                              nullable=False, server_default="0"))
    op.add_column("discovery_runs", sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("discovery_runs", sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("discovery_runs", sa.Column("error", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("discovery_runs", "error")
    op.drop_column("discovery_runs", "finished_at")
    op.drop_column("discovery_runs", "started_at")
    op.drop_column("discovery_runs", "targets_registered")
    op.drop_column("discovery_runs", "plan")
    op.drop_column("connectors", "agent_link")
    op.drop_column("connectors", "agent_version")
    op.drop_column("connectors", "agent_last_seen_at")
    op.drop_column("environments", "maintenance_windows")
    op.drop_column("environments", "maintenance_timezone")
    op.drop_column("environments", "maintenance_window_enabled")
