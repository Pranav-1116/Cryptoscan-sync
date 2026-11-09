"""os runtime sessions and metadata events

Revision ID: 0145
Revises: 0144
Create Date: 2026-10-16
"""

import sqlalchemy as sa
from alembic import op

revision = "0145"
down_revision = "0144"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "os_runtime_sessions",
        sa.Column("id", sa.Integer(), autoincrement=True,
                  nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=80), nullable=False),
        sa.Column("asset_id", sa.String(length=80), nullable=False),
        sa.Column("boot_id", sa.String(length=80), nullable=True),
        sa.Column("collection_profile", sa.String(length=80),
                  nullable=False),
        sa.Column("evidence_source", sa.String(length=200),
                  nullable=True),
        sa.Column("started_at", sa.String(length=40), nullable=True),
        sa.Column("ended_at", sa.String(length=40), nullable=True),
        sa.Column("attached_points", sa.JSON(), nullable=True),
        sa.Column("events_accepted", sa.Integer(), nullable=False,
                  server_default="0"),
        sa.Column("events_lost", sa.Integer(), nullable=False,
                  server_default="0"),
        sa.Column("refusals", sa.JSON(), nullable=True),
        sa.Column("notes", sa.JSON(), nullable=True),
        sa.Column("collected_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id",
                            name="uq_os_runtime_sessions_session_id"),
    )
    op.create_index("ix_os_runtime_sessions_tenant_asset",
                    "os_runtime_sessions",
                    ["tenant_id", "asset_id"])
    op.create_table(
        "os_runtime_events",
        sa.Column("id", sa.Integer(), autoincrement=True,
                  nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=80), nullable=False),
        sa.Column("asset_id", sa.String(length=80), nullable=False),
        sa.Column("event_id", sa.String(length=80), nullable=False),
        sa.Column("boot_id", sa.String(length=80), nullable=True),
        sa.Column("process_id", sa.String(length=40), nullable=True),
        sa.Column("process_start_time", sa.String(length=40),
                  nullable=True),
        sa.Column("executable_digest", sa.String(length=120),
                  nullable=True),
        sa.Column("operation_category", sa.String(length=60),
                  nullable=False),
        sa.Column("algorithm_identifier", sa.String(length=120),
                  nullable=True),
        sa.Column("provider_identifier", sa.String(length=120),
                  nullable=True),
        sa.Column("kernel_or_userspace", sa.String(length=20),
                  nullable=True),
        sa.Column("interface", sa.String(length=80), nullable=True),
        sa.Column("timestamp", sa.String(length=40), nullable=True),
        sa.Column("evidence_source", sa.String(length=200),
                  nullable=True),
        sa.Column("collection_profile", sa.String(length=80),
                  nullable=True),
        sa.Column("collected_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_os_runtime_events_tenant_session",
                    "os_runtime_events", ["tenant_id", "session_id"])


def downgrade() -> None:
    op.drop_index("ix_os_runtime_events_tenant_session",
                  "os_runtime_events")
    op.drop_table("os_runtime_events")
    op.drop_index("ix_os_runtime_sessions_tenant_asset",
                  "os_runtime_sessions")
    op.drop_table("os_runtime_sessions")
