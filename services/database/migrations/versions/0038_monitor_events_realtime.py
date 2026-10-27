"""Realtime event log tuning.

monitor_events is the durable event log behind the realtime SSE stream:
platform control-plane operations persist rows here and the stream seeds
its backlog from this table after an API restart. The created_at index
keeps the replay/backlog queries (ORDER BY created_at DESC LIMIT n) fast
as the log grows.

Revision ID: 0038
Revises: 0037
Create Date: 2026-09-01
"""
from alembic import op

# revision identifiers
revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_monitor_events_created_at",
        "monitor_events",
        ["created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_monitor_events_created_at", table_name="monitor_events")
