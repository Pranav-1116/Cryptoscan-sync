"""Widen monitor event types for platform events sharing the audit journal.

Revision ID: 0105
Revises: 0104
"""

from alembic import op
import sqlalchemy as sa

revision = "0105"
down_revision = "0104"
branch_labels = depends_on = None


def upgrade() -> None:
    # PostgreSQL widens this VARCHAR without rewriting rows; the existing
    # event-type index and audit records remain in place.
    with op.batch_alter_table("monitor_events") as batch_op:
        batch_op.alter_column(
            "event_type", existing_type=sa.String(30), type_=sa.String(120),
            existing_nullable=False,
        )


def downgrade() -> None:
    # Refuse a lossy rollback, including on SQLite (which does not enforce
    # VARCHAR lengths). Once long event types are archived/removed, retry.
    connection = op.get_bind()
    if connection.execute(sa.text(
        "SELECT 1 FROM monitor_events WHERE length(event_type) > 30 LIMIT 1"
    )).first() is not None:
        raise RuntimeError("cannot narrow monitor_events.event_type: values exceed 30 characters")
    with op.batch_alter_table("monitor_events") as batch_op:
        batch_op.alter_column(
            "event_type", existing_type=sa.String(120), type_=sa.String(30),
            existing_nullable=False,
        )
