"""Drift acknowledgment timestamps (report 31 §5/§6, round 23).

The acknowledge path reused the resolve path: acknowledging a drift event
stamped ``resolved_at`` and left no record of *when it was acknowledged* —
so drift MTTA (mean time to acknowledge) was uncomputable and the SLA
metrics report 31 asks for could not exist. This migration adds
``acknowledged_at`` / ``acknowledged_by``.

Historical rows keep NULL — an event acknowledged before this column
existed has an unknown acknowledge time, and that unknown is surfaced by
the SLA endpoint (``acknowledge_time_unknown``) rather than fabricated
from the resolve or audit timestamps.
"""

from alembic import op
import sqlalchemy as sa

revision = "0079"
down_revision = "0078"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("drift_events") as batch:
        batch.add_column(sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("acknowledged_by", sa.String(100), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("drift_events") as batch:
        batch.drop_column("acknowledged_by")
        batch.drop_column("acknowledged_at")
