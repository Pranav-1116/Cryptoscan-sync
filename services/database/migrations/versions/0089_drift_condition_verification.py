"""Drift condition-level verification columns (§4.7, round 40).

RESOLVED stays an administrative state. These columns record what a
LATER authorized scan's evidence said about the drifted condition:
``verification_status`` (VERIFIED | CONDITION_PRESENT), the scan whose
evidence produced the verdict, and when. UNCOVERED and NOT_CHECKABLE
outcomes are returned by the evaluation API but never stamped — no
verdict is recorded when the rescan did not observe the affected file.
"""

from alembic import op
import sqlalchemy as sa

revision = "0089"
down_revision = "0088"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("drift_events",
                  sa.Column("verification_status", sa.String(30), nullable=True))
    op.add_column("drift_events",
                  sa.Column("verified_by_scan_id", sa.String(36), nullable=True))
    op.add_column("drift_events",
                  sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("drift_events", "verified_at")
    op.drop_column("drift_events", "verified_by_scan_id")
    op.drop_column("drift_events", "verification_status")
