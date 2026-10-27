"""Complete existing job-state contracts on migrated PostgreSQL enums.

Revision ID: 0106
Revises: 0105

The ORM/SQLite already support UNKNOWN. The original PostgreSQL enum did not,
so interrupted attempts could not atomically retain UNKNOWN job state and their
reservations. No existing job, attempt, fence or reservation is rewritten.
"""
from alembic import op
import sqlalchemy as sa

revision = "0106"
down_revision = "0105"
branch_labels = depends_on = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        # PostgreSQL 12+ permits ADD VALUE inside a transaction; the label is
        # usable after migration commit. No data writes use it in this migration.
        for label in ("UNKNOWN", "DEFERRED", "CANCELLED"):
            # DEFERRED is read by the decision projection; CANCELLED is an
            # existing repository terminal state. Enum comparisons need labels
            # even when there are no matching rows.
            op.execute(f"ALTER TYPE scanjobstatus ADD VALUE IF NOT EXISTS '{label}'")


def downgrade() -> None:
    # SQLite already retained these strings before 0106; there is no enum
    # transition to fence and index-only rollbacks must still preserve rows.
    if op.get_bind().dialect.name != "postgresql":
        return
    if op.get_bind().execute(sa.text("SELECT 1 FROM scan_jobs WHERE status = 'UNKNOWN' LIMIT 1")).first():
        raise RuntimeError("cannot downgrade while UNKNOWN jobs require reconciliation; do not relabel or release their reservations")
    # PostgreSQL cannot remove one enum label without replacing its type.
    # Retain the additive label on an empty-of-UNKNOWN rollback rather than
    # rewrite/lock the job table. Re-upgrade is idempotent. Old binaries must
    # not resume admission until their recovery semantics are independently reviewed.
