"""Binary scan job trace continuity: the submitter's trace rides the job.

Revision ID: 0158
Revises: 0157

Distributed tracing must follow a scan across backend services: the async
binary submission stamps the originating trace/request id onto the job row,
and the worker's execution reads it back (``trace_id_from_job``) so logs and
spans correlate a running scan with the request that queued it — a scan
that outlives its HTTP request keeps its identity.
"""

import sqlalchemy as sa
from alembic import op

revision = "0158"
down_revision = "0157"
branch_labels = None
depends_on = None

TABLE = "binary_scan_jobs"


def upgrade() -> None:
    op.add_column(TABLE, sa.Column("trace_id", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column(TABLE, "trace_id")
