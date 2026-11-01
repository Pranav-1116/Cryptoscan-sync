"""Mark disputed facts at write time instead of regrouping the whole table.

Revision 0129. Adds ``estate_observations.conflict`` and its index, then
backfills it once.

The console's history summary answered "how many facts are in dispute" by
grouping **every** CURRENT fact by ``(asset_id, fact_type)`` and keeping the
groups with more than one row. That is correct, and at a million facts it cost
1.5 s per call — the first request the console makes after a bank-sized ingest —
because the cost is the size of the estate rather than the size of the answer.

Disputes are rare by construction: the write path knows, per fact, which values
are still asserted, so it can say so at the moment it decides. This revision
carries that decision in a column and an index, which turns the console read
into a lookup over a short list.

Backfill: existing stores have duplicates that predate the marker, so the
upgrade derives them once with the same grouping the read used to do. Downgrade
drops the column and index; nothing else depends on them.

Revision ID: 0129
Revises: 0128
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0129"
down_revision = "0128"
branch_labels = None
depends_on = None

INDEX = "ix_estate_observations_disputed"


def upgrade() -> None:
    op.add_column(
        "estate_observations",
        sa.Column("conflict", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    # Partial: only disputed rows are in it, so the console's question is
    # answered by a lookup over the disputes rather than over the estate.
    op.create_index(
        INDEX, "estate_observations", ["tenant_id", "asset_id", "fact_type"],
        sqlite_where=sa.text("conflict = 1"), postgresql_where=sa.text("conflict"),
    )
    # One-time backfill using the grouping the read path used to run per call.
    op.execute(
        """
        UPDATE estate_observations SET conflict = TRUE
        WHERE lifecycle_state = 'CURRENT'
          AND EXISTS (
            SELECT 1 FROM estate_observations AS other
            WHERE other.tenant_id IS NOT DISTINCT FROM estate_observations.tenant_id
              AND other.asset_id = estate_observations.asset_id
              AND other.fact_type = estate_observations.fact_type
              AND other.lifecycle_state = 'CURRENT'
              AND other.observation_id <> estate_observations.observation_id
          )
        """
    )


def downgrade() -> None:
    op.drop_index(INDEX, table_name="estate_observations")
    op.drop_column("estate_observations", "conflict")
