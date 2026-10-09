"""Evidence soft delete: tombstones that preserve the chain (audits 15/16).

Report 15 §6.2 and roadmap EVIDENCE-003: a hard ``DELETE`` on an evidence
row breaks the scan's hash chain (each row's chain_hash commits to its
predecessor), and CASCADE from a scan delete offered no way to retract a
single false finding without destroying integrity. This migration adds
tombstone columns instead:

* ``deleted_at`` / ``deleted_by`` / ``delete_reason`` — NULL means alive;
* consumption surfaces (findings listings, CBOM generation, conflicts,
  drift comparison, remediation suggestions, migration planning) read only
  alive rows by default;
* chain verification and exports still read every row — a tombstone stays
  in the chain it committed to, so ``verify_stored_scan`` keeps passing and
  the deletion itself is auditable.

Revision ID: 0075
Revises: 0074
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0075"
down_revision = "0074"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("evidence_records", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("evidence_records", sa.Column("deleted_by", sa.String(100), nullable=True))
    op.add_column("evidence_records", sa.Column("delete_reason", sa.Text(), nullable=True))
    op.create_index(
        "ix_evidence_records_deleted_at", "evidence_records", ["deleted_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_evidence_records_deleted_at", table_name="evidence_records")
    op.drop_column("evidence_records", "delete_reason")
    op.drop_column("evidence_records", "deleted_by")
    op.drop_column("evidence_records", "deleted_at")
