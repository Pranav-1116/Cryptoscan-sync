"""Report snapshot payload hashes (§4.4, round 69 — the report leg of
scan-run → BOM → report).

``report_snapshots`` rows already persist the exact rendered report, but
their ``report_hash`` covers only the rendered body: the signed PDF and
the RS256 signature member are attached AFTER hashing, and nothing
re-verified the stored payload on read. This migration adds the same
discipline the CBOM leg (round 45) has:

* ``payload_hash`` — SHA-256 over the canonical JSON of the EXACT stored
  payload (PDF, signature and the scan→BOM chain citation included), so a
  snapshot is content-addressed and a mutated payload is detectable on
  read (integrity self-check: OK / MISMATCH).
* ``uq_report_snapshot_scan_payload`` — identical (scan, payload) pins
  collapse to one row (idempotent creation), mirroring
  ``uq_cbom_snapshot_scan_hash``.

Legacy rows keep ``NULL`` — the read path reports them as
``UNVERIFIED_LEGACY`` rather than pretending they were content-addressed.

Batch mode throughout: SQLite cannot ALTER constraints in place, so the
unique constraint is applied with the copy-and-move strategy (the 0079
precedent).
"""

from alembic import op
import sqlalchemy as sa

revision = "0094"
down_revision = "0093"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("report_snapshots") as batch:
        batch.add_column(sa.Column("payload_hash", sa.String(64), nullable=True))
        batch.create_index("ix_report_snapshots_payload_hash", ["payload_hash"])
        batch.create_unique_constraint("uq_report_snapshot_scan_payload",
                                       ["scan_id", "payload_hash"])


def downgrade() -> None:
    with op.batch_alter_table("report_snapshots") as batch:
        batch.drop_constraint("uq_report_snapshot_scan_payload", type_="unique")
        batch.drop_index("ix_report_snapshots_payload_hash")
        batch.drop_column("payload_hash")
