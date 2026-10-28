"""Collector version and raw reference on an evidence record (spec 94 §11).

Revision 0116. Adds two columns to ``estate_evidence``.

Spec 94 §11's evidence object is ``{collector, collector_version, source, hash, fact}``.
The table kept the collector's *name* and the source path, which is enough to say who
reported a fact and not enough to reproduce it: "linux-static" does not identify a build,
and a path into a container that no longer exists cannot be re-read.

* ``collector_version`` — the build that produced the record. A value that changes while
  the fact stays the same is a collector upgrade, not an estate change;
* ``raw_reference`` — where the raw output lives (an artifact key, a file path, an object
  URL), so the record can be re-read instead of taken on trust.

Neither is part of the content-addressed ``evidence_id``: upgrading a probe does not change
the fact it observed. Re-observing the same fact keeps ONE row and corrects these two
fields, which is why they are nullable and why no backfill is attempted — an old row simply
does not claim a version it never stored.
"""
from alembic import op
import sqlalchemy as sa

revision = "0116"
down_revision = "0115"
branch_labels = depends_on = None


def upgrade():
    op.add_column("estate_evidence", sa.Column("collector_version", sa.String(80), nullable=True))
    op.add_column("estate_evidence", sa.Column("raw_reference", sa.String(600), nullable=True))


def downgrade():
    op.drop_column("estate_evidence", "raw_reference")
    op.drop_column("estate_evidence", "collector_version")
