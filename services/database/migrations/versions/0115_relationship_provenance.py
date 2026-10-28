"""Relationship provenance: the evidence *type* and time, on the edge itself (spec 94 §8).

Revision 0115. Adds two columns to ``estate_relationships``.

Spec 94 §8 is explicit that a relationship must not be a foreign key:

    Relationship { source, relation, target, evidence, confidence, source_type, observed_at }

``evidence_ids``, ``basis`` and ``confidence`` were already on the row. What was missing is
``source_type`` — *what kind of evidence* established the edge — and the time it was
observed. Without them a reader has to look up the evidence table to answer "was this
configuration, or an observation?", and the difference matters: a ``CONFIGURED`` edge says
the estate is set up this way, a ``RUNTIME_OBSERVATION`` edge says it was seen happening.

Both columns are nullable. An edge recorded before this revision keeps its evidence ids and
its basis; it simply does not claim a type it never stored, and the API reports ``null``
rather than inventing one from the ids at read time.

No backfill is attempted here: the evidence rows the ids point at are still in
``estate_evidence``, so the next observation of the same edge fills both columns.
"""
from alembic import op
import sqlalchemy as sa

revision = "0115"
down_revision = "0114"
branch_labels = depends_on = None


def upgrade():
    op.add_column("estate_relationships", sa.Column("evidence_type", sa.String(40), nullable=True))
    op.add_column("estate_relationships", sa.Column("observed_at", sa.String(64), nullable=True))


def downgrade():
    op.drop_column("estate_relationships", "observed_at")
    op.drop_column("estate_relationships", "evidence_type")
