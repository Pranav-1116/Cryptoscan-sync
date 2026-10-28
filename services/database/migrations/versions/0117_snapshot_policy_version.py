"""Policy version on a stored twin snapshot (spec 94 §19).

Revision 0117. Adds ``policy_version`` to ``estate_twin_snapshots``.

A snapshot's ``projection_id`` is a hash over the evidence: it answers "was the estate the
same?" and cannot answer "was it read the same way?". Those are different operational
questions. A build that changes the confidence table, the identity keys or the conflict
fields can re-read identical evidence and reach a different conclusion, and without this
column that shows up as a silent change in the twin rather than as a policy change.

``collector_versions`` already existed on this table but held collector *names*; it now
holds ``collector@version`` where the collector reported one, so a probe upgrade is visible.
Neither field is part of the projection id: the id identifies the evidence, and these
identify the reading of it.
"""
from alembic import op
import sqlalchemy as sa

revision = "0117"
down_revision = "0116"
branch_labels = depends_on = None


def upgrade():
    op.add_column("estate_twin_snapshots", sa.Column("policy_version", sa.String(80), nullable=True))


def downgrade():
    op.drop_column("estate_twin_snapshots", "policy_version")
