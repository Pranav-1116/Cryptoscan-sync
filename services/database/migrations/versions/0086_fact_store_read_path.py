"""Fact store read path (advanced/51 P0#1, round 37).

The materialised fact rows gain the last field the live projection
carries and the store lacked: the observed confidence values. With it,
a store row is *exactly* equivalent to a live-projected fact — the
equivalence is pinned by tests — which is what makes the store a
first-class read surface (``GET /facts/store``) instead of a
derived-only side table.
"""

from alembic import op
import sqlalchemy as sa

revision = "0086"
down_revision = "0085"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cryptographic_facts",
                  sa.Column("confidences", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("cryptographic_facts", "confidences")
