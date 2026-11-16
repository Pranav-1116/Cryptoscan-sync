"""Collection-time collector-authority stamp (truth side of provenance).

Revision ID: 0164
Revises: 0163

The provenance surface reported ``AUTHORIZED`` by matching a live
CollectorAuthority at READ time — an authority approved after the scan
would bless a collection it never covered, and one revoked after the
scan would deny a collection that WAS authorized. The honest signal
comes from the collection itself: which authority id and approved
revision was in force when this scan ran.

``scans`` gains two nullable columns: ``collector_authority_id`` and
``collector_authority_revision``. Nullable because legacy rows carry
none — those are reported ``NOT_RECORDED``, never guessed. The loaders
stamp new scans (evidence_loader, bulk_inserter, intelligence) and the
provenance surface validates the STAMP: recorded + unrevoked is the
common ``AUTHORIZED`` case; a later revocation is reported, not
re-judged; nothing recorded is the honest exception.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0164"
down_revision = "0163"
branch_labels = None
depends_on = None

TABLE = "scans"
COLUMNS = (
    ("collector_authority_id", sa.Column("collector_authority_id", sa.String(36), nullable=True)),
    ("collector_authority_revision",
     sa.Column("collector_authority_revision", sa.Integer(), nullable=True)),
)


def upgrade() -> None:
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns(TABLE)}
    for name, column in COLUMNS:
        if name not in existing:
            op.add_column(TABLE, column)


def downgrade() -> None:
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns(TABLE)}
    for name, _column in COLUMNS:
        if name in existing:
            op.drop_column(TABLE, name)
