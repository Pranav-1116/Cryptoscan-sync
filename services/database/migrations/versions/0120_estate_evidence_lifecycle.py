"""Evidence rows carry a lifecycle state, like the assets they describe.

Revision 0120. Adds ``estate_evidence.lifecycle_state`` and its index.

The ORM already had the column (``services/database/db/models/estate_catalog.py``):
an evidence row is ``ACTIVE`` while the collector still produces it and ``STALE``
once it stops. The migration never carried it, so a database built by
``alembic upgrade head`` and a database built by ``create_all`` disagreed — and
the one that ships is the migrated one. ``test_schema_parity`` caught it.

Existing rows get ``ACTIVE`` from the server default, which is what the model
would have written for them: they were produced by a collector run that has not
been reclassified.

Revision ID: 0120
Revises: 0119
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0120"
down_revision = "0119"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "estate_evidence",
        sa.Column("lifecycle_state", sa.String(20), nullable=False, server_default="ACTIVE"),
    )
    op.create_index("ix_estate_evidence_lifecycle_state", "estate_evidence", ["lifecycle_state"])


def downgrade() -> None:
    op.drop_index("ix_estate_evidence_lifecycle_state", table_name="estate_evidence")
    op.drop_column("estate_evidence", "lifecycle_state")
