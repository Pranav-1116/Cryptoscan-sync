"""Evidence-backed query indexes for the two hot evidence lookups.

Revision ID: 0162
Revises: 0161

The 50k-asset scale receipt (``scripts/scale_evidence.py`` run, gap-8 work)
ran EXPLAIN on the two heavy evidence shapes and recorded what the planner
actually did instead of what anyone hoped it did:

1. **Dashboard per-algorithm aggregate** — ``GROUP BY algorithm`` under a
   tenant scope: *Seq Scan*, candidate ``(tenant_id, algorithm)``.
2. **Findings lookup** — tenant + ``is_hardcoded_key`` page ordered newest
   first: *Seq Scan*, candidate ``(tenant_id, is_hardcoded_key, ...)``.

This migration adds those two indexes to the production ``evidence_records``
table. The receipt's second candidate named ``id`` as the trailing column
because the harness schema ordered by id; the production query
(``EvidenceRepository.list_all``) orders by ``created_at DESC``, so the
trailing column here is ``created_at`` — the receipt shape, mapped to the
columns production actually reads.

Both creations are guarded by an inspector check: re-running is a no-op.
The model declares the same two names (model/migration parity), and
``test_evidence_query_indexes_0162`` pins both the parity and the EXPLAIN
result the indexes were added for.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0162"
down_revision = "0161"
branch_labels = None
depends_on = None

TABLE = "evidence_records"
INDEXES = (
    ("ix_evidence_tenant_algorithm", ("tenant_id", "algorithm")),
    ("ix_evidence_tenant_hardcoded_created",
     ("tenant_id", "is_hardcoded_key", "created_at")),
)


def upgrade() -> None:
    bind = op.get_bind()
    existing = {ix["name"] for ix in sa.inspect(bind).get_indexes(TABLE)}
    for name, cols in INDEXES:
        if name not in existing:
            op.create_index(name, TABLE, list(cols))


def downgrade() -> None:
    bind = op.get_bind()
    existing = {ix["name"] for ix in sa.inspect(bind).get_indexes(TABLE)}
    for name, _cols in INDEXES:
        if name in existing:
            op.drop_index(name, table_name=TABLE)
