"""Close the NULL-tenant hole in the snapshot sequence guarantee.

Revision 0134. Adds a partial unique index on ``security_control_snapshots (sequence)``
where ``tenant_id IS NULL``.

0133 gave the chain ``UNIQUE (tenant_id, sequence)``, which looks like the sequence can
never repeat inside a tenant. It does not hold for the platform estate: ``tenant_id`` is
NULL there — NULL is the estate's identity, not a missing value — and SQL treats NULLs as
distinct in unique constraints, so two concurrent writers can both store ``(NULL, 3)``.
The sequence is evidence ("a gap is a deleted row"), so a silent duplicate is a chain that
lies.

The partial index makes the constraint true for the estate rows too: one row per sequence
where ``tenant_id IS NULL``, alongside the existing per-tenant constraint. Combined with
the write path's retry-on-collision, concurrent collectors allocate gapless unique
sequences on every supported backend.

Revision ID: 0134
Revises: 0133
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0134"
down_revision = "0133"
branch_labels = None
depends_on = None

SNAPSHOTS = "security_control_snapshots"


def upgrade() -> None:
    op.create_index(
        "uq_security_control_snapshot_seq_platform",
        SNAPSHOTS,
        ["sequence"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NULL"),
        sqlite_where=sa.text("tenant_id IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_security_control_snapshot_seq_platform", table_name=SNAPSHOTS)
