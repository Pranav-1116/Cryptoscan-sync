"""Backfill: tenant RLS on cryptolog partition children + index parity.

Revision ID: 0161
Revises: 0160

Two honest gaps the enforcement report and the model/migration parity pin:

1. **Partition children ran without their own RLS.** 0156 partitions
   ``cryptolog_events`` into monthly children; the parent's policies only
   apply when the parent is queried. A direct partition read — the kind a
   retention sweep or a curious operator runs — was guarded by nothing.
   Every relation with a tenant_id gets ENABLE + FORCE + the four
   isolation policies here, and db.partitions.ensure now does the same for
   every future monthly rollover.
2. **``uq_cryptolog_events_event_created`` existed in the model but not in
   the chain** on flat (SQLite) stores — create_all deployments had it,
   migrated ones did not. Created here when nothing already covers
   (event_id, created_at).

Both repairs are idempotent: re-running is a no-op.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0161"
down_revision = "0160"
branch_labels = None
depends_on = None

PARENT = "cryptolog_events"
COMPOSITE = ("event_id", "created_at")


def _partition_children(bind) -> list[str]:
    if bind.dialect.name != "postgresql":
        return []
    rows = bind.execute(sa.text(
        "SELECT c.relname FROM pg_inherits i "
        "JOIN pg_class c ON c.oid = i.inhrelid "
        "JOIN pg_class p ON p.oid = i.inhparent "
        "WHERE p.relname = :parent"
    ), {"parent": PARENT}).fetchall()
    return sorted({r[0] for r in rows})


def upgrade() -> None:
    bind = op.get_bind()

    # 1. RLS on every partition child (and the parent, for completeness).
    if bind.dialect.name == "postgresql":
        from db.rls import install_table_rls
        for name in [PARENT, *_partition_children(bind)]:
            install_table_rls(bind, name)

    # 2. Composite index parity for flat stores (and pg, where the rewritten
    #    per-month unique index may keep the old name but not always).
    inspector = sa.inspect(bind)
    covered = False
    for index in inspector.get_indexes(PARENT) if inspector.has_table(PARENT) else []:
        cols = [str(c) for c in index.get("column_names", []) if c is not None]
        if cols[:2] == list(COMPOSITE) or set(COMPOSITE) <= set(cols):
            covered = True
            break
    if not covered and inspector.has_table(PARENT):
        op.create_index("uq_cryptolog_events_event_created", PARENT,
                        list(COMPOSITE), unique=True)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for name in [PARENT, *_partition_children(bind)]:
            for policy in ("tenant_isolation_select", "tenant_isolation_insert",
                           "tenant_isolation_update", "tenant_isolation_delete"):
                op.execute(f"DROP POLICY IF EXISTS {policy} ON {name}")
    inspector = sa.inspect(bind)
    if inspector.has_table(PARENT):
        names = {i.get("name") for i in inspector.get_indexes(PARENT)}
        if "uq_cryptolog_events_event_created" in names:
            op.drop_index("uq_cryptolog_events_event_created", table_name=PARENT)
