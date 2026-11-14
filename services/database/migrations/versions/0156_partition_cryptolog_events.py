"""Partition cryptolog_events by month: continuous collection, constant-time disposal.

Revision ID: 0156
Revises: 0155

CryptoLog is the platform's continuous evidence stream — it grows forever
and its retention window is measured in months (180 days of activity, years
of change/audit). On a flat table the only way to remove a year of history
is a DELETE that touches every row and leaves the space to a vacuum war
with the ingest (0130's exact finding). This migration applies 0130's
proven conversion to ``cryptolog_events``:

* Range partitions on ``created_at`` month — already NOT NULL, so no
  backfill; a row with no creation time has no month to live in.
* **No DEFAULT partition** (0130's rule): a month with no partition rejects
  the insert — the maintenance job being late should page someone.
* PostgreSQL unique indexes on a partitioned parent must include the
  partition key: the ``event_id`` uniqueness becomes ``(event_id,
  created_at)`` — per-month uniqueness at the DB, exactly like
  0130's ``observation_id``. Cross-month idempotent identity is the
  ingest's ``deduplication_key`` lookup (\"a duplicate names the same
  stored event id\"), and the model now declares the same composite so
  create_all and migrated stores agree (0107's rule).
* Row-count proof before the flat table is dropped: partitioning that
  loses rows is an outage, not a migration.

SQLite has no partitioned tables (0130's rule): the chain stays flat there
and the retention sweep prunes rows instead of dropping partitions.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0156"
down_revision = "0155"
branch_labels = None
depends_on = None

PARENT = "cryptolog_events"
FLAT = "cryptolog_events_flat"
KEY = "created_at"


def _columns(connection, table: str) -> list[str]:
    rows = connection.execute(sa.text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = :t ORDER BY ordinal_position"), {"t": table}).all()
    return [row[0] for row in rows]


def _indexes(connection, table: str) -> list[tuple[str, str, bool]]:
    """``(name, column_list, unique)`` for every non-primary index on the
    table. Unique ones gain the partition key when they lack it — the
    PostgreSQL rule — and the key is stripped again on downgrade."""
    out = []
    for name, definition in connection.execute(sa.text(
        "SELECT indexname, indexdef FROM pg_indexes WHERE tablename = :t"
    ), {"t": table}).all():
        if name.endswith("_pkey"):
            continue
        unique = str(definition).upper().startswith("CREATE UNIQUE")
        cols = str(definition).split("(", 1)[1].rsplit(")", 1)[0]
        out.append((name, cols, unique))
    return out


def _months(connection, source: str, ahead: int = 12, behind: int = 1):
    import datetime as dt

    earliest = connection.execute(sa.text(
        f"SELECT min({KEY}), now() FROM {source}")).one()
    moment = (earliest[0] or earliest[1]).astimezone(dt.timezone.utc)
    now = earliest[1].astimezone(dt.timezone.utc)

    def add(month: dt.datetime, count: int) -> dt.datetime:
        index = month.month - 1 + count
        return month.replace(year=month.year + index // 12,
                             month=index % 12 + 1, day=1)

    start = min(moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0),
                now.replace(day=1, hour=0, minute=0, second=0, microsecond=0))
    start = add(start, -behind)
    end = add(now.replace(day=1, hour=0, minute=0, second=0, microsecond=0), ahead)
    out = []
    while start <= end:
        upper = add(start, 1)
        out.append((f"{PARENT}_y{start.year:04d}m{start.month:02d}",
                    start.isoformat(), upper.isoformat()))
        start = upper
    return out


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return  # SQLite: flat table stays (0130's rule), retention prunes rows.

    # Read the live table's shape first; after the rename it is FLAT.
    columns = _columns(connection, PARENT)
    indexes = _indexes(connection, PARENT)

    # 1. Move the flat table aside, freeing its index and constraint names.
    op.execute(f"ALTER TABLE {PARENT} RENAME TO {FLAT}")
    for name, _cols, _unique in indexes:
        op.execute(f"ALTER INDEX {name} RENAME TO {name}_flat")
    for name, _kind in connection.execute(sa.text(
        "SELECT conname, 'constraint' FROM pg_constraint "
        "WHERE conrelid = to_regclass(:t) AND contype = 'p'"
    ), {"t": FLAT}).all():
        op.execute(f"ALTER TABLE {FLAT} RENAME CONSTRAINT {name} TO {FLAT}_pkey")

    # 2. The partitioned parent: same columns, same defaults.
    op.execute(
        f"CREATE TABLE {PARENT} (LIKE {FLAT} INCLUDING DEFAULTS INCLUDING STORAGE) "
        f"PARTITION BY RANGE ({KEY})"
    )
    op.execute(f"ALTER TABLE {PARENT} ADD PRIMARY KEY (id, {KEY})")
    for name, cols, unique in indexes:
        if unique and KEY not in [c.strip() for c in cols.split(",")]:
            cols = f"{cols}, {KEY}"
        kind = "CREATE UNIQUE INDEX" if unique else "CREATE INDEX"
        op.execute(f"{kind} {name} ON {PARENT} ({cols})")

    # 3. Partitions, from the oldest row through next year.
    for name, lower, upper in _months(connection, FLAT):
        op.execute(f"CREATE TABLE {name} PARTITION OF {PARENT} "
                   f"FOR VALUES FROM ('{lower}') TO ('{upper}')")

    # 4. Copy, then prove nothing was left behind.
    column_list = ", ".join(columns)
    op.execute(f"INSERT INTO {PARENT} ({column_list}) "
               f"SELECT {column_list} FROM {FLAT}")
    before = connection.execute(sa.text(f"SELECT count(*) FROM {FLAT}")).scalar()
    after = connection.execute(sa.text(f"SELECT count(*) FROM {PARENT}")).scalar()
    if before != after:
        raise RuntimeError(
            f"partitioning lost rows: {before} in the flat table, {after} in "
            f"the partitioned one")
    op.execute(f"DROP TABLE {FLAT}")


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    columns = _columns(connection, PARENT)
    index_defs = _indexes(connection, PARENT)
    column_list = ", ".join(columns)
    op.execute(f"CREATE TABLE {FLAT} (LIKE {PARENT} INCLUDING DEFAULTS INCLUDING STORAGE)")
    op.execute(f"INSERT INTO {FLAT} ({column_list}) SELECT {column_list} FROM {PARENT}")
    # Dropping the parent takes its partitions with it; the flat copy survives.
    op.execute(f"DROP TABLE {PARENT}")
    op.execute(f"ALTER TABLE {FLAT} RENAME TO {PARENT}")
    op.execute(f"ALTER TABLE {PARENT} ADD PRIMARY KEY (id)")
    for name, cols, unique in index_defs:
        # The partition key comes back out of the unique index: on a flat
        # table (event_id) alone is the stricter rule the old model declared.
        cols_out = ", ".join(
            part.strip() for part in cols.split(",") if part.strip() != KEY)
        kind = "CREATE UNIQUE INDEX" if unique else "CREATE INDEX"
        op.execute(f"{kind} {name} ON {PARENT} ({cols_out})")
