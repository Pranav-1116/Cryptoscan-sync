"""Partition the twin's history by month, so a year of it can be dropped.

Revision 0130. Converts ``estate_observations`` into a range-partitioned table
on PostgreSQL, one partition per ``last_seen_at`` month.

Guide 115 graded partitioning FAIL for one reason: the table was a single flat
relation, so the retention policy's only way to remove a year of history was a
``DELETE`` of every row in it — a WAL record per row, a table rewrite's worth of
bloat and a vacuum that runs against the ingest it is making room for. Dropping
a partition is a catalogue operation: constant time, space returned to the
filesystem immediately.

The key is ``last_seen_at``, because that is the column the retention window is
measured on (``db.retention``), and because a row whose fact is re-observed moves
forward into the current month's partition as it is updated — so an old month
only ever holds facts nobody has looked at since.

What this costs, stated plainly:

* **PostgreSQL only.** SQLite has no partitioned tables; there the table stays
  flat and the row-by-row sweep in ``db.retention`` is the whole story. The
  migration is a no-op there, so the chain still applies.
* **The unique index has to carry the key.** PostgreSQL requires every unique
  index on a partitioned table to contain the partition key, so
  ``ix_estate_observations_tenant_obs`` becomes
  ``(tenant_id, observation_id, last_seen_at)``. Uniqueness of
  ``observation_id`` per tenant is still enforced by the write path's
  select-then-update (``api.estate_observations``), and a second row can only
  appear if the same observation id is inserted in two different months.
* **``last_seen_at`` becomes NOT NULL.** A row with no observation time has no
  month to live in; existing NULLs are backfilled from ``created_at``, which is
  when the fact was first written. An insert that omits it now fails loudly
  instead of landing in the wrong partition.
* **There is no DEFAULT partition.** A month with no partition rejects the
  insert. That is ``db.partitions.ensure`` not having run, and it should be
  visible rather than absorbed.

Revision ID: 0130
Revises: 0129
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0130"
down_revision = "0129"
branch_labels = None
depends_on = None

PARENT = "estate_observations"
FLAT = "estate_observations_flat"
KEY = "last_seen_at"
INDEX_PREFIX = "ix_estate_observations_"

#: Every index the flat table carries, exactly as the model and 0126/0129 name
#: them. Unique ones include the partition key; PostgreSQL refuses them otherwise.
INDEXES: tuple[tuple[str, str, bool, str | None], ...] = (
    ("ix_estate_observations_observation_id", "observation_id", False, None),
    ("ix_estate_observations_asset_id", "asset_id", False, None),
    ("ix_estate_observations_fact_type", "fact_type", False, None),
    ("ix_estate_observations_evidence_id", "evidence_id", False, None),
    ("ix_estate_observations_lifecycle_state", "lifecycle_state", False, None),
    ("ix_estate_observations_asset_fact", "asset_id, fact_type", False, None),
    ("ix_estate_observations_tenant_asset", "tenant_id, asset_id", False, None),
    ("ix_estate_observations_tenant_obs", f"tenant_id, observation_id, {KEY}", True, None),
    ("ix_estate_observations_disputed", "tenant_id, asset_id, fact_type", False, "conflict"),
)

#: Columns in table order, so the copy never depends on ``SELECT *`` ordering.
COLUMNS = (
    "id", "created_at", "updated_at", "tenant_id", "observation_id", "asset_id",
    "fact_type", "value", "value_kind", "evidence_id", "evidence_type", "layer",
    "lifecycle_state", "conflict", "first_seen_at", "last_seen_at",
    "observation_count",
)


def _months(connection, source: str, ahead: int = 12,
            behind: int = 1) -> list[tuple[str, str, str]]:
    """``(name, lower, upper)`` for every month the copied rows need.

    Read from the *source* table: by the time this runs the partitioned parent
    exists and is empty, and sizing the partitions off it would leave the oldest
    month of real data with nowhere to land.
    """
    import datetime as dt

    earliest = connection.execute(sa.text(
        f"SELECT min({KEY}), now() FROM {source}")).one()
    moment = (earliest[0] or earliest[1]).astimezone(dt.timezone.utc)
    start = moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    now = earliest[1].astimezone(dt.timezone.utc)
    start = min(start, now.replace(day=1, hour=0, minute=0, second=0, microsecond=0))

    def add(month: dt.datetime, count: int) -> dt.datetime:
        index = month.month - 1 + count
        return month.replace(year=month.year + index // 12, month=index % 12 + 1, day=1)

    start = add(start, -behind)
    end = add(now.replace(day=1, hour=0, minute=0, second=0, microsecond=0), ahead)
    out: list[tuple[str, str, str]] = []
    while start <= end:
        upper = add(start, 1)
        out.append((f"{PARENT}_y{start.year:04d}m{start.month:02d}",
                    start.isoformat(), upper.isoformat()))
        start = upper
    return out


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        # SQLite has no partitioned tables. The chain stays applicable and the
        # retention control prunes rows there instead of dropping partitions —
        # but the column the window is measured on still becomes required, so a
        # migrated store and ``create_all`` agree.
        op.execute(f"UPDATE {PARENT} SET {KEY} = created_at WHERE {KEY} IS NULL")
        with op.batch_alter_table(PARENT) as batch:
            batch.alter_column(KEY, existing_type=sa.DateTime(timezone=True),
                               nullable=False)
        return

    # 1. Every row needs a month. Existing stores may predate the column being
    #    populated; first write time is the honest stand-in.
    op.execute(f"UPDATE {PARENT} SET {KEY} = created_at WHERE {KEY} IS NULL")
    op.execute(f"ALTER TABLE {PARENT} ALTER COLUMN {KEY} SET NOT NULL")

    # 2. Move the flat table aside, freeing its index and constraint names.
    op.execute(f"ALTER TABLE {PARENT} RENAME TO {FLAT}")
    for name, _kind in connection.execute(sa.text(
        "SELECT indexname, 'index' FROM pg_indexes WHERE tablename = :table"
    ), {"table": FLAT}).all():
        if name.endswith("_pkey"):
            op.execute(f"ALTER TABLE {FLAT} RENAME CONSTRAINT {name} TO {FLAT}_pkey")
        else:
            op.execute(f"ALTER INDEX {name} RENAME TO {name}_flat")

    # 3. The partitioned parent: same columns, same types, same defaults.
    op.execute(
        f"CREATE TABLE {PARENT} (LIKE {FLAT} INCLUDING DEFAULTS INCLUDING STORAGE) "
        f"PARTITION BY RANGE ({KEY})"
    )
    op.execute(f"ALTER TABLE {PARENT} ADD PRIMARY KEY (id, {KEY})")
    for name, columns, unique, predicate in INDEXES:
        kind = "CREATE UNIQUE INDEX" if unique else "CREATE INDEX"
        where = f" WHERE {predicate}" if predicate else ""
        op.execute(f"{kind} {name} ON {PARENT} ({columns}){where}")

    # 4. Partitions, from the oldest row through next year.
    for name, lower, upper in _months(connection, FLAT):
        op.execute(f"CREATE TABLE {name} PARTITION OF {PARENT} "
                   f"FOR VALUES FROM ('{lower}') TO ('{upper}')")

    # 5. Copy, then prove nothing was left behind.
    columns = ", ".join(COLUMNS)
    op.execute(f"INSERT INTO {PARENT} ({columns}) SELECT {columns} FROM {FLAT}")
    before = connection.execute(sa.text(f"SELECT count(*) FROM {FLAT}")).scalar()
    after = connection.execute(sa.text(f"SELECT count(*) FROM {PARENT}")).scalar()
    if before != after:
        raise RuntimeError(
            f"partitioning lost rows: {before} in the flat table, {after} in the "
            f"partitioned one"
        )

    op.execute(f"DROP TABLE {FLAT}")


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        with op.batch_alter_table(PARENT) as batch:
            batch.alter_column(KEY, existing_type=sa.DateTime(timezone=True), nullable=True)
        return

    columns = ", ".join(COLUMNS)
    op.execute(f"CREATE TABLE {FLAT} (LIKE {PARENT} INCLUDING DEFAULTS INCLUDING STORAGE)")
    op.execute(f"INSERT INTO {FLAT} ({columns}) SELECT {columns} FROM {PARENT}")
    # Dropping the parent takes its partitions with it; the flat copy survives.
    op.execute(f"DROP TABLE {PARENT}")
    op.execute(f"ALTER TABLE {FLAT} RENAME TO {PARENT}")
    op.execute(f"ALTER TABLE {PARENT} ADD PRIMARY KEY (id)")
    for name, column_list, unique, predicate in INDEXES:
        # The partition key goes back out of the unique index: on a flat table
        # it is no longer required, and (tenant_id, observation_id) alone is the
        # stricter rule the models declare.
        columns_out = ", ".join(
            part.strip() for part in column_list.split(",") if part.strip() != KEY
        )
        kind = "CREATE UNIQUE INDEX" if unique else "CREATE INDEX"
        where = f" WHERE {predicate}" if predicate else ""
        op.execute(f"{kind} {name} ON {PARENT} ({columns_out}){where}")
