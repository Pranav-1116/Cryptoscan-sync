"""Monthly range partitions for the twin's history.

Guide 115 found two absences in the same place: nothing pruned
``estate_observations``, and the table was one flat relation, so the only way to
remove a year of history was a ``DELETE`` that touches every row, writes a WAL
record per row and leaves the space to be reclaimed by a vacuum that competes
with the ingest it is trying to make room for.

Partitioning by ``last_seen_at`` month changes that: a month of history that is
past its retention window is removed by dropping a table, which is a catalogue
operation. The rows are gone in constant time and the disk is freed
immediately.

Three rules make this safe to switch on:

1. **No ``DEFAULT`` partition.** A row whose month has no partition fails the
   insert with ``no partition of relation … found for row``. That failure is
   the maintenance job being late, and it should page someone. A default
   partition would accept the row silently and then have to be scanned and
   rewritten every time a real partition is attached.
2. **A partition is only droppable when every row in it is eligible.** The
   sweep asks the partition itself, not the policy: any ``CURRENT`` row, or any
   row newer than the cutoff, keeps the whole month.
3. **Nothing is dropped before it is archived.** ``db.retention`` writes the
   partition's rows to NDJSON, verifies the count, and only then detaches and
   drops.

The helpers take a SQLAlchemy ``Session``/``Connection`` for PostgreSQL and do
nothing on SQLite, which has no partitioned tables; the migration that creates
the partitioned parent is PostgreSQL-only for the same reason.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

#: Parent table this module maintains.
PARENT = "estate_observations"

#: Partition key: the column the retention window is measured on.
KEY = "last_seen_at"

_PARTITION_NAME = re.compile(r"^estate_observations_y\d{4}m\d{2}$")
_BOUND = re.compile(r"(?:FROM|TO) \('([^']+)'\)")


def is_postgres(db: Any) -> bool:
    """True when ``db`` is bound to a PostgreSQL server. Accepts a Session
    or a Connection — the maintenance paths use both."""
    bind = db.get_bind() if hasattr(db, "get_bind") else db
    return bind.dialect.name == "postgresql"


def month_start(moment: datetime) -> datetime:
    """First instant of ``moment``'s month, in UTC."""
    moment = moment.astimezone(timezone.utc) if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
    return moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _add_months(moment: datetime, months: int) -> datetime:
    month = moment.month - 1 + months
    return moment.replace(year=moment.year + month // 12, month=month % 12 + 1, day=1)


def month_bounds(moment: datetime) -> tuple[datetime, datetime]:
    """``(lower, upper)`` for the month containing ``moment``."""
    lower = month_start(moment)
    return lower, _add_months(lower, 1)


def name_for(moment: datetime, table: str = PARENT) -> str:
    return f"{table}_y{moment.year:04d}m{moment.month:02d}"


def partitioned(db: Any, table: str = PARENT) -> bool:
    """True when the parent is a partitioned table on this server."""
    if not is_postgres(db):
        return False
    from sqlalchemy import text

    value = db.execute(text(
        "SELECT relkind FROM pg_class WHERE oid = to_regclass(:name)"
    ), {"name": table}).scalar()
    return str(value or "") == "p"


def partitions(db: Any, table: str = PARENT) -> list[dict[str, Any]]:
    """Every attached partition, with its bounds parsed out of the catalogue."""
    if not partitioned(db, table):
        return []
    from sqlalchemy import text

    rows = db.execute(text(
        "SELECT child.relname, pg_get_expr(child.relpartbound, child.oid) "
        "FROM pg_inherits i JOIN pg_class child ON child.oid = i.inhrelid "
        "WHERE i.inhparent = to_regclass(:parent) ORDER BY child.relname"
    ), {"parent": table}).all()
    found: list[dict[str, Any]] = []
    for name, bound in rows:
        moments = _BOUND.findall(str(bound))
        found.append({
            "name": str(name),
            "bound": str(bound),
            "lower": moments[0] if moments else None,
            "upper": moments[1] if len(moments) > 1 else None,
            "default": "DEFAULT" in str(bound).upper(),
        })
    return found


def ensure(db: Any, *, now: datetime | None = None, ahead: int = 6,
           behind: int = 1, table: str = PARENT) -> list[str]:
    """Create the monthly partitions that should exist, and only those.

    Idempotent by construction (``CREATE TABLE IF NOT EXISTS … PARTITION OF``),
    so it is safe to call from the retention sweep and from a nightly job.
    """
    if not partitioned(db, table):
        return []
    from sqlalchemy import text

    moment = month_start(now or datetime.now(timezone.utc))
    existing = {row["name"] for row in partitions(db, table)}
    created: list[str] = []
    for offset in range(-behind, ahead + 1):
        lower = _add_months(moment, offset)
        upper = _add_months(lower, 1)
        name = name_for(lower, table)
        if name in existing:
            continue
        db.execute(text(
            f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF {table} "
            "FOR VALUES FROM (:lower) TO (:upper)"
        ), {"lower": lower, "upper": upper})
        created.append(name)
    return created


def count(db: Any, partition: str) -> int:
    from sqlalchemy import text

    return int(db.execute(text(f"SELECT count(*) FROM {partition}")).scalar() or 0)


def rows(db: Any, partition: str, limit: int | None = None) -> list[dict[str, Any]]:
    """Every row of one partition, as plain dicts (used before dropping it)."""
    from sqlalchemy import text

    statement = f"SELECT * FROM {partition}"
    if limit is not None:
        statement = f"{statement} LIMIT {int(limit)}"
    result = db.execute(text(statement))
    return [dict(row._mapping) for row in result]


def prune_candidates(db: Any, *, window_days: int, now: datetime | None = None,
                     states: Iterable[str] = ("HISTORICAL",)) -> list[dict[str, Any]]:
    """Partitions that are wholly past the window and wholly prunable.

    A partition qualifies only when its **upper** bound is at or before the
    cutoff — a partly-windowed month keeps its rows and is pruned row by row —
    and when nothing inside it is still current or newer than the cutoff.
    """
    if not partitioned(db):
        return []
    from sqlalchemy import text

    moment = now or datetime.now(timezone.utc)
    cutoff = moment - timedelta(days=window_days)
    eligible = list(states)
    candidates: list[dict[str, Any]] = []
    for partition in partitions(db):
        if partition["default"] or not partition["upper"]:
            continue
        upper = _as_moment(partition["upper"])
        if upper is None or upper > cutoff:
            continue
        blocked = db.execute(text(
            f"SELECT count(*) FROM {partition['name']} "
            f"WHERE {KEY} IS NULL OR {KEY} >= :cutoff "
            "OR lifecycle_state <> ALL(:states)"
        ), {"cutoff": cutoff, "states": eligible}).scalar()
        if int(blocked or 0):
            candidates.append({**partition, "droppable": False,
                               "blocked_rows": int(blocked or 0)})
            continue
        candidates.append({**partition, "droppable": True,
                           "rows": count(db, partition["name"])})
    return candidates


def drop(db: Any, partition: str) -> None:
    """Detach and drop one partition. The caller has already archived it."""
    if not _PARTITION_NAME.match(partition):
        raise ValueError(f"refusing to drop {partition!r}: not a history partition")
    from sqlalchemy import text

    db.execute(text(f"ALTER TABLE {PARENT} DETACH PARTITION {partition}"))
    db.execute(text(f"DROP TABLE {partition}"))


def _as_moment(text_value: str) -> datetime | None:
    """Parse a catalogue bound such as ``2026-03-01 00:00:00+00``.

    PostgreSQL writes a zone of ``+00`` for a whole-hour offset; ``%z`` wants
    ``+0000`` or ``+00:00``, so the short form is normalised first.
    """
    value = text_value.strip()
    if re.search(r"[+-]\d{2}$", value):
        value = f"{value}00"
    for pattern in ("%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(value, pattern)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None
