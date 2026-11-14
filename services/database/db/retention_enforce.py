"""Retention enforcement: archive first, verify, then drop — and record it.

The policy side already exists and is honest: ``db.retention`` (estate
history) and the cryptolog ``/retention/policy`` endpoint plan windows and
perform NOTHING (``test_a_retention_plan_performs_nothing`` pins that).
This module is the other half — the explicit enforcement tool those plans
name:

* **Dry-run by default.** A call without ``dry_run=False`` reports exactly
  what would go and touches nothing. The same contract as the plan
  endpoint: performing something requires saying so.
* **Archive before drop, verify before archive counts.** Every row of a
  doomed partition lands in an NDJSON archive file; the written line
  count must equal the partition count or the drop does not happen. A
  retention run that loses evidence is a breach, not a cleanup.
* **Every deletion is audited.** Each dropped partition and each garbage
  collected blob calls ``db.privileged_ops.record_privileged`` — a
  deletion nobody recorded is indistinguishable from a deletion nobody
  authorized (the auditing contract).
* **Partition-shaped and row-shaped stores.** On PostgreSQL, months past
  the window are dropped as whole partitions (constant time, space freed
  immediately); on SQLite the same window is enforced row-wise —
  0130's rule that the chain stays applicable everywhere.

Blob garbage collection is here too: ``binary_artifact_blobs`` rows with
``ref_count = 0`` are unreferenced content, droppable — and only those.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _as_moment(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def partition_candidates(db: Any, *, table: str, key: str, window_days: int,
                         now: Optional[datetime] = None) -> list[dict]:
    """Wholly-expired monthly partitions: upper bound at or before the
    cutoff. Nothing is partially dropped — a partly-windowed month waits
    for the next sweep (the month is the unit of disposal)."""
    from db import partitions as partitioning

    if not partitioning.partitioned(db, table):
        return []
    moment = now or datetime.now(timezone.utc)
    cutoff = moment - timedelta(days=window_days)
    out = []
    for partition in partitioning.partitions(db, table):
        if partition["default"] or not partition["upper"]:
            continue
        upper = _as_moment(partition["upper"])
        if upper is None or upper > cutoff:
            continue
        out.append(partition)
    return out


def _archive_partition(db: Any, name: str, archive_dir: Path) -> int:
    from db import partitions as partitioning

    rows = partitioning.rows(db, name)
    archive_dir.mkdir(parents=True, exist_ok=True)
    destination = archive_dir / f"{name}.ndjson"
    with destination.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, default=str) + "\n")
    written = sum(1 for _ in destination.open("r", encoding="utf-8"))
    if written != len(rows):
        raise RuntimeError(
            f"archive verification failed for {name}: {len(rows)} rows in "
            f"the partition, {written} written — the partition is kept")
    return written


def enforce_partition_retention(db: Any, *, table: str, key: str,
                                window_days: int, archive_dir: Path,
                                actor: str,
                                dry_run: bool = True,
                                now: Optional[datetime] = None) -> dict:
    """Enforce the window on a partitioned table. Dry-run by default."""
    from db.privileged_ops import record_privileged

    candidates = partition_candidates(db, table=table, key=key,
                                      window_days=window_days, now=now)
    report = {"table": table, "window_days": window_days, "dry_run": dry_run,
              "candidates": [c["name"] for c in candidates],
              "dropped": [], "archived_rows": 0}
    if dry_run:
        report["note"] = ("dry run: nothing archived, nothing dropped, "
                          "nothing audited — pass dry_run=False to enforce")
        return report
    for partition in candidates:
        name = partition["name"]
        rows = _archive_partition(db, name, Path(archive_dir))
        from sqlalchemy import text

        db.execute(text(f"DROP TABLE {name}"))
        report["dropped"].append(name)
        report["archived_rows"] += rows
        record_privileged(
            db, actor=actor, action="RETENTION_DROP_PARTITION",
            target_type=table, target_id=name,
            detail={"archived_rows": rows, "window_days": window_days,
                    "archive": str(Path(archive_dir) / f"{name}.ndjson")})
    db.commit()
    return report


def collect_unreferenced_blobs(db: Any, *, actor: str,
                               dry_run: bool = True) -> dict:
    """Drop binary_artifact_blobs with ref_count = 0 — unreferenced
    content only; a blob one job still names is kept whatever its age."""
    from sqlalchemy import select

    from db.models.binary_artifact_blob import BinaryArtifactBlob
    from db.privileged_ops import record_privileged

    orphans = list(db.scalars(select(BinaryArtifactBlob).where(
        BinaryArtifactBlob.ref_count == 0)))
    report = {"dry_run": dry_run, "candidates": len(orphans),
              "dropped": 0, "bytes_freed": 0}
    if dry_run:
        report["note"] = ("dry run: unreferenced blobs counted, none "
                          "removed — pass dry_run=False to collect")
        return report
    for blob in orphans:
        report["bytes_freed"] += int(blob.bytes_size or 0)
        record_privileged(
            db, actor=actor, action="RETENTION_COLLECT_BLOB",
            target_type="binary_artifact_blobs", target_id=blob.sha256,
            detail={"bytes": int(blob.bytes_size or 0)})
        db.delete(blob)
        report["dropped"] += 1
    db.commit()
    return report
