"""Retention for the twin's history: archive first, then prune.

Guide 115's retention row was a FAIL with a plain reason: every changed fact
adds a row and nothing ever removes one, so a bank's disk requirement is a
function of how often its estate changes. This module is the control.

The rules it enforces, in order:

1. **The present is never pruned.** Only ``HISTORICAL`` observations and
   ``STALE`` evidence are candidates. A ``CURRENT`` fact is what the twin
   believes *now*; deleting it would change an answer, not shorten a history.
2. **Nothing is deleted before it is archived.** Rows are written to an
   NDJSON file with a manifest that names the policy, the window and the
   SHA-256 of the exact bytes, and the file is flushed and fsynced before the
   first ``DELETE``. A prune whose archive failed does not happen.
3. **Evidence a live fact still points at is retained**, even when it is stale:
   observation rows carry ``evidence_id``, and deleting the record behind a
   claim would leave the console able to show a fact it cannot explain.
4. **A legal hold stops everything.** ``ESTATE_RETENTION_LEGAL_HOLD`` refuses
   the whole run rather than pruning the tables it was not told about.
5. **A window shorter than the floor is refused** unless explicitly forced:
   "set it to 30 days and let the sweep run" is a data-loss incident, not a
   configuration change.

The sweep is platform work — it deliberately crosses tenants — so every query
runs inside :func:`db.tenancy.platform_scope`, and the per-tenant counts are
kept in the receipt so an operator can see what a window did to each estate.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

#: Below this, a window is treated as a mistake rather than a policy.
MIN_WINDOW_DAYS = 30

#: Default window. Seven years is the usual bank/regulatory horizon; the point of
#: the default is that an untouched install prunes nothing, while the mechanism
#: exists and is measured.
DEFAULT_WINDOW_DAYS = 2555


@dataclass(frozen=True)
class Policy:
    """One table's retention rule."""

    table: str
    #: Lifecycle states eligible for pruning. Anything else is retained.
    states: tuple[str, ...]
    #: Column the window is measured on.
    timestamp: str
    window_days: int
    reason: str
    #: Model attribute path, resolved lazily so this module has no ORM import.
    model: str

    @property
    def eligible(self) -> str:
        return f"{self.table}.{'/'.join(self.states)} older than {self.window_days} d"


def policies(settings: Any = None) -> tuple[Policy, ...]:
    """The active policy set, from settings with a conservative default."""
    def days(name: str, fallback: int) -> int:
        value = getattr(settings, name, None) if settings is not None else None
        try:
            return int(value) if value is not None else fallback
        except (TypeError, ValueError):
            return fallback

    history = days("ESTATE_HISTORY_RETENTION_DAYS", DEFAULT_WINDOW_DAYS)
    evidence = days("ESTATE_EVIDENCE_RETENTION_DAYS", DEFAULT_WINDOW_DAYS)
    return (
        Policy(
            table="estate_observations",
            states=("HISTORICAL",),
            timestamp="last_seen_at",
            window_days=history,
            reason="a superseded fact value stops being history worth keeping",
            model="db.models.estate_catalog:EstateObservationRecord",
        ),
        Policy(
            table="estate_evidence",
            states=("STALE",),
            timestamp="last_seen_at",
            window_days=evidence,
            reason="evidence no current fact points at, and that no observation "
                   "references, stops being worth keeping",
            model="db.models.estate_catalog:EstateEvidenceRecord",
        ),
    )


def _model(path: str):
    import importlib

    module, _, name = path.partition(":")
    return getattr(importlib.import_module(module), name)


def _as_naive_utc(moment: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; the store is UTC."""
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


@dataclass
class Candidate:
    """What one policy would prune, and the rows themselves."""

    policy: Policy
    cutoff: datetime
    rows: list[dict[str, Any]] = field(default_factory=list)
    held_back_by_reference: int = 0

    @property
    def count(self) -> int:
        return len(self.rows)


def _row_dict(row: Any, columns: Iterable[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for column in columns:
        value = getattr(row, column, None)
        out[column] = value.isoformat() if isinstance(value, datetime) else value
    return out


def select_candidates(db: Any, policy: Policy, *, now: datetime,
                      limit: int = 50_000) -> Candidate:
    """Rows the policy would prune right now. Read-only."""
    from sqlalchemy import select

    from db.tenancy import platform_scope

    model = _model(policy.model)
    cutoff = now - timedelta(days=policy.window_days)
    candidate = Candidate(policy=policy, cutoff=cutoff)

    with platform_scope():
        stmt = (
            select(model)
            .where(getattr(model, policy.timestamp).is_not(None))
            .where(getattr(model, policy.timestamp) < cutoff)
            .where(getattr(model, "lifecycle_state").in_(policy.states))
            .limit(limit)
        )
        rows = list(db.execute(stmt).scalars())

        if policy.table == "estate_observations":
            candidate.rows = [_row_dict(row, _COLUMNS["estate_observations"]) for row in rows]
        else:
            # Evidence a surviving fact still points at is not garbage, however
            # stale it looks: the twin must be able to explain what it asserts.
            from db.models.estate_catalog import EstateObservationRecord

            referenced = set()
            evidence_ids = [row.evidence_id for row in rows if row.evidence_id]
            for start in range(0, len(evidence_ids), 500):
                chunk = evidence_ids[start:start + 500]
                referenced |= {
                    str(value) for (value,) in db.execute(
                        select(EstateObservationRecord.evidence_id)
                        .where(EstateObservationRecord.evidence_id.in_(chunk))
                        .distinct()
                    ).all()
                }
            keep = [row for row in rows if str(row.evidence_id) not in referenced]
            candidate.held_back_by_reference = len(rows) - len(keep)
            candidate.rows = [_row_dict(row, _COLUMNS["estate_evidence"]) for row in keep]
    return candidate


_COLUMNS = {
    "estate_observations": (
        "id", "tenant_id", "observation_id", "asset_id", "fact_type", "value",
        "value_kind", "evidence_id", "evidence_type", "layer", "lifecycle_state",
        "first_seen_at", "last_seen_at", "observation_count",
    ),
    "estate_evidence": (
        "id", "tenant_id", "id", "evidence_id", "evidence_type", "source",
        "collector", "collector_version", "raw_reference", "target_id", "layer",
        "lifecycle_state", "observed_at", "first_seen_at", "last_seen_at",
        "observation_count",
    ),
}


@dataclass
class Receipt:
    started_at: str
    dry_run: bool
    legal_hold: bool = False
    refused: str | None = None
    archive: dict[str, Any] | None = None
    deleted: dict[str, int] = field(default_factory=dict)
    per_tenant: dict[str, int] = field(default_factory=dict)
    held_back_by_reference: int = 0
    answerable_after: dict[str, Any] | None = None
    windows: dict[str, int] = field(default_factory=dict)
    partitions: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "cryptoscan.retention-receipt/1",
            "started_at": self.started_at,
            "dry_run": self.dry_run,
            "legal_hold": self.legal_hold,
            "refused": self.refused,
            "windows_days": self.windows,
            "archive": self.archive,
            "deleted": self.deleted,
            "deleted_per_tenant": dict(sorted(self.per_tenant.items())),
            "held_back_by_reference": self.held_back_by_reference,
            "answerable_after": self.answerable_after,
            "partitions": self.partitions,
        }


def _archive_file(candidates: list[Candidate], directory: Path, *, now: datetime) -> dict[str, Any]:
    """Write the rows to NDJSON and return the manifest — before any delete."""
    directory.mkdir(parents=True, exist_ok=True)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"estate-history-{stamp}.ndjson"
    digest = hashlib.sha256()
    written = 0
    with path.open("wb") as handle:
        for candidate in candidates:
            for row in candidate.rows:
                line = json.dumps(
                    {"table": candidate.policy.table, "policy": candidate.policy.eligible,
                     "row": row},
                    sort_keys=True, default=str,
                ).encode("utf-8") + b"\n"
                digest.update(line)
                handle.write(line)
                written += 1
        handle.flush()
        import os

        os.fsync(handle.fileno())
    return {
        "path": str(path),
        "rows": written,
        "bytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
        "tables": {policy.table: sum(c.count for c in candidates
                                     if c.policy.table == policy.table)
                   for policy in {c.policy for c in candidates}},
    }


def _delete(db: Any, candidate: Candidate) -> int:
    """Delete exactly the rows that were archived, by primary key."""
    from sqlalchemy import delete

    from db.tenancy import platform_scope

    model = _model(candidate.policy.model)
    ids = [row["id"] for row in candidate.rows if row.get("id")]
    if not ids:
        return 0
    deleted = 0
    with platform_scope():
        for start in range(0, len(ids), 1000):
            chunk = ids[start:start + 1000]
            result = db.execute(delete(model).where(model.id.in_(chunk)))
            deleted += int(result.rowcount or 0)
    return deleted


def _answerable(db: Any, candidates: list[Candidate]) -> dict[str, Any]:
    """After pruning, a surviving asset's history must still answer."""
    from sqlalchemy import func, select

    from db.models.estate_catalog import EstateObservationRecord
    from db.tenancy import platform_scope

    if not any(c.count for c in candidates):
        return {"checked": 0, "note": "nothing was pruned, so nothing changed"}
    with platform_scope():
        row = db.execute(
            select(EstateObservationRecord.tenant_id,
                   EstateObservationRecord.asset_id)
            .where(EstateObservationRecord.lifecycle_state == "CURRENT")
            .limit(1)
        ).first()
        if row is None:
            return {"checked": 0, "note": "no current fact survived, which the sweep "
                                          "would have refused to cause"}
        tenant_id, asset_id = row
        from api import estate_observations

        detail = estate_observations.history(db, asset_id, tenant_id=tenant_id)
        remaining = int(db.execute(
            select(func.count()).select_from(EstateObservationRecord)
            .where(EstateObservationRecord.asset_id == asset_id)
        ).scalar() or 0)
    return {"checked": 1, "asset_id": asset_id, "fact_count": detail.get("fact_count"),
            "rows_remaining_for_asset": remaining,
            "ok": bool(detail.get("fact_count")) and remaining > 0}


# ------------------------------------------------------------------ partitions --- #
def _partition_sweep(db: Any, active: Iterable[Policy], *, now: datetime,
                     archive_dir: Path | str | None, dry_run: bool) -> dict[str, Any]:
    """Drop whole months instead of deleting their rows, oldest first.

    A monthly partition that is entirely past the window and holds nothing the
    twin still asserts is removed by ``DROP TABLE``: constant time, and the
    space goes back to the filesystem without a vacuum. It is archived to its
    own NDJSON file first, for the same reason rows are — a dropped partition is
    even less recoverable than a delete.
    """
    from db import partitions as monthly

    if not monthly.partitioned(db):
        return {"supported": False,
                "note": ("this store is not partitioned; the row sweep below is the whole "
                         "retention story here (PostgreSQL and migration 0130 partition it)")}

    policy = next((p for p in active if p.table == monthly.PARENT), None)
    if policy is None:
        return {"supported": True, "candidates": [], "dropped": []}

    created = monthly.ensure(db, now=now)
    db.commit()
    found = monthly.prune_candidates(db, window_days=policy.window_days, now=now,
                                     states=policy.states)
    droppable = [candidate for candidate in found if candidate.get("droppable")]
    summary: dict[str, Any] = {
        "supported": True,
        "window_days": policy.window_days,
        "created": created,
        "candidates": [{k: v for k, v in candidate.items()} for candidate in found],
        "dropped": [],
        "archive": None,
        "rows_dropped": 0,
    }
    if dry_run or not droppable:
        return summary
    if archive_dir is None:
        raise ValueError("an archive directory is required: nothing is dropped before "
                         "it has been written somewhere durable")

    directory = Path(archive_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"estate-partitions-{now.strftime('%Y%m%dT%H%M%SZ')}.ndjson"
    digest = hashlib.sha256()
    written = 0
    per_partition: dict[str, int] = {}
    with path.open("wb") as handle:
        for candidate in droppable:
            rows = monthly.rows(db, candidate["name"])
            if len(rows) != candidate["rows"]:
                summary["refused"] = (
                    f"{candidate['name']} held {candidate['rows']} rows when it was "
                    f"chosen and {len(rows)} when it was archived; nothing was dropped")
                return summary
            for row in rows:
                line = json.dumps(
                    {"table": monthly.PARENT, "policy": policy.eligible,
                     "partition": candidate["name"], "row": row},
                    sort_keys=True, default=str,
                ).encode("utf-8") + b"\n"
                digest.update(line)
                handle.write(line)
                written += 1
            per_partition[candidate["name"]] = len(rows)
        handle.flush()
        import os

        os.fsync(handle.fileno())

    summary["archive"] = {
        "path": str(path),
        "rows": written,
        "bytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
        "partitions": per_partition,
    }
    if written != sum(per_partition.values()):
        summary["refused"] = (f"the partition archive wrote {written} rows but "
                              f"{sum(per_partition.values())} were selected; nothing was dropped")
        return summary

    for name in per_partition:
        monthly.drop(db, name)
        summary["dropped"].append(name)
    db.commit()
    summary["rows_dropped"] = written
    return summary


def apply(db: Any, *, now: datetime | None = None, dry_run: bool = False,
          archive_dir: Path | str | None = None, settings: Any = None,
          force: bool = False, audit: bool = True) -> Receipt:
    """Run the sweep once. Archives, then prunes; returns a receipt either way."""
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    receipt = Receipt(started_at=moment.isoformat(), dry_run=dry_run)
    active = policies(settings)
    receipt.windows = {policy.table: policy.window_days for policy in active}

    if getattr(settings, "ESTATE_RETENTION_LEGAL_HOLD", False) if settings is not None else False:
        receipt.legal_hold = True
        receipt.refused = ("a legal hold is in force (ESTATE_RETENTION_LEGAL_HOLD): "
                           "nothing was archived and nothing was deleted")
        return receipt
    too_short = [p for p in active if p.window_days < MIN_WINDOW_DAYS]
    if too_short and not force:
        receipt.refused = (
            f"window below the {MIN_WINDOW_DAYS}-day floor for "
            f"{', '.join(p.table for p in too_short)}; pass force to override")
        return receipt

    receipt.partitions = _partition_sweep(db, active, now=moment,
                                          archive_dir=archive_dir, dry_run=dry_run)
    if receipt.partitions and receipt.partitions.get("refused"):
        receipt.refused = str(receipt.partitions["refused"])
        return receipt

    candidates = [select_candidates(db, policy, now=moment) for policy in active]
    receipt.held_back_by_reference = sum(c.held_back_by_reference for c in candidates)
    total = sum(c.count for c in candidates)

    if dry_run or total == 0:
        receipt.deleted = {policy.table: 0 for policy in active}
        receipt.archive = {"rows": 0, "note": "dry run or nothing to prune"}
        return receipt

    if archive_dir is None:
        raise ValueError("an archive directory is required: nothing is deleted before "
                         "it has been written somewhere durable")
    receipt.archive = _archive_file(candidates, Path(archive_dir), now=moment)
    if receipt.archive["rows"] != total:
        # The archive must contain exactly what will be deleted. A short write
        # here is the one failure that would turn a prune into data loss.
        receipt.refused = (f"archive wrote {receipt.archive['rows']} rows but "
                           f"{total} were selected; nothing was deleted")
        receipt.archive["complete"] = False
        return receipt

    for candidate in candidates:
        count = _delete(db, candidate)
        receipt.deleted[candidate.policy.table] = count
        for row in candidate.rows:
            tenant = row.get("tenant_id") or "platform"
            receipt.per_tenant[tenant] = receipt.per_tenant.get(tenant, 0) + 1
    db.commit()

    receipt.answerable_after = _answerable(db, candidates)

    if audit:
        try:
            from db.repositories.user_repository import UserRepository
            from db.tenancy import platform_scope

            with platform_scope():
                UserRepository(db).audit(
                    "retention-sweep", "estate.retention.apply",
                    detail=receipt.as_dict(), outcome="SUCCESS")
                db.commit()
        except Exception as exc:  # noqa: BLE001 — the sweep already happened
            receipt.answerable_after = {
                **(receipt.answerable_after or {}),
                "audit_error": f"{type(exc).__name__}: {exc}",
            }
    return receipt
