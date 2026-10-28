"""Persist and read Digital Twin snapshots (spec 94 §14).

The store's whole job is to keep the identity rule intact: one row per distinct
**evidence state**, keyed by projection id. Capturing the same evidence twice must
never create two snapshots, because two snapshots that differ only by timestamp
are exactly how a drift report ends up crying wolf.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import select

from db.models.estate_twin_snapshot import EstateTwinSnapshot
from shared_models import estate_twin


def _utc(moment: datetime | None) -> datetime | None:
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def record_snapshot(
    db: Any,
    graph: Any,
    *,
    tenant_id: str | None,
    captured_by: str | None = None,
    source_run_id: str | None = None,
    note: str | None = None,
) -> tuple[EstateTwinSnapshot, bool]:
    """Capture a snapshot. Returns ``(row, created)``.

    ``created`` is False when this exact evidence was already captured — the row's
    ``observations`` counter and ``last_seen_at`` advance instead. That distinction
    is reported to the caller rather than hidden, because "we re-observed the same
    estate" and "the estate moved" are different operational facts.
    """
    snapshot = estate_twin.snapshot(graph)
    projection_id = str(snapshot["projection_id"])
    now = datetime.now(timezone.utc)

    stmt = select(EstateTwinSnapshot).where(EstateTwinSnapshot.projection_id == projection_id)
    stmt = stmt.where(
        EstateTwinSnapshot.tenant_id == tenant_id
        if tenant_id
        else EstateTwinSnapshot.tenant_id.is_(None)
    )
    row = db.execute(stmt).scalars().first()

    completeness = estate_twin.completeness(graph)
    counts = dict(snapshot["counts"])
    counts["unresolved_relationships"] = len(graph.unresolved_relationships())
    counts["completeness_percent"] = completeness["overall_percent"]

    if row is not None:
        row.observations = int(row.observations or 0) + 1
        row.last_seen_at = now
        row.updated_at = now
        db.commit()
        return row, False

    row = EstateTwinSnapshot(
        tenant_id=tenant_id,
        estate=graph.estate,
        scope=snapshot.get("scope"),
        snapshot_id=str(snapshot["snapshot_id"]),
        projection_id=projection_id,
        payload=snapshot["payload"],
        counts=counts,
        collector_versions=snapshot.get("collector_versions") or [],
        assets=len(graph.assets()),
        evidence=len(graph.evidence()),
        relationships=len(graph.relationships()),
        unresolved_relationships=len(graph.unresolved_relationships()),
        completeness_percent=completeness["overall_percent"],
        observations=1,
        first_seen_at=now,
        last_seen_at=now,
        source_run_id=source_run_id,
        captured_by=captured_by,
        note=note,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, True


def list_snapshots(db: Any, *, tenant_id: str | None, limit: int = 20) -> list[EstateTwinSnapshot]:
    """Snapshots newest-first. Ordering is by first observation, not last."""
    stmt = select(EstateTwinSnapshot).order_by(
        EstateTwinSnapshot.first_seen_at.desc(), EstateTwinSnapshot.id.desc()
    ).limit(max(1, min(limit, 100)))
    stmt = stmt.where(
        EstateTwinSnapshot.tenant_id == tenant_id
        if tenant_id
        else EstateTwinSnapshot.tenant_id.is_(None)
    )
    return list(db.execute(stmt).scalars())


def get_snapshot(db: Any, identifier: str, *, tenant_id: str | None) -> EstateTwinSnapshot | None:
    """Look a snapshot up by projection id, snapshot id (``twin:`` prefix) or row id."""
    identifier = str(identifier or "").strip()
    if not identifier:
        return None
    if identifier.startswith("twin:"):
        identifier = identifier[len("twin:"):]
    stmt = select(EstateTwinSnapshot).where(
        (EstateTwinSnapshot.projection_id == identifier) | (EstateTwinSnapshot.id == identifier)
    )
    stmt = stmt.where(
        EstateTwinSnapshot.tenant_id == tenant_id
        if tenant_id
        else EstateTwinSnapshot.tenant_id.is_(None)
    )
    return db.execute(stmt).scalars().first()


def public(row: EstateTwinSnapshot, *, include_payload: bool = False) -> dict[str, Any]:
    """API shape for one snapshot. The payload is opt-in: it is large."""
    data: dict[str, Any] = {
        "id": row.id,
        "snapshot_id": row.snapshot_id,
        "projection_id": row.projection_id,
        "estate": row.estate,
        "scope": row.scope,
        "counts": row.counts or {},
        "assets": row.assets,
        "evidence": row.evidence,
        "relationships": row.relationships,
        "unresolved_relationships": row.unresolved_relationships,
        "completeness_percent": row.completeness_percent,
        "observations": row.observations,
        "first_seen_at": _iso(row.first_seen_at),
        "last_seen_at": _iso(row.last_seen_at),
        "source_run_id": row.source_run_id,
        "captured_by": row.captured_by,
        "note": row.note,
    }
    if include_payload:
        data["payload"] = row.payload
    return data


def _iso(moment: datetime | None) -> str | None:
    value = _utc(moment)
    return value.isoformat() if value else None


def graph_from_row(row: EstateTwinSnapshot) -> Any:
    """Rebuild the graph from the stored payload — never from the live run."""
    payload = row.payload if isinstance(row.payload, Mapping) else {}
    return estate_twin.graph_from_snapshot({"payload": payload})


__all__ = [
    "get_snapshot",
    "graph_from_row",
    "list_snapshots",
    "public",
    "record_snapshot",
]
