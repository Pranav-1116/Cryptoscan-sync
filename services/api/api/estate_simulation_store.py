"""Persisted simulation runs, quarantined from estate state (spec 94 §17, §19).

Spec 94 §19 lists a ``simulation_runs`` table. The reason it is worth persisting is
also the reason it is dangerous: a simulation answers "what would happen if we
changed this", and a stored answer to a hypothetical is exactly the thing that gets
quoted a year later as if it had happened.

So persistence here is built with a quarantine, and the quarantine is enforced in
code rather than promised in a docstring:

* this module exposes **only** simulation reads/writes. There is deliberately no
  function that feeds a stored simulation back into an ``EstateGraph``, a snapshot,
  a drift comparison or a BOM projection — the single way to ask the twin a
  question is :func:`shared_models.estate_twin.simulate`, which operates on a copy;
* every stored row carries ``quarantined = True`` and ``is_estate_state = False``,
  and every read path returns them, so a caller that dumps the row into a report
  carries the label with it;
* a simulation is keyed by ``(tenant, simulation_id)`` where ``simulation_id`` is
  derived from the base projection id plus the scenario. Re-running the same
  question against the same evidence therefore *increments an observation counter*
  rather than creating a second "result" that looks like the estate moved;
* rows are scoped by the base projection id they were computed from. Once the
  estate moves, an old simulation is not stale-but-usable: it is a question asked
  about a different estate, and :func:`public_simulation` says so with
  ``computed_against`` and ``superseded_by``.

What is stored is the answer the engine produced — not a graph. Nothing here can
reconstruct estate facts, because nothing here stores estate facts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import select

from db.models.estate_simulation_run import EstateSimulationRun

#: compiler constants, repeated in every response so a consumer cannot drop them
QUARANTINE = {
    "quarantined": True,
    "is_estate_state": False,
    "counting_rule": (
        "a simulation is a question asked of a copy. It is never counted as an observation, a drift, a "
        "coverage result or an estate fact, and the live twin's projection id is unchanged by it"
    ),
}


def _utc(moment: datetime | None) -> datetime | None:
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _iso(moment: datetime | None) -> str | None:
    value = _utc(moment)
    return value.isoformat() if value else None


def record_simulation(
    db: Any,
    result: Mapping[str, Any],
    *,
    tenant_id: str | None,
    created_by: str | None = None,
    label: str | None = None,
) -> tuple[EstateSimulationRun, bool]:
    """Store one simulation result. Returns ``(row, created)``.

    Only an engine result with a ``simulation_id`` is storable. A ``NO_MATCH``
    simulation has no id (nothing was simulated) and is rejected here: storing
    "we could not find the thing you asked about" as a run would make an empty
    answer look like a finding.

    The row asserts, on write, that the engine reported the live state unmodified.
    If a future refactor ever makes ``simulate`` mutate its input, this refuses to
    store the result rather than recording a simulation that changed production.
    """
    if result.get("status") != "SIMULATED":
        raise ValueError(
            f"not storable: status {result.get('status')!r}. Only a completed SIMULATED result is a "
            "simulation; NO_MATCH means the scenario matched nothing"
        )
    if result.get("live_state_modified"):
        raise ValueError(
            "refusing to store a simulation that reports live_state_modified=True — a simulation must "
            "run on a copy, and a stored one must be known to have left the estate alone"
        )
    simulation_id = str(result.get("simulation_id") or "")
    if not simulation_id:
        raise ValueError("simulation result has no simulation_id")

    now = datetime.now(timezone.utc)
    stmt = select(EstateSimulationRun).where(EstateSimulationRun.simulation_id == simulation_id)
    stmt = stmt.where(
        EstateSimulationRun.tenant_id == tenant_id
        if tenant_id
        else EstateSimulationRun.tenant_id.is_(None)
    )
    row = db.execute(stmt).scalars().first()

    if row is not None:
        row.observations = int(row.observations or 0) + 1
        row.last_run_at = now
        row.updated_at = now
        db.commit()
        return row, False

    impact = result.get("impact") or {}
    row = EstateSimulationRun(
        tenant_id=tenant_id,
        simulation_id=simulation_id,
        kind=str(result.get("kind") or ""),
        scenario=dict(result.get("scenario") or {}),
        base_snapshot_id=result.get("base_snapshot"),
        base_projection_id=result.get("base_projection_id"),
        simulated_projection_id=result.get("simulated_projection_id"),
        matched_evidence=int(result.get("matched_evidence") or 0),
        affected_assets=list(result.get("affected_assets") or []),
        impact=dict(impact),
        bom_diff=dict(result.get("bom_diff") or {}),
        blockers=list(result.get("blockers") or []),
        live_state_modified=bool(result.get("live_state_modified")),
        observations=1,
        first_run_at=now,
        last_run_at=now,
        created_by=created_by,
        label=label,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, True


def list_simulations(db: Any, *, tenant_id: str | None, limit: int = 20) -> list[EstateSimulationRun]:
    stmt = (
        select(EstateSimulationRun)
        .order_by(EstateSimulationRun.first_run_at.desc(), EstateSimulationRun.id.desc())
        .limit(max(1, min(limit, 100)))
    )
    stmt = stmt.where(
        EstateSimulationRun.tenant_id == tenant_id
        if tenant_id
        else EstateSimulationRun.tenant_id.is_(None)
    )
    return list(db.execute(stmt).scalars())


def get_simulation(db: Any, identifier: str, *, tenant_id: str | None) -> EstateSimulationRun | None:
    identifier = str(identifier or "").strip()
    if not identifier:
        return None
    stmt = select(EstateSimulationRun).where(
        (EstateSimulationRun.simulation_id == identifier) | (EstateSimulationRun.id == identifier)
    )
    stmt = stmt.where(
        EstateSimulationRun.tenant_id == tenant_id
        if tenant_id
        else EstateSimulationRun.tenant_id.is_(None)
    )
    return db.execute(stmt).scalars().first()


def public_simulation(row: EstateSimulationRun, *, current_projection_id: str | None = None) -> dict[str, Any]:
    """API shape. Every response carries the quarantine and its own freshness.

    ``superseded_by`` matters more than it looks: a stored simulation was computed
    against one evidence state. Once the live projection id differs, the answer
    describes an estate that no longer exists — usable as history, never as a
    current impact assessment.
    """
    superseded = bool(
        current_projection_id
        and row.base_projection_id
        and current_projection_id != row.base_projection_id
    )
    return {
        "id": row.id,
        "simulation_id": row.simulation_id,
        "kind": row.kind,
        "scenario": row.scenario or {},
        "label": row.label,
        "base_snapshot_id": row.base_snapshot_id,
        "base_projection_id": row.base_projection_id,
        "simulated_projection_id": row.simulated_projection_id,
        "computed_against": row.base_projection_id,
        "superseded_by": current_projection_id if superseded else None,
        "superseded": superseded,
        "freshness": (
            "STALE — the estate has moved since this was simulated; re-run before quoting it"
            if superseded
            else "CURRENT — computed against the live projection id"
            if current_projection_id
            else "UNKNOWN — the live projection id was not supplied"
        ),
        "matched_evidence": row.matched_evidence,
        "affected_assets": row.affected_assets or [],
        "impact": row.impact or {},
        "bom_diff": row.bom_diff or {},
        "blockers": row.blockers or [],
        "live_state_modified": row.live_state_modified,
        "observations": row.observations,
        "first_run_at": _iso(row.first_run_at),
        "last_run_at": _iso(row.last_run_at),
        "created_by": row.created_by,
        **QUARANTINE,
    }


__all__ = [
    "QUARANTINE",
    "get_simulation",
    "list_simulations",
    "public_simulation",
    "record_simulation",
]
