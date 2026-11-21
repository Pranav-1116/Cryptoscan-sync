"""Remediation work read from the agents' estate (the Digital Twin), not from scan rows.

This is the glue between the stored estate observation, the pure planner in
``agility.estate_remediation_plan``, and the existing ``remediation_tasks`` table. A task
opened here is an ordinary remediation task. The differences are:

* ``source`` is ``estate`` (a weakness the agents observed) or ``migration`` (an issue of a
  simulated change);
* ``evidence_id`` is the finding's stable id (``rf-…``), and ``scan_id`` is the estate run it
  was observed in;
* verification reads the newest estate run. A finding that is gone while its asset is still
  observed is VERIFIED. A finding that is still there is FAILED. If no newer report exists,
  or the asset vanished, the result is INCONCLUSIVE.

Finding ids are recomputed on the server. A client cannot open a task for a finding the
estate does not show.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.remediation_task import RemediationTask, RemediationVerification

ESTATE_SOURCES = ("estate", "migration")
_OPEN = ("PROPOSED", "ACCEPTED", "COMPLETED", "PARTIAL", "FAILED", "REGRESSION")
MAX_TASKS_PER_CALL = 200


def _router():
    from api.routers import estate_graph

    return estate_graph


def _aware(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _last_seen(db: Session, run: Any, twin: dict[str, Any]) -> datetime | None:
    """When the agents last confirmed the state in ``run``.

    An unchanged observation stores no new run, only a heartbeat carrying the same projection
    id. So the newest confirmation is the later of the run itself and a matching heartbeat.
    """
    from db.repositories.scan_run_repository import ScanRunRepository
    from db.tenancy import current_tenant

    seen = _aware(getattr(run, "created_at", None))
    try:
        from api.routers.ingestion import HEARTBEAT_KIND
    except Exception:  # pragma: no cover - the ingestion router ships with the API
        return seen
    beats = ScanRunRepository(db).list_runs(limit=1, target_kind=HEARTBEAT_KIND, owner=current_tenant())
    beat = ((beats[0].result or {}).get("heartbeat") or {}) if beats else {}
    if beat and beat.get("projection_id") and beat.get("projection_id") == twin.get("projection_id"):
        at = _aware(beat.get("recorded_at"))
        if at and (seen is None or at > seen):
            seen = at
    return seen


def findings_for_run(run: Any) -> dict[str, Any]:
    from agility.estate_remediation_plan import estate_findings

    twin = _router()._estate_migration_twin(run)
    return estate_findings(twin, now=datetime.now(timezone.utc))


def waves_for_run(run: Any) -> dict[str, Any]:
    from agility.estate_remediation_plan import migration_waves

    twin = _router()._estate_migration_twin(run)
    return migration_waves(twin, findings_for_run(run))


def candidates_for_run(run: Any, from_algo: str, to_algo: str) -> dict[str, Any]:
    from agility.estate_remediation_plan import migration_task_candidates

    body = _router().TwinBomImpactRequest(from_algo=from_algo, to_algo=to_algo)
    impact = _router()._twin_bom_answer(run, body)
    out = migration_task_candidates(impact)
    out["strategy"] = (impact.get("strategy") or {}).get("recommended")
    return out


def task_index(db: Session, ids: Iterable[str]) -> dict[str, dict[str, Any]]:
    """The newest estate/migration task per finding id (one query)."""
    wanted = [i for i in set(ids) if i]
    if not wanted:
        return {}
    rows = db.execute(
        select(RemediationTask)
        .where(RemediationTask.evidence_id.in_(wanted))
        .where(RemediationTask.source.in_(ESTATE_SOURCES))
        .order_by(RemediationTask.created_at)
    ).scalars().all()
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        out[row.evidence_id] = {"id": row.id, "status": row.status, "owner": row.owner}
    return out


def with_tasks(db: Session, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    index = task_index(db, (i["id"] for i in items))
    return [{**i, "task": index.get(i["id"])} for i in items]


def create_tasks(db: Session, run: Any, *, source: str, ids: list[str], owner: str | None,
                 from_algo: str | None, to_algo: str | None, user: str) -> dict[str, Any]:
    from api.events.platform_events import emit_platform_event
    from db.repositories.remediation_repository import RemediationTaskRepository

    if source not in ESTATE_SOURCES:
        raise HTTPException(status_code=422, detail=f"source must be one of {', '.join(ESTATE_SOURCES)}")
    if not ids:
        raise HTTPException(status_code=422, detail="name at least one finding id")
    if len(ids) > MAX_TASKS_PER_CALL:
        raise HTTPException(status_code=422, detail=f"at most {MAX_TASKS_PER_CALL} tasks per call")
    if source == "migration":
        if not (from_algo and to_algo):
            raise HTTPException(status_code=422, detail="a migration task needs from_algo and to_algo")
        items = candidates_for_run(run, from_algo, to_algo)["candidates"]
    else:
        items = findings_for_run(run)["findings"]
    by_id = {i["id"]: i for i in items}
    existing = task_index(db, ids)
    repo = RemediationTaskRepository(db)
    created: list[str] = []
    already: list[dict[str, Any]] = []
    unknown: list[str] = []
    for fid in dict.fromkeys(ids):
        item = by_id.get(fid)
        if item is None:
            unknown.append(fid)
            continue
        prior = existing.get(fid)
        if prior and prior["status"] in _OPEN:
            already.append({"id": fid, "task_id": prior["id"], "status": prior["status"]})
            continue
        snapshot = {
            "id": item["id"], "code": item.get("code"), "severity": item.get("severity"),
            "title": item.get("title"), "cause": item.get("cause"), "effect": item.get("effect"),
            "action": item.get("action"), "who_acts": item.get("who_acts"),
            "bom": item.get("bom"), "basis": item.get("basis"), "verify_by": item.get("verify_by"),
            "asset_id": item.get("asset_id"), "asset_name": item.get("asset_name") or item.get("subject"),
            "asset_type": item.get("asset_type"), "algorithm": item.get("algorithm"),
            "systems": item.get("systems") or [], "system_ids": item.get("system_ids") or [],
            "observed_in_run": run.id, "from_algo": from_algo if source == "migration" else None,
            "to_algo": to_algo if source == "migration" else None,
        }
        where = " · ".join(x for x in (", ".join(item.get("systems") or []),
                                       str(item.get("asset_name") or item.get("subject") or "")) if x)
        task = repo.create(RemediationTask(
            evidence_id=fid, scan_id=str(run.id)[:36], rule_id=str(item.get("code") or "ESTATE")[:80],
            category=item.get("bom"), priority=item.get("priority"),
            replace_with=(str(item["replace_with"])[:80] if item.get("replace_with") else None),
            original_finding=snapshot, target_location=where or None, status="PROPOSED",
            owner=owner or None, notes=None, created_by=user, source=source,
            source_ref=(f"{from_algo}→{to_algo}"[:64] if source == "migration" else fid),
        ))
        created.append(task.id)
        emit_platform_event(
            "remediation.task_created",
            f"Remediation task proposed from the {source}: {item.get('title')}",
            {"task_id": task.id, "evidence_id": fid, "source": source, "rule": item.get("code"),
             "status": task.status, "run_id": run.id},
            target_name="remediation", session=db,
        )
    db.commit()
    message = (f"{len(created)} task(s) opened" + (f", {len(already)} already open" if already else "")
               + (f", {len(unknown)} no longer in the estate" if unknown else ""))
    return {"created": len(created), "task_ids": created, "already_open": already,
            "not_found": unknown, "message": message, "run_id": run.id}


def verify_estate_task(db: Session, task: RemediationTask, user: str) -> RemediationVerification:
    """Compare a task's finding with the newest estate observation and persist the proof."""
    from agility.estate_remediation_plan import verify_candidate
    from api.events.platform_events import emit_platform_event
    from db.repositories.remediation_repository import RemediationVerificationRepository
    from remediation.verification import apply_result_to_status

    snapshot = task.original_finding or {}
    comparison: dict[str, Any] = {"finding": snapshot.get("id") or task.evidence_id, "source": task.source,
                                  "observed_in_run": task.scan_id}
    run = None
    try:
        run = _router()._latest_run(db)
    except HTTPException:
        verdict = {"result": "INCONCLUSIVE", "reason": "no estate observation exists to verify against"}
    else:
        comparison["verified_against_run"] = run.id
        twin = _router()._estate_migration_twin(run)
        cutoff = _aware(task.completed_at or task.created_at)
        seen = _last_seen(db, run, twin)
        comparison["observed_at"] = seen.isoformat() if seen else None
        if not seen or not cutoff or seen <= cutoff:
            verdict = {"result": "INCONCLUSIVE",
                       "reason": "no agent report has arrived since the work was marked done — "
                                 "verification runs again when the agents report next"}
        else:
            if task.source == "migration":
                current = candidates_for_run(run, snapshot.get("from_algo") or "", snapshot.get("to_algo") or "")
                ids = [c["id"] for c in current["candidates"]]
                verdict = verify_candidate(task.evidence_id, ids, asset_id=None, observed_assets=None,
                                           system_ids=snapshot.get("system_ids") or [],
                                           observed_systems=[s.get("id") for s in twin.get("systems") or []])
            else:
                ids = [f["id"] for f in findings_for_run(run)["findings"]]
                observed_assets = {str(a.get("asset_id")) for a in twin.get("assets") or []}
                observed_assets |= {str(c.get("asset_id")) for c in twin.get("certificates") or []}
                observed_assets |= {str(e.get("asset_id")) for e in twin.get("network_endpoints") or []}
                observed_assets |= {str(h.get("asset_id")) for h in twin.get("hardware") or []}
                observed_assets |= {str(v.get("id")) for v in twin.get("vendors") or []}
                verdict = verify_candidate(task.evidence_id, ids, asset_id=snapshot.get("asset_id"),
                                           observed_assets=observed_assets,
                                           system_ids=snapshot.get("system_ids") or [],
                                           observed_systems=[s.get("id") for s in twin.get("systems") or []])
            verdict = {**verdict, "reason": f"{verdict['reason']} (agent report {run.id})"}
    verification = RemediationVerificationRepository(db).create(RemediationVerification(
        task_id=task.id, rescan_id=run.id if run is not None else None, result=verdict["result"],
        reason=verdict["reason"], comparison=comparison, verified_by=user,
        verified_at=datetime.now(timezone.utc),
    ))
    task.status = apply_result_to_status(verdict["result"])
    db.commit()
    emit_platform_event(
        "remediation.task_verified",
        f"Remediation task {task.id} verification against the estate: {verdict['result']}",
        {"task_id": task.id, "result": verdict["result"], "reason": verdict["reason"],
         "rescan_id": verification.rescan_id, "task_status": task.status, "verified_by": user},
        target_name="remediation",
    )
    return verification
