"""Durable approved scope and phase checkpoints, never a posture verdict."""
import hashlib
import json
from sqlalchemy import update
from db.models.assurance import CollectionPhaseReceipt as Phase
from db.models.scan_job import ScanJob
from db.models.base import utcnow


def plan(run, items):
    if not items or len(items) > 10000 or len(set(items)) != len(items):
        raise ValueError("Collection plan must be unique and bounded")
    if run._db.query(Phase).filter_by(job_id=run.job_id).first():
        raise ValueError("Collection plan is write-once")
    for ordinal, (endpoint, phase) in enumerate(items):
        run._db.add(Phase(job_id=run.job_id, tenant_id=run._tenant_id, ordinal=ordinal,
                          endpoint=endpoint, phase=phase, state="NOT_ATTEMPTED"))
    run._db.commit()  # before any packets; no later projection rollback erases this


def collect(run, endpoint, phase, operation, admission):
    db = run._db
    row = db.query(Phase).filter_by(job_id=run.job_id, tenant_id=run._tenant_id,
                                   endpoint=endpoint, phase=phase).one()

    def transition(before, after, **values):
        changed = db.execute(update(Phase).where(Phase.id == row.id, Phase.state == before).values(state=after, **values))
        if changed.rowcount != 1:
            db.rollback()
            raise RuntimeError("Collection phase transition refused")
        db.commit()

    try:
        decision = admission()
    except Exception:
        transition("NOT_ATTEMPTED", "REFUSED", reason="CURRENT_ADMISSION_REFUSED")
        raise
    transition("NOT_ATTEMPTED", "ATTEMPTING", started_at=utcnow())
    try:
        result = operation()
    except Exception:
        transition("ATTEMPTING", "UNKNOWN", reason="COLLECTOR_INTERRUPTED")
        raise
    # A completed transport can fail to observe the requested fact. Empty keys
    # or offers never become successful observations just because storage works.
    observed = result.get("status") == "OK" and bool(
        result.get("keys") if phase == "host_keys" else result.get("kex_algorithms")
    )
    raw = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > 65536:
        transition("ATTEMPTING", "UNKNOWN", reason="OBSERVATION_EXCEEDS_RECEIPT_LIMIT")
        raise RuntimeError("Observation exceeds bounded receipt limit")
    transition("ATTEMPTING", "COMPLETED", observation_succeeded=observed, observation=json.loads(raw),
               observation_sha256=hashlib.sha256(raw).hexdigest())
    return result, decision


def summary(db, owner, job_id, *, include_observations=False):
    job = db.query(ScanJob).filter_by(id=job_id, tenant_id=owner).one_or_none()
    if job is None:
        return None
    rows = db.query(Phase).filter_by(job_id=job_id, tenant_id=owner).order_by(Phase.ordinal).all()
    if not rows:
        return {"job_id": job_id, "scope_recorded": False, "collection_complete": None,
                "observation_succeeded": None, "posture_acceptable": None, "phases": []}
    phases = []
    for row in rows:
        state = "UNKNOWN" if row.state == "ATTEMPTING" and job.status != "RUNNING" else row.state
        item = {"endpoint": row.endpoint, "phase": row.phase, "state": state,
                "observation_succeeded": row.observation_succeeded, "reason": row.reason,
                "started_at": row.started_at.isoformat() if row.started_at else None,
                "observation_sha256": row.observation_sha256}
        if include_observations:
            item["observation"] = row.observation
        phases.append(item)
    return {"job_id": job_id, "scope_recorded": True, "recording_completed": job.status == "COMPLETED",
            "collection_complete": job.status == "COMPLETED" and all(r.state == "COMPLETED" for r in rows),
            "observation_succeeded": all(r.observation_succeeded is True for r in rows),
            "posture_acceptable": None, "posture_reason": "SEPARATE_POLICY_EVALUATION_REQUIRED",
            "intended_phases": len(rows), "phases": phases}
