"""Drift events."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from api.dependencies import get_current_user, get_db_session, get_drift_repository, require_auditor
from api.schemas.drift_schemas import DriftEventResponse, DriftListResponse
from db.repositories.drift_repository import DriftRepository

router = APIRouter(prefix="/drift", tags=["drift"])
logger = logging.getLogger(__name__)


class AckBody(BaseModel):
    notes: str | None = None
    # Audit 03's drift->remediation link: acknowledging a drift event can
    # auto-open remediation tasks for the non-compliant evidence behind it,
    # instead of the acknowledgement living in a separate world from the
    # fix-tracking. Owner is optional; tasks start PROPOSED like manual ones.
    create_remediation_tasks: bool = False
    task_owner: str | None = None


def _to_response(row, remediation_task_ids: list[str] | None = None) -> DriftEventResponse:
    return DriftEventResponse(
        drift_id=row.id,
        current_scan_id=row.current_scan_id,
        baseline_id=row.baseline_id,
        drift_type=row.drift_type,
        severity=row.severity,
        detected_at=row.detected_at.isoformat() if row.detected_at else None,
        resolution_status=row.resolution_status,
        drift_details=row.drift_details,
        acknowledged_at=row.acknowledged_at.isoformat() if getattr(row, "acknowledged_at", None) else None,
        acknowledged_by=getattr(row, "acknowledged_by", None),
        resolved_by=row.resolved_by,
        resolution_notes=row.resolution_notes,
        remediation_task_ids=remediation_task_ids or [],
    )


#: cap per acknowledgement — a drift event touching one algorithm can sit on
#: hundreds of failing evidence rows; auto-opening hundreds of tasks in one
#: request would be its own incident.
_MAX_AUTO_TASKS = 10


def _create_drift_remediation_tasks(db, drift_row, user: str, owner: str | None) -> list[str]:
    """Auto-open remediation tasks for the failing evidence behind a drift event.

    Looks for FAIL/WARN evidence in the drift's current scan matching the
    drift's algorithm (when the details name one). Honest about the no-op: a
    drift whose algorithm has no failing evidence creates no task rather than
    a hollow one. Tasks carry source="drift" + source_ref=drift_id so
    ``GET /drift/{id}/remediation-tasks`` can list them later.
    """
    from db.models.evidence_record import EvidenceRecord
    from db.models.remediation_task import RemediationTask
    from db.models.scan import Scan
    from db.repositories.remediation_repository import RemediationTaskRepository
    from db.tenancy import filtered_get
    from sqlalchemy import select

    details = dict(drift_row.drift_details or {})
    algorithm = details.get("algorithm")
    stmt = (
        select(EvidenceRecord)
        .where(
            EvidenceRecord.scan_id == drift_row.current_scan_id,
            EvidenceRecord.compliance_status.in_(("FAIL", "WARN")),
        )
        .order_by(EvidenceRecord.file_path, EvidenceRecord.line_number)
        .limit(_MAX_AUTO_TASKS * 4)
    )
    if algorithm:
        stmt = stmt.where(EvidenceRecord.algorithm == algorithm)
    rows = list(db.execute(stmt).scalars())
    tasks: list[str] = []
    repo = RemediationTaskRepository(db)
    for row in rows:
        if len(tasks) >= _MAX_AUTO_TASKS:
            break
        scan = filtered_get(db, Scan, row.scan_id)
        finding = {
            "algorithm": row.algorithm,
            "key_size": row.key_size,
            "mode": row.mode,
            "purpose": row.purpose,
            "file_path": row.file_path,
            "line_number": row.line_number,
            "is_hardcoded_key": row.is_hardcoded_key,
            "compliance_status": row.compliance_status,
        }
        rule = {"rule": "drift.followup", "category": "drift", "priority": None, "replace_with": None}
        evaluation = dict(row.policy_evaluation or {})
        if evaluation.get("rules_evaluated"):
            first = evaluation["rules_evaluated"][0]
            if isinstance(first, dict):
                rule = {
                    "rule": first.get("rule_id") or "drift.followup",
                    "category": "drift",
                    "priority": None,
                    "replace_with": None,
                }
        task = repo.create(RemediationTask(
            evidence_id=row.id,
            scan_id=row.scan_id,
            rule_id=rule["rule"],
            category=rule.get("category"),
            priority=rule.get("priority"),
            replace_with=rule.get("replace_with"),
            original_finding=finding,
            target_location=scan.target_location if scan is not None else None,
            status="PROPOSED",
            owner=owner,
            notes=(
                f"Auto-opened from drift event {drift_row.id} "
                f"({drift_row.drift_type}: {details.get('reason') or 'no reason recorded'})"
            ),
            created_by=user,
            source="drift",
            source_ref=drift_row.id,
        ))
        tasks.append(task.id)
    if tasks:
        try:
            from api.events.platform_events import emit_platform_event

            emit_platform_event(
                "remediation.drift_tasks_created",
                f"{len(tasks)} remediation task(s) auto-opened from drift event {drift_row.id}",
                {"drift_id": drift_row.id, "task_ids": tasks, "scan_id": drift_row.current_scan_id},
                target_name="remediation",
            )
        except Exception:
            logger.debug("drift_task_event_publish_failed", exc_info=True)
    return tasks


@router.get("", response_model=DriftListResponse)
def list_drift(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    status: str | None = None,
    scan_id: str | None = None,
    drift_type: str | None = Query(None, description="Filter by drift type, e.g. CONFIG_CHANGED"),
    user: str = Depends(get_current_user),
    repo: DriftRepository = Depends(get_drift_repository),
):
    rows, total = repo.list_events(
        severity=severity,
        status=status,
        scan_id=scan_id,
        drift_type=drift_type,
        page=page,
        page_size=page_size,
    )
    return DriftListResponse(
        events=[_to_response(r) for r in rows],
        total_count=total,
        page=page,
        page_size=page_size,
    )


@router.get("/sla")
def drift_sla(
    user: str = Depends(require_auditor),
    db=Depends(get_db_session),
):
    """Drift MTTA/MTTR + SLA compliance (report 31 §5/§6, round 23).

    Deterministic arithmetic over drift timestamps. Events acknowledged
    before ``acknowledged_at`` existed are counted as unknown (never
    imputed); historical resolved-only rows still count toward MTTR.
    """
    from db.repositories.drift_repository import DriftRepository

    return DriftRepository(db).sla_summary()


@router.get("/digest")
def drift_digest(
    hours: int = Query(24, ge=1, le=168),
    user: str = Depends(get_current_user),
    repo: DriftRepository = Depends(get_drift_repository),
):
    from drift.alerts.daily_digest import build_digest, window_start

    events = repo.list_since(window_start(hours=hours), page_size=500)
    return build_digest(events, window_hours=hours)


def _audit(db, actor: str, action: str, drift_id: str, body) -> None:
    try:
        from db.repositories.user_repository import UserRepository

        UserRepository(db).audit(
            actor, action, target_type="drift_event", target_id=drift_id,
            detail={"notes": body.notes if body else None},
        )
        db.commit()
    except Exception as audit_exc:
        db.rollback()
        logger.exception(
            "drift_audit_failed",
            extra={"error_type": type(audit_exc).__name__, "drift_id": drift_id},
        )
        raise HTTPException(status_code=503, detail="Drift audit is unavailable") from audit_exc


@router.post("/{drift_id}/acknowledge", response_model=DriftEventResponse)
def acknowledge(
    drift_id: str,
    body: AckBody | None = None,
    user: str = Depends(require_auditor),
    repo: DriftRepository = Depends(get_drift_repository),
    db=Depends(get_db_session),
):
    row = repo.acknowledge(drift_id, user, notes=(body.notes if body else None))
    if row is None:
        raise HTTPException(status_code=404, detail="Drift event not found")
    task_ids: list[str] = []
    if body is not None and body.create_remediation_tasks:
        task_ids = _create_drift_remediation_tasks(db, row, user, body.task_owner)
        db.commit()
    _audit(db, user, "drift.acknowledge", drift_id, body)
    return _to_response(row, remediation_task_ids=task_ids)


@router.get("/{drift_id}/remediation-tasks")
def drift_remediation_tasks(
    drift_id: str,
    user: str = Depends(get_current_user),
    db=Depends(get_db_session),
):
    """The remediation tasks auto-opened from one drift event (audit 03 link).

    Returns the task rows (same shape as GET /remediation/tasks) whose
    source is this drift event, so the acknowledgement -> fix -> verified
    chain is followable without grepping notes.
    """
    from db.models.drift_event import DriftEvent
    from db.models.remediation_task import RemediationTask
    from db.repositories.remediation_repository import RemediationVerificationRepository
    from db.tenancy import filtered_get

    # The ORM tenant guard filters both queries for the active scope.
    drift = filtered_get(db, DriftEvent, drift_id)
    if drift is None:
        raise HTTPException(status_code=404, detail="Drift event not found")
    tasks = (
        db.query(RemediationTask)
        .filter(RemediationTask.source == "drift", RemediationTask.source_ref == drift_id)
        .order_by(RemediationTask.created_at.desc())
        .limit(100)
        .all()
    )
    verifications = RemediationVerificationRepository(db)
    from api.routers.remediation import _task_out

    return {"drift_id": drift_id, "tasks": [_task_out(t, verifications.latest_for_task(t.id)) for t in tasks]}


@router.post("/{drift_id}/resolve", response_model=DriftEventResponse)
def resolve_drift(
    drift_id: str,
    body: AckBody | None = None,
    user: str = Depends(require_auditor),
    repo: DriftRepository = Depends(get_drift_repository),
    db=Depends(get_db_session),
):
    row = repo.resolve(drift_id, user, notes=(body.notes if body else None))
    if row is None:
        raise HTTPException(status_code=404, detail="Drift event not found")
    _audit(db, user, "drift.resolve", drift_id, body)
    return _to_response(row)


@router.post("/{drift_id}/false-positive", response_model=DriftEventResponse)
def false_positive(
    drift_id: str,
    body: AckBody | None = None,
    user: str = Depends(require_auditor),
    repo: DriftRepository = Depends(get_drift_repository),
    db=Depends(get_db_session),
):
    row = repo.mark_false_positive(drift_id, user, notes=(body.notes if body else None))
    if row is None:
        raise HTTPException(status_code=404, detail="Drift event not found")
    _audit(db, user, "drift.false_positive", drift_id, body)
    return _to_response(row)
