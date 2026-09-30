"""Deterministic governance API (P2) — rule-based approvals + migration gating.

No AI: every decision is produced by the explicit policy rule set and the
migration snapshot diff.

* POST /governance/requests            submit a change request -> policy decision
* GET  /governance/requests             list requests
* POST /governance/requests/{id}/decide approver decides (approve/deny)
* POST /governance/migration/validate   pre/post snapshot -> PASS/FAIL
* GET  /governance/migration            list validations
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from governance.migration_validate import MigrationSnapshot, validate_migration
from governance.rules import ChangeRequest, Decision, evaluate
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/governance", tags=["governance"])

_APPROVERS = ("admin", "superadmin", "ciso")


class ChangeRequestBody(BaseModel):
    request_type: str = Field(..., max_length=60)
    payload: dict = Field(default_factory=dict)
    in_maintenance_window: bool = False
    has_valid_ticket: bool = False


@router.post("/requests", status_code=201)
def submit_request(
    body: ChangeRequestBody,
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
):
    from db.models.p2 import GovernanceApproval

    requester_roles = _caller_roles(db, user)
    result = evaluate(ChangeRequest(
        request_type=body.request_type,
        requested_by=user,
        requester_roles=requester_roles,
        payload=body.payload,
        in_maintenance_window=body.in_maintenance_window,
        has_valid_ticket=body.has_valid_ticket,
    ))

    status_map = {
        Decision.AUTO_APPROVED: "AUTO_APPROVED",
        Decision.REQUIRES_APPROVAL: "PENDING",
        Decision.DENIED: "DENIED",
    }
    # retain a stable reference to the target resource (e.g. plugin id) so the
    # enforcing subsystem can pin the approval to the exact approved object.
    request_ref = str(body.payload.get("plugin_id")
                      or body.payload.get("scope")
                      or body.payload.get("reference")
                      or "") or None
    row = GovernanceApproval(
        request_type=body.request_type,
        request_ref=request_ref,
        requested_by=user,
        status=status_map[result.decision],
        decision=result.decision.value if result.decision in (Decision.AUTO_APPROVED, Decision.DENIED) else None,
        rationale=result.rationale,
        policy_rules=result.rules,
        risk_level=result.risk_level.value,
        payload={
            **body.payload,
            "required_approvers": result.required_approvers,
            "in_maintenance_window": body.in_maintenance_window,
            "has_valid_ticket": body.has_valid_ticket,
        },
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, **result.as_dict(), "status": row.status}


@router.get("/requests")
def list_requests(
    status: str | None = None,
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
):
    from db.models.p2 import GovernanceApproval

    stmt = select(GovernanceApproval).order_by(GovernanceApproval.created_at.desc()).limit(200)
    if status:
        stmt = stmt.where(GovernanceApproval.status == status.upper())
    rows = list(db.execute(stmt).scalars())
    return {"requests": [
        {
            "id": r.id,
            "request_type": r.request_type,
            "requested_by": r.requested_by,
            "status": r.status,
            "decision": r.decision,
            "decided_by": r.decided_by,
            "rationale": r.rationale,
            "risk_level": r.risk_level,
            "required_approvers": (r.payload or {}).get("required_approvers", []),
        }
        for r in rows
    ]}


class DecisionBody(BaseModel):
    approve: bool
    note: str = Field("", max_length=2000)


@router.post("/requests/{request_pk}/decide")
def decide_request(
    request_pk: str,
    body: DecisionBody,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_APPROVERS)),
):
    from db.models.p2 import GovernanceApproval

    row = db.get(GovernanceApproval, request_pk)
    if not row:
        raise HTTPException(status_code=404, detail="request not found")
    if row.status not in ("PENDING",):
        raise HTTPException(status_code=409, detail=f"request already {row.status}")
    # segregation of duties: requester cannot self-approve
    if body.approve and row.requested_by == user and row.risk_level in ("HIGH", "CRITICAL"):
        raise HTTPException(status_code=403, detail="segregation of duties: requester cannot self-approve a high-risk change")
    row.decision = "APPROVED" if body.approve else "DENIED"
    row.status = "APPROVED" if body.approve else "DENIED"
    row.decided_by = user
    row.rationale = (row.rationale + " | " if row.rationale else "") + f"{user}: {body.note or row.decision}"
    db.commit()
    return {"id": row.id, "status": row.status, "decision": row.decision, "decided_by": user}


class MigrationValidateBody(BaseModel):
    system_id: str | None = None
    migration_project_id: str | None = None
    pre_findings: list[dict] = Field(default_factory=list, max_length=20000)
    post_findings: list[dict] = Field(default_factory=list, max_length=20000)
    pre_covered_assets: list[str] = Field(default_factory=list, max_length=20000)
    post_covered_assets: list[str] = Field(default_factory=list, max_length=20000)


@router.post("/migration/validate", status_code=201)
def validate_migration_endpoint(
    body: MigrationValidateBody,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles("admin", "superadmin", "ciso", "security_analyst")),
):
    from db.models.p2 import MigrationValidation

    pre = MigrationSnapshot.from_findings(body.pre_findings, set(body.pre_covered_assets))
    post = MigrationSnapshot.from_findings(body.post_findings, set(body.post_covered_assets))
    res = validate_migration(pre, post)

    row = MigrationValidation(
        migration_project_id=body.migration_project_id,
        system_id=body.system_id,
        stage="POST",
        status="PASS" if res.passed else "FAIL",
        findings_before=len(body.pre_findings),
        findings_after=len(body.post_findings),
        regressions=res.regressions,
        coverage_delta=res.coverage_delta,
        report=res.as_dict(),
        validated_by=user,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "status": row.status, **res.as_dict()}


@router.get("/migration")
def list_validations(
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
):
    from db.models.p2 import MigrationValidation

    rows = list(db.execute(
        select(MigrationValidation).order_by(MigrationValidation.created_at.desc()).limit(100)
    ).scalars())
    return {"validations": [
        {
            "id": r.id,
            "system_id": r.system_id,
            "status": r.status,
            "stage": r.stage,
            "findings_before": r.findings_before,
            "findings_after": r.findings_after,
            "regression_count": len(r.regressions or []),
            "coverage_delta": r.coverage_delta,
            "summary": (r.report or {}).get("summary", ""),
        }
        for r in rows
    ]}


def _caller_roles(db: Session, username: str) -> list[str]:
    try:
        from db.repositories.user_repository import UserRepository

        u = UserRepository(db).get_by_username(username)
        if u is not None:
            return list(u.role_list)
    except Exception as _handler_exc:  # noqa: BLE001
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
    return []
