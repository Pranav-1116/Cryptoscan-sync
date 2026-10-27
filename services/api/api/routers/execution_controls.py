"""Selected-estate execution governance. No client-selected owner/actor fields."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from api.dependencies import TenantContext, get_current_user, get_db_session
from api.security.estate_history import history_context
from api.security.rbac import require_permission
from db.models.base import utcnow
from db.models.execution_control import (
    EstateExecutionPolicy, ScanApproval, ExecutionBudget, ExecutionAttempt, ExecutionControlEvent,
)
from db.models.user import User
from db.repositories.execution_control import aware, key, profile_for, settle_unknown

router = APIRouter(prefix="/execution-controls", tags=["execution-controls"])
manage = require_permission("platform.configure")


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Limits(Body):
    capacity: int = Field(ge=1, le=64)
    requests_per_second: int = Field(ge=1, le=100)


class Policy(Limits):
    expected_revision: int = Field(ge=0)
    legal_entity: str = Field(min_length=1, max_length=200)
    execution_region: str = Field(min_length=1, max_length=80)
    evidence_region: str = Field(min_length=1, max_length=80)
    evidence_destination: str = Field(min_length=1, max_length=200)
    max_runtime_seconds: int = Field(ge=10, le=3600)
    stopped: bool = False


class Approval(Body):
    target: str = Field(min_length=1, max_length=2000)
    profile: Literal["local-source/v1"] = "local-source/v1"
    subject_kind: Literal["user", "api_key", "repository"]
    subject_id: str = Field(min_length=1, max_length=36)
    not_before: datetime
    expires_at: datetime
    max_requests: int = Field(ge=1, le=10000)
    supersedes_id: str | None = Field(default=None, max_length=36)
    evidence_ref: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def window(self):
        if self.not_before.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Approval windows must include an explicit timezone")
        if not self.not_before < self.expires_at or self.expires_at - self.not_before > timedelta(days=30):
            raise ValueError("Approval window must be positive and at most 30 days")
        return self


class Reconciliation(Body):
    resolution: Literal["CONFIRMED_STOPPED", "CONFIRMED_COMPLETED"]
    evidence_ref: str = Field(min_length=1, max_length=500)
    confirm_external_work_stopped: Literal[True]


def human(db, request, username):
    from db.repositories.execution_control import current_request_principal
    from db.models.user import UserSession
    from api.security.rbac import normalize_roles, PERMISSION_MATRIX
    principal = current_request_principal()
    if not principal or principal.get("v") != 2 or principal.get("kind") != "user" or isinstance(getattr(request.state, "api_key_auth", None), tuple):
        raise HTTPException(403, "Typed human approval/reconciliation is required")
    user = db.execute(select(User).where(User.id == principal["id"], User.username == username,
        User.is_active.is_(True), User.deleted_at.is_(None))).scalar_one_or_none()
    credential = db.get(UserSession, principal["credential_id"])
    if (user is None or credential is None or credential.username != user.username or credential.user_id != user.id or credential.revoked_at
            or aware(credential.expires_at) <= utcnow()
            or not set(normalize_roles(user.role_list)) & PERMISSION_MATRIX["platform.configure"]):
        raise HTTPException(403, "Current durable human administrative authority is required")
    return user.id


def event(db, owner, actor, action, entity_id, detail):
    db.add(ExecutionControlEvent(tenant_id=owner, actor_id=actor, action=action, entity_id=entity_id, detail=detail))


def policy_row(db, owner):
    return db.execute(select(EstateExecutionPolicy).where(EstateExecutionPolicy.tenant_id == owner, EstateExecutionPolicy.estate_key == key("estate", owner))).scalar_one_or_none()


def _limits(db, budget_id, body):
    row = db.execute(select(ExecutionBudget).where(ExecutionBudget.id == budget_id)).scalar_one_or_none()
    if row is None:
        db.add(ExecutionBudget(id=budget_id, capacity=body.capacity, requests_per_second=body.requests_per_second))
    else:
        changed = db.execute(update(ExecutionBudget).execution_options(synchronize_session=False).where(ExecutionBudget.id == row.id, ExecutionBudget.version == row.version).values(
            capacity=body.capacity, requests_per_second=body.requests_per_second, version=row.version + 1))
        if changed.rowcount != 1:
            raise HTTPException(409, "Budget changed concurrently; retry after reading current policy")


@router.put("/provider-budget")
def provider_budget(body: Limits, request: Request, user: str = Depends(manage),
                    db: Session = Depends(get_db_session), ctx: TenantContext = Depends(history_context)):
    if ctx.tenant_id is not None:
        raise HTTPException(403, "Provider budgets require the platform estate")
    actor = human(db, request, user)
    budget_id = key("provider-budget", "local-source/v1")
    _limits(db, budget_id, body)
    event(db, None, actor, "PROVIDER_LIMITS", budget_id, body.model_dump())
    db.commit()
    return {"profile": "local-source/v1", **body.model_dump()}


@router.post("/emergency-stop")
def emergency_stop(request: Request, user: str = Depends(manage),
                   db: Session = Depends(get_db_session), ctx: TenantContext = Depends(history_context)):
    if ctx.tenant_id is not None:
        raise HTTPException(403, "Global emergency stop requires platform estate")
    actor = human(db, request, user)
    budget_id = key("provider-budget", "local-source/v1")
    row = db.execute(select(ExecutionBudget).where(ExecutionBudget.id == budget_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(409, "Provider execution budget is not provisioned")
    changed = db.execute(update(ExecutionBudget).execution_options(synchronize_session=False).where(
        ExecutionBudget.id == row.id, ExecutionBudget.version == row.version
    ).values(capacity=0, version=row.version + 1))
    if changed.rowcount != 1:
        raise HTTPException(409, "Stop raced another transition; retry immediately")
    event(db, None, actor, "GLOBAL_EMERGENCY_STOP", budget_id, {"profile": "local-source/v1", "reservations_released": False})
    db.commit()
    return {"stopped": True, "profile": "local-source/v1", "reservations_released": False,
            "resume": "HUMAN_PROVIDER_BUDGET_UPDATE_REQUIRED", "stop_slo": "DEPLOYMENT_QUALIFICATION_REQUIRED"}


@router.put("/policy")
def put_policy(body: Policy, request: Request, user: str = Depends(manage),
               db: Session = Depends(get_db_session), ctx: TenantContext = Depends(history_context)):
    actor = human(db, request, user)
    row = policy_row(db, ctx.tenant_id)
    contract = body.model_dump(exclude={"expected_revision", "stopped"})
    if row is None:
        if body.expected_revision != 0:
            raise HTTPException(409, "Policy revision conflict")
        row = EstateExecutionPolicy(tenant_id=ctx.tenant_id, estate_key=key("estate", ctx.tenant_id), revision=1, contract=contract, stopped=body.stopped)
        db.add(row)
        db.flush()
        revision = 1
    else:
        revision = body.expected_revision + 1
        changed = db.execute(update(EstateExecutionPolicy).execution_options(synchronize_session=False).where(EstateExecutionPolicy.id == row.id, EstateExecutionPolicy.tenant_id == ctx.tenant_id,
            EstateExecutionPolicy.revision == body.expected_revision).values(revision=revision, contract=contract, stopped=body.stopped))
        if changed.rowcount != 1:
            raise HTTPException(409, "Policy revision conflict")
    _limits(db, key("estate-budget", ctx.tenant_id), body)
    event(db, ctx.tenant_id, actor, "POLICY_REVISION", row.id, {"revision": revision, "contract": contract, "stopped": body.stopped})
    db.commit()
    return {"revision": revision, "contract": contract, "stopped": body.stopped}


@router.get("/policy")
def get_policy(user: str = Depends(get_current_user), db: Session = Depends(get_db_session), ctx: TenantContext = Depends(history_context)):
    row = policy_row(db, ctx.tenant_id)
    if row is None:
        raise HTTPException(404, "Execution policy not found")
    return row.to_dict()


@router.post("/approvals", status_code=201)
def create_approval(body: Approval, request: Request, user: str = Depends(manage),
                    db: Session = Depends(get_db_session), ctx: TenantContext = Depends(history_context)):
    actor = human(db, request, user)
    policy = policy_row(db, ctx.tenant_id)
    if policy is None or policy.stopped:
        raise HTTPException(409, "An active estate execution policy is required")
    if aware(body.expires_at) <= utcnow():
        raise HTTPException(422, "Approval is already expired")
    profile_for(body.target)
    from api.security.target_validation import validate_source_target, TargetValidationError
    from pathlib import Path
    raw = body.target.removeprefix("local://").removeprefix("file://")
    try:
        validate_source_target(body.target, label="target")
    except TargetValidationError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not Path(raw).is_absolute() or ".." in Path(raw).parts:
        raise HTTPException(422, "Controlled source targets must be absolute, without parent traversal")
    from db.models.api_key import ApiKey
    from db.models.repo_configuration import RepoConfiguration
    from db.models.tenant import TenantMembership
    if body.subject_kind == "user":
        subject = db.execute(select(User).where(User.id == body.subject_id, User.is_active.is_(True), User.deleted_at.is_(None))).scalar_one_or_none()
        if subject is None or subject.id == actor:
            raise HTTPException(409, "A separate active executing principal is required")
        if ctx.tenant_id is not None:
            member = db.execute(select(TenantMembership).where(TenantMembership.tenant_id == ctx.tenant_id, TenantMembership.username == subject.username)).scalar_one_or_none()
            if member is None or member.tenant_role == "viewer":
                raise HTTPException(404, "Executing principal not found in selected estate")
    else:
        model = ApiKey if body.subject_kind == "api_key" else RepoConfiguration
        subject = db.execute(select(model).where(model.id == body.subject_id, model.tenant_id == ctx.tenant_id)).scalar_one_or_none()
        if subject is None:
            raise HTTPException(404, "Executing principal not found in selected estate")
        if body.subject_kind == "repository" and subject.repo_url != body.target:
            raise HTTPException(409, "Repository approval target mismatch")
        if body.subject_kind == "api_key" and not subject.is_active_key:
            raise HTTPException(409, "Executing credential is inactive")
    old = None
    if body.supersedes_id:
        old = db.execute(select(ScanApproval).where(ScanApproval.id == body.supersedes_id, ScanApproval.tenant_id == ctx.tenant_id, ScanApproval.revoked_at.is_(None))).scalar_one_or_none()
        if old is None:
            raise HTTPException(404, "Previous approval not found")
        changed = db.execute(update(ScanApproval).execution_options(synchronize_session=False).where(ScanApproval.id == old.id, ScanApproval.tenant_id == ctx.tenant_id,
            ScanApproval.version == old.version, ScanApproval.revoked_at.is_(None)).values(revoked_at=utcnow(), version=old.version + 1))
        if changed.rowcount != 1:
            raise HTTPException(409, "Previous approval changed concurrently")
    contract = body.model_dump(mode="json", exclude={"supersedes_id"})
    contract["policy_snapshot"] = policy.contract
    row = ScanApproval(tenant_id=ctx.tenant_id, policy_revision=policy.revision, contract=contract,
                       approved_by=actor, supersedes_id=body.supersedes_id)
    db.add(row)
    db.flush()
    event(db, ctx.tenant_id, actor, "APPROVAL_CREATED", row.id, {"policy_revision": policy.revision, "supersedes_id": body.supersedes_id})
    db.commit()
    return row.to_dict()


@router.get("/approvals")
def approvals(limit: int = Query(100, ge=1, le=200), user: str = Depends(get_current_user),
              db: Session = Depends(get_db_session), ctx: TenantContext = Depends(history_context)):
    rows = db.execute(select(ScanApproval).where(ScanApproval.tenant_id == ctx.tenant_id).order_by(ScanApproval.created_at.desc(), ScanApproval.id).limit(limit)).scalars()
    return {"approvals": [row.to_dict() for row in rows]}


@router.post("/approvals/{approval_id}/revoke")
def revoke(approval_id: str, request: Request, user: str = Depends(manage),
           db: Session = Depends(get_db_session), ctx: TenantContext = Depends(history_context)):
    actor = human(db, request, user)
    row = db.execute(select(ScanApproval).where(ScanApproval.id == approval_id, ScanApproval.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Approval not found")
    changed = db.execute(update(ScanApproval).execution_options(synchronize_session=False).where(ScanApproval.id == row.id, ScanApproval.tenant_id == ctx.tenant_id,
        ScanApproval.version == row.version).values(revoked_at=utcnow(), version=row.version + 1))
    if changed.rowcount != 1:
        raise HTTPException(409, "Approval changed concurrently")
    event(db, ctx.tenant_id, actor, "APPROVAL_REVOKED", row.id, {})
    db.commit()
    return {"id": row.id, "revoked": True}


@router.get("/attempts")
def attempts(limit: int = Query(100, ge=1, le=200), user: str = Depends(get_current_user),
             db: Session = Depends(get_db_session), ctx: TenantContext = Depends(history_context)):
    rows = db.execute(select(ExecutionAttempt).where(ExecutionAttempt.tenant_id == ctx.tenant_id).order_by(ExecutionAttempt.created_at.desc(), ExecutionAttempt.id).limit(limit)).scalars()
    return {"attempts": [row.to_dict(exclude={"fence", "budget_ids"}) for row in rows]}


@router.post("/attempts/{attempt_id}/reconcile")
def reconcile(attempt_id: str, body: Reconciliation, request: Request, user: str = Depends(manage),
              db: Session = Depends(get_db_session), ctx: TenantContext = Depends(history_context)):
    actor = human(db, request, user)
    row = db.execute(select(ExecutionAttempt).where(ExecutionAttempt.id == attempt_id, ExecutionAttempt.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Attempt not found")
    settle_unknown(db, row, resolution=body.resolution)
    event(db, ctx.tenant_id, actor, "OUTCOME_RECONCILED", row.id, body.model_dump())
    db.commit()
    return {"id": row.id, "status": "RESOLVED", "resubmission": "NEW_JOB_AND_CURRENT_APPROVAL_REQUIRED"}


@router.get("/events")
def events(limit: int = Query(100, ge=1, le=200), user: str = Depends(get_current_user),
           db: Session = Depends(get_db_session), ctx: TenantContext = Depends(history_context)):
    rows = db.execute(select(ExecutionControlEvent).where(ExecutionControlEvent.tenant_id == ctx.tenant_id).order_by(ExecutionControlEvent.created_at.desc(), ExecutionControlEvent.id).limit(limit)).scalars()
    return {"events": [row.to_dict() for row in rows]}


@router.get("/ownership-register")
def ownership_register(user: str = Depends(manage), db: Session = Depends(get_db_session), ctx: TenantContext = Depends(history_context)):
    if ctx.tenant_id is not None:
        raise HTTPException(403, "Product-wide ownership review requires platform estate")
    from db.connection.session import Base
    from db.tenancy import TenantScoped, platform_scope
    exact = {"scan_approvals", "estate_execution_policies", "execution_attempts", "execution_outbox", "execution_control_events"}
    rows = []
    with platform_scope():
        for mapper in sorted(Base.registry.mappers, key=lambda m: m.local_table.name):
            model = mapper.class_
            scoped = issubclass(model, TenantScoped)
            rows.append({"table": mapper.local_table.name, "ownership": "EXACT_ESTATE" if model.__tablename__ in exact else "TENANT_PLUS_LEGACY_NULL_REQUIRES_REVIEW" if scoped else "PLATFORM_REQUIRES_CLASSIFICATION",
                         "legacy_null_rows": db.scalar(select(func.count()).select_from(model).where(model.tenant_id.is_(None))) if scoped else None,
                         "reviewed": False})
    return {"sql_tables": rows, "external_stores": ["graph", "cache/search", "exports", "notifications", "audit", "backups", "regional_copies"],
            "qualification": "INCOMPLETE_EXTERNAL_AND_CONSUMER_REVIEW_REQUIRED", "null_history_declassification": "FORBIDDEN"}
