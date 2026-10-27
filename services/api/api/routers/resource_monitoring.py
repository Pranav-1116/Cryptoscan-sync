"""Resource monitoring scope, imported observations and non-executing control drafts."""

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy.orm import Session
from api.dependencies import get_current_user, get_db_session
from api.routers.assurance_boundary import Key, author, estate
from api.assurance import collection as base, resource_monitoring as core, store
from shared_models.resource_monitoring import ResourceDecision, ResourceIntake, ResourceScope, TrafficProposal


def no_store(response: Response):
    response.headers["Cache-Control"] = "no-store"


router = APIRouter(prefix="/resource-monitoring", tags=["resource-monitoring"], dependencies=[Depends(no_store)])


@router.post("/plans", status_code=201)
def create_plan(
    body: ResourceScope,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.create_plan(db, ctx.tenant_id, body, author(db, request, user), user)


@router.get("/plans")
def plans(
    cursor: str = Query(default="", max_length=36),
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.listing(db, ctx.tenant_id, core.PLAN, cursor)


@router.get("/plans/{identifier}")
def plan(identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)):
    base.boundary()
    return {"history": [store.public(r) for r in base.chain(db, ctx.tenant_id, core.PLAN, identifier)]}


@router.post("/plans/{identifier}/approve")
def approve(
    identifier: Key,
    body: ResourceDecision,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.decision(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.trust"), user)


@router.post("/plans/{identifier}/revoke")
def revoke(
    identifier: Key,
    body: ResourceDecision,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.decision(
        db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.trust"), user, revoke=True
    )


@router.get("/plans/{identifier}/authorization")
def authorization(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    base.boundary()
    return core.approved(db, ctx.tenant_id, identifier).model_dump(mode="json")


@router.post("/captures", status_code=201)
def intake(
    body: ResourceIntake,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.intake(db, ctx.tenant_id, body, author(db, request, user), user)


@router.get("/captures")
def captures(
    cursor: str = Query(default="", max_length=36),
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.listing(db, ctx.tenant_id, core.CAPTURE, cursor)


@router.get("/captures/{identifier}")
def capture(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    row, _ = core.retained(db, ctx.tenant_id, identifier)
    return store.public(row)


@router.post("/traffic-proposals", status_code=201)
def propose(
    body: TrafficProposal,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.propose(db, ctx.tenant_id, body, author(db, request, user), user)


@router.get("/traffic-proposals/{identifier}")
def proposal(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return core.proposal(db, ctx.tenant_id, identifier)
