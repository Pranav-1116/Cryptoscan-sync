"""No remote execution or real-host apply endpoint."""

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session
from api.dependencies import get_current_user, get_db_session
from api.routers.assurance_boundary import Key, author, estate
from api.assurance import collection as base, store, traffic_control as core
from shared_models.linux_traffic_control import PreflightRequest, PreflightIntake, ValidationChange, ValidationDecision


def no_store(response: Response):
    response.headers["Cache-Control"] = "no-store"


router = APIRouter(prefix="/traffic-control", tags=["traffic-control"], dependencies=[Depends(no_store)])


@router.post("/proposals/{identifier}/preflight-requests", status_code=201)
def request_preflight(
    identifier: Key,
    body: PreflightRequest,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.request(db, ctx.tenant_id, identifier, body, author(db, request, user), user)


@router.get("/preflight-requests/{identifier}")
def preflight_request(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    base.boundary()
    return store.public(core.request_source(db, ctx.tenant_id, identifier)[0])


@router.post("/preflight-requests/{identifier}/captures", status_code=201)
def intake(
    identifier: Key,
    body: PreflightIntake,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.intake(db, ctx.tenant_id, identifier, body, author(db, request, user), user)


@router.get("/preflights/{identifier}")
def preflight(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return store.public(core.retained(db, ctx.tenant_id, identifier)[0])


@router.post("/validations", status_code=201)
def propose(
    body: ValidationChange,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.propose(db, ctx.tenant_id, body, author(db, request, user), user)


@router.get("/validations/{identifier}")
def validation(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    base.boundary()
    return {"history": [store.public(r) for r in core.change_source(db, ctx.tenant_id, identifier)[0]]}


@router.post("/validations/{identifier}/approve")
def approve(
    identifier: Key,
    body: ValidationDecision,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.approve(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.review"), user)


@router.get("/validations/{identifier}/authorization")
def authorization(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return core.authorization(db, ctx.tenant_id, identifier)


@router.get("/preflight-requests/{identifier}/specification")
def specification(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    base.boundary()
    return core.request_source(db, ctx.tenant_id, identifier, True)[1]
