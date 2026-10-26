"""Authenticated metadata-only OCI workflow; never execute collection over HTTP."""

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session
from api.dependencies import get_current_user, get_db_session
from api.routers.assurance_boundary import Key, author, estate
from api.assurance import collection as base, oci_collection as core, store
from shared_models.oci_collection import OciTarget
from shared_models.oci_intake import OciDecision, OciIntakeRequest, OciJobAction, OciJobRequest, OciTargetUpdate

router = APIRouter(prefix="/collection/oci", tags=["offline-oci-evidence"])


@router.post("/targets", status_code=201)
def register(
    body: OciTarget,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.register(db, ctx.tenant_id, body, author(db, request, user), user)


@router.put("/targets/{identifier}")
def update(
    identifier: Key,
    body: OciTargetUpdate,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.register(
        db,
        ctx.tenant_id,
        body.target,
        author(db, request, user, "assurance.trust"),
        user,
        identifier=identifier,
        expected=body.expected_revision,
    )


@router.post("/targets/{identifier}/authorize")
def authorize(
    identifier: Key,
    body: OciDecision,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.decision(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.trust"), user)


@router.post("/targets/{identifier}/revoke")
def revoke(
    identifier: Key,
    body: OciDecision,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.decision(
        db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.trust"), user, revoke=True
    )


@router.get("/targets")
def targets(
    cursor: str = Query(default="", max_length=36),
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.listing(db, ctx.tenant_id, core.TARGET, cursor)


@router.get("/targets/{identifier}")
def target(identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)):
    base.boundary()
    return {"history": [store.public(row) for row in core.chain(db, ctx.tenant_id, core.TARGET, identifier)]}


@router.post("/jobs", status_code=201)
def create_job(
    body: OciJobRequest,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.create_job(db, ctx.tenant_id, body, author(db, request, user), user)


@router.get("/jobs")
def jobs(
    cursor: str = Query(default="", max_length=36),
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.listing(db, ctx.tenant_id, core.JOB, cursor)


@router.get("/jobs/{identifier}")
def job(identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)):
    base.boundary()
    rows, _, _ = core.resolve(db, ctx.tenant_id, identifier)
    return {"history": [store.public(row) for row in rows]}


@router.post("/jobs/{identifier}/handoff")
def handoff(
    identifier: Key,
    body: OciJobAction,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.transition(db, ctx.tenant_id, identifier, body, author(db, request, user), user)


@router.post("/jobs/{identifier}/cancel")
def cancel(
    identifier: Key,
    body: OciJobAction,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.transition(db, ctx.tenant_id, identifier, body, author(db, request, user), user, cancel=True)


@router.post("/jobs/{identifier}/intake", status_code=201)
def intake(
    identifier: Key,
    body: OciIntakeRequest,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.intake(db, ctx.tenant_id, identifier, body, author(db, request, user), user)


@router.get("/jobs/{identifier}/evidence")
def evidence(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return core.retained(db, ctx.tenant_id, identifier).model_dump(mode="json")


@router.get("/jobs/{identifier}/projections")
def projections(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return core.projections(db, ctx.tenant_id, identifier)
