"""Launch records reuse assurance's exact-estate/residency and durable-human gates."""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from api.dependencies import get_current_user, get_db_session
from api.routers.assurance_boundary import estate, author, Key, new_id
from api.assurance import launch, store
from shared_models.assurance import Approval
from shared_models.launch_assurance import (
    Engagement,
    SignedReport,
    FindingPlan,
    FindingCompletion,
    OperatingAssignment,
    OperatingExercise,
    Pilot,
)

router = APIRouter(prefix="/launch", tags=["launch-readiness"])


@router.post("/engagements", status_code=201)
def engagement(
    body: Engagement,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.manage")
    return store.public(launch.engagement(db, ctx.tenant_id, body, actor))


@router.post("/engagements/{identifier}/approve", status_code=201)
def review_engagement(
    identifier: Key,
    body: Approval,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.trust")
    return store.public(launch.review_engagement(db, ctx.tenant_id, identifier, body, actor))


@router.post("/engagements/{identifier}/withdraw", status_code=201)
def withdraw_engagement(
    identifier: Key,
    body: Approval,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.trust")
    return store.public(launch.review_engagement(db, ctx.tenant_id, identifier, body, actor, withdraw=True))


@router.post("/engagements/{identifier}/reports", status_code=201)
def report(
    identifier: Key,
    body: SignedReport,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.manage")
    return store.public(launch.report(db, ctx.tenant_id, identifier, body, actor))


@router.post("/findings/{identifier}/plan", status_code=201)
def plan_finding(
    identifier: Key,
    body: FindingPlan,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.manage")
    return store.public(launch.finding_action(db, ctx.tenant_id, identifier, body, actor, "plan"))


@router.post("/findings/{identifier}/approve", status_code=201)
def approve_finding(
    identifier: Key,
    body: Approval,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.review")
    return store.public(launch.finding_action(db, ctx.tenant_id, identifier, body, actor, "approve"))


@router.post("/findings/{identifier}/report-complete", status_code=201)
def complete_finding(
    identifier: Key,
    body: FindingCompletion,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.operate")
    return store.public(launch.finding_action(db, ctx.tenant_id, identifier, body, actor, "complete"))


@router.post("/assignments", status_code=201)
def assignment(
    body: OperatingAssignment,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.manage")
    return store.public(launch.assignment(db, ctx.tenant_id, body, actor))


@router.post("/assignments/{identifier}/acknowledge", status_code=201)
def acknowledge(
    identifier: Key,
    body: Approval,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.operate")
    return store.public(launch.acknowledge(db, ctx.tenant_id, identifier, body, actor))


@router.post("/assignments/{identifier}/exercises", status_code=201)
def exercise(
    identifier: Key,
    body: OperatingExercise,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.operate")
    return store.public(launch.exercise(db, ctx.tenant_id, identifier, body, actor))


@router.post("/assignments/{identifier}/review-exercise", status_code=201)
def review_exercise(
    identifier: Key,
    body: Approval,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.review")
    return store.public(launch.review_exercise(db, ctx.tenant_id, identifier, body, actor))


@router.post("/pilots", status_code=201)
def pilot(
    body: Pilot,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.manage")
    return store.public(launch.pilot(db, ctx.tenant_id, new_id(), body, actor))


@router.put("/pilots/{identifier}", status_code=201)
def revise_pilot(
    identifier: Key,
    body: Pilot,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.manage")
    store.latest(db, ctx.tenant_id, "customer_pilot", identifier)
    return store.public(launch.pilot(db, ctx.tenant_id, identifier, body, actor))


@router.post("/pilots/{identifier}/technical-review", status_code=201)
def review_pilot(
    identifier: Key,
    body: Approval,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.operate")
    return store.public(launch.review_pilot(db, ctx.tenant_id, identifier, body, actor))


@router.post("/pilots/{identifier}/accept", status_code=201)
def accept_pilot(
    identifier: Key,
    body: Approval,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(estate),
):
    actor = author(db, request, user, "assurance.review")
    return store.public(launch.accept_pilot(db, ctx.tenant_id, identifier, body, actor))


@router.get("/engagements/{identifier}/status")
def security_status(
    identifier: Key, user=Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(estate)
):
    return launch.security_status(db, ctx.tenant_id, identifier)


@router.get("/operations")
def operations_status(user=Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return launch.operations_status(db, ctx.tenant_id)


@router.get("/pilots/{identifier}/status")
def pilot_status(
    identifier: Key, user=Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(estate)
):
    return launch.pilot_status(db, ctx.tenant_id, identifier)
