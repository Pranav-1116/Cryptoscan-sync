"""Human-assigned qualification receipt workflow; never dispatches host execution."""

from typing import Literal
from starlette.concurrency import run_in_threadpool
from fastapi import APIRouter, Depends, Request, Query, Response, HTTPException
from sqlalchemy.orm import Session
from api.dependencies import get_current_user, get_db_session
from api.routers.assurance_boundary import estate, author, Key
from api.assurance import qualification as core, store
from db.models.assurance import AssuranceRevision
from shared_models.qualification_workflow import (
    CampaignCreate,
    Assignments,
    FreezeEvidence,
    SubmitReview,
    ExpectedRevision,
)
from shared_models.host_collection import Token


def current_human_reader(request: Request, db: Session = Depends(get_db_session), user=Depends(get_current_user)):
    # Metadata/read/export are human-only too; ordinary estate access alone also
    # admits machine/legacy development principals on older collection routes.
    return author(db, request, user, "crypto.read")


router = APIRouter(prefix="/qualification", tags=["host qualification"], dependencies=[Depends(current_human_reader)])


@router.post("/campaigns", status_code=201)
def create(
    body: CampaignCreate,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.create(db, ctx.tenant_id, body, author(db, request, user, "assurance.trust"), user)


@router.get("/campaigns")
def campaigns(
    cursor: str = Query("", max_length=36),
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    rows = (
        store.rows(db, AssuranceRevision, ctx.tenant_id)
        .filter_by(kind=core.KIND, revision=1)
        .filter(AssuranceRevision.subject_id > cursor)
        .order_by(AssuranceRevision.subject_id)
        .limit(26)
        .all()
    )
    return {
        "campaigns": [core.status(db, ctx.tenant_id, core.load(db, ctx.tenant_id, r.subject_id)) for r in rows[:25]],
        "next_cursor": rows[24].subject_id if len(rows) > 25 else None,
    }


@router.get("/campaigns/{identifier}")
def campaign(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return core.status(db, ctx.tenant_id, core.load(db, ctx.tenant_id, identifier))


@router.post("/campaigns/{identifier}/assignments")
def assignments(
    identifier: Key,
    body: Assignments,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.assign(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.trust"), user)


@router.post("/campaigns/{identifier}/artifacts", status_code=201)
async def artifact(
    identifier: Key,
    request: Request,
    expected_revision: int = Query(ge=1, le=320),
    kind: Literal["native", "public_json", "tpm_attest", "tpm_signature"] = Query(),
    evidence_reference: Token = Query(),
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    actor = author(db, request, user)
    allowed = "application/json" if kind in {"native", "public_json"} else "application/octet-stream"
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != allowed:
        raise HTTPException(415, "Use the declared public artifact media type")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > core.MAX_FILE:
            raise HTTPException(413, "Original artifact exceeds 2 MiB")
        data.extend(chunk)
    return await run_in_threadpool(
        core.upload,
        db,
        ctx.tenant_id,
        identifier,
        expected_revision,
        kind,
        bytes(data),
        evidence_reference,
        actor,
        user,
    )


@router.post("/campaigns/{identifier}/freeze")
def freeze(
    identifier: Key,
    body: FreezeEvidence,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.freeze(db, ctx.tenant_id, identifier, body, author(db, request, user), user)


@router.post("/campaigns/{identifier}/reviews")
def reviews(
    identifier: Key,
    body: SubmitReview,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.review(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.review"), user)


@router.post("/campaigns/{identifier}/withdraw")
def withdraw(
    identifier: Key,
    body: ExpectedRevision,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.withdraw(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.trust"), user)


@router.get("/campaigns/{identifier}/artifacts/{digest}")
def original(
    identifier: Key,
    digest: str,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    row = core.load(db, ctx.tenant_id, identifier)
    author(db, request, user, "assurance.raw")  # preserve existing raw-original privilege
    entry = row.payload["artifacts"].get(digest)
    if entry is None:
        raise HTTPException(404, "Qualification artifact not found")
    blob = store.blob(db, ctx.tenant_id, entry["blob_id"])
    if blob.sha256 != digest:
        raise HTTPException(409, "Qualification artifact integrity mismatch")
    media = "application/json" if entry["kind"] in {"native", "public_json"} else "application/octet-stream"
    return Response(
        blob.data,
        media_type=media,
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": f'attachment; filename="{digest}.artifact"',
        },
    )


@router.get("/campaigns/{identifier}/export")
def export_campaign(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    from shared_models.tpm_quote_verification import canonical

    value = core.status(db, ctx.tenant_id, core.load(db, ctx.tenant_id, identifier))
    return Response(
        canonical(value),
        media_type="application/json",
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": 'attachment; filename="qualification-record.json"',
        },
    )
