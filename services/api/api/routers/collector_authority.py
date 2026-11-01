"""Collector authority: one descriptor per plane, and the decision a collection runs.

Four routes, and the point of them is that they are the *only* way a collector's
authority is answered:

* ``GET  /collectors/authority`` — the matrix: every plane, its entry, its
  permission, its approval revision, its window and its budget, with the gaps
  named. This is what guide 116's table is rendered from.
* ``POST /collectors/authority/{plane}`` — approve a plane (bumps the revision).
  Superadmin only, because an approval is a standing permission.
* ``POST /collectors/authority/{plane}/revoke`` — withdraw it. The row stays, so
  "who withdrew what, when" survives the withdrawal.
* ``POST /collectors/authorize`` — evaluate one collection against its plane's
  authority and answer all six questions, refusing with the question that failed.

The matrix is not documentation generated from the same strings as the decision:
both are :mod:`api.security.collector_authority`, so a plane cannot be described
as governed and behave otherwise.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_db_session
from api.security import collector_authority as authority
from api.security.rbac import require_permission, require_principal

router = APIRouter(tags=["collectors"])


class ApprovalIn(BaseModel):
    permission: str | None = Field(default=None, max_length=80)
    valid_days: int = Field(default=90, ge=1, le=366)
    max_targets: int | None = Field(default=None, ge=1, le=100_000)
    max_requests: int | None = Field(default=None, ge=1, le=1_000_000)
    max_runtime_seconds: int | None = Field(default=None, ge=1, le=86_400)
    window_seconds: int | None = Field(default=None, ge=60, le=86_400)


class RevokeIn(BaseModel):
    reason: str = Field(default="", max_length=300)


class AuthorizeIn(BaseModel):
    plane: str = Field(min_length=2, max_length=40)
    target: str = Field(min_length=1, max_length=300)
    revision: int | None = Field(default=None, ge=0)
    requests: int = Field(default=1, ge=1, le=10_000)
    runtime_seconds: int = Field(default=0, ge=0, le=86_400)


# ------------------------------------------------------------------ responses --- #
# These are the contract, not a restatement: a console renders the matrix, so the
# matrix's keys are declared here and validated on the way out. The artifact in
# docs/bank-environment/116-collector-authority.json is generated through these
# responses, which is why a field that changes shape fails loudly rather than
# quietly emptying a column.


class PlaneBudgetOut(BaseModel):
    window_seconds: int
    max_targets: int
    max_requests: int
    max_runtime_seconds: int
    requests_used: int


class PlaneRowOut(BaseModel):
    """One plane: what it collects, what it costs, and what is missing."""

    plane: str
    entry: str
    permission: str
    target_kind: str
    note: str
    approved: bool
    gaps: list[str]
    revision: int | None = None
    approved_by: str | None = None
    expires_at: str | None = None
    budget: PlaneBudgetOut


class MatrixOut(BaseModel):
    """Every plane, the six questions, and the count that goes in the guide."""

    planes: list[PlaneRowOut]
    questions: dict[str, str]
    approved: list[str]
    unapproved: list[str]
    counts: dict[str, int]


class ApprovalOut(BaseModel):
    plane: str
    revision: int
    permission: str
    approved_by: str | None = None
    expires_at: str | None = None


class RevocationOut(BaseModel):
    plane: str
    revoked_at: str | None = None
    revision: int
    reason: str


class AnswerOut(BaseModel):
    question: str
    mechanism: str
    detail: str
    meaning: str


class DecisionOut(BaseModel):
    """The answer to all six questions for one collection, allowed or refused."""

    plane: str
    allowed: bool
    answers: dict[str, AnswerOut]
    refusals: list[dict[str, Any]]
    revision: int | None = None
    remaining_requests: int | None = None
    remaining_runtime_seconds: int | None = None
    note: str = ""


def _refused(exc: authority.AuthorityRefused) -> HTTPException:
    status_code = 422 if exc.code in {authority.UNKNOWN_PLANE, authority.OUTSIDE_WINDOW,
                                      authority.PERMISSION_DENIED} else 409
    if exc.code == authority.PERMISSION_DENIED:
        status_code = 403
    return HTTPException(status_code=status_code,
                         detail={"error": exc.code, "reason": exc.detail})


@router.get("/collectors/authority", response_model=MatrixOut)
def collector_authority_matrix(
    db: Session = Depends(get_db_session),
    _user: str = Depends(require_permission("audit.read")),
):
    """Every collector plane, with the six questions answered or the gap named."""
    rows = authority.matrix(db)
    approved = [row["plane"] for row in rows if row["approved"]]
    return {
        "planes": rows,
        "questions": authority.QUESTION_TEXT,
        "approved": approved,
        "unapproved": [row["plane"] for row in rows if not row["approved"]],
        "counts": {"planes": len(rows), "approved": len(approved),
                   "unapproved": len(rows) - len(approved)},
    }


@router.post("/collectors/authority/{plane}", response_model=ApprovalOut)
def approve_collector_authority(
    plane: str,
    body: ApprovalIn,
    db: Session = Depends(get_db_session),
    approver: str = Depends(require_permission("platform.configure")),
):
    """Approve (or re-approve) a plane's authority. Bumps the revision."""
    try:
        row = authority.approve(
            db, plane=plane.upper(), approver=approver, permission=body.permission,
            valid_days=body.valid_days, max_targets=body.max_targets,
            max_requests=body.max_requests, max_runtime_seconds=body.max_runtime_seconds,
            window_seconds=body.window_seconds,
        )
    except authority.AuthorityRefused as exc:
        raise _refused(exc) from exc
    return {"plane": row.plane, "revision": row.revision, "permission": row.permission,
            "approved_by": row.approved_by,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None}


@router.post("/collectors/authority/{plane}/revoke", response_model=RevocationOut)
def revoke_collector_authority(
    plane: str,
    body: RevokeIn,
    db: Session = Depends(get_db_session),
    approver: str = Depends(require_permission("platform.configure")),
):
    """Withdraw a plane's authority. The row is kept as the record of the act."""
    try:
        row = authority.revoke(db, plane=plane.upper(), revoked_by=approver)
    except authority.AuthorityRefused as exc:
        raise _refused(exc) from exc
    return {"plane": row.plane, "revoked_at": row.revoked_at.isoformat()
            if row.revoked_at else None, "revision": row.revision,
            "reason": body.reason}


@router.post("/collectors/authorize", response_model=DecisionOut)
def authorize_collection(
    body: AuthorizeIn,
    db: Session = Depends(get_db_session),
    caller: dict[str, Any] = Depends(require_principal),
):
    """Answer the six questions for one collection, and refuse with the one that failed.

    200 carries the decision whether it allowed or refused: a refusal is an
    *answer with a code*, and a caller (or a drill) needs to read which question
    failed without pattern-matching on a 403 body. 401 is the only refusal that
    is not a decision, because there is no principal to make it for.
    """
    decision = authority.evaluate(
        db, plane=body.plane.upper(), principal=caller["principal"],
        roles=caller["roles"], target=body.target, revision=body.revision,
        requests=body.requests, runtime_seconds=body.runtime_seconds,
    )
    return decision.as_dict()
