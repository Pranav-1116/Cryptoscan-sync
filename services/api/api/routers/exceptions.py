"""Policy exception request / approval / review / expiration."""

from __future__ import annotations

from db.tenancy import filtered_get

import hashlib
import hmac
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session
from db.models.crypto_asset import CryptoAsset
from db.repositories.maturity_repository import MaturityRepository

router = APIRouter(prefix="/exceptions", tags=["exceptions"])


class ExceptionCreate(BaseModel):
    asset_id: str | None = None
    system_id: str | None = None
    policy_rule_id: str | None = None
    exception_type: str = "RISK_ACCEPTANCE"
    justification: str
    risk_statement: str
    compensating_controls: str | None = None
    expiration_date: datetime | None = None
    review_frequency: str = "QUARTERLY"


class DecisionBody(BaseModel):
    notes: str | None = None


class ReviewBody(BaseModel):
    still_valid: bool = True
    notes: str | None = None
    action_taken: str = "RENEWED"


def _sign(exception_id: str, approver: str, stamp: str) -> str:
    secret = get_settings().SECRET_KEY.encode("utf-8")
    return hmac.new(secret, f"{exception_id}|{approver}|{stamp}".encode("utf-8"), hashlib.sha256).hexdigest()


@router.get("")
def list_exceptions(
    status: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    rows = MaturityRepository(db).list_exceptions(status=status)
    return {"exceptions": [row.to_dict() for row in rows], "total_count": len(rows)}


@router.post("")
def create_exception(body: ExceptionCreate, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    row = MaturityRepository(db).create_exception(**body.model_dump(), requested_by=user)
    return row.to_dict()


@router.get("/{exception_id}")
def get_exception(exception_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    row = MaturityRepository(db).get_exception(exception_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Exception not found")
    payload = row.to_dict()
    payload["reviews"] = [item.to_dict() for item in row.reviews]
    return payload


@router.post("/{exception_id}/approve")
def approve_exception(
    exception_id: str,
    body: DecisionBody | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = MaturityRepository(db)
    row = repo.get_exception(exception_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Exception not found")
    stamp = datetime.now(timezone.utc).isoformat()
    updated = repo.set_exception_status(
        exception_id,
        status="APPROVED",
        approved_by=user,
        approved_at=datetime.now(timezone.utc),
        approval_signature=_sign(exception_id, user, stamp),
        notes=(body.notes if body else None) or row.notes,
    )
    if updated and updated.asset_id:
        asset = filtered_get(db, CryptoAsset, updated.asset_id)
        if asset is not None:
            extra = dict(asset.extra or {})
            extra["compliance_status"] = "EXCEPTION"
            extra["exception_id"] = updated.id
            asset.extra = extra
    return updated.to_dict() if updated else {}


@router.post("/{exception_id}/reject")
def reject_exception(
    exception_id: str,
    body: DecisionBody | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    row = MaturityRepository(db).set_exception_status(
        exception_id, status="REJECTED", notes=body.notes if body else None, approved_by=user
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Exception not found")
    return row.to_dict()


@router.post("/{exception_id}/revoke")
def revoke_exception(
    exception_id: str,
    body: DecisionBody | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = MaturityRepository(db)
    row = repo.set_exception_status(exception_id, status="REVOKED", notes=body.notes if body else None)
    if row is None:
        raise HTTPException(status_code=404, detail="Exception not found")
    if row.asset_id:
        asset = filtered_get(db, CryptoAsset, row.asset_id)
        if asset is not None:
            extra = dict(asset.extra or {})
            extra["compliance_status"] = "FAIL"
            asset.extra = extra
    return row.to_dict()


@router.post("/{exception_id}/review")
def review_exception(
    exception_id: str,
    body: ReviewBody,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = MaturityRepository(db)
    if repo.get_exception(exception_id) is None:
        raise HTTPException(status_code=404, detail="Exception not found")
    review = repo.add_review(
        exception_id,
        reviewer=user,
        still_valid=body.still_valid,
        notes=body.notes,
        action_taken=body.action_taken if body.still_valid else "REVOKED",
    )
    if not body.still_valid:
        repo.set_exception_status(exception_id, status="REVOKED")
    return review.to_dict()


@router.post("/expire-due")
def expire_due(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    repo = MaturityRepository(db)
    expired = repo.expire_due()
    for row in expired:
        if not row.asset_id:
            continue
        asset = filtered_get(db, CryptoAsset, row.asset_id)
        if asset is None:
            continue
        extra = dict(asset.extra or {})
        extra["compliance_status"] = "FAIL"
        asset.extra = extra
    return {"expired": [row.to_dict() for row in expired], "count": len(expired)}
