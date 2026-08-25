"""Cloud / IaC crypto scan endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from cloud_scanner.core.scanner import CloudScanner
from db.repositories.intelligence_repository import IntelligenceRepository

router = APIRouter(prefix="/cloud", tags=["cloud"])


class CloudScanRequest(BaseModel):
    path: str
    live: bool = False


class CloudAccountCreate(BaseModel):
    cloud_provider: str
    account_identifier: str
    role_arn: str | None = None
    regions: list[str] | None = None
    enabled: bool = True


@router.post("/scan")
def scan_cloud(body: CloudScanRequest, user: str = Depends(get_current_user)):
    if not body.path:
        raise HTTPException(status_code=400, detail="path required")
    return CloudScanner(live=body.live).scan_filesystem(body.path)


@router.get("/accounts")
def list_accounts(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = IntelligenceRepository(db).list_cloud_accounts()
    return {"accounts": [row.to_dict() for row in rows]}


@router.post("/accounts")
def create_account(body: CloudAccountCreate, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    row = IntelligenceRepository(db).create_cloud_account(
        cloud_provider=body.cloud_provider.upper(),
        account_identifier=body.account_identifier,
        role_arn=body.role_arn,
        regions=body.regions,
        enabled=body.enabled,
    )
    return row.to_dict()
