"""FastAPI dependencies."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from api.security.session_manager import SessionManager
from db.connection.session import get_session
from db.repositories.baseline_repository import BaselineRepository
from db.repositories.drift_repository import DriftRepository
from db.repositories.evidence_repository import EvidenceRepository
from db.repositories.job_repository import JobRepository
from db.repositories.repo_config_repository import RepoConfigRepository
from db.repositories.scan_repository import ScanRepository
from db.repositories.verification_repository import VerificationRepository


def get_db_session():
    yield from get_session()


def get_scan_repository(db: Session = Depends(get_db_session)) -> ScanRepository:
    return ScanRepository(db)


def get_evidence_repository(db: Session = Depends(get_db_session)) -> EvidenceRepository:
    return EvidenceRepository(db)


def get_drift_repository(db: Session = Depends(get_db_session)) -> DriftRepository:
    return DriftRepository(db)


def get_job_repository(db: Session = Depends(get_db_session)) -> JobRepository:
    return JobRepository(db)


def get_baseline_repository(db: Session = Depends(get_db_session)) -> BaselineRepository:
    return BaselineRepository(db)


def get_repo_config_repository(db: Session = Depends(get_db_session)) -> RepoConfigRepository:
    return RepoConfigRepository(db)


def get_verification_repository(db: Session = Depends(get_db_session)) -> VerificationRepository:
    return VerificationRepository(db)


def _token_from_request(request: Request) -> str | None:
    cookie = request.cookies.get("cryptoscan_session") or request.cookies.get("session_token")
    if cookie:
        return cookie
    header = request.headers.get("Authorization")
    if header and header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


def get_current_user(request: Request) -> str:
    token = _token_from_request(request)
    if token:
        username = SessionManager().validate_session(token)
        if username:
            return username
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_optional_user(request: Request) -> str | None:
    try:
        return get_current_user(request)
    except HTTPException:
        return None
