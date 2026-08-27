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
    # Explicit Authorization header wins over any session cookie.
    header = request.headers.get("Authorization")
    if header and header.lower().startswith("bearer "):
        return header[7:].strip()
    cookie = request.cookies.get("cryptoscan_session") or request.cookies.get("session_token")
    if cookie:
        return cookie
    return None


def get_current_user(request: Request) -> str:
    token = _token_from_request(request)
    if token:
        username = SessionManager().validate_session(token)
        if username and _session_store_allows(token, username):
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


# ---------------------------------------------------------------------------
# Session store (revocation) + RBAC
# ---------------------------------------------------------------------------

from api.config.settings import get_settings as _get_settings  # noqa: E402


def _session_store_allows(token: str, username: str) -> bool:
    """Reject revoked/disabled credentials.

    Strict in production (unknown token or DB error => deny). In development
    and test the HMAC token alone is accepted so local flows and the test
    suite keep working without a database.
    """
    settings = _get_settings()
    strict = settings.is_production
    try:
        from db.connection.session import SessionLocal
        from db.repositories.user_repository import UserRepository

        session = SessionLocal()
        try:
            repo = UserRepository(session)
            row = repo.get_session(token)
            if row is not None:
                from datetime import datetime, timezone

                if row.revoked_at is not None:
                    return False
                if row.expires_at and row.expires_at < datetime.now(timezone.utc):
                    return False
            elif strict:
                # Token never issued through /auth/login — treat as revoked.
                return False
            user = repo.get_by_username(username)
            if user is not None and not user.is_active:
                return False
            return True
        finally:
            session.close()
    except Exception:  # pragma: no cover - DB unavailable
        return not strict


def _user_roles(username: str, token: str | None) -> list[str]:
    """Fresh roles from the users table; falls back to token claims."""
    try:
        from db.connection.session import SessionLocal
        from db.repositories.user_repository import UserRepository

        session = SessionLocal()
        try:
            user = UserRepository(session).get_by_username(username)
            if user is not None:
                return user.role_list
        finally:
            session.close()
    except Exception:  # pragma: no cover - DB unavailable
        pass
    if token:
        session = SessionManager().get_session(token)
        if session:
            return list(session.roles)
    return []


def require_roles(*allowed: str):
    """Dependency factory: allow only bearers holding one of `allowed` roles.

    Tokens without any known role (e.g. legacy env-admin sessions) are treated
    as admins to stay backward compatible with single-admin deployments.
    """

    def dependency(request: Request) -> str:
        token = _token_from_request(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        username = SessionManager().validate_session(token)
        if not username or not _session_store_allows(token, username):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        roles = _user_roles(username, token)
        if not roles or set(roles) & set(allowed):
            return username
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires one of roles: {', '.join(allowed)}",
        )

    return dependency


require_admin = require_roles("admin")
require_auditor = require_roles("admin", "auditor")
