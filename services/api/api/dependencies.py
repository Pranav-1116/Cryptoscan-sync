"""
FastAPI dependency injection providers.
Centralised DI for DB sessions, repositories, and authentication.
"""
from __future__ import annotations

import logging
from typing import Annotated, AsyncGenerator

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from db.connection.session import AsyncSessionFactory
from db.repositories.baseline_repository import BaselineRepository
from db.repositories.drift_repository import DriftRepository
from db.repositories.evidence_repository import EvidenceRepository
from db.repositories.job_repository import JobRepository
from db.repositories.repo_config_repository import RepoConfigRepository
from db.repositories.scan_repository import ScanRepository
from db.repositories.verification_repository import VerificationRepository

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Database session
# ---------------------------------------------------------------------------

async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Yield an async SQLAlchemy session.
    Session is committed on success, rolled back on exception.
    """
    async with AsyncSessionFactory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ---------------------------------------------------------------------------
# Repository dependencies
# ---------------------------------------------------------------------------

async def get_scan_repository(
    db: AsyncSession = Depends(get_db_session),
) -> ScanRepository:
    return ScanRepository(db)


async def get_evidence_repository(
    db: AsyncSession = Depends(get_db_session),
) -> EvidenceRepository:
    return EvidenceRepository(db)


async def get_drift_repository(
    db: AsyncSession = Depends(get_db_session),
) -> DriftRepository:
    return DriftRepository(db)


async def get_job_repository(
    db: AsyncSession = Depends(get_db_session),
) -> JobRepository:
    return JobRepository(db)


async def get_baseline_repository(
    db: AsyncSession = Depends(get_db_session),
) -> BaselineRepository:
    return BaselineRepository(db)


async def get_repo_config_repository(
    db: AsyncSession = Depends(get_db_session),
) -> RepoConfigRepository:
    return RepoConfigRepository(db)


async def get_verification_repository(
    db: AsyncSession = Depends(get_db_session),
) -> VerificationRepository:
    return VerificationRepository(db)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

async def get_current_user(request: Request) -> str:
    """
    Extract and validate the current authenticated user.

    Supports:
    1. Session cookie (web dashboard)
    2. Bearer token (API clients / CI)

    Returns the username string.
    Raises HTTP 401 if not authenticated.
    """
    from api.security.session_manager import SessionManager

    session_manager = SessionManager()

    # Check session cookie first
    session_token = request.cookies.get("cryptoscan_session")
    if session_token:
        username = await session_manager.validate_session(session_token)
        if username:
            return username

    # Check Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer "):]
        username = await session_manager.validate_api_token(token)
        if username:
            return username

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_optional_user(request: Request) -> str | None:
    """
    Like get_current_user but returns None instead of raising 401.
    Used for public endpoints that optionally enhance response for logged-in users.
    """
    try:
        return await get_current_user(request)
    except HTTPException:
        return None