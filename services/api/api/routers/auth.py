"""
Authentication router.

Provides:
- POST /auth/login: Username/password login, returns session token
- POST /auth/logout: Invalidate session
- GET /auth/me: Current user info
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field

from api.dependencies import get_db_session
from api.security.auth import AuthService, AuthenticationError
from api.security.session_manager import SessionManager

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["authentication"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)


class LoginResponse(BaseModel):
    message: str
    username: str
    session_expires_at: datetime


class UserInfo(BaseModel):
    username: str
    roles: list[str]
    session_expires_at: datetime


class LogoutResponse(BaseModel):
    message: str


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Authenticate and receive session cookie",
    responses={
        200: {"description": "Login successful"},
        401: {"description": "Invalid credentials"},
        429: {"description": "Too many login attempts"},
    },
)
async def login(
    request: Request,
    body: LoginRequest,
    response: Response,
    session=Depends(get_db_session),
) -> LoginResponse:
    """
    Authenticate with username and password.

    On success:
    - Returns session cookie (HttpOnly, Secure, SameSite=Strict)
    - Session expires after configured timeout

    Rate limited: 5 attempts per minute per IP.
    """
    client_ip = request.client.host if request.client else "unknown"

    log = logger.bind(
        username=body.username,
        client_ip=client_ip,
    )

    try:
        auth_service = AuthService(session)
        session_manager = SessionManager()

        # Validate credentials
        user = await auth_service.authenticate(
            username=body.username,
            password=body.password,
        )

        # Create session
        session_token, expires_at = await session_manager.create_session(
            user_id=user.user_id,
            username=user.username,
            roles=user.roles,
        )

        # Set HttpOnly session cookie
        response.set_cookie(
            key="session_token",
            value=session_token,
            httponly=True,
            secure=True,  # HTTPS only
            samesite="strict",
            expires=int((expires_at - datetime.now(timezone.utc)).total_seconds()),
            path="/",
        )

        log.info("login_successful")

        return LoginResponse(
            message="Login successful",
            username=user.username,
            session_expires_at=expires_at,
        )

    except AuthenticationError as exc:
        log.warning("login_failed", reason=str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Invalidate current session",
)
async def logout(
    response: Response,
    session_token: Annotated[str | None, Cookie()] = None,
) -> LogoutResponse:
    """
    Invalidate the current session.

    Clears the session cookie and removes the session from the store.
    """
    if session_token:
        session_manager = SessionManager()
        await session_manager.invalidate_session(session_token)

    response.delete_cookie(
        key="session_token",
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )

    logger.info("session_invalidated")

    return LogoutResponse(message="Logged out successfully")


@router.get(
    "/me",
    response_model=UserInfo,
    summary="Get current user information",
)
async def get_current_user(
    request: Request,
    session_token: Annotated[str | None, Cookie()] = None,
) -> UserInfo:
    """
    Return information about the currently authenticated user.

    Requires valid session cookie.
    """
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    session_manager = SessionManager()

    try:
        session_data = await session_manager.get_session(session_token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
        )

    return UserInfo(
        username=session_data.username,
        roles=session_data.roles,
        session_expires_at=session_data.expires_at,
    )