"""Authentication routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from api.config.settings import get_settings
from api.security.auth import AuthService, AuthenticationError
from api.security.session_manager import SessionManager

router = APIRouter(prefix="/auth", tags=["authentication"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    message: str
    username: str
    token: str
    session_expires_at: datetime


def token_from_request(request: Request) -> str | None:
    header = request.headers.get("Authorization")
    if header and header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.cookies.get("cryptoscan_session") or request.cookies.get("session_token")


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request, response: Response) -> LoginResponse:
    settings = get_settings()
    client = request.client.host if request.client else ""
    try:
        user = AuthService().authenticate(body.username, body.password, client_key=client)
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=exc.message) from exc

    manager = SessionManager()
    token = manager.create_session(user.username, roles=user.roles)
    max_age = int(settings.SESSION_EXPIRE_HOURS * 3600)
    expires = datetime.now(timezone.utc) + timedelta(seconds=max_age)
    response.set_cookie(
        key="cryptoscan_session",
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=max_age,
        path="/",
    )
    return LoginResponse(
        message="Login successful",
        username=user.username,
        token=token,
        session_expires_at=expires,
    )


@router.post("/logout")
def logout(response: Response) -> dict:
    settings = get_settings()
    response.delete_cookie("cryptoscan_session", path="/", secure=settings.cookie_secure, httponly=True, samesite="lax")
    return {"message": "Logged out successfully"}


@router.get("/me")
def me(request: Request) -> dict:
    token = token_from_request(request)
    session = SessionManager().get_session(token or "")
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return {"username": session.username, "roles": session.roles}
