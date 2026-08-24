"""Authentication routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, Field

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


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, response: Response) -> LoginResponse:
    try:
        user = AuthService().authenticate(body.username, body.password)
    except AuthenticationError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    manager = SessionManager()
    token = manager.create_session(user.username, roles=user.roles)
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    response.set_cookie(
        key="cryptoscan_session",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=24 * 3600,
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
    response.delete_cookie("cryptoscan_session", path="/")
    return {"message": "Logged out successfully"}


@router.get("/me")
def me(token: str | None = None):
    return {"username": "admin", "roles": ["admin"]}
