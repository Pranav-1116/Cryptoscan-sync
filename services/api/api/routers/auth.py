"""Authentication routes: login/logout, user management (admin), audit trail."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.config.settings import get_settings
from api.dependencies import get_db_session, require_admin
from api.security.auth import AuthService, AuthenticationError
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager

router = APIRouter(prefix="/auth", tags=["authentication"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    message: str
    username: str
    roles: list[str] = Field(default_factory=list)
    token: str
    session_expires_at: datetime


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=10, max_length=200)
    roles: list[str] = Field(default_factory=lambda: ["viewer"])
    display_name: str | None = None
    email: str | None = None


class UserUpdateRequest(BaseModel):
    roles: list[str] | None = None
    is_active: bool | None = None
    password: str | None = Field(None, min_length=10, max_length=200)


class UserResponse(BaseModel):
    username: str
    display_name: str | None
    email: str | None
    roles: list[str]
    is_active: bool
    last_login_at: datetime | None

    class Config:
        from_attributes = True


def token_from_request(request: Request) -> str | None:
    header = request.headers.get("Authorization")
    if header and header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.cookies.get("cryptoscan_session") or request.cookies.get("session_token")


def _user_repo(db: Session):
    from db.repositories.user_repository import UserRepository

    return UserRepository(db)


def _auth_service(db: Session | None) -> AuthService:
    """AuthService bound to the DB when possible; legacy env fallback otherwise."""
    if db is None:
        settings = get_settings()
        if settings.is_production:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="Authentication store unavailable")
    return AuthService(session=db)


def _auth_db_error(exc: Exception) -> HTTPException | None:
    """Translate auth-store failures: 503 in production, degrade in dev/test."""
    settings = get_settings()
    if settings.is_production:
        return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                             detail="Authentication store unavailable")
    import logging

    logging.getLogger(__name__).warning("auth_db_unavailable_fallback_env_admin: %s", exc)
    return None


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db_session)) -> LoginResponse:
    settings = get_settings()
    client = request.client.host if request.client else ""
    roles = ["admin"]
    try:
        user = AuthService(session=db).authenticate(body.username, body.password, client_key=client)
        roles = user.roles
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=exc.message) from exc
    except Exception as exc:
        fallback = _auth_db_error(exc)
        if fallback is not None:
            raise fallback from exc
        try:
            db.rollback()
        except Exception:
            pass
        try:
            user = AuthService(session=None).authenticate(body.username, body.password, client_key=client)
            roles = user.roles
        except AuthenticationError as exc2:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=exc2.message) from exc2

    manager = SessionManager()
    token = manager.create_session(user.username, roles=roles)
    max_age = int(settings.SESSION_EXPIRE_HOURS * 3600)
    expires = datetime.now(timezone.utc) + timedelta(seconds=max_age)
    try:
        _user_repo(db).create_session(token, user.username, expires, ip=client)
        db.commit()
    except Exception as exc:
        fallback = _auth_db_error(exc)
        if fallback is not None:
            raise fallback from exc
        try:
            db.rollback()
        except Exception:
            pass

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
        roles=roles,
        token=token,
        session_expires_at=expires,
    )


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db_session)) -> dict:
    settings = get_settings()
    token = token_from_request(request)
    actor = "unknown"
    if token:
        view = SessionManager().get_session(token)
        actor = view.username if view else "unknown"
        try:
            if _user_repo(db).revoke_session(token):
                _user_repo(db).audit(actor, "auth.logout", ip=request.client.host if request.client else None)
                db.commit()
        except Exception:
            pass  # revocation is best-effort; the token still expires naturally
    response.delete_cookie("cryptoscan_session", path="/", secure=settings.cookie_secure, httponly=True, samesite="lax")
    return {"message": "Logged out successfully"}


@router.get("/me")
def me(request: Request, db: Session = Depends(get_db_session)) -> dict:
    token = token_from_request(request)
    session = SessionManager().get_session(token or "")
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        from api.dependencies import _session_store_allows

        if not _session_store_allows(token or "", session.username):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked")
    except HTTPException:
        raise
    except Exception:  # pragma: no cover - store unavailable
        pass
    roles = session.roles
    try:
        user = _user_repo(db).get_by_username(session.username)
        if user is not None:
            roles = user.role_list
    except Exception:  # pragma: no cover
        pass
    return {"username": session.username, "roles": roles}


# ------------------------------------------------------------------ user management

@router.get("/users", response_model=list[UserResponse])
def list_users(
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    return [
        UserResponse(
            username=u.username,
            display_name=u.display_name,
            email=u.email,
            roles=u.role_list,
            is_active=u.is_active,
            last_login_at=u.last_login_at,
        )
        for u in _user_repo(db).list_users()
    ]


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreateRequest,
    request: Request,
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    from db.models.user import VALID_ROLES

    repo = _user_repo(db)
    if repo.get_by_username(body.username) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    bad_roles = [r for r in body.roles if r not in VALID_ROLES]
    if bad_roles:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown roles: {bad_roles}. Valid: {list(VALID_ROLES)}",
        )
    user = repo.create_user(
        body.username,
        hash_password(body.password),
        roles=body.roles,
        display_name=body.display_name,
        email=body.email,
    )
    repo.audit(
        admin,
        "user.create",
        target_type="user",
        target_id=user.username,
        detail={"roles": user.role_list},
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return UserResponse(
        username=user.username,
        display_name=user.display_name,
        email=user.email,
        roles=user.role_list,
        is_active=user.is_active,
        last_login_at=user.last_login_at,
    )


@router.patch("/users/{username}", response_model=UserResponse)
def update_user(
    username: str,
    body: UserUpdateRequest,
    request: Request,
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    repo = _user_repo(db)
    user = repo.get_by_username(username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    changes: dict = {}
    if body.roles is not None:
        from db.models.user import VALID_ROLES

        bad = [r for r in body.roles if r not in VALID_ROLES]
        if bad:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Unknown roles: {bad}")
        updated = repo.set_roles(username, body.roles)
        changes["roles"] = updated.role_list
    if body.is_active is not None:
        repo.set_active(username, body.is_active)
        changes["is_active"] = body.is_active
        if not body.is_active:
            changes["revoked_sessions"] = repo.revoke_all_sessions(username)
    if body.password is not None:
        repo.set_password(username, hash_password(body.password))
        changes["password_rotated"] = True
        changes["revoked_sessions"] = repo.revoke_all_sessions(username)
    repo.audit(
        admin,
        "user.update",
        target_type="user",
        target_id=username,
        detail=changes,
        ip=request.client.host if request.client else None,
    )
    db.commit()
    user = repo.get_by_username(username)
    return UserResponse(
        username=user.username,
        display_name=user.display_name,
        email=user.email,
        roles=user.role_list,
        is_active=user.is_active,
        last_login_at=user.last_login_at,
    )


# ------------------------------------------------------------------ audit trail

@router.get("/audit")
def list_audit(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    actor: str | None = None,
    action: str | None = None,
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    rows = _user_repo(db).list_audit(page=page, page_size=page_size, actor=actor, action=action)
    events = []
    for r in rows:
        detail = r.detail
        try:
            detail = json.loads(detail) if detail and detail.startswith(("{", "[")) else detail
        except Exception:
            pass
        events.append(
            {
                "id": r.id,
                "actor": r.actor,
                "action": r.action,
                "target_type": r.target_type,
                "target_id": r.target_id,
                "detail": detail,
                "ip_address": r.ip_address,
                "outcome": r.outcome,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
        )
    return {"events": events, "page": page, "page_size": page_size}
