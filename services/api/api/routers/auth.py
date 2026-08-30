"""Authentication routes: login/logout, user management (admin), audit trail."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session, require_admin
from api.security import totp
from api.security.auth import AuthService, AuthenticationError
from api.security.passwords import hash_password, verify_password
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
    # MFA second factor: when mfa_required is true no session was issued;
    # exchange mfa_token + a TOTP/recovery code at /auth/login/mfa
    mfa_required: bool = False
    mfa_token: str | None = None


class MfaLoginRequest(BaseModel):
    mfa_token: str = Field(..., min_length=10)
    code: str = Field(..., min_length=4, max_length=16)


class MfaEnableRequest(BaseModel):
    code: str = Field(..., min_length=4, max_length=12)


class MfaDisableRequest(BaseModel):
    password: str = Field(..., min_length=1)
    code: str = Field(..., min_length=4, max_length=16)


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

    # Second factor gate: password alone must never mint a session for
    # an MFA-enabled account. The challenge token is purpose-scoped and
    # expires in 5 minutes.
    if getattr(user, "mfa_enabled", False):
        manager = SessionManager()
        mfa_token = manager.create_mfa_challenge(user.username)
        try:
            _user_repo(db).audit(user.username, "auth.mfa_challenge_issued", ip=client)
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        return LoginResponse(
            message="MFA code required",
            username=user.username,
            roles=roles,
            token="",
            session_expires_at=datetime.now(timezone.utc) + timedelta(seconds=300),
            mfa_required=True,
            mfa_token=mfa_token,
        )

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


class OidcLoginRequest(BaseModel):
    token: str = Field(..., min_length=20)  # JWT from the corporate IdP


@router.post("/oidc", response_model=LoginResponse)
def oidc_login(body: OidcLoginRequest, request: Request, response: Response, db: Session = Depends(get_db_session)) -> LoginResponse:
    """Federated login: verify an IdP-issued RS256 token, mint a CryptoScan session.

    The IdP owns the credential (and its MFA); CryptoScan only maps a verified
    subject to a local account. Roles stay local — no IdP role mapping claimed.
    Requires OIDC_ISSUER; unknown users are rejected unless OIDC_AUTO_PROVISION
    is on (they get the viewer role).
    """
    settings = get_settings()
    client = request.client.host if request.client else ""
    if not (settings.OIDC_ISSUER or "").strip():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OIDC SSO not configured")
    from api.security.oidc import OidcError, verify_id_token

    try:
        claims = verify_id_token(
            body.token,
            issuer=settings.OIDC_ISSUER.strip(),
            audience=(settings.OIDC_CLIENT_ID or "").strip() or None,
            jwks_url=(settings.OIDC_JWKS_URL or "").strip() or None,
            jwks_file=(settings.OIDC_JWKS_FILE or "").strip() or None,
            clock_leeway=settings.OIDC_CLOCK_LEEWAY,
        )
    except OidcError as exc:
        repo = _user_repo(db)
        try:
            repo.audit("unknown", "auth.oidc_login", outcome="FAILURE", ip=client, detail=str(exc)[:200])
            db.commit()
        except Exception:
            db.rollback()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    email = str(claims.get("email") or "").strip().lower() or None
    username = str(claims.get("preferred_username") or claims.get("sub") or "").strip().lower()
    if not username and email:
        username = email.split("@")[0]
    if not username:
        raise HTTPException(status_code=401, detail="token carries no subject (preferred_username/sub/email)")

    repo = _user_repo(db)
    user = repo.get_by_username(username)
    if user is None and settings.OIDC_AUTO_PROVISION:
        import secrets

        user = repo.create_user(
            username,
            password_hash=secrets.token_urlsafe(48),  # unguessable: password login impossible
            roles=["viewer"],
            display_name=str(claims.get("name") or username),
            email=email,
        )
    if user is None:
        try:
            repo.audit(username, "auth.oidc_login", outcome="FAILURE", ip=client, detail="no local user and auto-provision disabled")
            db.commit()
        except Exception:
            db.rollback()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="verified token but no local user (enable OIDC_AUTO_PROVISION or create the account)")
    if not getattr(user, "is_active", True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="account disabled")

    roles = user.role_list
    manager = SessionManager()
    token = manager.create_session(user.username, roles=roles)
    max_age = int(settings.SESSION_EXPIRE_HOURS * 3600)
    expires = datetime.now(timezone.utc) + timedelta(seconds=max_age)
    try:
        repo.create_session(token, user.username, expires, ip=client)
        repo.audit(user.username, "auth.oidc_login", ip=client, detail={"issuer": settings.OIDC_ISSUER})
        db.commit()
    except Exception:
        db.rollback()

    response.set_cookie(
        key="cryptoscan_session", value=token, httponly=True, samesite="lax",
        secure=settings.cookie_secure, max_age=max_age, path="/",
    )
    return LoginResponse(
        message="OIDC login successful",
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
    user = None
    try:
        user = _user_repo(db).get_by_username(session.username)
        if user is not None:
            roles = user.role_list
    except Exception:  # pragma: no cover
        pass
    mfa_enabled = bool(user.mfa_enabled) if user is not None else False
    return {"username": session.username, "roles": roles, "mfa_enabled": mfa_enabled}

# ------------------------------------------------------------------ mfa (totp)

def _recovery_hash(code: str) -> str:
    """Recovery codes are random high-entropy strings — SHA-256 lookup hash."""
    return hashlib.sha256(code.strip().upper().encode("utf-8")).hexdigest()


def _issue_session(response: Response, username: str, roles: list[str], client: str, db: Session) -> LoginResponse:
    """Shared tail of login and login/mfa: token + DB session row + cookie."""
    settings = get_settings()
    manager = SessionManager()
    token = manager.create_session(username, roles=roles)
    max_age = int(settings.SESSION_EXPIRE_HOURS * 3600)
    expires = datetime.now(timezone.utc) + timedelta(seconds=max_age)
    try:
        _user_repo(db).create_session(token, username, expires, ip=client)
        db.commit()
    except Exception:
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
    try:  # real-time stream: sessions issued (no token material, ever)
        from api.events.bus import get_event_bus

        get_event_bus().publish("auth.login", {"user": username, "roles": roles}, source="auth")
    except Exception:
        pass
    return LoginResponse(
        message="Login successful",
        username=username,
        roles=roles,
        token=token,
        session_expires_at=expires,
    )


@router.post("/login/mfa", response_model=LoginResponse)
def login_mfa(
    body: MfaLoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db_session),
) -> LoginResponse:
    """Second factor: exchange the short-lived challenge + TOTP/recovery code."""
    client = request.client.host if request.client else ""
    username = SessionManager().validate_mfa_challenge(body.mfa_token)
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA challenge invalid or expired")

    repo = _user_repo(db)
    row = repo.get_by_username(username)
    if row is None or not row.is_active or not row.mfa_enabled or not row.mfa_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA not active for this account")

    locked_until = row.locked_until
    if locked_until is not None and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    if locked_until is not None and locked_until > datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account temporarily locked. Try again later.")

    used_recovery = False
    if totp.verify(row.mfa_secret, body.code):
        ok = True
    else:
        ok = repo.consume_recovery_code(row.id, _recovery_hash(body.code))
        used_recovery = ok

    if not ok:
        repo.record_failure(
            username,
            max_failures=get_settings().LOGIN_MAX_FAILURES,
            lockout_seconds=get_settings().LOGIN_LOCKOUT_SECONDS,
        )
        repo.audit(username, "auth.login_mfa", outcome="FAILURE", ip=client, detail="bad TOTP/recovery code")
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    repo.reset_failures(username)
    repo.audit(username, "auth.login_mfa", ip=client, detail="recovery code" if used_recovery else "totp")
    db.commit()
    return _issue_session(response, username, row.role_list, client, db)


@router.post("/mfa/enroll")
def mfa_enroll(
    request: Request,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict:
    """Start TOTP enrollment: returns the secret + otpauth:// URI (unconfirmed)."""
    client = request.client.host if request.client else ""
    repo = _user_repo(db)
    row = repo.get_by_username(user)
    if row is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA requires a database-backed account")
    if row.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is already enabled for this account")

    secret = totp.generate_secret()
    repo.set_mfa_secret(user, secret, enabled=False)  # pending until a code proves possession
    repo.audit(user, "auth.mfa_enroll", ip=client)
    db.commit()
    return {
        "secret": secret,
        "otpauth_uri": totp.provisioning_uri(secret, user),
        "digits": totp.DEFAULT_DIGITS,
        "period": totp.DEFAULT_PERIOD,
        "issuer": "CryptoScan",
        "next": "Confirm with POST /auth/mfa/enable {code}",
    }


@router.post("/mfa/enable")
def mfa_enable(
    body: MfaEnableRequest,
    request: Request,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict:
    """Activate MFA by proving the authenticator works; issues recovery codes once."""
    client = request.client.host if request.client else ""
    repo = _user_repo(db)
    row = repo.get_by_username(user)
    if row is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA requires a database-backed account")
    if row.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is already enabled for this account")
    if not row.mfa_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Enroll first (POST /auth/mfa/enroll)")

    if not totp.verify(row.mfa_secret, body.code):
        repo.audit(user, "auth.mfa_enable", outcome="FAILURE", ip=client, detail="bad confirmation code")
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code — enrollment not activated")

    repo.set_mfa_secret(user, row.mfa_secret, enabled=True)
    codes = totp.generate_recovery_codes()
    repo.set_recovery_codes(row.id, [_recovery_hash(code) for code in codes])  # hashes only
    repo.audit(user, "auth.mfa_enable", ip=client)
    db.commit()
    return {"enabled": True, "recovery_codes": codes, "warning": "Recovery codes are shown once — store them now"}


@router.post("/mfa/disable")
def mfa_disable(
    body: MfaDisableRequest,
    request: Request,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict:
    """Disable MFA: requires the password AND a valid code, then kills all sessions."""
    client = request.client.host if request.client else ""
    repo = _user_repo(db)
    row = repo.get_by_username(user)
    if row is None or not row.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is not enabled for this account")

    if not verify_password(body.password, row.password_hash):
        repo.audit(user, "auth.mfa_disable", outcome="FAILURE", ip=client, detail="bad password")
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")

    code_ok = (row.mfa_secret and totp.verify(row.mfa_secret, body.code)) or repo.consume_recovery_code(
        row.id, _recovery_hash(body.code)
    )
    if not code_ok:
        repo.audit(user, "auth.mfa_disable", outcome="FAILURE", ip=client, detail="bad code")
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA code")

    repo.set_mfa_secret(user, None, enabled=False)
    repo.set_recovery_codes(row.id, [])
    repo.revoke_all_sessions(user)
    repo.audit(user, "auth.mfa_disable", ip=client)
    db.commit()
    return {"disabled": True, "sessions_revoked": True}


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


@router.get("/audit/verify")
def verify_audit(
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Walk the audit hash chain and report the first break (W57-58)."""
    from db.repositories.user_repository import verify_audit_chain

    return verify_audit_chain(db)


@router.get("/audit/export")
def export_audit(
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Immutable audit export: JSONL entries + manifest, SHA-256 over the body.

    The export is the WORM/archive artifact: ship the bytes to S3/Glacier with
    object lock, or print them for an auditor. The hash chain makes any later
    modification of stored entries detectable against a kept export.
    """
    import hashlib as _hashlib

    from fastapi.responses import PlainTextResponse

    from db.models.user import AuditLog as _AuditLog
    from db.repositories.user_repository import verify_audit_chain

    rows = list(
        db.query(_AuditLog)
        .order_by(_AuditLog.created_at.asc(), _AuditLog.id.asc())
        .all()
    )
    lines = []
    for r in rows:
        try:
            detail = json.loads(r.detail) if r.detail and r.detail.startswith(("{", "[")) else r.detail
        except Exception:
            detail = r.detail
        lines.append(
            json.dumps(
                {
                    "id": r.id,
                    "sequence": r.chain_sequence,
                    "previous_hash": r.previous_hash,
                    "entry_hash": r.entry_hash,
                    "actor": r.actor,
                    "action": r.action,
                    "target_type": r.target_type,
                    "target_id": r.target_id,
                    "detail": detail,
                    "ip_address": r.ip_address,
                    "outcome": r.outcome,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                },
                default=str,
                sort_keys=True,
            )
        )
    body = "\n".join(lines) + ("\n" if lines else "")
    digest = _hashlib.sha256(body.encode("utf-8")).hexdigest()
    chain = verify_audit_chain(db)
    manifest = json.dumps(
        {
            "format": "cryptoscan-audit-export/1",
            "entry_count": len(rows),
            "sha256": digest,
            "chain_status": chain["status"],
            "chain_checked": chain.get("checked"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "note": "store under WORM/object-lock retention; verify with sha256 of the body",
        },
        sort_keys=True,
    )
    return PlainTextResponse(
        content=manifest + "\n" + body,
        media_type="application/jsonl",
        headers={"X-Audit-Export-Sha256": digest, "X-Audit-Chain-Status": chain["status"]},
    )
