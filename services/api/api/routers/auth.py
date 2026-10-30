"""Authentication routes: login/logout, user management (admin), audit trail."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.config.settings import get_settings
from api.dependencies import (
    get_current_user,
    get_db_session,
    require_admin,
    require_roles,
)
from api.events.auth import publish_auth
from db.models.custom_role import CustomRole
from api.security import totp
from api.security.audit_diff import audit_detail_with_changes, field_diff
from api.security.auth import AuthenticationError, AuthService
from api.security.passwords import (
    PasswordPolicyError,
    hash_password,
    validate_password_policy,
    verify_password,
)
from api.security.session_manager import SessionManager
from api.security.client_ip import client_ip

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
    password: str = Field(..., min_length=12, max_length=200)
    roles: list[str] = Field(default_factory=lambda: ["viewer"])
    display_name: str | None = None
    email: str | None = None


class UserUpdateRequest(BaseModel):
    roles: list[str] | None = None
    is_active: bool | None = None
    password: str | None = Field(None, min_length=12, max_length=200)


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
    client = client_ip(request) or ""
    roles = ["admin"]
    try:
        user = AuthService(session=db).authenticate(body.username, body.password, client_key=client)
        roles = user.roles
    except AuthenticationError as exc:
        publish_auth("login_failed", {"user": body.username, "reason": "invalid_credentials", "ip": client})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=exc.message) from exc
    except Exception as exc:
        fallback = _auth_db_error(exc)
        if fallback is not None:
            raise fallback from exc
        try:
            db.rollback()
        except Exception as rollback_exc:
            logger.exception("auth_login_rollback_failed", extra={"error_type": type(rollback_exc).__name__})
        try:
            user = AuthService(session=None).authenticate(body.username, body.password, client_key=client)
            roles = user.roles
        except AuthenticationError as exc2:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=exc2.message) from exc2

    # Canonicalize legacy role names (admin → superadmin, viewer → readonly)
    # so callers see the 8-role catalog consistently.
    from api.security.rbac import normalize_roles
    roles = normalize_roles(roles)

    # Second factor gate: password alone must never mint a session for
    # an MFA-enabled account. The challenge token is purpose-scoped and
    # expires in 5 minutes.
    if getattr(user, "mfa_enabled", False):
        manager = SessionManager()
        mfa_token = manager.create_mfa_challenge(user.username)
        try:
            _user_repo(db).audit(user.username, "auth.mfa_challenge_issued", ip=client)
            db.commit()
        except Exception as exc:
            try:
                db.rollback()
            except Exception:
                logger.exception("auth_mfa_challenge_rollback_failed", extra={"user": user.username})
            fallback = _auth_db_error(exc)
            if fallback is not None:
                raise fallback from exc
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
        except Exception as rollback_exc:
            logger.exception("auth_session_rollback_failed", extra={"error_type": type(rollback_exc).__name__})

    response.set_cookie(
        key="cryptoscan_session",
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=max_age,
        path="/",
    )
    publish_auth("login", {"user": user.username, "roles": roles, "mfa": False, "ip": client})
    return LoginResponse(
        message="Login successful",
        username=user.username,
        roles=roles,
        token=token,
        session_expires_at=expires,
    )


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=12, max_length=200)
    role: str = "readonly"
    display_name: str | None = None
    email: str | None = None


class RegisterResponse(BaseModel):
    message: str
    username: str
    roles: list[str]


#: Public registration creates only least-privilege identities. The existing
#: administrator user-management API grants elevated roles after review.
SELF_SERVICE_ALLOWED_ROLES = frozenset({"readonly"})


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db_session)) -> RegisterResponse:
    """Create a read-only account; public callers cannot assign privileges."""
    from db.models.user import VALID_ROLES

    from api.security.rbac import ROLE_ALIASES

    role = ROLE_ALIASES.get(body.role.strip().lower(), body.role.strip().lower())
    if role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown role: {body.role}. Valid: {', '.join(VALID_ROLES)}",
        )
    if role not in SELF_SERVICE_ALLOWED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public registration grants read-only access only; ask an administrator to assign elevated roles",
        )
    try:
        validate_password_policy(body.password)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=f"Weak password: {exc}")
    repo = _user_repo(db)
    if repo.get_by_username(body.username) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    email = (body.email or "").strip().lower() or None
    if email is not None and ("@" not in email or len(email) > 320):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid email address")
    user = repo.create_user(
        body.username,
        hash_password(body.password),
        roles=[role],
        display_name=(body.display_name or "").strip() or None,
        email=email,
    )
    repo.audit(
        body.username,
        "user.register",
        target_type="user",
        target_id=user.username,
        detail={"roles": [role]},
        ip=client_ip(request),
    )
    db.commit()
    publish_auth(
        "register",
        {"user": body.username, "role": role, "self_service": True,
         "ip": client_ip(request)},
    )
    return RegisterResponse(message="account created", username=user.username, roles=[role])


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
    client = client_ip(request) or ""
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

    return _oidc_identity_to_session(db, request, response, claims,
                                     settings=settings, client=client)


def _oidc_identity_to_session(db: Session, request: Request, response: Response,
                              claims: dict, *, settings, client: str,
                              audit_action: str = "auth.oidc_login") -> LoginResponse:
    """Map verified IdP claims to a local account and mint a normal session.

    Shared by POST /auth/oidc (token relay) and GET /auth/oidc/callback
    (authorization code). Roles stay local and admin-managed — no IdP role
    mapping is claimed; unknown subjects are auto-provisioned as viewers only
    when explicitly enabled. Works for both JSON and redirect responses (the
    session cookie is set on whichever response object is passed in).
    """
    email = str(claims.get("email") or "").strip().lower() or None
    username = str(claims.get("preferred_username") or claims.get("sub") or "").strip().lower()
    if not username and email:
        username = email.split("@")[0]
    if not username:
        raise HTTPException(status_code=401, detail="token carries no subject (preferred_username/sub/email)")

    repo = _user_repo(db)
    user = repo.get_by_username(username)
    if user is None and settings.OIDC_AUTO_PROVISION:
        user = repo.create_user(
            username,
            password_hash=secrets.token_urlsafe(48),  # unguessable: password login impossible
            roles=["viewer"],
            display_name=str(claims.get("name") or username),
            email=email,
        )
    if user is None:
        try:
            repo.audit(username, audit_action, outcome="FAILURE", ip=client, detail="no local user and auto-provision disabled")
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
        repo.audit(user.username, audit_action, ip=client, detail={"issuer": settings.OIDC_ISSUER})
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


@router.get("/oidc/authorize")
def oidc_authorize(request: Request) -> RedirectResponse:
    """Begin the OIDC authorization-code flow: 302 the browser to the IdP.

    The state parameter is HMAC-signed with the platform secret and carries
    the nonce, so the callback can validate it without server-side session
    state. The authorization endpoint comes from OIDC_AUTHORIZATION_URL or
    standard discovery — with the same SSRF discipline as JWKS discovery.
    """
    settings = get_settings()
    issuer = (settings.OIDC_ISSUER or "").strip()
    if not issuer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OIDC SSO not configured")
    client_id = (settings.OIDC_CLIENT_ID or "").strip()
    if not client_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OIDC_CLIENT_ID not configured")
    from api.security import oidc as oidc_mod
    from api.security.oidc import OidcError, _validate_jwks_uri, make_authorize_url, make_state

    endpoint = (settings.OIDC_AUTHORIZATION_URL or "").strip()
    if endpoint:
        _validate_jwks_uri(endpoint, issuer.rstrip("/"))
    else:
        try:
            endpoints = oidc_mod.discover_oidc_endpoints(issuer)
        except OidcError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
        endpoint = endpoints.get("authorization_endpoint", "")
        if not endpoint:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="IdP discovery document has no authorization_endpoint")
    nonce = secrets.token_urlsafe(16)
    state = make_state(settings.SECRET_KEY, nonce)
    redirect_uri = (settings.OIDC_REDIRECT_URI or "").strip() or \
        str(request.base_url).rstrip("/") + "/api/v1/auth/oidc/callback"
    # RFC 7636: with no client secret we are a PUBLIC client — PKCE S256 is
    # mandatory. The verifier rides a short-lived HttpOnly cookie scoped to
    # the callback path; it must never travel the front channel (the state
    # is visible to the IdP and the browser, so it can't carry it).
    pkce_verifier, code_challenge = ("", "")
    if not (settings.OIDC_CLIENT_SECRET or "").strip():
        pkce_verifier, code_challenge = oidc_mod.make_pkce()
    url = make_authorize_url(endpoint, client_id=client_id, redirect_uri=redirect_uri,
                             scope=(settings.OIDC_SCOPES or "openid").strip(),
                             state=state, nonce=nonce, code_challenge=code_challenge)
    response = RedirectResponse(url, status_code=302)
    if pkce_verifier:
        response.set_cookie(
            key="cryptoscan_pkce", value=pkce_verifier, httponly=True, samesite="lax",
            secure=settings.cookie_secure, max_age=600, path="/api/v1/auth/oidc/callback",
        )
    return response


@router.get("/oidc/callback")
def oidc_callback(request: Request, db: Session = Depends(get_db_session),
                  code: str = "", state: str = "", error: str = "") -> RedirectResponse:
    """Finish the authorization-code flow: verify the signed state, exchange
    the code confidentially, verify the id_token (same rules as the token
    relay, plus the nonce bound at authorization time), map to the local
    account, set the session cookie and redirect onward."""
    settings = get_settings()
    if not (settings.OIDC_ISSUER or "").strip():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OIDC SSO not configured")
    client = client_ip(request) or ""
    from api.security import oidc as oidc_mod
    from api.security.oidc import OidcError, verify_id_token

    def _audit_failure(detail: str) -> None:
        try:
            _user_repo(db).audit("unknown", "auth.oidc_callback", outcome="FAILURE",
                                 ip=client, detail=detail[:200])
            db.commit()
        except Exception:
            db.rollback()

    if error:
        detail = f"IdP returned authorization error: {error}"
        _audit_failure(detail)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

    nonce = oidc_mod.read_state(settings.SECRET_KEY, state or "")
    if not nonce:
        detail = "login state invalid or expired — restart the SSO login"
        _audit_failure(detail)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)
    if not code:
        _audit_failure("authorization code missing")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="authorization code missing")

    # PKCE (public clients): the verifier comes from the HttpOnly cookie set
    # at authorize time. Fail closed — no cookie means the flow was started
    # elsewhere or the cookie expired; either way we do not exchange blind.
    code_verifier = ""
    if (settings.OIDC_CLIENT_SECRET or "").strip():
        code_verifier = ""  # confidential client — secret auth, no PKCE
    else:
        code_verifier = request.cookies.get("cryptoscan_pkce") or ""
        if not code_verifier:
            detail = "PKCE verifier missing — restart the SSO login"
            _audit_failure(detail)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

    issuer = settings.OIDC_ISSUER.strip()
    token_endpoint = (settings.OIDC_TOKEN_URL or "").strip()
    if not token_endpoint:
        try:
            token_endpoint = oidc_mod.discover_oidc_endpoints(issuer)["token_endpoint"]
        except OidcError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    redirect_uri = (settings.OIDC_REDIRECT_URI or "").strip() or \
        str(request.base_url).rstrip("/") + "/api/v1/auth/oidc/callback"
    try:
        tokens = oidc_mod.exchange_code(
            token_endpoint, code=code, client_id=(settings.OIDC_CLIENT_ID or "").strip(),
            redirect_uri=redirect_uri, client_secret=(settings.OIDC_CLIENT_SECRET or "").strip(),
            code_verifier=code_verifier)
        id_token = str(tokens.get("id_token") or "")
        if not id_token:
            raise OidcError("token endpoint returned no id_token")
        claims = verify_id_token(
            id_token,
            issuer=issuer,
            audience=(settings.OIDC_CLIENT_ID or "").strip() or None,
            jwks_url=(settings.OIDC_JWKS_URL or "").strip() or None,
            jwks_file=(settings.OIDC_JWKS_FILE or "").strip() or None,
            clock_leeway=settings.OIDC_CLOCK_LEEWAY,
        )
    except OidcError as exc:
        _audit_failure(str(exc))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    if str(claims.get("nonce") or "") != nonce:
        detail = "nonce mismatch — response does not correspond to this login"
        _audit_failure(detail)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

    redirect = RedirectResponse((settings.OIDC_POST_LOGIN_REDIRECT or "/"), status_code=303)
    redirect.delete_cookie(key="cryptoscan_pkce", path="/api/v1/auth/oidc/callback")
    _oidc_identity_to_session(db, request, redirect, claims, settings=settings,
                              client=client, audit_action="auth.oidc_callback")
    return redirect


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
                _user_repo(db).audit(actor, "auth.logout", ip=client_ip(request))
                db.commit()
        except Exception as exc:
            try:
                db.rollback()
            except Exception:
                logger.exception("auth_logout_rollback_failed", extra={"actor": actor})
            if settings.is_production:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Authentication store unavailable; logout was not confirmed",
                ) from exc
            logger.warning("auth_logout_revocation_failed", extra={"actor": actor}, exc_info=True)
        if actor != "unknown":
            publish_auth("logout", {"user": actor, "ip": client_ip(request)})
    response.delete_cookie("cryptoscan_session", path="/", secure=settings.cookie_secure, httponly=True, samesite="lax")
    return {"message": "Logged out successfully"}


@router.get("/me")
def me(request: Request, db: Session = Depends(get_db_session)) -> dict:
    from api.security.rbac import normalize_roles, permissions_for_roles

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
    except Exception as exc:  # pragma: no cover - store unavailable
        if get_settings().is_production:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication store unavailable",
            ) from exc
        logger.warning("auth_session_store_check_failed", exc_info=True)
    roles = session.roles
    user = None
    active_sessions = None
    try:
        repo = _user_repo(db)
        user = repo.get_by_username(session.username)
        if user is not None:
            roles = user.role_list
            try:
                active_sessions = repo.count_active_sessions(user.username)
            except Exception:  # pragma: no cover - older stores lack the helper/table
                logger.warning("auth_active_session_count_failed", exc_info=True)
                active_sessions = None
    except Exception as exc:  # pragma: no cover
        if get_settings().is_production:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication store unavailable",
            ) from exc
        logger.warning("auth_user_lookup_failed", exc_info=True)
    raw_roles = list(roles)
    roles = normalize_roles(roles)
    my_permissions = permissions_for_roles(roles)
    try:
        from api.security.rbac import (custom_role_names,
                                       load_custom_roles_index,
                                       permissions_with_custom)

        custom_index = load_custom_roles_index(db)
        roles = roles + custom_role_names(raw_roles, custom_index)
        my_permissions = permissions_with_custom(roles, custom_index)
    except Exception:  # pragma: no cover - custom roles table unavailable
        logger.warning("auth_me_custom_roles_unavailable", exc_info=True)
    return {
        "username": session.username,
        "roles": roles,
        "permissions": my_permissions,
        "mfa_enabled": bool(user.mfa_enabled) if user is not None else False,
        "display_name": user.display_name if user is not None else None,
        "email": user.email if user is not None else None,
        "is_active": bool(user.is_active) if user is not None else True,
        "active_sessions": active_sessions,
    }


class MeUpdateRequest(BaseModel):
    """Self-service profile update — a user may change only their own
    display name and contact email. Roles, status and password are out of
    scope here (roles/status are admin-only; password goes through
    /auth/me/password with the old password as proof)."""

    display_name: str | None = Field(None, max_length=200)
    email: str | None = Field(None, max_length=320)


@router.patch("/me")
def update_me(
    body: MeUpdateRequest,
    request: Request,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict:
    """Update the caller's own profile (display name / email)."""
    repo = _user_repo(db)
    user = repo.get_by_username(username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    # field-level audit diff (audit 78): capture the before snapshot up front
    before = {"display_name": user.display_name, "email": user.email}
    changes: dict = {}
    if body.display_name is not None:
        user.display_name = body.display_name.strip() or None
        changes["display_name"] = user.display_name
    if body.email is not None:
        email = body.email.strip().lower() or None
        if email is not None and ("@" not in email or len(email) > 320):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid email address")
        user.email = email
        changes["email"] = user.email
    db.flush()
    repo.audit(
        username,
        "user.profile_update",
        target_type="user",
        target_id=username,
        detail=audit_detail_with_changes(field_diff(before, {
            "display_name": user.display_name, "email": user.email})),
        ip=client_ip(request),
    )
    db.commit()
    publish_auth("profile_update", {"user": username, "fields": sorted(changes)})
    return {
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
        "roles": user.role_list,
        "mfa_enabled": bool(user.mfa_enabled),
    }


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=12, max_length=200)


@router.post("/me/password")
def change_my_password(
    body: ChangePasswordRequest,
    request: Request,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict:
    """Self-service password change.

    Requires the current password as proof of possession. By default the
    caller's other sessions are revoked (the current token stays valid so
    they are not logged out mid-request); pass ``revoke_other_sessions=false``
    to keep every existing session alive. A ``user.password_change`` audit
    entry and an ``auth.password_change`` realtime event are emitted.
    """
    client = client_ip(request)
    repo = _user_repo(db)
    user = repo.get_by_username(username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    if not verify_password(body.current_password, user.password_hash):
        repo.audit(username, "user.password_change", outcome="FAILURE", ip=client, detail="bad current password")
        db.commit()
        publish_auth("password_change_failed", {"user": username, "ip": client})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")
    if verify_password(body.new_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="New password must differ from the current password",
        )
    try:
        validate_password_policy(body.new_password)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=f"Weak password: {exc}")
    settings = get_settings()
    if settings.is_production and body.new_password.lower() in {"", "cryptoscan", "admin", "password", "changeme", "secret"}:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="New password is too weak")

    token = token_from_request(request)
    repo.set_password(username, hash_password(body.new_password))
    # Keep the caller's current session alive; revoke every other token so a
    # stolen/old session cannot outlive the credential rotation.
    revoked = repo.revoke_other_sessions(username, token or "") if token else repo.revoke_all_sessions(username)
    repo.audit(
        username,
        "user.password_change",
        target_type="user",
        target_id=username,
        detail={"revoked_other_sessions": revoked},
        ip=client,
    )
    db.commit()
    publish_auth("password_change", {"user": username, "revoked_other_sessions": revoked, "ip": client})
    return {"message": "Password changed", "revoked_other_sessions": revoked}


@router.get("/me/sessions")
def list_my_sessions(
    request: Request,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict:
    """The caller's own active sessions (for self-service device audit).

    Tokens are never returned — only timestamps, IP, expiry and whether the
    row is the session making this request.
    """
    from db.models.user import UserSession as _Session
    from db.repositories.user_repository import token_hash

    token = token_from_request(request)
    current_hash = token_hash(token) if token else None
    rows = list(
        db.query(_Session)
        .filter(_Session.username == username, _Session.revoked_at.is_(None))
        .order_by(_Session.created_at_ts.desc())
        .all()
    )
    from shared_models.chrono import aware

    now = datetime.now(timezone.utc)
    sessions = []
    for r in rows:
        expires = aware(r.expires_at)
        sessions.append(
            {
                "id": r.id,
                "current": bool(current_hash and r.token_hash == current_hash),
                "created_at": r.created_at_ts.isoformat() if r.created_at_ts else None,
                "expires_at": expires.isoformat() if expires else None,
                "ip_address": r.ip_address,
                "expired": bool(expires and expires < now),
            }
        )
    return {"sessions": sessions, "active_count": len(sessions)}


class RevokeSessionsRequest(BaseModel):
    """Log out every session except the current one (self-service)."""

    include_current: bool = False


@router.post("/me/sessions/revoke")
def revoke_my_sessions(
    body: RevokeSessionsRequest,
    request: Request,
    response: Response,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict:
    """Self-service "log out everywhere else". By default the current session
    is kept (``include_current=false``); pass ``include_current=true`` to also
    revoke the calling token (full sign-out on all devices)."""
    client = client_ip(request)
    token = token_from_request(request)
    repo = _user_repo(db)
    if body.include_current:
        revoked = repo.revoke_all_sessions(username)
        response.delete_cookie("cryptoscan_session", path="/",
                               secure=get_settings().cookie_secure, httponly=True, samesite="lax")
    else:
        revoked = repo.revoke_other_sessions(username, token or "")
    repo.audit(
        username,
        "auth.sessions_revoke",
        target_type="user",
        target_id=username,
        detail={"revoked": revoked, "include_current": body.include_current},
        ip=client,
    )
    db.commit()
    publish_auth("sessions_revoke", {"user": username, "revoked": revoked,
                                     "include_current": body.include_current, "ip": client})
    return {"revoked": revoked, "include_current": body.include_current}

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
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            logger.exception("auth_session_rollback_failed", extra={"user": username})
        fallback = _auth_db_error(exc)
        if fallback is not None:
            # Never mint a production session that the revocation store did
            # not record. In development _auth_db_error logs the degraded
            # mode explicitly for the local in-memory fallback.
            raise fallback from exc
    response.set_cookie(
        key="cryptoscan_session",
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=max_age,
        path="/",
    )
    # real-time stream: sessions issued (no token material, ever)
    publish_auth("login", {"user": username, "roles": roles, "mfa": True, "ip": client})
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
    client = client_ip(request) or ""
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
    client = client_ip(request) or ""
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
    client = client_ip(request) or ""
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
    client = client_ip(request) or ""
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



def _valid_role_names(db) -> set[str]:
    """Built-in role names plus this deployment's custom role names."""
    from db.models.user import VALID_ROLES

    names = set(VALID_ROLES)
    try:
        from api.security.rbac import load_custom_roles_index

        names.update(load_custom_roles_index(db).keys())
    except Exception:  # noqa: BLE001 — no table yet: built-ins only, and it says so
        logger.debug("custom_roles_index_unavailable", exc_info=True)
    return names


@router.get("/roles")
def list_roles(
    request: Request,
    user: str = Depends(require_roles(
        "admin", "auditor", "viewer", "readonly", "superadmin", "ciso",
        "security_analyst", "developer", "business_owner", "scanner",
    )),
    db: Session = Depends(get_db_session),
):
    """The 8-role catalog (logic-5 W57–58) plus the permission matrix.

    Any authenticated caller may read it — knowing the matrix is not a
    privilege. Enforcement happens per endpoint via require_permission.
    """
    from api.dependencies import _token_from_request
    from api.security.rbac import (
        PERMISSION_MATRIX,
        ROLE_CATALOG,
        normalize_roles,
    )
    from api.security.session_manager import SessionManager

    roles: list[str] = []
    try:
        from db.connection.session import SessionLocal
        from db.repositories.user_repository import UserRepository

        session = SessionLocal()
        try:
            row = UserRepository(session).get_by_username(user)
            roles = normalize_roles(row.role_list if row is not None else [])
        finally:
            session.close()
    except Exception:  # pragma: no cover - DB unavailable
        token = _token_from_request(request)
        stored = SessionManager().get_session(token) if token else None
        roles = normalize_roles(list(getattr(stored, "roles", []) or []) if stored else [])

    from api.security.rbac import (ALL_PERMISSIONS, load_custom_roles_index,
                                    permissions_with_custom)

    custom_index = load_custom_roles_index(db)
    return {
        "roles": ROLE_CATALOG,
        "permission_matrix": {
            action: sorted(allowed) for action, allowed in PERMISSION_MATRIX.items()
        },
        "custom_roles": {
            name: sorted(perms) for name, perms in sorted(custom_index.items())
        },
        "my_permissions": permissions_with_custom(roles, custom_index),
        "all_permissions": sorted(ALL_PERMISSIONS),
    }


@router.get("/users", response_model=list[UserResponse])
def list_users(
    include_deleted: bool = Query(False, description="Include soft-deleted accounts"),
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    repo = _user_repo(db)
    users = repo.list_users()
    if not include_deleted:
        users = [u for u in users if getattr(u, "deleted_at", None) is None]
    return [
        UserResponse(
            username=u.username,
            display_name=u.display_name,
            email=u.email,
            roles=u.role_list,
            is_active=u.is_active,
            last_login_at=u.last_login_at,
        )
        for u in users
    ]


@router.delete("/users/{username}")
def delete_user(
    username: str,
    request: Request,
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
) -> dict:
    """Soft-delete a user (compliance-safe).

    The row is retained (deleted_at stamped, account disabled, all sessions
    revoked) so the audit hash chain and historical actor references stay
    intact and verifiable. The bootstrap superadmin account cannot be
    removed — a platform must always retain at least one owner.
    """
    repo = _user_repo(db)
    target = repo.get_by_username(username)
    if target is None or getattr(target, "deleted_at", None) is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    from api.security.rbac import normalize_roles

    if "superadmin" in normalize_roles(target.role_list):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The superadmin account cannot be deleted — revoke its other roles or disable it instead",
        )
    revoked = repo.revoke_all_sessions(username)
    repo.soft_delete_user(username)
    repo.audit(
        admin,
        "user.delete",
        target_type="user",
        target_id=username,
        detail={"soft_delete": True, "sessions_revoked": revoked},
        ip=client_ip(request),
    )
    db.commit()
    publish_auth("user_deleted", {"user": username, "by": admin, "sessions_revoked": revoked})
    return {"deleted": True, "username": username, "sessions_revoked": revoked}


@router.post("/users/{username}/restore", response_model=UserResponse)
def restore_user(
    username: str,
    request: Request,
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Restore a soft-deleted account (clears deleted_at, re-enables)."""
    repo = _user_repo(db)
    user = repo.restore_user(username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deleted user not found")
    repo.audit(
        admin,
        "user.restore",
        target_type="user",
        target_id=username,
        ip=client_ip(request),
    )
    db.commit()
    publish_auth("user_restored", {"user": username, "by": admin})
    return UserResponse(
        username=user.username,
        display_name=user.display_name,
        email=user.email,
        roles=user.role_list,
        is_active=user.is_active,
        last_login_at=user.last_login_at,
    )


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreateRequest,
    request: Request,
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):

    try:
        validate_password_policy(body.password)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=f"Weak password: {exc}")
    repo = _user_repo(db)
    if repo.get_by_username(body.username) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    valid_names = _valid_role_names(db)
    bad_roles = [r for r in body.roles if r not in valid_names]
    if bad_roles:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown roles: {bad_roles}. Valid: {sorted(valid_names)}",
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
        ip=client_ip(request),
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
    # field-level audit diff (audit 78): before/after per changed field
    before = {
        "roles": list(user.role_list or []),
        "is_active": bool(user.is_active),
    }
    changes: dict = {}
    if body.roles is not None:

        bad = [r for r in body.roles if r not in _valid_role_names(db)]
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
        try:
            validate_password_policy(body.password)
        except PasswordPolicyError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail=f"Weak password: {exc}")
        repo.set_password(username, hash_password(body.password))
        changes["password_rotated"] = True
        changes["revoked_sessions"] = repo.revoke_all_sessions(username)
    diff = field_diff(before, {
        "roles": list(user.role_list or []),
        "is_active": bool(user.is_active),
    })
    if body.password is not None:
        # rotation is auditable; the value never is — sentinels mask to ***
        diff.extend(field_diff({"password": "<previous>"}, {"password": "<rotated>"}))
    repo.audit(
        admin,
        "user.update",
        target_type="user",
        target_id=username,
        detail=audit_detail_with_changes(
            diff,
            **{k: v for k, v in changes.items() if k != "revoked_sessions"},
            **({"revoked_sessions": changes["revoked_sessions"]}
               if "revoked_sessions" in changes else {}),
        ),
        ip=client_ip(request),
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
        except (TypeError, ValueError, json.JSONDecodeError) as parse_exc:
            logger.warning(
                "auth_audit_detail_parse_failed",
                extra={"error_type": type(parse_exc).__name__},
            )
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


@router.get("/audit/timeline")
def unified_timeline(
    source: str = Query("all", pattern="^(all|audit|platform)$"),
    actor: str | None = None,
    action: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Unified cross-system timeline (audit 78 P0#4).

    One chronology across the two event histories the platform keeps: the
    hash-chained audit log (mutations) and the platform event stream
    (lifecycle transitions, automation, alerts). Pure merge —
    deterministic, no clock reads; identical timestamps keep their
    per-source order rather than an invented interleaving.

    Each source is read newest-first and capped (newest 3x limit per
    source), so this is a recent-window view, not an unbounded scan of
    history.
    """
    from api.security.timeline import merge_timeline
    from db.models.monitor import MonitorEvent
    from db.models.user import AuditLog

    fetch = max(limit * 3, 300)
    audit_rows: list = []
    platform_rows: list = []
    if source in ("all", "audit"):
        stmt = db.query(AuditLog).order_by(AuditLog.created_at.desc())
        if actor:
            stmt = stmt.filter(AuditLog.actor == actor)
        if action:
            stmt = stmt.filter(AuditLog.action == action)
        audit_rows = stmt.limit(fetch).all()
    if source in ("all", "platform"):
        stmt = db.query(MonitorEvent).order_by(MonitorEvent.created_at.desc())
        if action:
            stmt = stmt.filter(MonitorEvent.event_type == action)
        platform_rows = stmt.limit(fetch).all()
    merged = merge_timeline(audit_rows, platform_rows, limit=fetch)
    if source == "platform" and actor:
        # platform rows only carry actor inside the payload
        merged = [e for e in merged if e.get("actor") == actor]
    return {
        "model": "unified-timeline/v1",
        "sources": {"audit": len(audit_rows), "platform": len(platform_rows)},
        "entries": merged[offset:offset + limit],
        "total_in_window": len(merged),
        "limit": limit,
        "offset": offset,
    }


@router.get("/audit/verify")
def verify_audit(
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
    full: bool = Query(False, description="Force a full-chain re-verification"),
):
    """Verify the audit hash chain and report the first break (W57-58).

    Incremental by default (re-anchors at the last verified chain head; see
    verify_audit_chain_incremental) — pass ?full=true for a complete walk."""
    from db.repositories.user_repository import verify_audit_chain_incremental

    return verify_audit_chain_incremental(db, force_full=full)


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

    from db.models.user import AuditLog as _AuditLog
    from db.repositories.user_repository import verify_audit_chain
    from fastapi.responses import PlainTextResponse

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


# ---------------------------------------------------------- custom roles
# Report 13 §2.2 open item (round 30): tenant-defined named permission
# subsets of the existing matrix. A custom role is a narrower key, never
# a bypass — it cannot grant an action the matrix does not know and
# cannot collide with a built-in role name.


class CustomRoleCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, pattern=r"^[a-z][a-z0-9_-]*$")
    description: str | None = Field(None, max_length=2000)
    permissions: list[str] = Field(..., min_length=1)


class CustomRoleUpdateRequest(BaseModel):
    description: str | None = Field(None, max_length=2000)
    permissions: list[str] | None = Field(None, min_length=1)


def _validate_custom_role(db, name: str, permissions: list[str]) -> None:
    from api.security.rbac import ALL_PERMISSIONS, ROLE_ALIASES, ROLE_CATALOG

    lower = name.strip().lower()
    if lower in ROLE_CATALOG or lower in ROLE_ALIASES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{lower!r} is a built-in role name; custom roles cannot shadow it",
        )
    unknown = sorted(set(permissions) - set(ALL_PERMISSIONS))
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown permissions: {unknown}. "
                   f"Valid: {sorted(ALL_PERMISSIONS)}",
        )
    existing = db.query(CustomRole).filter(CustomRole.name == lower).first()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Custom role {lower!r} already exists",
        )


@router.get("/custom-roles")
def list_custom_roles(
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Every defined custom role with its declared permission subset."""
    rows = db.query(CustomRole).order_by(CustomRole.name).all()
    return {
        "custom_roles": [
            {"name": row.name, "description": row.description,
             "permissions": sorted(row.permissions or []),
             "created_by": row.created_by}
            for row in rows
        ],
        "count": len(rows),
    }


@router.post("/custom-roles")
def create_custom_role(
    body: CustomRoleCreateRequest,
    request: Request,
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    name = body.name.strip().lower()
    _validate_custom_role(db, name, body.permissions)
    row = CustomRole(name=name, description=body.description,
                     permissions=sorted(set(body.permissions)), created_by=admin)
    db.add(row)
    db.flush()
    _user_repo(db).audit(
        admin, "custom_role.create", target_type="custom_role", target_id=name,
        detail={"permissions": row.permissions, "description": row.description},
        ip=client_ip(request),
    )
    db.commit()
    return {"name": row.name, "description": row.description,
            "permissions": sorted(row.permissions or []), "created_by": row.created_by}


@router.put("/custom-roles/{name}")
def update_custom_role(
    name: str,
    body: CustomRoleUpdateRequest,
    request: Request,
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    from api.security.rbac import ALL_PERMISSIONS

    row = db.query(CustomRole).filter(CustomRole.name == name.strip().lower()).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Custom role not found")
    before = {"permissions": sorted(row.permissions or []),
              "description": row.description}
    if body.permissions is not None:
        unknown = sorted(set(body.permissions) - set(ALL_PERMISSIONS))
        if unknown:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unknown permissions: {unknown}")
        row.permissions = sorted(set(body.permissions))
    if body.description is not None:
        row.description = body.description
    db.flush()
    _user_repo(db).audit(
        admin, "custom_role.update", target_type="custom_role", target_id=row.name,
        detail=audit_detail_with_changes(field_diff(before, {
            "permissions": sorted(row.permissions or []),
            "description": row.description,
        })),
        ip=client_ip(request),
    )
    db.commit()
    return {"name": row.name, "description": row.description,
            "permissions": sorted(row.permissions or [])}


@router.delete("/custom-roles/{name}")
def delete_custom_role(
    name: str,
    request: Request,
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    row = db.query(CustomRole).filter(CustomRole.name == name.strip().lower()).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Custom role not found")
    db.delete(row)
    _user_repo(db).audit(
        admin, "custom_role.delete", target_type="custom_role", target_id=row.name,
        detail={"permissions": sorted(row.permissions or [])},
        ip=client_ip(request),
    )
    db.commit()
    return {"deleted": row.name,
            "note": "users holding only this role lose its grants immediately"}
