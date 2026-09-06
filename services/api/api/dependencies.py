"""FastAPI dependencies."""

from __future__ import annotations

from db.connection.session import get_session
from db.repositories.baseline_repository import BaselineRepository
from db.repositories.drift_repository import DriftRepository
from db.repositories.evidence_repository import EvidenceRepository
from db.repositories.job_repository import JobRepository
from db.repositories.repo_config_repository import RepoConfigRepository
from db.repositories.scan_repository import ScanRepository
from db.repositories.verification_repository import VerificationRepository
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from api.security.session_manager import SessionManager


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


# ---------------------------------------------------------------------------
# Machine API keys (X-API-Key) — CI pipelines, SIEM pulls, scripts.
# Raw keys are looked up by SHA-256 hash; roles come from the key row itself,
# never from the users table. last_used_at is stamped at most once a minute.
# ---------------------------------------------------------------------------

import time  # noqa: E402

_API_KEY_INVALID = object()  # sentinel: header present but lookup failed

_last_use_writes: dict[str, float] = {}
_LAST_USE_MIN_INTERVAL = 60.0


def should_stamp_last_use(key_id: str, *, now: float | None = None) -> bool:
    moment = now if now is not None else time.monotonic()
    last = _last_use_writes.get(key_id)
    if last is not None and moment - last < _LAST_USE_MIN_INTERVAL:
        return False
    _last_use_writes[key_id] = moment
    if len(_last_use_writes) > 10_000:  # bound the cache
        _last_use_writes.clear()
    return True


def _resolve_api_key(request: Request) -> tuple[str, list[str], str] | None | object:
    """Returns (principal, roles, key_id), None (no header), or _API_KEY_INVALID."""
    raw = request.headers.get("x-api-key")
    if not raw:
        return None
    try:
        from db.connection.session import SessionLocal
        from db.repositories.api_key_repository import ApiKeyRepository

        session = SessionLocal()
        try:
            row = ApiKeyRepository(session).get_by_raw(raw.strip())
            if row is None:
                return _API_KEY_INVALID
            key_id = row.id
            # Enforce P2 API-key platform policy: endpoint scopes, HTTP method
            # allowlist, and per-key rate quota. Raises 403/429 on violation.
            _authorize_key_policy(request, row, session)
            principal = f"apikey:{row.name}"
            roles = row.role_list
            if should_stamp_last_use(key_id):
                from db.repositories.api_key_repository import ApiKeyRepository as _Repo

                _Repo(session).mark_used(key_id)
                session.commit()
            return principal, roles, key_id
        finally:
            session.close()
    except HTTPException:
        raise
    except Exception:  # DB unavailable — fail like the session store does
        settings = _get_settings()
        return _API_KEY_INVALID if settings.is_production else None


def _authorize_key_policy(request, row, session) -> None:
    """Scope / method / quota / network enforcement for a machine API key."""
    # Per-key IP allowlist (fail-closed). Client IP honours X-Forwarded-For
    # only as the last hop (the edge nginx sets it); fall back to the socket.
    try:
        from identity.api_key_guard import ip_allowed

        client_ip = request.client.host if request.client else None
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            client_ip = fwd.split(",")[0].strip() or client_ip
        if not ip_allowed(client_ip, getattr(row, "allowed_ips", None)):
            try:
                from db.repositories.api_key_repository import ApiKeyRepository as _Repo

                _Repo(session).record_request(row.id, denied=True)
                session.commit()
            except Exception:  # pragma: no cover
                session.rollback()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key not permitted from client address {client_ip}",
                headers={"WWW-Authenticate": "ApiKey"},
            )
    except HTTPException:
        raise
    except Exception:  # pragma: no cover - guard must not crash the request
        pass

    try:
        from apikeys.policy import DenyReason, KeyPolicy, authorize
    except Exception:  # pragma: no cover - policy package always present
        return
    policy = KeyPolicy.from_row(row)
    result = authorize(
        key_id=row.id,
        method=request.method,
        path=request.url.path,
        policy=policy,
    )
    if result.allowed:
        # best-effort usage accounting (no extra DB write on the hot path beyond
        # the throttled last-use stamp; counters increment on that cadence)
        return
    # record the denial (best effort), then fail closed
    try:
        from db.repositories.api_key_repository import ApiKeyRepository as _Repo

        _Repo(session).record_request(row.id, denied=True)
        session.commit()
    except Exception:  # pragma: no cover
        session.rollback()
    if result.reason is DenyReason.QUOTA:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=result.detail or "API key rate quota exceeded",
            headers={"Retry-After": "60", "WWW-Authenticate": "ApiKey"},
        )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=result.detail or "API key not permitted for this resource",
        headers={"WWW-Authenticate": "ApiKey"},
    )


def get_current_user(request: Request) -> str:
    api_key = _resolve_api_key(request)
    if api_key is _API_KEY_INVALID:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if isinstance(api_key, tuple):
        return api_key[0]
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

    Roles are normalized through the 8-role catalog (api.security.rbac), so
    legacy ``admin``/``viewer`` values are equivalent to ``superadmin``/
    ``readonly`` everywhere. Tokens without any known role (e.g. legacy
    env-admin sessions) are treated as admins to stay backward compatible
    with single-admin deployments.
    """
    from api.security.rbac import normalize_roles

    allowed_norm = set(normalize_roles(list(allowed)))

    def dependency(request: Request) -> str:
        api_key = _resolve_api_key(request)
        if api_key is _API_KEY_INVALID:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        if isinstance(api_key, tuple):
            principal, key_roles, _key_id = api_key
            # Key roles are explicit: no legacy "no roles => admin" fallback.
            if set(normalize_roles(list(key_roles))) & allowed_norm:
                return principal
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key requires one of roles: {', '.join(allowed)} (has: {', '.join(key_roles) or 'none'})",
            )
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
        roles = normalize_roles(_user_roles(username, token))
        if not roles or set(roles) & allowed_norm:
            return username
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires one of roles: {', '.join(allowed)}",
        )

    return dependency


require_admin = require_roles("admin")
require_auditor = require_roles("admin", "auditor")
