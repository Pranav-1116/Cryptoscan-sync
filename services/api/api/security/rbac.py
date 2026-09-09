"""Role-Based Access Control — the spec's 8-role catalog (logic-5 W57–58).

The original implementation shipped 3 roles (admin / auditor / viewer).
This module completes the catalog defined in the spec:

    SuperAdmin       full access (platform configuration)
    CISO             all compliance, policy, exceptions
    SecurityAnalyst  view findings, create exceptions
    Developer        view findings for own systems
    Auditor          read-only access to all reports
    BusinessOwner    view findings for owned systems
    Scanner          API-only (scan job submission)
    ReadOnly         dashboard view only

Legacy aliases are resolved so existing deployments keep working:
``admin`` -> ``superadmin``, ``viewer`` -> ``readonly``. Anything that
previously accepted admin/auditor/viewer keeps accepting those values.

Enforcement model: permissions are *actions*, mapped to the set of roles
allowed to perform them (``PERMISSION_MATRIX``). Endpoints declare
``Depends(require_permission("drift.acknowledge"))`` and the dependency
checks the caller's normalized role set. ``require_roles`` remains for
coarse-grained checks and normalizes aliases the same way, so both models
agree.
"""

from __future__ import annotations

from fastapi import HTTPException, Request, status

from api.dependencies import _resolve_api_key, _token_from_request  # noqa: F401  (re-exported for tests)
from api.security.session_manager import SessionManager

# ------------------------------------------------------------------ catalog

ROLE_CATALOG: dict[str, str] = {
    "superadmin": "Full access (platform configuration)",
    "ciso": "All compliance, policy and exceptions",
    "security_analyst": "View findings, create exceptions",
    "developer": "View findings for own systems",
    "auditor": "Read-only access to all reports",
    "business_owner": "View findings for owned systems",
    "scanner": "API-only (scan job submission)",
    "readonly": "Dashboard view only",
}

ROLE_ALIASES: dict[str, str] = {
    "admin": "superadmin",   # legacy
    "viewer": "readonly",    # legacy
}

ALL_ROLES = frozenset(ROLE_CATALOG)
ALL_ALIASES = frozenset(ROLE_ALIASES)


def normalize_roles(roles: list[str] | tuple[str, ...] | None) -> list[str]:
    """Resolve aliases, dedupe, drop unknown values.

    Unknown role names are dropped rather than rejected so a token minted
    before an upgrade cannot break a session; enforcement still only ever
    grants what the matrix allows.
    """
    out: list[str] = []
    seen: set[str] = set()
    for raw in roles or []:
        role = str(raw).strip().lower()
        if not role:
            continue
        canonical = ROLE_ALIASES.get(role, role)
        if canonical not in ALL_ROLES or canonical in seen:
            continue
        seen.add(canonical)
        out.append(canonical)
    return out


# ------------------------------------------------------------ permission map

# action -> roles allowed to perform it
PERMISSION_MATRIX: dict[str, frozenset[str]] = {
    # account & platform administration
    "users.manage": frozenset({"superadmin"}),
    "api_keys.manage": frozenset({"superadmin", "ciso"}),
    "audit.read": frozenset({"superadmin", "ciso", "auditor"}),
    "platform.configure": frozenset({"superadmin"}),
    "monitor.manage": frozenset({"superadmin", "ciso"}),
    # scanning
    "scan.trigger": frozenset({"superadmin", "ciso", "security_analyst", "developer", "scanner"}),
    "scan.manage": frozenset({"superadmin", "ciso", "security_analyst"}),
    # compliance & policy
    "baseline.approve": frozenset({"superadmin", "ciso", "auditor"}),
    "drift.acknowledge": frozenset({"superadmin", "ciso", "security_analyst"}),
    "exceptions.create": frozenset({"superadmin", "ciso", "security_analyst", "business_owner"}),
    "exceptions.approve": frozenset({"superadmin", "ciso"}),
    "policy.configure": frozenset({"superadmin", "ciso"}),
    "certificates.manage": frozenset({"superadmin", "ciso", "security_analyst"}),
    # intelligence & remediation
    "intelligence.use": frozenset({"superadmin", "ciso", "security_analyst", "auditor"}),
    "remediation.apply": frozenset({"superadmin", "ciso", "security_analyst"}),
    "migrations.manage": frozenset({"superadmin", "ciso", "security_analyst"}),
    # read surfaces
    "reports.read": frozenset({"superadmin", "ciso", "auditor", "security_analyst", "business_owner"}),
    "findings.read": ALL_ROLES,
    "systems.view": ALL_ROLES,
    "payment.view": frozenset({"superadmin", "ciso", "auditor"}),
    "vendor.view": frozenset({"superadmin", "ciso", "auditor", "security_analyst"}),
    "runtime.ingest": frozenset({"superadmin", "scanner"}),
    # 24/7 live hardware engine
    "hardware.read": ALL_ROLES,
    "hardware.manage": frozenset({"superadmin", "ciso", "security_analyst"}),
    "hardware.ingest": frozenset({"superadmin", "ciso", "scanner"}),
    # universal crypto scanner — live state/CBOM/timeline + accuracy
    "crypto.read": ALL_ROLES,
    "crypto.manage": frozenset({"superadmin", "ciso", "security_analyst"}),
    "crypto.ingest": frozenset({"superadmin", "ciso", "scanner"}),
}

ALL_PERMISSIONS = frozenset(PERMISSION_MATRIX)


def roles_for_action(action: str) -> frozenset[str]:
    return PERMISSION_MATRIX.get(action, frozenset())


def has_permission(roles: list[str] | None, action: str) -> bool:
    """True iff the normalized role set contains a role allowed for `action`."""
    allowed = roles_for_action(action)
    if not allowed:
        return False
    return bool(set(normalize_roles(roles)) & allowed)


def permissions_for_roles(roles: list[str] | None) -> list[str]:
    """Every action the normalized role set may perform (for the API)."""
    normalized = set(normalize_roles(roles))
    return sorted(action for action, allowed in PERMISSION_MATRIX.items() if normalized & allowed)


# ---------------------------------------------------------------- FastAPI dep


def _caller_roles(request: Request) -> tuple[str, list[str]]:
    """Resolve (principal, normalized roles) for the current request.

    Mirrors ``require_roles``: API keys carry explicit roles; sessions read
    fresh roles from the users table, falling back to token claims.
    """
    from api.dependencies import _API_KEY_INVALID

    api_key = _resolve_api_key(request)
    if api_key is _API_KEY_INVALID:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if isinstance(api_key, tuple):
        principal, key_roles, _key_id = api_key
        return principal, normalize_roles(list(key_roles))
    token = _token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    username = SessionManager().validate_session(token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        from db.connection.session import SessionLocal
        from db.repositories.user_repository import UserRepository

        session = SessionLocal()
        try:
            user = UserRepository(session).get_by_username(username)
            if user is not None:
                return username, normalize_roles(user.role_list)
        finally:
            session.close()
    except Exception:  # pragma: no cover - DB unavailable
        pass
    session = SessionManager().get_session(token)
    if session:
        return username, normalize_roles(list(session.roles))
    return username, []


def require_permission(*actions: str):
    """Dependency factory: allow only callers whose roles cover any action."""

    def dependency(request: Request) -> str:
        principal, roles = _caller_roles(request)
        for action in actions:
            if has_permission(roles, action):
                return principal
        detail = (
            f"Requires one of permissions: {', '.join(actions)} "
            f"(roles: {', '.join(roles) or 'none'})"
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

    return dependency


# ------------------------------------------------- coarse-grained role deps


def require_any_role(*allowed: str):
    """Like require_roles but with alias normalization (admin==superadmin)."""

    def dependency(request: Request) -> str:
        principal, roles = _caller_roles(request)
        allowed_norm = set(normalize_roles(list(allowed)))
        if roles and (set(roles) & allowed_norm):
            return principal
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires one of roles: {', '.join(allowed)} (roles: {', '.join(roles) or 'none'})",
        )

    return dependency
