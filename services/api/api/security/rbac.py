"""Role-Based Access Control — the spec's 8-role catalog (logic-5 W57–58),
extended with the read-only ``supervisor`` role for the regulatory portal.

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

import logging

logger = logging.getLogger(__name__)


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
    "supervisor": "Financial supervisor / regulator — read-only supervisory view "
                  "(group posture, DORA register, migration roadmap)",
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
    # Evidence assurance is metadata-only; trust changes and independent
    # review require human sessions in addition to these durable role checks.
    "assurance.manage": frozenset({"superadmin", "ciso", "security_analyst"}),
    "assurance.review": frozenset({"superadmin", "ciso", "auditor", "business_owner"}),
    "assurance.operate": frozenset({"superadmin", "ciso", "security_analyst", "developer", "auditor", "business_owner"}),
    "assurance.raw": frozenset({"superadmin", "ciso"}),
    "assurance.trust": frozenset({"superadmin", "ciso"}),
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
    "reports.read": frozenset({"superadmin", "ciso", "auditor", "security_analyst", "business_owner", "supervisor"}),
    # supervisory portal: read-only pack/roadmap/register surfaces for the
    # bank's supervisor(s) — never configuration, ingestion or management
    "supervision.read": frozenset({"superadmin", "ciso", "auditor", "supervisor"}),
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
    # storage optimization (spec 2.1/7): usage truth is an estate read;
    # sweeps/GC/restore tests are operations; policy overrides configure
    # retention — each tier gated like its nearest neighbour.
    "storage.read": ALL_ROLES,
    "storage.ingest": frozenset({"superadmin", "ciso", "security_analyst", "scanner"}),
    "storage.operate": frozenset({"superadmin", "ciso", "security_analyst"}),
    "storage.policy": frozenset({"superadmin", "ciso"}),
    # telecom realtime scanner — estate registry vs operator-side ingest
    "telecom.manage": frozenset({"superadmin", "ciso", "security_analyst"}),
    "telecom.ingest": frozenset({"superadmin", "ciso", "scanner"}),
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


def _request_custom_index(request: Request) -> dict[str, frozenset[str]]:
    """Per-request cache of the custom-role index (one DB read per request)."""
    cached = getattr(request.state, "custom_roles_index", None)
    if cached is not None:
        return cached
    index: dict[str, frozenset[str]] = {}
    try:
        from db.connection.session import SessionLocal

        session = SessionLocal()
        try:
            index = load_custom_roles_index(session)
        finally:
            session.close()
    except Exception:  # noqa: BLE001 — DB unavailable: built-ins only
        index = {}
    request.state.custom_roles_index = index
    return index


def _with_custom_roles(request: Request, raw_roles: list[str]) -> list[str]:
    """Normalized built-ins plus the defined custom role names (kept)."""
    roles = normalize_roles(list(raw_roles))
    roles.extend(custom_role_names(list(raw_roles), _request_custom_index(request)))
    return roles


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
        return principal, _with_custom_roles(request, list(key_roles))
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
                return username, _with_custom_roles(request, list(user.role_list))
        finally:
            session.close()
    except Exception as _handler_exc:  # pragma: no cover - DB unavailable
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
    session = SessionManager().get_session(token)
    if session:
        return username, _with_custom_roles(request, list(session.roles))
    return username, []


def require_principal(request: Request) -> dict:
    """Dependency: the authenticated principal and the durable roles it holds.

    ``require_permission`` answers "may this caller do this action?" and throws
    the identity away. A collector authority has to record *who* asked, so the
    identity has to be an object the handler can use rather than a string the
    guard consumed. 401 is raised here, exactly as the guards do, so a route that
    needs an identity cannot be reached without one.
    """
    principal, roles = _caller_roles(request)
    return {"principal": principal, "roles": roles}


def require_permission(*actions: str):
    """Dependency factory: allow only callers whose roles cover any action."""

    def dependency(request: Request) -> str:
        principal, roles = _caller_roles(request)
        custom_index = _request_custom_index(request)
        for action in actions:
            if has_permission_with_custom(roles, action, custom_index):
                return principal
        detail = (
            f"Requires one of permissions: {', '.join(actions)} "
            f"(roles: {', '.join(roles) or 'none'})"
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

    # Introspection, exactly as `require_roles` does it: the actions otherwise live
    # in a closure and cannot be read off the route table, so "which role may call
    # this?" is answerable only by reading the router source. The boundary drill
    # needs the declaration in order to compare it with what the server enforces.
    dependency.permissions = tuple(actions)
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


# ---------------------------------------------------------- custom roles
#
# Report 13 §2.2 open item (round 30): a custom role is a named permission
# SUBSET of the matrix — a narrower key, never a bypass. The pure core
# stays pure; the DB index is loaded by the dependency layer.


def has_permission_with_custom(
    roles: list[str] | None,
    action: str,
    custom_index: dict[str, frozenset[str]] | None = None,
) -> bool:
    """Permission check that also honors custom-role grants.

    ``custom_index`` maps a custom role name (lowercased) to its declared
    permission set. Built-in matrix first, then custom grants — a custom
    role grants an action iff the action is in its declared set, and the
    set is validated against ``ALL_PERMISSIONS`` at write time, so it can
    never grant an action the platform does not know.
    """
    if has_permission(roles, action):
        return True
    if not custom_index:
        return False
    for raw in roles or []:
        granted = custom_index.get(str(raw).strip().lower())
        if granted and action in granted:
            return True
    return False


def permissions_with_custom(
    roles: list[str] | None,
    custom_index: dict[str, frozenset[str]] | None = None,
) -> list[str]:
    """Every action the role set may perform, custom grants included."""
    out = set(permissions_for_roles(roles))
    for raw in roles or []:
        granted = (custom_index or {}).get(str(raw).strip().lower())
        if granted:
            out |= set(granted)
    return sorted(out)


def load_custom_roles_index(session) -> dict[str, frozenset[str]]:
    """DB index of custom roles: name (lower) -> declared permissions.

    Unknown permission values (e.g. left over from a matrix change) are
    dropped at read time — a stale row grants nothing it should not.
    """
    index: dict[str, frozenset[str]] = {}
    try:
        from db.models.custom_role import CustomRole

        rows = session.query(CustomRole).all()
        for row in rows:
            declared = {
                str(item).strip()
                for item in (row.permissions or [])
                if str(item).strip() in ALL_PERMISSIONS
            }
            index[str(row.name).strip().lower()] = frozenset(declared)
    except Exception:  # noqa: BLE001 — no table yet / DB unavailable
        return {}
    return index


def custom_role_names(raw_roles: list[str] | None,
                      custom_index: dict[str, frozenset[str]] | None) -> list[str]:
    """The custom role names inside a raw role list (kept, not dropped).

    ``normalize_roles`` must keep dropping unknown names for legacy-token
    safety; this companion recovers exactly the names that ARE defined
    custom roles, so they survive into the permission check.
    """
    if not custom_index:
        return []
    return [str(raw).strip()
            for raw in (raw_roles or [])
            if str(raw).strip().lower() in custom_index]
