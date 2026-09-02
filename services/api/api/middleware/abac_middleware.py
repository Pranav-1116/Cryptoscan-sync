"""ABAC enforcement middleware — scope-level authorization on EVERY route.

RBAC (api.security.rbac) decides *which actions a role may perform*; the
``/control/authorize`` endpoint produces ABAC *decisions* on demand. This
middleware is what makes those decisions real: it runs inside the auth gate
for every ``/api/v1`` request and enforces the large-bank isolation doctrine

    Region -> Business Unit -> Environment -> Asset (fail-closed).

Request path (mutations):
    resolve principal + roles -> load active grants -> extract the target
    scope from query params / JSON body / headers -> ``authorize_request``.
    A deny returns 403 before the route ever runs, is audit-logged, and lands
    on the realtime bus as ``security.abac_denied``.

Response path (reads):
    list/single-object JSON payloads are post-filtered: rows carrying scope
    attributes outside every grant covering the caller are stripped (with a
    ``X-ABAC-Hidden`` count header). Rows with no scope attributes are
    platform/reference data and stay visible.

Deployment gate: enforcement is active only when ``ABAC_ENFORCED`` is truthy
AND at least one grant exists in the store. A deployment that has not yet
provisioned grants fails *open* for scope (RBAC still applies) with a logged
warning — this protects greenfield installs and the self-hosted demo while a
configured large-bank deployment is strictly fail-closed.
"""

from __future__ import annotations

import json
import logging
import os
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

#: paths that never carry a scope / must stay reachable for the platform.
_UNPROTECTED_FRAGMENTS = (
    "/events/stream", "/events/recent", "/events/stats",
    "/healthz", "/readyz", "/meta", "/metrics", "/docs", "/openapi.json",
    "/auth/", "/oidc", "/webhooks",  # auth flows + machine webhooks have their own auth
)

#: response list-keys whose contents are scope-filtered on reads.
_LIST_KEYS = (
    "items", "results", "rows", "data", "findings", "assets", "systems",
    "scans", "tickets", "events", "agents", "credentials", "records",
    "integrations", "policies", "controls", "grants", "tenants",
)

_GRANTS_CACHE_TTL = 5.0
_grants_cache: dict | None = None
_grants_cache_at = 0.0


def reset_abac_cache() -> None:
    global _grants_cache, _grants_cache_at
    _grants_cache = None
    _grants_cache_at = 0.0


def _enforced() -> bool:
    return os.environ.get("ABAC_ENFORCED", "").lower() in {"1", "true", "yes", "on"}


def _load_grants_and_tenant(tenant_id: str | None):
    """Return (grants, tenant) — grants cached briefly to protect the hot path.

    An empty result is never cached: a greenfield deployment may provision its
    first grant at any moment, and caching "no grants" would suppress
    enforcement for the TTL window.
    """
    global _grants_cache, _grants_cache_at
    now = time.monotonic()
    if _grants_cache is None or (now - _grants_cache_at) > _GRANTS_CACHE_TTL:
        from db.connection.session import SessionLocal
        from db.repositories.control_plane_repository import ControlPlaneRepository

        session = SessionLocal()
        try:
            repo = ControlPlaneRepository(session)
            loaded = [g.to_dict() for g in repo.list_grants()]
            if loaded:
                _grants_cache = loaded
                _grants_cache_at = now
        finally:
            session.close()
    grants = _grants_cache or []
    tenant = None
    if tenant_id:
        from db.connection.session import SessionLocal
        from db.repositories.control_plane_repository import ControlPlaneRepository

        session = SessionLocal()
        try:
            row = ControlPlaneRepository(session).get_tenant(tenant_id)
            tenant = row.to_dict() if row else None
        finally:
            session.close()
    return grants, tenant


def _resolve_principal(request) -> tuple[str | None, list[str]]:
    """(username, normalized roles) or (None, []) when unauthenticated.

    Auth failures are swallowed here: the session gate / route dependencies
    own the 401 decision; this middleware only enforces scope for callers it
    can positively identify.
    """
    username = getattr(request.state, "user_id", None)
    if username:
        try:
            from api.security.rbac import _caller_roles

            principal, roles = _caller_roles(request)
            return principal, roles
        except Exception:
            logger.debug("abac caller resolution from state failed; retrying", exc_info=True)
    try:
        from api.security.rbac import _caller_roles

        principal, roles = _caller_roles(request)
        return principal, roles
    except Exception:  # noqa: BLE001 - anonymous / invalid: not this layer's job
        return None, []


def _scope_from_request(request, body: dict | None):
    from control_plane.abac import scope_from_payload

    query = {k: v for k, v in request.query_params.multi_items()}
    headers = {}
    for h in ("x-zelnx-region", "x-region", "x-zelnx-business-unit",
              "x-zelnx-environment", "x-tenant-id"):
        if request.headers.get(h):
            headers[h.replace("x-zelnx-", "").replace("x-", "").replace("-", "_")] = request.headers[h]
    return scope_from_payload(query, body or {}, headers)


def _record_denial(request, username, reason: str, scope) -> None:
    try:
        from api.events.bus import get_event_bus

        get_event_bus().publish(
            "security.abac_denied",
            {"actor": username, "method": request.method, "path": request.url.path,
             "reason": reason, "region": scope.region, "business_unit": scope.business_unit,
             "environment": scope.environment, "asset_id": scope.asset_id},
            source="abac",
        )
    except Exception:
        logger.debug("abac_deny_event_failed", exc_info=True)
    try:
        from db.connection.session import SessionLocal
        from db.repositories.user_repository import UserRepository

        session = SessionLocal()
        try:
            UserRepository(session).audit(
                username or "anonymous", "security.abac_denied", target_type="abac",
                detail={"path": request.url.path, "method": request.method, "reason": reason},
            )
            session.commit()
        finally:
            session.close()
    except Exception:
        logger.debug("abac_deny_audit_failed", exc_info=True)


class AbacMiddleware(BaseHTTPMiddleware):
    """Enforce hierarchical scope authorization across every API router."""

    def __init__(self, app, *, enabled: bool | None = None):
        super().__init__(app)
        self.enabled = enabled

    async def dispatch(self, request, call_next):
        path = request.url.path
        if not path.startswith("/api/v1/") or any(f in path for f in _UNPROTECTED_FRAGMENTS):
            return await call_next(request)

        enabled = _enforced() if self.enabled is None else self.enabled
        if not enabled:
            return await call_next(request)

        username, roles = _resolve_principal(request)
        if not username:
            # Unauthenticated — the session gate / route deps answer 401.
            return await call_next(request)

        body_json: dict | None = None
        if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            ctype = request.headers.get("content-type", "")
            if "application/json" in ctype:
                try:
                    raw = await request.body()
                    if raw:
                        parsed = json.loads(raw)
                        if isinstance(parsed, dict):
                            body_json = parsed
                except Exception:  # noqa: BLE001 - non-JSON / unreadable: no scope from body
                    body_json = None

        try:
            scope = _scope_from_request(request, body_json)
            grants, tenant = _load_grants_and_tenant(scope.tenant_id)
        except Exception:
            logger.warning("abac_grant_store_unavailable; failing open for scope (RBAC still applies)",
                           exc_info=True)
            return await call_next(request)

        if not grants:
            # Greenfield: nothing provisioned yet — warn and pass (RBAC still applies).
            logger.debug("abac_no_grants_provisioned; scope enforcement permissive")
            return await call_next(request)

        from control_plane.abac import authorize_request

        scoped = any((scope.region, scope.business_unit, scope.environment,
                      scope.asset_id, scope.tenant_id))
        if scoped:
            allowed, reason = authorize_request(
                grants, username=username, roles=roles, method=request.method,
                path=path, scope=scope, tenant=tenant,
            )
            if not allowed:
                _record_denial(request, username, reason, scope)
                return JSONResponse(
                    status_code=403,
                    content={"detail": f"Access denied by scope policy: {reason}",
                             "error_code": "ABAC_DENIED",
                             "scope": {"region": scope.region, "business_unit": scope.business_unit,
                                       "environment": scope.environment, "asset_id": scope.asset_id}},
                )
        # Unscoped platform reads/writes are not gate-denied here (RBAC already
        # restricts the action); response post-filtering still strips any
        # out-of-scope rows the payload happens to contain.

        response = await call_next(request)

        # Post-filter reads so list/detail payloads never leak out-of-scope rows.
        if request.method.upper() == "GET" and response.status_code == 200 and hasattr(response, "body"):
            try:
                response = self._filter_response(response, grants, username, roles, tenant)
            except Exception:
                logger.debug("abac_response_filter_failed", exc_info=True)
        return response

    # ------------------------------------------------------------------ filter
    def _filter_response(self, response, grants, username, roles, tenant):
        ctype = response.headers.get("content-type", "")
        if "application/json" not in ctype:
            return response
        try:
            payload = json.loads(response.body)
        except Exception:  # noqa: BLE001
            return response

        from control_plane.abac import authorize_request, filter_rows, row_scope

        hidden_total = 0

        def deny_object(obj: dict) -> bool:
            scope = row_scope(obj)
            if scope is None:
                return False
            ok, _ = authorize_request(grants, username=username, roles=roles,
                                      method="GET", path="", scope=scope, tenant=tenant)
            return not ok

        if isinstance(payload, list):
            visible, hidden = filter_rows(grants, payload, username=username,
                                          roles=roles, tenant=tenant)
            hidden_total += hidden
            new_payload = visible
        elif isinstance(payload, dict):
            # single scoped object?
            if deny_object(payload):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Access denied by scope policy", "error_code": "ABAC_DENIED"},
                )
            new_payload = payload
            for key in _LIST_KEYS:
                value = payload.get(key)
                if isinstance(value, list):
                    visible, hidden = filter_rows(grants, value, username=username,
                                                  roles=roles, tenant=tenant)
                    if hidden:
                        new_payload[key] = visible
                        hidden_total += hidden
        else:
            return response

        if hidden_total == 0:
            return response
        body = json.dumps(new_payload, default=str).encode()
        response.body = body
        response.headers["content-length"] = str(len(body))
        response.headers["x-abac-hidden"] = str(hidden_total)
        return response
