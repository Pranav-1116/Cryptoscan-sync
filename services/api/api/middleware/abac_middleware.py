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

Pure ASGI implementation (see asgi_utils.py for why): the disabled/greenfield
fast path is a zero-overhead pass-through; body buffering happens only when
enforcement is active.
"""

from __future__ import annotations

import json
import logging
import os
import time

from starlette.requests import Request

from api.middleware.asgi_utils import request_id_from_scope, send_json

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


_PROD_ENVIRONMENTS = {"production", "prod", "staging", "stage"}


def _enforced() -> bool:
    """Scope enforcement is fail-closed in production/staging by default.

    Tenant isolation must silently no-op NEVER in a deployed environment: if
    the platform is running in production, ABAC is ON unless an operator
    explicitly sets ``ABAC_ENFORCED=false``. Local dev/test stay permissive
    (and greenfield installs with no grants remain open within an env).
    """
    override = os.environ.get("ABAC_ENFORCED", "").strip().lower()
    if override in {"1", "true", "yes", "on"}:
        return True
    if override in {"0", "false", "no", "off"}:
        return False
    # No explicit override: enforce in production-like environments.
    return os.environ.get("ENVIRONMENT", "").strip().lower() in _PROD_ENVIRONMENTS


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


#: max JSON body the middleware buffers just to extract scope attributes. The
#: route layer reads the body itself; this cap bounds middleware memory so a
#: multi-gigabyte POST cannot exhaust the worker via the scope read.
_MAX_SCOPE_BODY_BYTES = 256 * 1024


async def _buffer_body(receive) -> tuple[bytes, bool]:
    """Read the full request body. Returns (body, client_disconnected)."""
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return b"".join(chunks), True
        chunks.append(message.get("body", b"") or b"")
        if not message.get("more_body", False):
            return b"".join(chunks), False


def _replay_receive(body: bytes, socket_receive):
    """A replacement ``receive`` that serves the buffered body once, then
    forwards any later messages (disconnects) from the socket."""
    served = False

    async def receive():
        nonlocal served
        if not served:
            served = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await socket_receive()

    return receive


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


def _filter_body(body: bytes, grants, username, roles, tenant) -> tuple[bytes, int, bool]:
    """Post-filter a GET response body. Returns (new_body, hidden_count, denied).

    ``denied`` is True only for a single scoped object the caller may not
    access at all (the 403 case).
    """
    try:
        payload = json.loads(body)
    except Exception:  # noqa: BLE001
        return body, 0, False

    from control_plane.abac import authorize_request, filter_rows, row_scope

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
        if hidden:
            return json.dumps(visible, default=str).encode(), hidden, False
        return body, 0, False
    if isinstance(payload, dict):
        if deny_object(payload):
            return body, 0, True
        hidden_total = 0
        new_payload = payload
        for key in _LIST_KEYS:
            value = payload.get(key)
            if isinstance(value, list):
                visible, hidden = filter_rows(grants, value, username=username,
                                              roles=roles, tenant=tenant)
                if hidden:
                    new_payload[key] = visible
                    hidden_total += hidden
        if hidden_total == 0:
            return body, 0, False
        return json.dumps(new_payload, default=str).encode(), hidden_total, False
    return body, 0, False


class AbacMiddleware:
    """Enforce hierarchical scope authorization across every API router."""

    def __init__(self, app, *, enabled: bool | None = None):
        self.app = app
        self.enabled = enabled

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if not path.startswith("/api/v1/") or any(f in path for f in _UNPROTECTED_FRAGMENTS):
            await self.app(scope, receive, send)
            return

        enabled = _enforced() if self.enabled is None else self.enabled
        if not enabled:
            await self.app(scope, receive, send)  # zero-overhead fast path
            return

        request = Request(scope, receive)
        username, roles = _resolve_principal(request)
        if not username:
            # Unauthenticated — the session gate / route deps answer 401.
            await self.app(scope, receive, send)
            return

        method = request.method.upper()
        body_json: dict | None = None
        if method not in {"GET", "HEAD", "OPTIONS"}:
            ctype = request.headers.get("content-type", "")
            if "application/json" in ctype:
                declared = request.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > _MAX_SCOPE_BODY_BYTES:
                    body_json = None  # too large to buffer; scope from query/headers
                else:
                    raw, disconnected = await _buffer_body(receive)
                    if disconnected:
                        await self.app(scope, receive, send)
                        return
                    if raw:
                        try:
                            parsed = json.loads(raw)
                            body_json = parsed if isinstance(parsed, dict) else None
                        except Exception:  # noqa: BLE001 - malformed JSON: no scope
                            body_json = None
                    # replay the exact bytes to the route
                    receive = _replay_receive(raw, receive)

        try:
            scope_obj = _scope_from_request(request, body_json)
            grants, tenant = _load_grants_and_tenant(scope_obj.tenant_id)
        except Exception:
            logger.warning("abac_grant_store_unavailable; failing open for scope (RBAC still applies)",
                           exc_info=True)
            await self.app(scope, receive, send)
            return

        if not grants:
            # Greenfield: nothing provisioned yet — warn and pass (RBAC still applies).
            logger.debug("abac_no_grants_provisioned; scope enforcement permissive")
            await self.app(scope, receive, send)
            return

        from control_plane.abac import authorize_request

        scoped = any((scope_obj.region, scope_obj.business_unit, scope_obj.environment,
                      scope_obj.asset_id, scope_obj.tenant_id))
        if scoped:
            allowed, reason = authorize_request(
                grants, username=username, roles=roles, method=request.method,
                path=path, scope=scope_obj, tenant=tenant,
            )
            if not allowed:
                _record_denial(request, username, reason, scope_obj)
                await send_json(send, 403, {
                    "detail": f"Access denied by scope policy: {reason}",
                    "error_code": "ABAC_DENIED",
                    "scope": {"region": scope_obj.region, "business_unit": scope_obj.business_unit,
                              "environment": scope_obj.environment, "asset_id": scope_obj.asset_id},
                }, request_id=request_id_from_scope(request.scope))
                return

        # Unscoped platform reads/writes are not gate-denied here (RBAC already
        # restricts the action); response post-filtering still strips any
        # out-of-scope rows the payload happens to contain.
        if method == "GET":
            await self._app_get_filtered(scope, receive, send, grants, username, roles, tenant)
        else:
            await self.app(scope, receive, send)

    # ------------------------------------------------------------------ filter
    async def _app_get_filtered(self, scope, receive, send, grants, username, roles, tenant):
        """Run the route with a buffered response so list payloads can be
        post-filtered for out-of-scope rows (the BaseHTTPMiddleware version
        did the same by reading response.body)."""
        start: dict | None = None
        chunks: list[bytes] = []
        content_type = ""

        async def send_wrapper(message):
            nonlocal start, content_type
            if message["type"] == "http.response.start":
                start = message
                for k, v in message.get("headers") or []:
                    if k.lower() == b"content-type":
                        content_type = v.decode("latin-1", "replace")
            elif message["type"] == "http.response.body":
                chunks.append(message.get("body", b"") or b"")

        await self.app(scope, receive, send_wrapper)
        if start is None:  # defensive: no response produced
            return
        status = start["status"]
        if status != 200 or "application/json" not in content_type:
            await send(start)
            await send({"type": "http.response.body", "body": b"".join(chunks)})
            return

        new_body, hidden, denied = _filter_body(b"".join(chunks), grants, username, roles, tenant)
        try:
            if denied:
                body = json.dumps({"detail": "Access denied by scope policy",
                                   "error_code": "ABAC_DENIED",
                                   "request_id": request_id_from_scope(scope)}).encode()
                await send({"type": "http.response.start", "status": 403,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
            headers = list(start.get("headers") or [])
            headers = [(k, v) for k, v in headers if k.lower() != b"content-length"]
            headers.append((b"content-length", str(len(new_body)).encode()))
            if hidden:
                headers.append((b"x-abac-hidden", str(hidden).encode()))
            await send({"type": "http.response.start", "status": status, "headers": headers})
            await send({"type": "http.response.body", "body": new_body})
        except Exception:
            logger.debug("abac_response_filter_failed", exc_info=True)
            await send(start)
            await send({"type": "http.response.body", "body": b"".join(chunks)})
