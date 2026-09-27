"""Apply the request's tenant scope to every database read it performs.

``get_tenant_context`` scopes the routes that depend on it, but only 5 of ~90
routers do. Adding the dependency to the other 85 would be 85 chances to miss
one, and a missed router is not a visible failure — it is a router that quietly
returns every tenant's rows. So the scope is entered once, here, for the whole
request.

What this middleware does **not** do is decide who you are. It reads the
membership-validated tenant that :func:`api.dependencies.resolve_tenant_for_request`
returns, which rejects an ``X-Tenant-ID`` the caller is not a member of. A
forged header therefore cannot be used to scope into — and so read — another
tenant's data; it 404s before it reaches the filter.

Resolution costs one indexed query on the memberships table, and is skipped
entirely for unauthenticated paths (health, login, metrics, static) and for
anything that is not an API route.

Failure is closed-ish by design: if the tenant cannot be resolved the request
proceeds **unscoped**, which is correct because the only ways to get here are
(a) a platform operator with no active tenant, whose job is the platform
estate, or (b) an unauthenticated request, which the auth gate has already
rejected. It is never the case that an authenticated tenant member silently
loses their filter — that path raises, and the error surfaces.
"""

from __future__ import annotations

import logging

from starlette.requests import Request

logger = logging.getLogger(__name__)

# Paths that never carry a tenant and must not pay for a lookup.
_SKIP_PREFIXES = (
    "/health", "/ready", "/metrics", "/assets", "/favicon", "/static", "/login",
    "/api/docs", "/api/redoc", "/api/openapi.json",
    "/api/v1/auth/", "/api/v1/saas/signup", "/api/v1/saas/invites/accept",
    "/api/v1/meta", "/api/v1/healthz", "/api/v1/readyz", "/api/v1/webhooks",
    "/api/v1/discovery",
)


class TenantScopeMiddleware:
    """Pure ASGI: the decision needs the path and the resolved tenant, never the body."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith("/api/") or path.startswith(_SKIP_PREFIXES):
            await self.app(scope, receive, send)
            return

        tenant_id = await self._resolve(Request(scope, receive))
        if tenant_id is None:
            await self.app(scope, receive, send)
            return

        from db.tenancy import tenant_scope

        with tenant_scope(tenant_id):
            await self.app(scope, receive, send)

    async def _resolve(self, request: Request) -> str | None:
        """The membership-validated tenant for this request, or None."""
        from starlette.concurrency import run_in_threadpool

        try:
            from api.dependencies import resolve_tenant_for_request

            return await run_in_threadpool(resolve_tenant_for_request, request)
        except Exception:  # pragma: no cover - never fail a request on scoping
            # Resolution problems are the route's business (it will raise the
            # proper 403/404/423 through get_tenant_context). Here, leaving the
            # request unscoped is safe: an unauthenticated caller was already
            # refused by the auth gate, and a platform operator legitimately
            # has no tenant.
            logger.debug("tenant scope not resolved for %s", request.url.path, exc_info=True)
            return None
