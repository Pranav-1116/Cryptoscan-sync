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

Failure is closed. The request proceeds **unscoped** only when the principal
affirmatively has no tenant: (a) a platform operator with no active tenant,
whose job is the platform estate, or (b) an unauthenticated request, which the
auth gate has already rejected. Any other outcome — a refusal (403/404/423/400)
or an unexpected error — raises ``TenantResolutionRefused`` and is answered
with that status here.

That distinction is the whole point. Outside a tenant scope the ORM guard in
``db.tenancy`` is inert, so "unscoped" means *every tenant's rows*. While
these refusals were swallowed into an unscoped request, a member sending
another tenant's ``X-Tenant-ID`` (404) or a member of two tenants sending no
header at all (400) read the entire estate on any of the ~85 routers that do
not depend on ``get_tenant_context`` — the very routers this middleware
covers.
"""

from __future__ import annotations

from starlette.requests import Request

# Paths that never carry a tenant and must not pay for a lookup.
_SKIP_PREFIXES = (
    "/health", "/ready", "/metrics", "/assets", "/favicon", "/static", "/login",
    "/api/docs", "/api/redoc", "/api/openapi.json",
    "/api/v1/auth/", "/api/v1/saas/signup", "/api/v1/saas/memberships",
    "/api/v1/saas/invites/accept", "/api/v1/meta", "/api/v1/healthz",
    "/api/v1/readyz", "/api/v1/webhooks",
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

        from api.dependencies import TenantResolutionRefused

        try:
            tenant_id = await self._resolve(Request(scope, receive))
        except TenantResolutionRefused as exc:
            from starlette.responses import JSONResponse

            from api.observability.operational_counters import incr

            # Counted here because a correctly refused cross-tenant request
            # leaves no row behind: without this the only evidence that the
            # guard is doing anything is its absence of incidents.
            incr("tenant_isolation_violation")
            response = JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
            await response(scope, receive, send)
            return

        if tenant_id is None:
            await self.app(scope, receive, send)
            return

        from db.tenancy import tenant_scope

        with tenant_scope(tenant_id):
            await self.app(scope, receive, send)

    async def _resolve(self, request: Request) -> str | None:
        """The membership-validated tenant, or None when there legitimately is none.

        Raises :class:`api.dependencies.TenantResolutionRefused` for every
        other outcome. Swallowing it here would put the request back on the
        unscoped path this middleware exists to close.
        """
        from starlette.concurrency import run_in_threadpool
        from api.dependencies import resolve_tenant_for_request

        return await run_in_threadpool(resolve_tenant_for_request, request)
