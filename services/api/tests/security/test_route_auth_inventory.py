"""Route-auth inventory: no API route ships without an authentication seam.

The 2026-10 audit that produced this gate found the real gaps only after
three passes, because authentication lives in four different shapes:

1. a ``Depends(get_current_user)``-style dependency (module
   ``api.dependencies``);
2. a router-level dependency (``APIRouter(dependencies=[...])``) — the
   common shape for whole routers like telecom/hardware;
3. an aliased ``require_permission(...)`` factory dependency — the inner
   function's *name* says nothing, only its module (``api.security.rbac``)
   identifies it;
4. an inline check in the handler body (``require_auditor(request)``,
   ``token_from_request`` + manual 401).

Name-matching catches only shape 1. This test resolves every dependency
by module and falls back to source inspection for shape 4, then fails if
any non-exempt route carries none of the four shapes. The exemption list
is imported from AuthMiddleware — one source of truth — plus the
middleware-independent probes (/metrics, docs, statics).

A new route without an auth seam now fails CI by name, instead of
shipping open until someone remembers to check.
"""

from __future__ import annotations

import inspect

from api.main import create_app
from api.middleware.auth_middleware import UNPROTECTED_PREFIXES

# Paths that are never behind the session gate and are not APIRouter
# routes (Prometheus scrape, docs, statics) — must stay deliberately open.
EXTRA_EXEMPT = (
    "/metrics",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/docs/oauth2-redirect",
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/",
)

#: dependency callables that authenticate, by module-qualified name prefix
AUTH_MODULE_PREFIXES = ("api.security.rbac",)
AUTH_QUALIFIED_NAMES = (
    "api.dependencies.get_current_user",
    "api.dependencies.get_tenant_context",
    "api.dependencies.get_optional_user",
    "api.dependencies.resolve_tenant_for_request",
)

#: inline authentication markers searched in the handler's source
INLINE_AUTH_MARKERS = (
    "require_auditor(",
    "require_permission(",
    "get_current_user(",
    "_require_admin(",
    "token_from_request(",
    "_token_from_request(",
    "get_session(",  # session-token validation raising its own 401
    "verify_webhook(",  # signature-verified ingestion (webhook routers)
)


def _is_exempt(path: str) -> bool:
    for p in UNPROTECTED_PREFIXES:
        base = p.rstrip("/")
        if path == base or path.startswith(base + "/"):
            return True
    return path in EXTRA_EXEMPT


def _qual(dep) -> str:
    call = getattr(dep, "call", None)
    if call is None:
        return ""
    mod = getattr(call, "__module__", "") or ""
    name = getattr(call, "__name__", "") or ""
    return f"{mod}.{name}"


def _route_quals(route, router_deps: list[str]) -> list[str]:
    out = list(router_deps)
    d = getattr(route, "dependant", None)
    stack = list(d.dependencies) if d else []
    while stack:
        dep = stack.pop()
        out.append(_qual(dep))
        stack.extend(dep.dependencies)
    return out


def _has_auth_dependency(route, router_deps: list[str]) -> bool:
    for q in _route_quals(route, router_deps):
        if q.startswith(AUTH_MODULE_PREFIXES) or q in AUTH_QUALIFIED_NAMES:
            return True
        if q.endswith("._require_admin") or q.endswith(".require_auditor"):
            return True
    return False


def _has_inline_auth(route) -> bool:
    fn = getattr(route, "endpoint", None)
    if fn is None:
        return False
    try:
        src = inspect.getsource(fn)
    except (OSError, TypeError):  # pragma: no cover - builtins/lambdas
        return False
    return any(marker in src for marker in INLINE_AUTH_MARKERS)


def _inventory() -> list[tuple[str, str, str]]:
    """Every (method, path, router-module) route that carries no auth seam."""
    app = create_app()
    gaps: list[tuple[str, str, str]] = []
    audited = 0
    for r in app.routes:
        included = type(r).__name__ == "_IncludedRouter"
        router = getattr(r, "original_router", None) if included else None
        if router is None:
            # plain APIRoute mounted directly on the app shell (health, docs)
            methods = ",".join(sorted(m for m in getattr(r, "methods", [])
                                      if m not in ("HEAD", "OPTIONS")))
            path = getattr(r, "path", "")
            if methods and not _is_exempt(path) and not _has_auth_dependency(r, []):
                gaps.append(("app", methods, path))
            continue
        rdeps = [_qual(d) for d in getattr(router, "dependencies", [])]
        ctx = getattr(r, "include_context", None)
        prefix = (getattr(ctx, "prefix", "") or "") if ctx is not None else ""
        for route in router.routes:
            methods = ",".join(sorted(m for m in getattr(route, "methods", [])
                                      if m not in ("HEAD", "OPTIONS")))
            if not methods:
                continue
            audited += 1
            path = prefix + getattr(route, "path", "")
            if _is_exempt(path):
                continue
            if _has_auth_dependency(route, rdeps) or _has_inline_auth(route):
                continue
            fn = getattr(route, "endpoint", None)
            mod = getattr(fn, "__module__", "?").split(".")[-1]
            gaps.append((mod, methods, path))
    assert audited > 700, f"inventory walked only {audited} routes — mount shape changed"
    return gaps


def test_every_api_route_has_an_authentication_seam():
    gaps = _inventory()
    assert not gaps, (
        "routes without any authentication seam (dependency, router-level "
        "dependency, rbac factory or inline check):\n  "
        + "\n  ".join(f"{m:7s} {p} ({mod})" for mod, m, p in sorted(gaps))
    )


def test_billing_webhook_is_exempt_from_the_session_gate():
    """Stripe cannot carry a session: its HMAC signature is the credential.
    If this exemption is removed, every production billing callback 401s."""
    assert any(p.rstrip("/") == "/api/v1/saas/billing/webhook"
               for p in UNPROTECTED_PREFIXES)


# ---------------------------------------------------------- behavioral pins

def _authless_app():
    """The real app + the real session gate (added manually: create_app
    skips AuthMiddleware under ENVIRONMENT=test)."""
    from api.middleware.auth_middleware import AuthMiddleware

    app = create_app()
    app.add_middleware(AuthMiddleware)
    return app


def test_retention_requires_authentication():
    """/compliance/retention used to answer anonymous readers with the
    caller-partitioned retention clock (2026-10 audit finding)."""
    from fastapi.testclient import TestClient

    with TestClient(_authless_app()) as client:
        resp = client.get("/api/v1/compliance/retention")
    assert resp.status_code == 401, (
        f"retention must not answer anonymous callers, got {resp.status_code}")


def test_billing_webhook_reaches_the_route_without_a_session():
    """End-to-end proof of the exemption: an unsigned Stripe callback is
    answered by the ROUTE (400 invalid signature), not by the session gate
    (401) — which is what production saw before the fix."""
    from fastapi.testclient import TestClient

    with TestClient(_authless_app()) as client:
        resp = client.post("/api/v1/saas/billing/webhook", json={"type": "x"})
    assert resp.status_code != 401, (
        "the session gate intercepted the billing webhook — Stripe cannot "
        "carry a session; the signature check must be the first gate"
    )
    assert resp.status_code == 400, (
        f"expected the route's own signature verdict (400), got {resp.status_code}"
    )
