"""SecurityHeadersMiddleware: pure-ASGI header injection.

Regression guard for the str/bytes ``setdefault`` bug: a ``Cache-Control``
value set by the route (e.g. the SSE stream's ``no-cache, no-transform``)
must be preserved verbatim, not doubled or overridden by the ``/api/``
``no-store`` default.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from api.middleware.security_headers import SecurityHeadersMiddleware


def _app():
    async def ping(request):
        return JSONResponse({"ok": True})

    async def stream(request):
        async def gen():
            yield b"event: ping\n\n"
        return StreamingResponse(gen(), media_type="text/event-stream",
                                  headers={"Cache-Control": "no-cache, no-transform",
                                           "X-Accel-Buffering": "no"})

    return Starlette(
        routes=[Route("/api/v1/ping", ping), Route("/api/v1/events/stream", stream)],
        middleware=[Middleware(SecurityHeadersMiddleware)],
    )


def _header_values(headers, name):
    return [v for k, v in headers.multi_items() if k.lower() == name]


def test_route_cache_control_is_preserved_not_doubled():
    client = TestClient(_app())
    resp = client.get("/api/v1/events/stream")
    assert resp.status_code == 200
    # exactly one cache-control, with the route's value
    cc = _header_values(resp.headers, "cache-control")
    assert cc == ["no-cache, no-transform"], cc


def test_api_gets_no_store_when_route_sets_none():
    client = TestClient(_app())
    resp = client.get("/api/v1/ping")
    assert resp.status_code == 200
    cc = _header_values(resp.headers, "cache-control")
    assert cc == ["no-store"], cc


def test_baseline_security_headers_present():
    client = TestClient(_app())
    resp = client.get("/api/v1/ping")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("referrer-policy") == "no-referrer"
    assert resp.headers.get("content-security-policy")


def test_app_set_headers_never_overridden():
    """The middleware uses setdefault semantics — app headers win."""
    async def custom(request):
        return JSONResponse({"ok": True}, headers={"X-Frame-Options": "SAMEORIGIN"})

    app = Starlette(routes=[Route("/api/v1/custom", custom)],
                    middleware=[Middleware(SecurityHeadersMiddleware)])
    resp = TestClient(app).get("/api/v1/custom")
    assert resp.headers.get("x-frame-options") == "SAMEORIGIN"


# ── API versioning + deprecation contract (§B: API maturity) ────────────


def test_every_api_response_declares_its_version():
    """The contract a client can assert without parsing URLs."""
    client = TestClient(_app())
    resp = client.get("/api/v1/ping")
    assert resp.headers.get("x-api-version") == "1"


def test_non_api_paths_do_not_claim_an_api_version():
    async def index(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/", index)],
                    middleware=[Middleware(SecurityHeadersMiddleware)])
    resp = TestClient(app).get("/")
    assert "x-api-version" not in resp.headers


def test_withdrawn_paths_carry_the_rfc8594_lifecycle_trail():
    """A deprecated endpoint is a promise, not a deletion: Deprecation,
    Sunset and a successor Link ride the response — including the 410."""

    async def gone(request):
        return JSONResponse({"detail": "withdrawn"}, status_code=410)

    app = Starlette(routes=[Route("/api/v1/enterprise/airgap/bundle", gone)],
                    middleware=[Middleware(SecurityHeadersMiddleware)])
    resp = TestClient(app).get("/api/v1/enterprise/airgap/bundle")
    assert resp.status_code == 410
    assert resp.headers.get("deprecation") == "true"
    assert resp.headers.get("sunset")  # an HTTP-date, RFC 8594
    assert 'rel="successor-version"' in resp.headers.get("link", "")


def test_live_paths_carry_no_lifecycle_headers():
    client = TestClient(_app())
    resp = client.get("/api/v1/ping")
    assert "deprecation" not in resp.headers
    assert "sunset" not in resp.headers
