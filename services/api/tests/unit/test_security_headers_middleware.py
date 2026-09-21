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
