"""RequestID/Trace middleware: correlation + duration headers, W3C-style id."""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from api.middleware.logging_middleware import LoggingMiddleware
from api.middleware.request_id_middleware import RequestIDMiddleware


def _app():
    async def home(request):
        return JSONResponse({"path": request.url.path})

    return Starlette(
        routes=[__import__("starlette.routing", fromlist=["Route"]).Route("/ping", home)],
        middleware=[
            Middleware(LoggingMiddleware),
            Middleware(RequestIDMiddleware),
        ],
    )


def test_request_id_and_trace_and_duration_headers():
    client = TestClient(_app())
    resp = client.get("/ping")
    assert resp.status_code == 200
    assert resp.headers.get("X-Request-ID")
    assert resp.headers.get("X-Trace-Id")
    assert resp.headers.get("X-Request-Duration-ms")


def test_inbound_trace_id_is_propagated():
    client = TestClient(_app())
    resp = client.get("/ping", headers={"X-Trace-Id": "abc123", "X-Request-ID": "req-9"})
    assert resp.headers.get("X-Trace-Id") == "abc123"
    assert resp.headers.get("X-Request-ID") == "req-9"
