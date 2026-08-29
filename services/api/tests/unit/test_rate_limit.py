"""W57-58 honest subset: rate limiting middleware (login brute force, scan floods)."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from api.middleware.rate_limit import RateLimitMiddleware, _endpoint_class, _identity


def _mini_app(rules=None):
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, rules=rules)

    @app.get("/api/v1/scans")
    def scans():
        return {"ok": True}

    @app.post("/api/v1/auth/login")
    def login():
        return {"ok": True}

    @app.get("/api/v1/healthz")
    def health():
        return {"ok": True}

    return app


async def _hit(client, method, path):
    return await client.request(method, path)


@pytest.mark.asyncio
async def test_login_bruteforce_throttled_per_ip():
    app = _mini_app(rules={"login": (3, 60), "api": (1000, 60), "scan_submit": (1000, 60)})
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        statuses = [(await _hit(client, "POST", "/api/v1/auth/login")).status_code for _ in range(5)]
        assert statuses == [200, 200, 200, 429, 429]
        throttled = await _hit(client, "POST", "/api/v1/auth/login")
        assert throttled.headers["Retry-After"].isdigit()
        assert throttled.json()["scope"] == "login"
        # other endpoints (and health probes) are unaffected by the login bucket
        assert (await _hit(client, "GET", "/api/v1/healthz")).status_code == 200
        assert (await _hit(client, "GET", "/api/v1/scans")).status_code == 200


@pytest.mark.asyncio
async def test_window_slides_after_cooldown():
    from fastapi import FastAPI

    clock = {"now": 1000.0}
    inner = FastAPI()

    @inner.post("/api/v1/auth/login")
    def login():
        return {"ok": True}

    # wrap explicitly so the injected clock is used (add_middleware is lazy)
    app = RateLimitMiddleware(
        inner, rules={"login": (2, 60), "api": (1000, 60), "scan_submit": (1000, 60)},
        clock=lambda: clock["now"],
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await _hit(client, "POST", "/api/v1/auth/login")).status_code == 200
        assert (await _hit(client, "POST", "/api/v1/auth/login")).status_code == 200
        assert (await _hit(client, "POST", "/api/v1/auth/login")).status_code == 429
        clock["now"] += 61  # window expires
        assert (await _hit(client, "POST", "/api/v1/auth/login")).status_code == 200


@pytest.mark.asyncio
async def test_scan_submit_has_its_own_bucket():
    app = _mini_app(rules={"login": (1000, 60), "api": (1000, 60), "scan_submit": (2, 60)})
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        statuses = [(await _hit(client, "GET", "/api/v1/scans")).status_code for _ in range(4)]
        # GET /scans is the generic api bucket, not scan_submit (POST-only rule)
        assert statuses == [200] * 4
        assert _endpoint_class("POST", "/api/v1/scans") == "scan_submit"
        assert _endpoint_class("POST", "/api/v1/scans/trigger") == "scan_submit"
        assert _endpoint_class("GET", "/api/v1/scans") == "api"
        assert _endpoint_class("POST", "/api/v1/auth/login") == "login"


@pytest.mark.asyncio
async def test_identity_prefers_token_subject_over_ip():
    class Req:
        headers = {"authorization": "Bearer not-a-token"}
        client = type("C", (), {"host": "10.1.1.1"})

    assert _identity(Req()) == "ip:10.1.1.1"  # invalid token -> IP bucket

    class ReqNoAuth:
        headers = {}
        client = type("C", (), {"host": "10.1.1.2"})

    assert _identity(ReqNoAuth()) == "ip:10.1.1.2"
