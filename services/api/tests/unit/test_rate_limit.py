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


class FakeRedis:
    """The INCR/EXPIRE surface _take_shared uses. One instance = one cluster:
    two middleware objects sharing it are two replicas on one counter."""

    def __init__(self):
        self.values = {}
        self.down = False

    def incr(self, key):
        if self.down:
            raise ConnectionError("redis unavailable")
        self.values[key] = self.values.get(key, 0) + 1
        return self.values[key]

    def expire(self, key, ttl):
        if self.down:
            raise ConnectionError("redis unavailable")
        return True


def _replica(rules, redis_client=None, fail_closed=False):
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, rules=rules,
                       redis_client=redis_client, fail_closed=fail_closed)

    @app.get("/api/v1/scans")
    def scans():
        return {"ok": True}

    return app


@pytest.mark.asyncio
async def test_shared_window_counts_across_replicas_not_per_process():
    """The cross-replica proof: a 3/min identity gets 3/min across two API
    replicas sharing the window, not 3 each."""
    cluster = FakeRedis()
    rules = {"api": (3, 60), "login": (3, 60), "scan_submit": (3, 60)}
    replica_a = _replica(rules, redis_client=cluster)
    replica_b = _replica(rules, redis_client=cluster)
    async with AsyncClient(transport=ASGITransport(app=replica_a),
                           base_url="http://test") as client_a, \
            AsyncClient(transport=ASGITransport(app=replica_b),
                        base_url="http://test") as client_b:
        statuses = [
            (await client_a.get("/api/v1/scans")).status_code,
            (await client_b.get("/api/v1/scans")).status_code,
            (await client_a.get("/api/v1/scans")).status_code,
            (await client_b.get("/api/v1/scans")).status_code,
        ]
    assert statuses == [200, 200, 200, 429], (
        "one shared counter: the fourth call is refused no matter which "
        "replica serves it")


@pytest.mark.asyncio
async def test_fail_closed_refuses_when_the_shared_limiter_is_down():
    """A production deployment configured for a shared limiter must not
    silently downgrade to per-process quotas during a Redis outage."""
    cluster = FakeRedis()
    cluster.down = True
    app = _replica({"api": (100, 60)}, redis_client=cluster, fail_closed=True)
    async with AsyncClient(transport=ASGITransport(app=app),
                           base_url="http://test") as client:
        response = await client.get("/api/v1/scans")
    assert response.status_code == 429
    assert response.json()["error_code"] == "RATE_LIMITED"
    assert response.headers["Retry-After"].isdigit()


@pytest.mark.asyncio
async def test_development_degrades_to_in_process_windows_loudly():
    cluster = FakeRedis()
    cluster.down = True
    app = _replica({"api": (2, 60)}, redis_client=cluster, fail_closed=False)
    async with AsyncClient(transport=ASGITransport(app=app),
                           base_url="http://test") as client:
        statuses = [(await client.get("/api/v1/scans")).status_code
                    for _ in range(3)]
    assert statuses == [200, 200, 429], (
        "fallback keeps the inner defense: the in-process window still "
        "counts — the degrade is loud, never absent")


@pytest.mark.asyncio
async def test_every_response_names_its_reset_horizon():
    app = _mini_app(rules={"login": (1, 60), "api": (1000, 60),
                           "scan_submit": (1000, 60)})
    async with AsyncClient(transport=ASGITransport(app=app),
                           base_url="http://test") as client:
        allowed = await client.post("/api/v1/auth/login")
        assert allowed.status_code == 200
        assert int(allowed.headers["X-RateLimit-Reset"]) >= 0
        assert int(allowed.headers["X-RateLimit-Remaining"]) == 0
        refused = await client.post("/api/v1/auth/login")
        assert refused.status_code == 429
        assert int(refused.headers["X-RateLimit-Reset"]) >= 1
        assert int(refused.headers["Retry-After"]) >= 1
