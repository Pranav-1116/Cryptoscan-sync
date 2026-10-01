"""Cluster-aware rate limiting + readiness gating."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from api.middleware.rate_limit import RateLimitMiddleware
from db.connection.session import Base


class FakeRedis:
    """Minimal INCR/EXPIRE client for cluster-window tests."""

    def __init__(self, fail: bool = False):
        self.store: dict[str, int] = {}
        self.ttl: dict[str, int] = {}
        self.fail = fail

    def incr(self, key: str) -> int:
        if self.fail:
            raise ConnectionError("redis down")
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    def expire(self, key: str, seconds: int) -> None:
        if self.fail:
            raise ConnectionError("redis down")
        self.ttl[key] = seconds


def test_shared_backend_one_budget_across_instances():
    clock = [1_000.0]
    middleware = RateLimitMiddleware(app=None, rules={"api": (3, 60)}, clock=lambda: clock[0],
                                     redis_client=FakeRedis())
    _replica_a = middleware._take(("user:soc", "api"), 3, 60)
    replica_b = RateLimitMiddleware(app=None, rules={"api": (3, 60)}, clock=lambda: clock[0],
                                    redis_client=middleware.redis)
    # three hits spread across two "replicas" sharing the same Redis
    assert middleware._take(("user:soc", "api"), 3, 60)[0] is True
    assert replica_b._take(("user:soc", "api"), 3, 60)[0] is True
    assert replica_b._take(("user:soc", "api"), 3, 60)[0] is False   # shared budget exhausted
    clock[0] += 61                                                   # next window
    assert replica_b._take(("user:soc", "api"), 3, 60)[0] is True


def test_shared_backend_outage_falls_back_in_process():
    middleware = RateLimitMiddleware(app=None, rules={"api": (2, 60)}, clock=lambda: 1.0,
                                     redis_client=FakeRedis(fail=True))
    assert middleware._take(("user:x", "api"), 2, 60)[0] is True     # degraded, not broken
    assert middleware._take(("user:x", "api"), 2, 60)[0] is True
    assert middleware._take(("user:x", "api"), 2, 60)[0] is False


def test_shared_backend_outage_fails_closed_in_production():
    middleware = RateLimitMiddleware(app=None, rules={"api": (2, 60)}, clock=lambda: 1.0,
                                     redis_client=FakeRedis(fail=True), fail_closed=True)
    allowed, remaining, retry_after = middleware._take(("user:x", "api"), 2, 60)
    assert (allowed, remaining) == (False, 0)
    assert retry_after > 0


@pytest.mark.asyncio
async def test_readyz_reports_database_state(monkeypatch, tmp_path):
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "soc"
    app.dependency_overrides[require_auditor] = lambda: "soc"
    app.dependency_overrides[get_db_session] = lambda: (yield session)

    from db.connection import engine as engine_module

    # healthy database -> 200 ready (LB routes here)
    monkeypatch.setattr(engine_module, "get_engine", lambda: engine, raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        ready = await client.get("/api/v1/readyz")
        assert ready.status_code == 200
        assert ready.json()["status"] == "ready"

        # database down -> 503 (LB drains this replica until failover completes)
        class _DeadEngine:
            def connect(self):
                raise RuntimeError("connection refused (failover in progress)")

        monkeypatch.setattr(engine_module, "get_engine", lambda: _DeadEngine(), raising=False)
        drained = await client.get("/api/v1/readyz")
        assert drained.status_code == 503
        assert drained.json()["status"] == "not_ready"
