"""Component-level dependency health endpoint."""

from __future__ import annotations

import pytest


def test_probe_statuses():
    from api.routers.health import _probe

    ok = _probe("x", True, lambda: "fine")
    assert ok["status"] == "ok" and ok["detail"] == "fine" and "latency_ms" in ok

    down = _probe("y", True, lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert down["status"] == "down" and "boom" in down["detail"]

    skipped = _probe("z", False, lambda: "never")
    assert skipped["status"] == "skipped"


def test_dependency_report_rolls_up_degraded(monkeypatch):
    from api.routers import health

    # database ok, redis configured but down, neo4j not configured
    monkeypatch.setattr(health, "check_db_health",
                        lambda *a, **k: {"status": "healthy", "dialect": "sqlite"})

    class _Settings:
        REDIS_URL = "redis://127.0.0.1:9/hang"
        NEO4J_URI = ""

    monkeypatch.setattr(health, "get_settings", lambda: _Settings())

    report = health.dependency_report()
    by_name = {c["name"]: c["status"] for c in report["checks"]}
    assert by_name["database"] == "ok"
    assert by_name["redis"] == "down"        # configured but unreachable
    assert by_name["neo4j"] == "skipped"     # not configured
    assert report["status"] == "degraded"
    assert report["down"] == ["redis"]


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/dep.db")
    monkeypatch.setenv("NEO4J_URI", "")
    monkeypatch.setenv("REDIS_URL", "")
    from api.config.settings import get_settings
    get_settings.cache_clear()
    from db.connection import engine as engine_mod
    engine_mod._ENGINE = None
    from api.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        yield c


def test_dependency_endpoint_reachable_without_auth(client):
    # unauthenticated (whitelisted like /healthz), DB present, others skipped
    r = client.get("/api/v1/healthz/dependencies")
    assert r.status_code == 200
    body = r.json()
    by_name = {c["name"]: c["status"] for c in body["checks"]}
    assert by_name["database"] == "ok"
    assert by_name["redis"] == "skipped"
    assert by_name["neo4j"] == "skipped"
    assert body["status"] == "ok"


# --- root-level probe aliases (LB / smoke-test surface) ----------------------

def test_root_probe_aliases_are_registered():
    from api.main import create_app

    app = create_app()
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/healthz" in paths
    assert "/readyz" in paths


def test_root_probe_aliases_behaviour(monkeypatch):
    from fastapi.testclient import TestClient

    from api.main import create_app
    from api.routers import health

    monkeypatch.setattr(
        health, "check_db_health", lambda *a, **k: {"status": "healthy", "dialect": "sqlite"}
    )

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, *args, **kwargs):
            return None

    class _OkEngine:
        def connect(self):
            return _Conn()

    monkeypatch.setattr("db.connection.engine.get_engine", lambda: _OkEngine())

    with TestClient(create_app()) as client:
        liveness = client.get("/healthz")
        assert liveness.status_code == 200
        assert liveness.json()["status"] == "ok"
        readiness = client.get("/readyz")
        assert readiness.status_code == 200
        assert readiness.json() == {"status": "ready", "database": "ok"}

    class _BadEngine:
        def connect(self):
            raise RuntimeError("db gone")

    monkeypatch.setattr("db.connection.engine.get_engine", lambda: _BadEngine())

    with TestClient(create_app()) as client:
        drained = client.get("/readyz")
        assert drained.status_code == 503
        assert drained.json()["status"] == "not_ready"
        # liveness stays 200 through a database outage
        assert client.get("/healthz").status_code == 200
