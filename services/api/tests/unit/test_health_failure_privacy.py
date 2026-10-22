"""Synthetic connection failures must remain down, not expose credentials."""
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from api.routers import health
from db.connection import engine as database

CANARY = "synthetic-probe-password-CANARY-f29a"


def fail(*_args, **_kwargs):
    raise RuntimeError("postgresql://private-user:" + CANARY + "@private-db/customer; private SQL")


@pytest.mark.parametrize("dependency", ["database", "redis", "neo4j"])
def test_probe_reports_failure_without_returning_exception_message(dependency):
    result = health._probe(dependency, True, fail)
    assert result["status"] == "down"
    assert result["detail"] == "Dependency probe failed"
    assert result["error_type"] == "RuntimeError"
    assert result["latency_ms"] >= 0
    assert CANARY not in str(result)


@pytest.mark.parametrize("phase", ["construct", "connect"])
def test_database_health_failure_is_safe_in_result_and_logs(monkeypatch, caplog, phase):
    engine = SimpleNamespace(connect=fail)
    monkeypatch.setattr(database, "get_engine", fail if phase == "construct" else lambda: engine)
    result = database.check_db_health()
    assert result["status"] == "unhealthy"
    assert result["error_type"] == "RuntimeError"
    assert CANARY not in str(result) and CANARY not in caplog.text
    record = next(r for r in caplog.records if r.message == "database_health_failed")
    assert record.error_type == "RuntimeError" and record.exc_info is None


@pytest.mark.parametrize("path,status", [
    ("/readyz", 503), ("/api/v1/readyz", 503), ("/api/v1/healthz/dependencies", 200),
])
@pytest.mark.parametrize("phase", ["construct", "connect"])
def test_anonymous_health_paths_do_not_expose_failed_dependency_secrets(monkeypatch, caplog, path, status, phase):
    from api.main import create_app
    # Do not enter lifespan: isolate actual HTTP probe routes and middleware
    # from startup/migration/bootstrap. No real socket or database is contacted.
    app = create_app()
    engine = SimpleNamespace(connect=fail)
    monkeypatch.setattr(database, "get_engine", fail if phase == "construct" else lambda: engine)
    monkeypatch.setattr(health, "get_settings", lambda: SimpleNamespace(
        is_production=False, REDIS_URL="", REDIS_SENTINELS="", NEO4J_URI=""))
    client = TestClient(app)
    try:
        response = client.get(path)
        assert response.status_code == status, response.text
        assert CANARY not in response.text and CANARY not in caplog.text
        body = response.json()
        if "dependencies" in path:
            assert body["status"] == "degraded" and body["down"] == ["database"]
        else:
            assert body["status"] == "not_ready"
            assert body["error_type"] == "RuntimeError"
        assert client.get("/healthz").status_code == 200
    finally:
        client.close()
