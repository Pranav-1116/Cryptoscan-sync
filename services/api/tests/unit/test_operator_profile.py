"""Explicit supported-profile configuration does not enable graph/realtime adapters."""
import pytest
from api.config.settings import APISettings, validate_runtime_settings
from api.security.passwords import hash_password
from worker.config.settings import WorkerSettings
from api.routers import health

PROFILE = "kubernetes-external-services/local-source-v1"


def api_settings(**changes):
    value = dict(ENVIRONMENT="production", CRYPTOSCAN_DEPLOYMENT_PROFILE=PROFILE,
        SECRET_KEY="n8f3k2p9q1w4e6r8t0y2u4i6o8a1s3d5", ADMIN_PASSWORD="",
        ADMIN_PASSWORD_HASH=hash_password("synthetic-test-password"),
        GITHUB_WEBHOOK_SECRET="synthetic-only-webhook-secret-0123456789",
        METRICS_TOKEN="m" * 32, ALERTMANAGER_WEBHOOK_TOKEN="a" * 32,
        REGISTRY_WEBHOOK_SECRET="r" * 32, CBOM_SIGNING_SECRET="c" * 32,
        STREAM_SECRET="s" * 32, AUDITOR_API_KEY="a" * 32,
        DATABASE_URL="postgresql://fixture:fixture@db/fixture",
        REDIS_URL="rediss://replay:synthetic-only-secret@redis:6379/0",
        CORS_ORIGINS="https://console.example", TRUSTED_HOSTS=["console.example"], NEO4J_URI="")
    return APISettings(_env_file=None, **{**value, **changes})


def test_explicit_operator_profile_has_no_dummy_graph_requirement():
    validate_runtime_settings(api_settings())
    WorkerSettings(_env_file=None, ENVIRONMENT="production", CRYPTOSCAN_DEPLOYMENT_PROFILE=PROFILE,
        DATABASE_URL="postgresql://fixture:fixture@db/fixture", REDIS_URL="rediss://fixture:fixture@redis/0",
        STREAM_SECRET="s" * 32, NEO4J_URI="", CRYPTOSCAN_SCANNER_IMAGE="scanner@sha256:" + "a" * 64).validate_runtime()


@pytest.mark.parametrize("changes,reason", [({"NEO4J_URI": "bolt://graph:7687"}, "graph is not enabled"),
    ({"CRYPTOSCAN_DEPLOYMENT_PROFILE": "unknown"}, "Unknown"), ({"SECRET_KEY": "short"}, "SECRET_KEY"),
    ({"REDIS_URL": "redis://insecure:secret@redis:6379/0"}, "verified TLS")])
def test_profile_does_not_remove_other_production_guards(changes, reason):
    with pytest.raises(RuntimeError, match=reason):
        validate_runtime_settings(api_settings(**changes))


def test_readiness_does_not_require_intentionally_disabled_realtime(monkeypatch):
    monkeypatch.setattr(health, "get_settings", api_settings)
    observed = []
    def probe(name, configured, fn):
        observed.append((name, configured))
        return {"name": name, "status": "ok" if configured else "skipped"}
    monkeypatch.setattr(health, "_probe", probe)
    monkeypatch.setattr("api.events.bus.get_event_bus", lambda: (_ for _ in ()).throw(AssertionError("disabled adapter must not be opened")))
    result = health.dependency_report()
    assert result["status"] == "ok"
    assert ("database", True) in observed and ("redis", True) in observed and ("neo4j", False) in observed
    assert next(c for c in result["checks"] if c["name"] == "realtime_events")["status"] == "skipped"
