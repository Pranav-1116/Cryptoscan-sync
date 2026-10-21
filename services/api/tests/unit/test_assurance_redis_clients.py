"""All consumer transports share strict production TLS/Sentinel, never HA proof."""
from types import SimpleNamespace
from unittest.mock import Mock
import fakeredis
import pytest
from shared_models.assurance import REDIS_ROLES
from shared_models.redis_connection import connection_settings, connection_fingerprint, verified_redis_client, probe_role_commands, RedisConfigurationError


def settings(**kw):
    return SimpleNamespace(is_production=True, REDIS_URL="rediss://scoped:synthetic@redis.internal/0",
        REDIS_CA_CERTS="", REDIS_SENTINELS="", REDIS_SENTINEL_MASTER="", REDIS_SENTINEL_USERNAME="", REDIS_SENTINEL_PASSWORD="", **kw)


@pytest.mark.parametrize("role", REDIS_ROLES)
def test_every_consumer_refuses_unverified_transport_and_uses_named_verified_tls(role, monkeypatch):
    import redis
    c = settings()
    c.REDIS_URL = "redis://not-tls:synthetic@redis/0"
    with pytest.raises(RedisConfigurationError):
        verified_redis_client(connection_settings(c, role))
    c.REDIS_URL = "rediss://scoped:synthetic@redis.internal/0"
    factory = Mock()
    monkeypatch.setattr(redis.Redis, "from_url", factory)
    verified_redis_client(connection_settings(c, role))
    assert factory.call_args.kwargs["ssl_check_hostname"] is True
    assert factory.call_args.kwargs["ssl_cert_reqs"] == "required"


@pytest.mark.parametrize("role", REDIS_ROLES)
def test_each_role_can_be_explicitly_separated_without_inheriting_wrong_sentinel(role, monkeypatch):
    config = settings()
    config.REDIS_SENTINELS = '[["a",26379],["b",26379],["c",26379]]'
    config.REDIS_SENTINEL_MASTER = "original"
    prefix = "CRYPTOSCAN_REDIS_" + role.upper() + "_"
    monkeypatch.setenv(prefix + "URL", "rediss://dedicated:synthetic@separate/0")
    selected = connection_settings(config, role)
    assert selected.REDIS_SENTINELS == selected.REDIS_SENTINEL_MASTER == ""
    assert selected.REDIS_URL != config.REDIS_URL
    monkeypatch.setenv(prefix + "SENTINELS", '[["d",26379],["e",26379],["f",26379]]')
    monkeypatch.setenv(prefix + "SENTINEL_MASTER", "dedicated")
    assert connection_settings(config, role).REDIS_SENTINEL_MASTER == "dedicated"


@pytest.mark.parametrize("role", REDIS_ROLES)
def test_role_commands_actually_round_trip_and_cleanup_hermetic_scratch(role):
    c = fakeredis.FakeRedis()
    c.set("existing-private-state", "untouched")
    assert probe_role_commands(c, role)["commands_exercised"] is True
    assert c.keys("*") == [b"existing-private-state"]


@pytest.mark.parametrize("url", [
    "rediss://scoped:secret@redis/0?ssl_cert_reqs=none&ssl_cert_reqs=required",
    "rediss://scoped:secret@redis/0?ssl_check_hostname=false&ssl_check_hostname=true",
    "rediss://scoped:secret@redis/0?ssl_ca_certs=/unapproved/other-root",
])
def test_query_override_cannot_bypass_any_role_tls(url):
    c = settings()
    c.REDIS_URL = url
    with pytest.raises(RedisConfigurationError):
        verified_redis_client(c)


def test_cache_identity_detects_credential_discovery_or_ca_file_rotation(tmp_path):
    c = settings()
    pem = tmp_path / "public-ca.pem"
    pem.write_text("synthetic public trust root A")
    c.REDIS_CA_CERTS = str(pem)
    before = connection_fingerprint(c)
    pem.write_text("synthetic rotated public trust root B, different size")
    assert connection_fingerprint(c) != before
    before = connection_fingerprint(c)
    c.REDIS_SENTINEL_PASSWORD = "rotated synthetic credential"
    assert connection_fingerprint(c) != before


def test_api_and_worker_consumers_actually_call_the_shared_role_factory(monkeypatch):
    from api import platform_state, main
    from api.security import sso_state
    from api.routers import telecom, health
    from api.live_scan.current_run import get_current_run_store
    from worker.core.job_consumer import JobConsumer
    config = settings()
    config.NEO4J_URI = ""
    roles = []
    def factory(selected, **kwargs):
        from urllib.parse import urlsplit
        roles.append(urlsplit(selected.REDIS_URL).hostname.split(".")[0])
        return Mock()
    for role in REDIS_ROLES:
        monkeypatch.setenv("CRYPTOSCAN_REDIS_" + role.upper() + "_URL", "rediss://scoped:synthetic@" + role + ".redis.internal/0")
    monkeypatch.setattr("shared_models.redis_connection.verified_redis_client", factory)
    monkeypatch.setattr("api.config.settings.get_settings", lambda: config)
    monkeypatch.setattr("worker.config.settings.get_settings", lambda: config)
    monkeypatch.setattr(sso_state, "get_settings", lambda: config)
    monkeypatch.setattr(health, "get_settings", lambda: config)
    monkeypatch.setattr(health, "check_db_health", lambda: {"status": "healthy"})
    monkeypatch.setattr(platform_state, "_REDIS", None)
    monkeypatch.setattr(sso_state, "_REDIS", None)
    main._shared_rate_limit_backend()
    platform_state._client()
    sso_state._client()
    telecom._redis_snapshot_client()
    health.dependency_report()
    get_current_run_store("rediss://scoped:synthetic@redis.internal/0", required=True)
    JobConsumer(redis_url="rediss://scoped:synthetic@redis.internal/0", allow_memory_fallback=False)
    assert set(roles) == set(REDIS_ROLES) - {"realtime"}


def test_production_queue_does_not_downgrade_bad_transport_to_memory(monkeypatch):
    from worker.core.job_consumer import JobConsumer
    config = settings()
    monkeypatch.setattr("worker.config.settings.get_settings", lambda: config)
    with pytest.raises(RuntimeError):
        JobConsumer(redis_url="redis://scoped:synthetic@redis.internal/0", allow_memory_fallback=False)
