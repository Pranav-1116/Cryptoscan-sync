"""Transport/configuration and actual command readiness contracts, not HA proof."""

from unittest.mock import Mock

import fakeredis
import pytest
from api.config.settings import APISettings
from api.events.redis_backend import (
    validate_realtime_redis,
    realtime_redis_client,
    RedisConfigurationError,
    probe_journal_commands,
)
from api.events.redis_sync import start_redis_federation
from api.events.bus import EventBus


def settings(**changes):
    return APISettings.model_construct(
        ENVIRONMENT="production", REDIS_URL="rediss://replay:unit-secret@redis.internal:6379/0", **changes
    )


@pytest.mark.parametrize(
    "url",
    [
        "redis://replay:secret@redis:6379/0",
        "unix:///redis.sock",
        "redis+cluster://redis/0",
        "rediss://redis:6379/0",
        "rediss://default:secret@redis:6379/0",
        "rediss://replay:secret@redis:6379/0?ssl_cert_reqs=none",
        "rediss://replay:secret@redis:6379/0?ssl_cert_reqs=optional",
        "rediss://replay:secret@redis:6379/0?ssl_check_hostname=false",
    ],
)
def test_production_refuses_unverified_or_anonymous_redis(url):
    config = settings()
    config.REDIS_URL = url
    with pytest.raises(RedisConfigurationError):
        validate_realtime_redis(config)


@pytest.mark.parametrize(
    "nodes", ["{}", "[]", '[["host",true]]', '[["host",0]]', '[["host",26379]]', '[["h",1],["h",1],["h",1]]']
)
def test_production_sentinel_requires_valid_distinct_endpoints_and_credentials(nodes):
    config = settings(
        REDIS_SENTINELS=nodes,
        REDIS_SENTINEL_MASTER="bank",
        REDIS_SENTINEL_USERNAME="discovery",
        REDIS_SENTINEL_PASSWORD="test",
    )
    with pytest.raises(RedisConfigurationError):
        validate_realtime_redis(config)


def test_sentinel_uses_verified_tls_and_separate_discovery_credentials(monkeypatch):
    import redis.sentinel

    sentinel = Mock()
    constructor = Mock(return_value=sentinel)
    monkeypatch.setattr(redis.sentinel, "Sentinel", constructor)
    config = settings(
        REDIS_SENTINELS='[["a",26379],["b",26379],["c",26379]]',
        REDIS_SENTINEL_MASTER="bank",
        REDIS_SENTINEL_USERNAME="discovery",
        REDIS_SENTINEL_PASSWORD="separate-secret",
        REDIS_CA_CERTS="/approved/ca.pem",
    )
    assert realtime_redis_client(config) == sentinel.master_for.return_value
    args, kwargs = constructor.call_args
    assert len(args[0]) == 3
    assert kwargs["ssl"] and kwargs["ssl_check_hostname"] and kwargs["ssl_cert_reqs"] == "required"
    assert kwargs["username"] == "replay" and kwargs["password"] == "unit-secret"
    assert kwargs["sentinel_kwargs"]["username"] == "discovery"
    assert kwargs["sentinel_kwargs"]["password"] == "separate-secret"
    assert kwargs["sentinel_kwargs"]["ssl_check_hostname"] is True
    sentinel.master_for.assert_called_once_with("bank")


def test_direct_tls_factory_never_disables_verification(monkeypatch):
    import redis

    factory = Mock()
    monkeypatch.setattr(redis.Redis, "from_url", factory)
    realtime_redis_client(settings())
    assert factory.call_args.kwargs["ssl_check_hostname"] is True
    assert factory.call_args.kwargs["ssl_cert_reqs"] == "required"
    assert factory.return_value.replay_bind_primary_epoch is True


def test_command_probe_cleans_scratch_and_does_not_mutate_real_journals():
    client = fakeredis.FakeRedis()
    client.set("zelinx:events:unchanged", "keep")
    probe_journal_commands(client)
    assert client.keys("*") == [b"zelinx:events:unchanged"]


def test_ping_only_backend_cannot_become_required_journal_ready():
    class PingOnly:
        def ping(self):
            return True

        def get(self, key):
            return None

        def xrange(self, *args, **kwargs):
            return []

    bus = EventBus()
    sync = start_redis_federation(PingOnly(), bus, required=True)
    assert sync is not None and not sync.ready
    with pytest.raises(RuntimeError):
        bus.publish("must-not-pass", {})
    assert not bus._history


def test_sentinel_snapshot_epoch_binds_to_actual_primary_and_refuses_demoted_source():
    import json
    from api.events.redis_estate_journal import RedisEstateJournal
    from api.events.estate_replay import replay_page, ReplayError

    client = Mock(replay_bind_primary_epoch=True)
    # A MagicMock is used only for the transactional wire seam. Real TLS tests
    # below exercise the actual server's INFO/MULTI/WATCH behavior.
    from unittest.mock import MagicMock

    pipe = MagicMock()
    client.pipeline.return_value = pipe
    pipe.__enter__.return_value = pipe
    raw_epoch = "a" * 32
    frame = {"tenant_id": "a", "estate_sequence": 1, "estate_epoch": raw_epoch, "payload": {}}
    pipe.hgetall.return_value = {b"epoch": raw_epoch.encode(), b"latest": b"1"}
    row = [(b"1-0", {b"frame": json.dumps(frame).encode()})]
    pipe.xrange.return_value = row
    pipe.xrevrange.return_value = row
    pipe.execute.return_value = [{"role": "master"}, {"run_id": "primary-one"}]
    provider = RedisEstateJournal(client).page
    first = replay_page(provider, "a")
    assert first["complete"] and first["epoch"] != raw_epoch
    pipe.execute.return_value = [{"role": "master"}, {"run_id": "primary-two"}]
    with pytest.raises(ReplayError, match="epoch changed"):
        replay_page(provider, "a", first["next_cursor"])
    assert replay_page(provider, "a")["complete"]
    pipe.execute.return_value = [{"role": "slave"}, {"run_id": "primary-one"}]
    with pytest.raises(RuntimeError, match="not the current primary"):
        replay_page(provider, "a")
    client.connection_pool.disconnect.assert_called_once()


def test_subscription_reconnect_revalidates_commands_and_stop_interrupts_backoff(monkeypatch):
    from api.events.redis_sync import RedisEventSync
    from unittest.mock import MagicMock

    client, bus = Mock(), Mock()
    sync = RedisEventSync(client, bus, "local", required=True)
    broken, restored = MagicMock(), MagicMock()
    broken.get_message.side_effect = ConnectionError("not logged")
    sync._pubsub = broken
    client.pubsub.return_value = restored
    probe = Mock()
    monkeypatch.setattr("api.events.redis_backend.probe_journal_commands", probe)
    waits = []

    def wait(delay):
        waits.append(delay)
        return sync._stop.is_set()

    monkeypatch.setattr(sync._stop, "wait", wait)

    messages = iter([None, {"type": "message", "data": '{"node":"remote","payload":{}}'}])

    def next_message(**kwargs):
        assert kwargs == {"timeout": 1.0}
        try:
            return next(messages)
        except StopIteration:
            sync._stop.set()
            return None

    restored.get_message.side_effect = next_message
    sync._run()
    probe.assert_called_once_with(client)
    bus.inject_remote.assert_called_once()
    assert waits == [0.1, 0.1]
    broken.close.assert_called_once()
    restored.close.assert_called_once()
    assert not sync.ready
