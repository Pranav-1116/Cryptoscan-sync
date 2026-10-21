"""Realtime shared-state tests: event-bus Redis sync + current-run store.

These use stubbed redis clients because no live Redis is available in CI here.
They verify wiring and explicit configured-journal refusal, not distributed
correctness. An unconfigured memory bus remains independent of Redis; a
configured journal must not claim a successful append during an outage.
"""

from __future__ import annotations

import json

import fakeredis
import pytest

from api.events.bus import EventBus
from api.events.redis_sync import RedisEventSync, start_redis_federation
from api.live_scan.current_run import MemoryCurrentRun, RedisCurrentRun, get_current_run_store


class _FakePub:
    def __init__(self):
        self.messages: list[dict] = []
        self.subscribed: list[str] = []

    def subscribe(self, channel: str) -> None:
        self.subscribed.append(channel)

    def listen(self):
        while self.messages:
            yield self.messages.pop(0)


class _FakeRedis:
    """Minimal redis-py stand-in: pub/sub + get/set for the tests."""

    def __init__(self, node: str = "a"):
        self.node = node
        self.published: list[str] = []
        self._pub = _FakePub()
        self._store: dict = {}

    def publish(self, channel: str, data: str) -> int:
        self.published.append(data)
        return 1

    def pubsub(self):
        return self._pub

    def get(self, key):
        return self._store.get(key)

    def set(self, key, value, ex=None):
        self._store[key] = value

    # test helpers
    def inject(self, data: str) -> None:
        self._pub.messages.append({"type": "message", "data": data})


def test_event_bus_in_memory_delivers_when_no_redis():
    bus = EventBus()
    claimed = bus.publish("a.b", {"x": 1}, source="test")
    assert claimed["id"] == 1
    assert bus.recent(limit=5)[0]["type"] == "a.b"


def test_redis_sync_publishes_local_events():
    bus = EventBus()
    redis = fakeredis.FakeRedis()
    sync = RedisEventSync(redis, bus, "node-a")
    bus.set_remote_publisher(sync.publish)
    from api.events.redis_sync import CHANNEL

    with redis.pubsub() as subscriber:
        subscriber.subscribe(CHANNEL)
        subscriber.get_message()
        bus.publish("scan.started", {"scan_id": "S1"}, source="scan")
        frame = json.loads(subscriber.get_message()["data"])
    assert frame["node"] == "node-a"
    assert frame["type"] == "scan.started"
    assert frame["estate_sequence"] == 1


def test_redis_sync_injects_remote_and_ignores_own_echo():
    bus = EventBus()
    redis = _FakeRedis("node-a")
    sync = RedisEventSync(redis, bus, "node-a")
    bus.set_remote_publisher(sync.publish)
    # drive the reader synchronously (no background thread) for a deterministic test
    sync._pubsub = redis.pubsub()

    # inject a remote event as if it arrived from another node
    redis.inject(json.dumps({"node": "node-b", "type": "remote.evt", "source": "scan", "payload": {"a": 1}, "ts": "t"}))
    sync._run()
    assert any(e["type"] == "remote.evt" for e in bus.recent(limit=10))

    # inject our OWN echo -> must be ignored (no local re-publish / no dup)
    before = len(bus.recent(limit=50))
    redis.inject(json.dumps({"node": "node-a", "type": "scan.started", "source": "scan", "payload": {}, "ts": "t"}))
    sync._run()
    assert len(bus.recent(limit=50)) == before


def test_configured_redis_outage_refuses_publication_without_local_fallback():
    class BadRedis:
        def pubsub(self):
            raise RuntimeError("no redis")

        def publish(self, channel, data):
            raise RuntimeError("no redis")

    bus = EventBus()
    sync = start_redis_federation(BadRedis(), bus)
    assert sync is not None
    assert not sync.ready
    with pytest.raises(RuntimeError, match="durable realtime event publication failed"):
        bus.publish("a.b", {}, source="test")
    assert not bus._history
    with pytest.raises((AttributeError, RuntimeError)):
        bus.estate_page(None)
    sync.stop()


def test_current_run_memory_store():
    store = MemoryCurrentRun()
    assert store.get() is None
    store.set({"scan": {"scan_id": "S1"}})
    assert store.get()["scan"]["scan_id"] == "S1"


def test_current_run_redis_store_roundtrip_and_fallback():
    redis = _FakeRedis()
    store = RedisCurrentRun(redis)
    assert store.get() is None
    store.set({"scan": {"scan_id": "S1"}})
    assert store.get()["scan"]["scan_id"] == "S1"

    # a failing redis must not raise / corrupt
    class BadRedis:
        def get(self, key):
            raise RuntimeError("down")

        def set(self, key, value, ex=None):
            raise RuntimeError("down")

    bad = RedisCurrentRun(BadRedis())
    assert bad.get() is None
    bad.set({"scan": {}})  # must not raise


def test_current_run_factory_memory_when_no_url():
    store = get_current_run_store(None)
    assert isinstance(store, MemoryCurrentRun)
