"""Durable realtime journal contract without requiring a live Redis server."""
from __future__ import annotations

from api.events.bus import EventBus
from api.events.redis_sync import RedisEventSync


class _RedisStream:
    def __init__(self):
        self.sequence = 0
        self.entries = []
        self.published = []

    def incr(self, _key):
        self.sequence += 1
        return self.sequence

    def xadd(self, _key, fields, **_kwargs):
        self.entries.append(fields)
        return f"{len(self.entries)}-0"

    def xrange(self, _key, **_kwargs):
        return [(f"{index + 1}-0", fields) for index, fields in enumerate(self.entries)]

    def get(self, _key):
        return self.sequence

    def publish(self, _channel, frame):
        self.published.append(frame)


def test_event_bus_replays_durable_stream_after_local_history_is_empty():
    redis = _RedisStream()
    writer = EventBus()
    sync = RedisEventSync(redis, writer, "node-a")
    writer.set_durable_history(next_id=sync.next_id, recent=sync.recent, latest=sync.latest)
    writer.set_remote_publisher(sync.publish)
    writer.publish("scan.completed", {"scan_id": "S1"}, source="worker")

    restarted = EventBus()
    reader = RedisEventSync(redis, restarted, "node-b")
    restarted.set_durable_history(next_id=reader.next_id, recent=reader.recent, latest=reader.latest)

    replayed = restarted.recent(since_id=0, limit=10)
    assert [event["type"] for event in replayed] == ["scan.completed"]
    assert replayed[0]["payload"] == {"scan_id": "S1"}
    assert restarted.latest_id() == 1
    assert len(redis.published) == 1


def test_durable_sequence_is_shared_between_replicas():
    redis = _RedisStream()
    first = EventBus()
    first_sync = RedisEventSync(redis, first, "a")
    first.set_durable_history(next_id=first_sync.next_id,
                              recent=first_sync.recent, latest=first_sync.latest)
    second = EventBus()
    second_sync = RedisEventSync(redis, second, "b")
    second.set_durable_history(next_id=second_sync.next_id,
                               recent=second_sync.recent, latest=second_sync.latest)
    assert first.publish("a", {})["id"] == 1
    assert second.publish("b", {})["id"] == 2
