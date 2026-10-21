"""Durable realtime journal contract without requiring a live Redis server."""
from __future__ import annotations

from api.events.bus import EventBus
import fakeredis
from api.events.redis_sync import RedisEventSync, CHANNEL



def test_event_bus_replays_durable_stream_after_local_history_is_empty():
    redis = fakeredis.FakeRedis()
    writer = EventBus()
    sync = RedisEventSync(redis, writer, "node-a")
    writer.set_durable_history(next_id=sync.next_id, recent=sync.recent, latest=sync.latest)
    writer.set_remote_publisher(sync.publish)
    pubsub = redis.pubsub()
    pubsub.subscribe(CHANNEL)
    pubsub.get_message()
    writer.publish("scan.completed", {"scan_id": "S1"}, source="worker")

    restarted = EventBus()
    reader = RedisEventSync(redis, restarted, "node-b")
    restarted.set_durable_history(next_id=reader.next_id, recent=reader.recent, latest=reader.latest)

    replayed = restarted.recent(since_id=0, limit=10)
    assert [event["type"] for event in replayed] == ["scan.completed"]
    assert replayed[0]["payload"] == {"scan_id": "S1"}
    assert restarted.latest_id() == 1
    assert pubsub.get_message()["type"] == "message"
    pubsub.close()


def test_durable_sequence_is_shared_between_replicas():
    redis = fakeredis.FakeRedis()
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
