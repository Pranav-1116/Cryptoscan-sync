"""Retained replay contracts on memory and a Redis command emulator, not HA certification."""

from concurrent.futures import ThreadPoolExecutor
import pytest
import fakeredis
from api.events.bus import EventBus
from api.events.estate_replay import ReplayError
from api.events.redis_estate_journal import RedisEstateJournal
from api.events.redis_sync import RedisEventSync, EVENT_STREAM, CHANNEL


@pytest.fixture(params=["memory", "redis-bytes", "redis-text"])
def journal(request):
    bus = EventBus(history_size=7)
    redis = None
    if request.param.startswith("redis"):
        redis = fakeredis.FakeRedis(decode_responses=request.param == "redis-text")
        journal = RedisEstateJournal(redis, retention=7)
        sync = RedisEventSync(redis, bus, "writer", required=True)
        bus.set_durable_history(next_id=sync.next_id, recent=sync.recent, latest=sync.latest)
        bus.set_estate_history(journal.page)
        bus.set_remote_publish_required(True)
        bus.set_remote_publisher(
            lambda event: journal.append(
                event, global_stream=EVENT_STREAM, channel=CHANNEL, node="writer", global_retention=10
            )
        )
    return bus, redis


@pytest.mark.parametrize("owner", [None, "a", "b"])
def test_foreign_burst_cannot_evict_estate_and_limits_are_after_ownership(journal, owner):
    bus, _ = journal
    for n in range(5):
        bus.publish("own", {"n": n}, tenant_id=owner)
    for n in range(300):
        bus.publish("foreign", {"secret": n}, tenant_id="foreign")
    cursor, seen = None, []
    while True:
        page = bus.estate_page(owner, cursor, 2)
        assert page["latest_sequence"] == 5 and page["oldest_sequence"] == 1
        assert not page["retention_gap"]
        seen += [e["payload"]["n"] for e in page["events"]]
        cursor = page["next_cursor"]
        if not page["has_more"]:
            assert page["complete"]
            break
    assert seen == list(range(5))
    assert bus.estate_page(owner, cursor)["events"] == []


def test_snapshot_watermark_is_frozen_and_final_cursor_can_tail(journal):
    bus, _ = journal
    for n in range(5):
        bus.publish("own", {"n": n}, tenant_id="a")
    first = bus.estate_page("a", limit=2)
    bus.publish("own", {"n": 5}, tenant_id="a")
    middle = bus.estate_page("a", first["next_cursor"], 2)
    final = bus.estate_page("a", middle["next_cursor"], 2)
    assert [e["payload"]["n"] for e in final["events"]] == [4]
    assert final["snapshot_through"] == 5 and final["latest_sequence"] == 6
    assert [e["payload"]["n"] for e in bus.estate_page("a", final["next_cursor"])["events"]] == [5]


def test_trim_loss_is_explicit_and_only_selected_estate_counts(journal):
    bus, _ = journal
    bus.publish("own", {}, tenant_id="a")
    cursor = bus.estate_page("a")["next_cursor"]
    for n in range(12):
        bus.publish("own", {"n": n}, tenant_id="a")
    page = bus.estate_page("a", cursor)
    assert page["retention_gap"] and not page["complete"]
    assert page["oldest_sequence"] == 7 and page["latest_sequence"] == 13
    assert [e["payload"]["n"] for e in page["events"]] == list(range(5, 12))


def test_cursor_foreign_malformed_ahead_and_reset_fail_closed(journal):
    bus, redis = journal
    bus.publish("own", {}, tenant_id="a")
    cursor = bus.estate_page("a")["next_cursor"]
    for bad in ["bad", "1", "x" * 2048]:
        with pytest.raises(ReplayError):
            bus.estate_page("a", bad)
    with pytest.raises(ReplayError):
        bus.estate_page("b", cursor)
    if redis:
        redis.flushall()
    else:
        bus._estate_journal._partitions.clear()
    with pytest.raises(ReplayError):
        bus.estate_page("a", cursor)


def test_missing_or_conflicting_envelope_is_not_served(journal):
    bus, _ = journal
    bus.publish("fake", {"tenant_id": "b", "secret": "b"}, tenant_id="a")
    with pytest.raises(ReplayError):
        bus.estate_page("a")
    assert bus.estate_page("b")["events"] == []


def test_restart_and_shared_replica_replay_not_local_cache():
    redis = fakeredis.FakeRedis()
    writer, reader = EventBus(), EventBus()
    sync = RedisEventSync(redis, writer, "a", required=True)
    writer.set_remote_publisher(sync.publish)
    writer.set_remote_publish_required(True)
    writer.set_estate_history(RedisEstateJournal(redis).page)
    for n in range(8):
        writer.publish("own", {"n": n}, tenant_id="a")
    reader.set_estate_history(RedisEstateJournal(redis).page)
    assert [e["payload"]["n"] for e in reader.estate_page("a")["events"]] == list(range(8))
    assert reader.estate_page("a")["durable"]
    assert reader.recent() == []  # test really read shared journal


def test_backend_error_does_not_fall_back_to_local_history(journal, monkeypatch):
    bus, _ = journal
    bus.publish("own", {}, tenant_id="a")

    def failure(*args):
        raise ConnectionError("down")

    bus.set_estate_history(failure)
    with pytest.raises(ConnectionError):
        bus.estate_page("a")


def test_required_publish_fails_before_live_or_local_history():
    bus = EventBus()

    def failure(event):
        raise ConnectionError("down")

    bus.set_remote_publisher(failure)
    bus.set_remote_publish_required(True)
    with pytest.raises(RuntimeError):
        bus.publish("own", {}, tenant_id="a")
    assert bus.recent() == [] and bus.published_total() == 0


def test_redis_missing_middle_and_missing_stream_are_not_empty_success():
    redis = fakeredis.FakeRedis()
    journal = RedisEstateJournal(redis)
    for n in range(3):
        journal.append(
            {"id": n, "tenant_id": "a"}, global_stream=EVENT_STREAM, channel=CHANNEL, node="n", global_retention=10
        )
    bus = EventBus()
    bus.set_estate_history(journal.page)
    _, stream = journal.keys("a")
    redis.xdel(stream, "2-0")
    with pytest.raises(ReplayError):
        bus.estate_page("a")
    redis.delete(stream)
    with pytest.raises(ReplayError):
        bus.estate_page("a")


def test_concurrent_writers_keep_accepted_sequence_contiguous_and_refuse_contention():
    redis = fakeredis.FakeRedis()
    journal = RedisEstateJournal(redis)

    def append(n):
        try:
            journal.append(
                {"id": n, "tenant_id": "a", "payload": {"n": n}},
                global_stream=EVENT_STREAM,
                channel=CHANNEL,
                node="n",
                global_retention=100,
            )
            return n, True
        except ReplayError as exc:
            # Bounded admission may refuse contention; it must never claim a
            # successful append with a missing/duplicated estate sequence.
            assert str(exc) == "Event journal contention; append refused"
            return n, False

    with ThreadPoolExecutor(max_workers=3) as pool:
        outcomes = list(pool.map(append, range(30)))
    accepted = {n for n, success in outcomes if success}
    assert accepted  # at least one writer made progress, not just refusal
    bus = EventBus()
    bus.set_estate_history(journal.page)
    events = bus.estate_page("a")["events"]
    assert [e["estate_sequence"] for e in events] == list(range(1, len(accepted) + 1))
    assert {e["payload"]["n"] for e in events} == accepted


def test_wrong_type_global_stream_refuses_before_estate_append():
    redis = fakeredis.FakeRedis()
    redis.set(EVENT_STREAM, "wrong-type")
    journal = RedisEstateJournal(redis)
    with pytest.raises(ReplayError):
        journal.append(
            {"id": 1, "tenant_id": "a"}, global_stream=EVENT_STREAM, channel=CHANNEL, node="n", global_retention=10
        )
    meta, stream = journal.keys("a")
    assert not redis.exists(meta, stream)


def test_no_silent_success_on_configured_optional_journal_append_failure():
    bus = EventBus()
    bus.set_estate_history(lambda *args: (None, 1, 0, 0, []))

    def fail(event):
        raise ConnectionError("down")

    bus.set_remote_publisher(fail)
    with pytest.raises(RuntimeError):
        bus.publish("own", {}, tenant_id="a")
    assert bus.recent() == []


def test_missing_redis_metadata_fields_are_not_zero_history():
    redis = fakeredis.FakeRedis()
    journal = RedisEstateJournal(redis)
    meta, _ = journal.keys("a")
    redis.hset(meta, mapping={"wrong": "field"})
    bus = EventBus()
    bus.set_estate_history(journal.page)
    with pytest.raises(ReplayError):
        bus.estate_page("a")


def test_public_identity_and_frame_metadata_never_reveal_foreign_volume(journal):
    bus, _ = journal
    bus.publish("own", {}, tenant_id="a")
    for _ in range(35):
        bus.publish("foreign", {}, tenant_id="b")
    bus.publish("own", {}, tenant_id="a")
    page = bus.estate_page("a")
    assert [e["id"] for e in page["events"]] == [1, 2]
    assert all("node" not in event for event in page["events"])


@pytest.mark.parametrize("operation", ["append", "page"])
def test_watch_interleaving_retries_instead_of_reporting_false_corruption(monkeypatch, operation):
    server = fakeredis.FakeServer()
    redis = fakeredis.FakeRedis(server=server)
    journal = RedisEstateJournal(redis)
    concurrent = RedisEstateJournal(fakeredis.FakeRedis(server=server))

    def append(target, n):
        target.append(
            {"id": n, "tenant_id": "a", "payload": {"n": n}},
            global_stream=EVENT_STREAM,
            channel=CHANNEL,
            node="n",
            global_retention=100,
        )

    append(journal, 1)
    original = redis.pipeline
    raced = False

    def pipeline(*args, **kwargs):
        pipe = original(*args, **kwargs)
        read = pipe.hgetall

        def interleaved_read(key):
            nonlocal raced
            state = read(key)
            if not raced:
                raced = True
                # A valid atomic commit after metadata was read but before
                # stream reads. This is a changed WATCH version, not corruption.
                append(concurrent, 2)
            return state

        pipe.hgetall = interleaved_read
        return pipe

    monkeypatch.setattr(redis, "pipeline", pipeline)
    bus = EventBus()
    bus.set_estate_history(journal.page)
    if operation == "append":
        append(journal, 3)
    page = bus.estate_page("a")
    assert raced
    expected = [1, 2, 3] if operation == "append" else [1, 2]
    assert [e["payload"]["n"] for e in page["events"]] == expected
    assert [e["estate_sequence"] for e in page["events"]] == expected


@pytest.mark.parametrize("configuration", ["required", "read-only-provider"])
def test_configured_bus_without_publisher_refuses_unjournaled_local_success(configuration):
    bus = EventBus()
    if configuration == "required":
        bus.set_remote_publish_required(True)
    else:
        bus.set_estate_history(lambda *args: (None, 1, 0, 0, []))
    with pytest.raises(RuntimeError, match="Configured estate journal publisher unavailable"):
        bus.publish("must-not-fanout", {"private": "uncommitted"}, tenant_id="a")
    assert not bus._history
    assert bus._estate_journal.page("a", 0, None, 10)[2] == 0
