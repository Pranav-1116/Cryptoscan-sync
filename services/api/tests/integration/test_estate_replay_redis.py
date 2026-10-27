"""Opt-in real standalone Redis command/fanout contracts, not HA qualification.

Use only a disposable server. Keys are namespaced and only that namespace is
removed; no FLUSHDB/FLUSHALL. Set ESTATE_REPLAY_REDIS_SOCKET to its Unix socket.
"""

import os
import threading
import uuid
import pytest
import redis
from api.events.bus import EventBus
from api.events.estate_replay import ReplayError
from api.events.redis_estate_journal import RedisEstateJournal
from api.events.redis_sync import start_redis_federation

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("ESTATE_REPLAY_REDIS_SOCKET"), reason="disposable Redis Unix socket not supplied"
    ),
]


@pytest.fixture(params=[False, True])
def backend(request, monkeypatch):
    client = redis.Redis(
        unix_socket_path=os.environ["ESTATE_REPLAY_REDIS_SOCKET"], decode_responses=request.param, socket_timeout=3
    )
    client.ping()
    namespace = "estate-qualification:" + uuid.uuid4().hex + ":"
    monkeypatch.setattr("api.events.redis_estate_journal.PREFIX", namespace + "estate:")
    monkeypatch.setattr("api.events.redis_sync.EVENT_STREAM", namespace + "global")
    monkeypatch.setattr("api.events.redis_sync.EVENT_SEQUENCE", namespace + "sequence")
    monkeypatch.setattr("api.events.redis_sync.CHANNEL", namespace + "channel")
    yield client, namespace
    keys = list(client.scan_iter(match=namespace + "*"))
    if keys:
        client.delete(*keys)
    client.close()


def test_real_redis_fanout_and_restart_reader_are_owner_partitioned(backend, monkeypatch):
    client, _ = backend
    writer, reader = EventBus(), EventBus()
    received = threading.Event()
    original = reader.inject_remote

    def inject(frame):
        original(frame)
        if frame["tenant_id"] == "a":
            received.set()

    monkeypatch.setattr(reader, "inject_remote", inject)
    first = start_redis_federation(client, writer, node_id="a", required=True)
    second = start_redis_federation(client, reader, node_id="b", required=True)
    try:
        assert first.ready and second.ready
        for n in range(12):
            writer.publish("own", {"n": n}, tenant_id="a")
        assert received.wait(3), "real Pub/Sub fanout did not arrive"
        for n in range(60):
            writer.publish("foreign", {"private": n}, tenant_id="b")
        restarted = EventBus()
        restarted.set_estate_history(RedisEstateJournal(client).page)
        cursor, seen = None, []
        while True:
            page = restarted.estate_page("a", cursor, 3)
            seen.extend(e["payload"]["n"] for e in page["events"])
            assert page["latest_sequence"] == 12 and not page["retention_gap"]
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break
        assert seen == list(range(12))
        assert reader.estate_page("a")["events"] == restarted.estate_page("a")["events"]
    finally:
        first.stop()
        second.stop()


def test_real_redis_exact_trim_and_corrupt_journal_refusal(backend):
    client, namespace = backend
    journal = RedisEstateJournal(client, retention=7)
    bus = EventBus()
    bus.set_estate_history(journal.page)
    for n in range(12):
        journal.append(
            {"id": n, "tenant_id": "a", "payload": {"n": n}},
            global_stream=namespace + "global",
            channel=namespace + "channel",
            node="n",
            global_retention=5,
        )
    page = bus.estate_page("a")
    assert len(page["events"]) == 7 and page["oldest_sequence"] == 6
    assert page["retention_gap"] and not page["complete"]
    _, stream = journal.keys("a")
    client.xdel(stream, "9-0")
    with pytest.raises(ReplayError):
        bus.estate_page("a")


def test_real_redis_wrong_type_refuses_before_estate_write(backend):
    client, namespace = backend
    journal = RedisEstateJournal(client)
    client.set(namespace + "global", "wrong-type")
    with pytest.raises(ReplayError):
        journal.append(
            {"id": 1, "tenant_id": "a"},
            global_stream=namespace + "global",
            channel=namespace + "channel",
            node="n",
            global_retention=5,
        )
    meta, stream = journal.keys("a")
    assert not client.exists(meta, stream)


def test_real_redis_concurrent_writers_preserve_every_accepted_append(backend):
    from concurrent.futures import ThreadPoolExecutor

    client, namespace = backend
    journal = RedisEstateJournal(client)

    def append(n):
        owner = "a" if n % 2 else "b"
        try:
            journal.append(
                {"id": n, "tenant_id": owner, "payload": {"n": n}},
                global_stream=namespace + "global",
                channel=namespace + "channel",
                node="concurrent",
                global_retention=100,
            )
            return owner, n, True
        except ReplayError as exc:
            assert str(exc) == "Event journal contention; append refused"
            return owner, n, False

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(append, range(80)))
    bus = EventBus()
    bus.set_estate_history(journal.page)
    for owner in ("a", "b"):
        accepted = {n for tenant, n, success in outcomes if success and tenant == owner}
        assert accepted  # progress only, not a fairness/load qualification
        page = bus.estate_page(owner)
        assert not page["retention_gap"] and page["complete"]
        assert {e["payload"]["n"] for e in page["events"]} == accepted
        assert [e["estate_sequence"] for e in page["events"]] == list(range(1, len(accepted) + 1))
