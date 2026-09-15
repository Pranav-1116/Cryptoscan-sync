"""Envelope signing, topic registry, and the persistent bus."""

from __future__ import annotations

import json

import pytest

from eventstream.bus import StreamBus
from eventstream.envelope import canonical_bytes, content_hash, sign_envelope, verify_envelope
from eventstream.topics import CONSUMERS, PRODUCERS, TOPICS, validate_topic

SECRET = "test-stream-secret-0123456789ab"


def test_canonical_bytes_are_deterministic():
    a = {"b": 1, "a": [2, {"z": True, "y": None}]}
    b = {"a": [2, {"y": None, "z": True}], "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b)
    assert content_hash(a) == content_hash(b)


def test_envelope_sign_and_verify():
    env = sign_envelope({"hello": "world"}, topic="raw-events", key="k1", seq=1,
                        source="test", secret=SECRET)
    assert verify_envelope(env, SECRET)
    assert env["seq"] == 1 and env["topic"] == "raw-events"

    tampered = dict(env)
    tampered["payload"] = {"hello": "evil"}
    assert not verify_envelope(tampered, SECRET)

    wrong_key = dict(env)
    wrong_key["hmac"] = "0" * 64
    assert not verify_envelope(wrong_key, SECRET)

    assert not verify_envelope(env, "other-secret")


def test_topic_registry_is_the_contract():
    assert set(TOPICS) == {"raw-events", "normalized-events", "policy-results",
                           "attack-detections", "cbom-updates", "graph-sync",
                           "audit-log", "alerts"}
    # every topic declares its producers and consumers
    assert set(PRODUCERS) == set(TOPICS) and set(CONSUMERS) == set(TOPICS)
    with pytest.raises(ValueError):
        validate_topic("not-a-topic")


def test_bus_publish_replay_and_persistence(tmp_path):
    bus = StreamBus(tmp_path / "logs", secret=SECRET)
    e1 = bus.publish("raw-events", {"kind": "tls_finding", "endpoint": "a:443"},
                     key="a", source="t")
    e2 = bus.publish("raw-events", {"kind": "tls_finding", "endpoint": "b:443"},
                     key="b", source="t")
    assert (e1["seq"], e2["seq"]) == (1, 2)
    replayed = [e["payload"]["endpoint"] for e in bus.replay("raw-events")]
    assert replayed == ["a:443", "b:443"]
    # persistence: a fresh bus on the same dir replays the same log
    bus2 = StreamBus(tmp_path / "logs", secret=SECRET)
    assert bus2._seq["raw-events"] == 2
    assert [e["seq"] for e in bus2.replay("raw-events")] == [1, 2]


def test_bus_consumer_groups_are_independent(tmp_path):
    bus = StreamBus(tmp_path / "logs", secret=SECRET)
    for i in range(5):
        bus.publish("cbom-updates", {"n": i})
    a = bus.read("cbom-updates", "group-a", limit=2)
    b = bus.read("cbom-updates", "group-b", limit=3)
    assert len(a) == 2 and len(b) == 3
    bus.commit("cbom-updates", "group-a", a[-1]["seq"])
    again = bus.read("cbom-updates", "group-a")
    assert [e["seq"] for e in again] == [3, 4, 5]
    # group-b cursor untouched by group-a's commit
    assert bus.read("cbom-updates", "group-b")[0]["seq"] == 1
    stats = bus.stats()["topics"]["cbom-updates"]
    assert stats["consumer_groups"]["group-a"]["lag"] == 3
    assert stats["consumer_groups"]["group-b"]["lag"] == 5


def test_bus_never_delivers_a_tampered_line(tmp_path):
    bus = StreamBus(tmp_path / "logs", secret=SECRET)
    bus.publish("alerts", {"ok": True})
    with open(tmp_path / "logs" / "alerts.jsonl", "a", encoding="utf-8") as fh:
        evil = {"v": 1, "topic": "alerts", "key": "k", "seq": 99, "source": "attacker",
                "ts": "now", "payload": {"ok": False}, "payload_hash": "0" * 64,
                "hmac": "0" * 64}
        fh.write(json.dumps(evil) + "\n")
    bus2 = StreamBus(tmp_path / "logs", secret=SECRET)
    delivered = bus2.read("alerts", "g")
    assert [e["payload"] for e in delivered] == [{"ok": True}]
    assert [e["seq"] for e in bus2.replay("alerts")] == [1]
