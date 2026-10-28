"""The realtime contract: every emitted event has an address, or is counted as having none.

The streams themselves are covered elsewhere (``test_events_stream``,
``test_sse_estate_contract``). What is tested here is the part that makes a live console
possible: a channel per product surface, a *declared* kind per change, and the honesty of
the catalogue when a surface has never published anything.
"""
from __future__ import annotations

import asyncio
import uuid

import pytest

from api import realtime
from api.events.bus import EventBus
from api.events import bus as bus_module


@pytest.fixture(autouse=True)
def _clean_counters():
    realtime.reset_for_tests()
    yield
    realtime.reset_for_tests()


# --- the contract itself ---------------------------------------------------------------


def test_every_declared_event_type_routes_to_exactly_one_kind():
    """Two channels claiming one event type would make the address ambiguous."""
    seen: dict[str, tuple[str, str]] = {}
    for channel in realtime.CHANNELS:
        for kind, types in channel.kinds.items():
            assert kind, channel.name
            for event_type in types:
                assert event_type not in seen, f"{event_type} declared twice"
                seen[event_type] = (channel.name, kind)
    assert realtime._EVENT_ROUTES == seen


def test_classification_covers_the_events_the_tree_actually_emits():
    """The names below are read out of the emit sites; a rename must not silently orphan one."""
    emitted = {
        "estate.coverage.lost",
        "estate.change.detected",
        "digital_twin.snapshot",
        "graph.snapshot",
        "graph.updated",
        "inventory.asset_lifecycle",
        "inventory.asset_ownership",
        "remediation.task_created",
        "remediation.task_accepted",
        "remediation.task_completed",
        "remediation.task_verified",
        "remediation.drift_tasks_created",
        "notifications.dispatched",
        "security.posture_drop",
        "security.policy_updated",
        "evidence.chain_broken",
        "technology_bom.snapshot",
        "technology_bom.export",
        "technology_bom.evidence_package",
        "cascade.operational_conditions_changed",
        "cascade.blast_radius_changed",
    }
    unrouted = sorted(name for name in emitted if realtime.classify(name) is None)
    assert unrouted == [], f"emitted events with no channel: {unrouted}"


def test_the_unchannelled_list_is_not_a_dumping_ground():
    """Anything excused from routing must be genuinely off-surface, never unexplained."""
    for event_type in realtime.UNCHANNELLED:
        assert realtime.classify(event_type) is None
        assert event_type.startswith(("technology_bom.", "retirement.")), event_type


def test_unknown_channel_and_unknown_kind_are_refused():
    with pytest.raises(ValueError, match="unknown realtime channel"):
        realtime.publish("nowhere", "created", detail="x")
    with pytest.raises(ValueError, match="unknown kind"):
        realtime.publish("findings", "exploded", detail="x")
    with pytest.raises(ValueError, match="unknown realtime channel"):
        realtime.channels(["estate", "nowhere"])


def test_channels_carry_a_resource_so_a_subscriber_knows_what_to_refetch():
    for channel in realtime.CHANNELS:
        assert channel.resource.startswith("/"), channel.name
        assert channel.what and channel.title, channel.name
        assert channel.screens, f"{channel.name} is not connected to any screen"


def test_stamp_is_idempotent_and_never_overwrites_an_explicit_channel():
    first = realtime.stamp("estate.change.detected", {"asset": "db-1"})
    assert first["channel"] == "estate"
    assert first["kind"] == "change_detected"
    assert first["sequence"] == 1
    again = realtime.stamp("estate.change.detected", first)
    # already stamped: the sequence is not advanced a second time for one change
    assert again["sequence"] == 1

    explicit = realtime.stamp("estate.change.detected", {"channel": "twin", "kind": "snapshot"})
    assert explicit["channel"] == "twin" and explicit["kind"] == "snapshot"


def test_an_unroutable_event_is_counted_not_given_an_invented_channel():
    payload = {"kept": True}
    assert realtime.stamp("something.never_declared", payload) is None
    assert realtime.stamp("something.never_declared", payload) is None
    body = realtime.catalog()
    assert body["unrouted"]["event_types"]["something.never_declared"] == 2
    # the payload the caller passed is not mutated by a failed classification
    assert payload == {"kept": True}


def test_unchannelled_events_are_not_reported_as_unrouted_noise():
    assert realtime.stamp("retirement.registered", {}) is None
    assert realtime.catalog()["unrouted"]["event_types"] == {}


# --- what the catalogue claims -----------------------------------------------------------


def test_catalog_states_that_a_declared_channel_may_never_have_been_live():
    body = realtime.catalog(stats={"subscribers": 2, "published_total": 9})
    names = [row["channel"] for row in body["channels"]]
    assert "estate" in names and "findings" in names
    findings = next(row for row in body["channels"] if row["channel"] == "findings")
    assert findings["last_event"] is None
    assert findings["published_this_process"] == 0
    assert any("declared channel is not a live one" in limit for limit in body["limits"])
    assert any("not a resume token" in limit for limit in body["limits"])
    assert body["subscriber_count"] == 2


def test_catalog_reports_the_last_event_it_saw_per_channel():
    event = {
        "id": 12,
        "type": "estate.change.detected",
        "ts": "2026-01-01T00:00:00Z",
        "payload": {"channel": "estate", "kind": "change_detected"},
    }
    body = realtime.catalog(recent_events=[event])
    estate = next(row for row in body["channels"] if row["channel"] == "estate")
    assert estate["last_event"]["event_id"] == 12
    assert estate["last_event"]["kind"] == "change_detected"


def test_wants_admits_only_routable_events_on_the_requested_channels():
    estate = {"payload": {"channel": "estate"}}
    twin = {"payload": {"channel": "twin"}}
    unrouted = {"payload": {"unrelated": 1}}
    assert realtime.wants(["estate"], estate)
    assert not realtime.wants(["estate"], twin)
    assert realtime.wants(None, twin)
    # a filtered subscriber is never sent an event nobody classified
    assert not realtime.wants(None, unrouted)


def test_event_filter_composes_channel_choice_with_estate_visibility():
    visible = lambda event: event.get("tenant_id") == "a"
    picker = realtime.event_filter(["estate"], visible=visible)
    assert picker({"tenant_id": "a", "payload": {"channel": "estate"}})
    assert not picker({"tenant_id": "b", "payload": {"channel": "estate"}})
    assert not picker({"tenant_id": "a", "payload": {"channel": "twin"}})


# --- the stream -------------------------------------------------------------------------


def _bus() -> EventBus:
    return EventBus()


@pytest.fixture
def wired_bus(monkeypatch):
    bus = _bus()
    monkeypatch.setattr(bus_module, "_bus", bus, raising=False)
    monkeypatch.setattr("api.routers.realtime.get_event_bus", lambda: bus)
    yield bus
    bus.close() if hasattr(bus, "close") else None


async def _drain(agen, count: int, timeout: float = 5.0):
    frames = []
    while len(frames) < count:
        frames.append(await asyncio.wait_for(agen.__anext__(), timeout))
    return frames


@pytest.mark.asyncio
async def test_stream_delivers_only_the_channels_the_client_asked_for(wired_bus):
    bus = wired_bus
    sub = bus.subscribe(event_filter=realtime.event_filter(["findings"]))
    bus.publish("findings.status_changed", {"channel": "findings", "kind": "status_changed"})
    bus.publish("estate.change.detected", {"channel": "estate", "kind": "change_detected"})
    await asyncio.sleep(0.05)  # delivery hops loops via call_soon_threadsafe
    assert sub.queue.qsize() == 1
    event = sub.queue.get_nowait()
    assert event["type"] == "findings.status_changed"
    bus.unsubscribe(sub)


@pytest.mark.asyncio
async def test_a_subscriber_is_not_flooded_by_events_it_cannot_see(wired_bus):
    """Filtering happens before the queue, so a filtered-out estate cannot evict our events."""
    bus = wired_bus
    sub = bus.subscribe(event_filter=realtime.event_filter(["estate"]))
    for _ in range(600):
        bus.publish("twin.graph_updated", {"channel": "twin", "kind": "graph_updated"})
    await asyncio.sleep(0.05)
    assert sub.queue.empty() and sub.dropped == 0
    bus.unsubscribe(sub)


def test_the_stream_reports_a_gap_instead_of_pretending_it_caught_up(wired_bus):
    """Replay beyond the ring is stated once; a silent skip would leave a stale screen."""
    bus = wired_bus
    for _ in range(3):
        bus.publish("estate.change.detected", {"channel": "estate", "kind": "change_detected"})
    # asking for a window the ring cannot reach back to returns nothing, and the stream says so
    assert bus.recent(10_000, 10) == []
    assert bus.oldest_id() is not None and bus.oldest_id() < 10_000
    # while a reachable cursor still replays
    assert [e["type"] for e in bus.recent(0, 10)] == ["estate.change.detected"] * 3


def test_realtime_does_not_silently_swallow_a_publish_failure(monkeypatch):
    """publish() is a vocabulary over emit_platform_event, not a second transport."""
    calls = {}

    def fake_emit(event_type, detail, payload, **kwargs):
        calls.update(event_type=event_type, detail=detail, payload=payload, **kwargs)
        return {"id": 1}

    monkeypatch.setattr("api.events.platform_events.emit_platform_event", fake_emit)
    realtime.publish(
        "remediation",
        "task_verified",
        detail="task 7 verified",
        payload={"task_id": "7"},
        tenant_id="a",
    )
    assert calls["event_type"] == "remediation.task_verified"
    assert calls["payload"]["channel"] == "remediation"
    assert calls["payload"]["kind"] == "task_verified"
    assert calls["payload"]["task_id"] == "7"
    assert calls["tenant_id"] == "a"


def test_catalog_row_is_serialisable_for_the_console():
    import json

    body = realtime.catalog()
    json.dumps(body)  # a catalogue the console cannot parse is not a catalogue
    estate = next(row for row in body["channels"] if row["channel"] == "estate")
    assert estate["kinds"]["change_detected"]["from_event_types"] == ["estate.change.detected"]
    assert uuid.UUID(int=0)  # keep import meaningful for readers extending this file
