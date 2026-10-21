"""Event bus mechanics: thread-safe publish, drop-oldest, history, SSE format."""

from __future__ import annotations

import asyncio
import json
import threading

from api.events.bus import HISTORY_SIZE, SUBSCRIBER_QUEUE, EventBus, reset_event_bus


def test_publish_from_thread_reaches_subscriber():
    bus = EventBus()

    async def main():
        sub = bus.subscribe()
        worker = threading.Thread(
            target=lambda: bus.publish("scan.stage", {"stage": "clone"}, source="pipeline")
        )
        worker.start()
        worker.join()
        event = await asyncio.wait_for(sub.queue.get(), timeout=1.0)
        assert event["type"] == "scan.stage"
        assert event["payload"] == {"stage": "clone"}
        assert event["source"] == "pipeline"
        assert isinstance(event["id"], int) and event["id"] >= 1

    asyncio.run(main())


def test_slow_subscriber_drops_oldest_never_blocks_publisher():
    bus = EventBus()

    async def main():
        sub = bus.subscribe()
        for _ in range(SUBSCRIBER_QUEUE + 25):
            bus.publish("t.flood", {"n": 1}, source="test")  # must never block
        for _ in range(20):
            await asyncio.sleep(0)  # drain call_soon callbacks
        assert sub.queue.qsize() <= SUBSCRIBER_QUEUE
        assert sub.dropped >= 25

    asyncio.run(main())


def test_history_recent_and_latest_id():
    bus = EventBus(history_size=10)
    for i in range(15):
        bus.publish("t.n", {"i": i}, source="test")
    assert bus.latest_id() == 15
    recent = bus.recent(since_id=0, limit=100)
    assert len(recent) == 10  # ring buffer kept the last 10
    assert recent[0]["payload"] == {"i": 5}
    tail = bus.recent(since_id=12, limit=5)
    assert [e["id"] for e in tail] == [13, 14, 15]


def test_history_is_bounded():
    bus = EventBus()
    for _ in range(HISTORY_SIZE + 100):
        bus.publish("t.bound", {}, source="test")
    assert len(bus.recent(0, 10_000)) <= HISTORY_SIZE


def test_unsubscribe_stops_delivery_and_stats_track():
    bus = EventBus()

    async def main():
        sub = bus.subscribe()
        assert bus.subscriber_count() == 1
        bus.unsubscribe(sub)
        bus.publish("t.after", {}, source="test")
        for _ in range(10):
            await asyncio.sleep(0)
        assert bus.subscriber_count() == 0
        try:
            await asyncio.wait_for(sub.queue.get(), timeout=0.1)
            raised = False
        except (asyncio.TimeoutError, TimeoutError):
            raised = True
        assert raised

    asyncio.run(main())
    stats = bus.stats()
    assert stats["subscribers"] == 0 and stats["latest_id"] >= 1


def test_format_sse_frames():
    from api.routers.events import format_sse

    frame = format_sse(
        {"id": 7, "replay_cursor": "owner-bound-cursor", "ts": "2026-08-30T00:00:00+00:00", "type": "scan.completed",
         "source": "pipeline", "payload": {"findings": 12}}
    )
    lines = frame.splitlines()
    assert lines[0] == "id: owner-bound-cursor"
    assert lines[1] == "event: scan.completed"
    assert lines[2].startswith("data: ")
    payload = json.loads(lines[2][len("data: "):])
    assert payload["payload"] == {"findings": 12}
    assert frame.endswith("\n\n")


def test_pipeline_publishes_stage_and_completion_events():
    from worker.pipeline.pipeline_runner import PipelineContext, PipelineRunner

    bus = reset_event_bus()
    ctx = PipelineContext(
        job_id="job-1", target_repo="https://example.invalid/x.git", target_branch="main",
        triggered_by="tester", workspace_dir="/tmp/ws", scan_id="scan-1",
    )
    runner = PipelineRunner()
    runner._publish_event(ctx, "clone", "RUNNING", "", None)
    ctx.scan_meta["gate"] = {"decision": "FAIL", "counts": {"blocking": 5}}
    runner._publish_event(ctx, "alert", "COMPLETED", "", None)
    types = [e["type"] for e in bus.recent(0, 100)]
    assert "scan.stage" in types
    completed = bus.recent(0, 100)[-1]
    assert completed["type"] == "scan.completed"
    assert completed["payload"]["extra"]["gate_decision"] == "FAIL"
    assert completed["source"] == "pipeline"


def test_production_remote_publish_failure_is_not_reported_as_success():
    bus = EventBus()
    bus.set_remote_publisher(lambda _event: (_ for _ in ()).throw(OSError("redis down")))
    bus.set_remote_publish_required(True)

    try:
        bus.publish("scan.completed", {"scan_id": "S1"})
    except RuntimeError as exc:
        assert "publication failed" in str(exc)
    else:  # pragma: no cover - assertion branch
        raise AssertionError("durable publication failure was swallowed")

    assert bus.stats()["remote_publish_failures"] == 1
