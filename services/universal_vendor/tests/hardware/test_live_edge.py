"""24/7 distributed hardware monitoring — edge agent (§21).

Edge keeps operating with the control plane down: local durable queue,
local evidence chain, central sync drains only after ACK.
"""

from __future__ import annotations

from universal_vendor.hardware.live import (
    EdgeHardwareAgent,
    HardwareEvent,
    HardwareEventType,
)


def _event(asset: str, etype=HardwareEventType.HARDWARE_CHANGED, agent=None):
    return HardwareEvent(event_type=etype, asset_id=asset, agent_id=agent)


def test_edge_ingest_durable_across_restart(tmp_path):
    queue_path = tmp_path / "events.jsonl"
    agent = EdgeHardwareAgent("edge-a", queue_path=queue_path,
                              evidence_path=tmp_path / "evidence.jsonl")
    agent.ingest(_event("srv-1", agent="edge-a"))
    agent.ingest(_event("srv-2", etype=HardwareEventType.BIOS_CHANGED, agent="edge-a"))
    assert agent.pending_count() == 2
    assert agent.evidence_count() == 2

    # restart: new instance reads the durable file
    restarted = EdgeHardwareAgent("edge-a", queue_path=queue_path,
                                  evidence_path=tmp_path / "evidence.jsonl")
    assert restarted.pending_count() == 2
    assert [e.asset_id for e in restarted.queue.pending()] == ["srv-1", "srv-2"]


def test_edge_sync_drains_only_after_ack(tmp_path):
    agent = EdgeHardwareAgent("edge-b", queue_path=tmp_path / "q.jsonl",
                              evidence_path=tmp_path / "e.jsonl")
    agent.ingest(_event("srv-1"))
    received = []

    def flush(payload):
        received.extend(payload)

    result = agent.sync(flush)
    assert result["synced"] is True
    assert result["events_sent"] == 1
    assert agent.pending_count() == 0
    assert len(received) == 1
    assert received[0]["asset_id"] == "srv-1"


def test_edge_sync_keeps_queue_when_central_down(tmp_path):
    agent = EdgeHardwareAgent("edge-c", queue_path=tmp_path / "q.jsonl",
                              evidence_path=tmp_path / "e.jsonl")
    agent.ingest(_event("srv-1"))
    agent.ingest(_event("srv-2"))

    def failing_flush(payload):
        raise ConnectionError("control plane unreachable")

    result = agent.sync(failing_flush)
    assert result["synced"] is False
    assert result["events_sent"] == 0
    assert agent.pending_count() == 2  # nothing lost

    # central comes back: the same queue drains fully
    received = []
    ok = agent.sync(lambda payload: received.extend(payload))
    assert ok["synced"] is True and ok["events_sent"] == 2
    assert agent.pending_count() == 0
    assert agent.state()["sync_failures"] == 0


def test_edge_evidence_chain_verifies(tmp_path):
    agent = EdgeHardwareAgent("edge-d", queue_path=tmp_path / "q.jsonl",
                              evidence_path=tmp_path / "e.jsonl")
    for i in range(5):
        agent.ingest(_event(f"srv-{i}"))
    verification = agent.evidence.verify(scan_id=f"edge:{agent.agent_id}")
    assert verification.get("valid", verification.get("verified")) is True
    records = agent.evidence.records()
    for i in range(1, len(records)):
        assert records[i]["previous_hash"] == records[i - 1]["chain_hash"]


def test_edge_event_gets_agent_id_stamped(tmp_path):
    agent = EdgeHardwareAgent("edge-e", queue_path=tmp_path / "q.jsonl",
                              evidence_path=tmp_path / "e.jsonl")
    event = _event("srv-1")  # no agent id
    agent.ingest(event)
    assert event.agent_id == "edge-e"
    assert agent.queue.pending()[0].agent_id == "edge-e"
