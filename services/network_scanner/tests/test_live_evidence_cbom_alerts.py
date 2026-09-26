"""Live layer — evidence chain, event-sourced CBOM, alert engine, health."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from network_scanner.enterprise.live.agent import (
    ControlPlane,
    EdgeAgent,
    EvidenceCache,
    LocalQueue,
    SecureSyncEngine,
)
from network_scanner.enterprise.live.alerts import (
    SEVERITIES,
    Alert,
    AlertDeduplicator,
    AlertEngine,
    CorrelatedIncident,
)
from network_scanner.enterprise.live.cbom import (
    CBOM_EVENT_TYPES,
    CbomEvent,
    CbomEventLog,
    CbomMaterializer,
    LiveCBOM,
)
from network_scanner.enterprise.live.evidence import (
    GENESIS_HASH,
    EvidenceChain,
    canonical_bytes,
)
from network_scanner.enterprise.live.health import (
    HEALTH_STATES,
    ScannerHealthMonitor,
)

T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------- evidence

def test_evidence_chain_appends_and_links():
    chain = EvidenceChain()
    r1 = chain.append({"event": "A"})
    r2 = chain.append({"event": "B"})
    assert r1.previous_hash == GENESIS_HASH
    assert r2.previous_hash == r1.content_hash
    assert len(chain) == 2
    assert chain.verify() is True


def test_evidence_chain_detects_tamper():
    chain = EvidenceChain()
    chain.append({"event": "A"})
    chain.append({"event": "B"})
    record = chain.records()[0]
    record.canonical = canonical_bytes({"event": "EVIL"}).decode("utf-8")
    assert chain.verify() is False


def test_evidence_chain_detects_middle_break():
    chain = EvidenceChain()
    chain.append({"event": "A"})
    r2 = chain.append({"event": "B"})
    r3 = chain.append({"event": "C"})
    # break the middle link by mutating r2's previous hash
    r2.previous_hash = "TAMPERED"
    assert chain.verify() is False
    assert r3.previous_hash == r2.content_hash


def test_evidence_canonical_serialization_deterministic():
    assert canonical_bytes({"b": 1, "a": 2}) == canonical_bytes({"a": 2, "b": 1})


def test_evidence_record_id_changes_with_content():
    chain = EvidenceChain()
    r1 = chain.append({"x": 1})
    r2 = chain.append({"x": 2})
    assert r1.record_id != r2.record_id


def test_evidence_verify_from_tail():
    chain = EvidenceChain()
    chain.append({"event": "A"})
    chain.append({"event": "B"})
    chain.append({"event": "C"})
    assert chain.verify_from(1) is True
    chain.records()[2].canonical = canonical_bytes({"event": "X"}).decode("utf-8")
    assert chain.verify_from(1) is False


def test_evidence_record_dict_shape():
    chain = EvidenceChain(clock=lambda: T0)
    record = chain.append({"event": "A"})
    d = record.to_dict()
    assert d["sequence"] == 0
    assert d["previous_hash"] == "GENESIS"
    assert d["observed_at"] == T0.isoformat()
    assert d["record_id"]


def test_evidence_extend():
    chain = EvidenceChain()
    records = chain.extend([{"n": 1}, {"n": 2}, {"n": 3}])
    assert len(records) == 3
    assert [r.sequence for r in records] == [0, 1, 2]


# ---------------------------------------------------------------- CBOM

def test_cbom_event_validation():
    CbomEventLog()
    with pytest.raises(ValueError):
        CbomEvent(sequence=0, event_type="BOGUS", asset_id="a", occurred_at=T0)


def test_cbom_event_log_sequences():
    log = CbomEventLog()
    e1 = log.append("ASSET_DISCOVERED", "a", occurred_at=T0)
    e2 = log.append("ASSET_DISCOVERED", "b", occurred_at=T0)
    assert e1.sequence == 0
    assert e2.sequence == 1
    assert len(log) == 2


def test_cbom_event_log_filters():
    log = CbomEventLog()
    log.append("ASSET_DISCOVERED", "a", occurred_at=T0)
    log.append("TLS_CHANGED", "a", occurred_at=T0)
    log.append("ASSET_DISCOVERED", "b", occurred_at=T0)
    assert [e.asset_id for e in log.events(after=0)] == ["a", "b"]
    assert [e.asset_id for e in log.events(asset_id="a")] == ["a", "a"]
    assert [e.asset_id for e in log.events(event_type="ASSET_DISCOVERED")] == ["a", "b"]


def test_live_cbom_applies_upsert_and_remove():
    log = CbomEventLog()
    log.append("ASSET_DISCOVERED", "web-1", occurred_at=T0,
               snapshot={"tls_version": "TLSv1.3"})
    log.append("TLS_CHANGED", "web-1", occurred_at=T0,
               snapshot={"tls_version": "TLSv1.2"}, change={"from": "TLSv1.3"})
    log.append("ASSET_REMOVED", "web-1", occurred_at=T0)
    cbom = LiveCBOM()
    for event in log.events():
        cbom.apply(event)
    assert cbom.get("web-1") is None


def test_cbom_materializer_live_and_reconstruct():
    materializer = CbomMaterializer()
    materializer.ingest("ASSET_DISCOVERED", "web-1",
                        snapshot={"tls_version": "TLSv1.3"}, occurred_at=T0)
    materializer.ingest("ASSET_DISCOVERED", "db-1",
                        snapshot={"tls_version": "TLSv1.2"}, occurred_at=T0)
    materializer.ingest("TLS_CHANGED", "web-1",
                        snapshot={"tls_version": "TLSv1.2"}, occurred_at=T0 + timedelta(days=1))
    materializer.ingest("DEVICE_REMOVED", "db-1", occurred_at=T0 + timedelta(days=2))

    live = materializer.live()
    assert live.get("web-1")["tls_version"] == "TLSv1.2"
    assert live.get("db-1") is None

    historical = materializer.reconstruct(T0 + timedelta(hours=12))
    assert historical.get("web-1")["tls_version"] == "TLSv1.3"
    assert historical.get("db-1") is not None
    summary = live.summary()
    assert summary["component_count"] == 1


def test_cbom_materializer_ingest_report():
    materializer = CbomMaterializer()
    events = materializer.ingest_report({
        "assets": [{"asset_id": "web-1", "hostname": "web-1"},
                   {"asset_id": "db-1", "hostname": "db-1"}],
        "tls_intelligence": [{"endpoint": "web-1:443"}],
        "tunnels": [{"tunnel_id": "tun-1"}],
    })
    kinds = [e.event_type for e in events]
    assert "ASSET_DISCOVERED" in kinds
    assert "TLS_CHANGED" in kinds
    assert "VPN_CHANGED" in kinds
    assert len(events) == 4


def test_cbom_history():
    materializer = CbomMaterializer()
    materializer.ingest("ASSET_DISCOVERED", "web-1", snapshot={}, occurred_at=T0)
    materializer.ingest("TLS_CHANGED", "web-1", snapshot={}, occurred_at=T0)
    history = materializer.history("web-1")
    assert len(history) == 2


def test_cbom_event_types():
    for event_type in ("ASSET_DISCOVERED", "CERTIFICATE_CHANGED", "TLS_CHANGED",
                       "VPN_CHANGED", "DEVICE_REMOVED"):
        assert event_type in CBOM_EVENT_TYPES


# ---------------------------------------------------------------- alerts

def test_severities_order():
    assert SEVERITIES == ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_alert_validation():
    with pytest.raises(ValueError):
        Alert(severity="EXTREME", title="x")


def test_alert_fields_spec():
    alert = AlertEngine().raise_alert(
        severity="CRITICAL",
        title="Weak crypto on internet-facing banking system",
        what_changed="TLS 1.0 enabled",
        where="bank-web-1:443",
        owner="payments-team",
        evidence=[{"finding": "WEAK_TLS_VERSION"}],
        impact="PCI data exposure",
        dependencies=["bank-web-1", "bank-app-1"],
        recommended_action="Disable TLS 1.0",
        correlation_key="tls-policy:bank-web-1",
        source="tls_watcher",
    )
    d = alert.to_dict()
    assert d["severity"] == "CRITICAL"
    assert d["who_owns_asset"] == "payments-team"
    assert d["dependencies"] == ["bank-web-1", "bank-app-1"]
    assert d["recommended_action"]
    assert d["correlation_key"] == "tls-policy:bank-web-1"


def test_alert_engine_history_and_pending():
    engine = AlertEngine()
    engine.raise_alert(severity="LOW", title="New internal TLS endpoint detected",
                       what_changed="new endpoint", where="svc-1:443")
    assert len(engine.pending()) == 1
    assert len(engine.history()) == 1
    engine.drain(correlate=False)
    assert engine.pending() == []


def test_alert_deduplication_correlates():
    dedup = AlertDeduplicator()
    alerts = [
        Alert(severity="HIGH", title="Root CA change",
              correlation_key="root-ca:fp-9",
              dependencies=[f"app-{i}"])
        for i in range(3)
    ]
    incidents = dedup.correlate(alerts)
    assert len(incidents) == 1
    assert incidents[0].alerts_collapsed == 3
    assert incidents[0].impacted_count == 3


def test_alert_deduplication_merges_many_alerts():
    dedup = AlertDeduplicator()
    alerts = [
        Alert(severity="MEDIUM", title="cert affected", where=f"endpoint-{i}",
              correlation_key="root-ca:fp-9", dependencies=[f"app-{i}"])
        for i in range(500)
    ]
    incidents = dedup.correlate(alerts)
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.alerts_collapsed == 500
    assert incident.impacted_count == 1000  # 500 endpoints + 500 apps
    assert len(incident.affected_assets) == 200  # capped


def test_alert_deduplication_separate_keys():
    dedup = AlertDeduplicator()
    incidents = dedup.correlate([
        Alert(severity="HIGH", title="a", correlation_key="k1"),
        Alert(severity="LOW", title="b", correlation_key="k2"),
    ])
    assert len(incidents) == 2
    assert incidents[0].correlation_key == "k1"


def test_alert_engine_drain_correlated():
    engine = AlertEngine()
    for i in range(50):
        engine.raise_alert(severity="HIGH", title="Root CA rotated",
                           where=f"ep-{i}", correlation_key="root-ca:fp-9",
                           dependencies=[f"app-{i}"])
    incidents = engine.drain(correlate=True)
    assert isinstance(incidents, list)
    assert len(incidents) == 1
    assert isinstance(incidents[0], CorrelatedIncident)
    assert incidents[0].alerts_collapsed == 50


def test_alert_engine_sink_called():
    seen = []
    engine = AlertEngine(sink=seen.append)
    engine.raise_alert(severity="INFO", title="t")
    assert len(seen) == 1


# ---------------------------------------------------------------- health

def test_health_states():
    assert HEALTH_STATES == ("HEALTHY", "DEGRADED", "UNREACHABLE",
                             "FAILED", "MAINTENANCE")


def test_health_healthy_with_heartbeat():
    monitor = ScannerHealthMonitor()
    monitor.heartbeat(now=T0)
    assert monitor.state(now=T0) == "HEALTHY"


def test_health_unreachable_without_heartbeat():
    monitor = ScannerHealthMonitor()
    assert monitor.state(now=T0) == "UNREACHABLE"


def test_health_degraded_on_high_cpu():
    monitor = ScannerHealthMonitor()
    monitor.tick(cpu=99.0, heartbeat=True, now=T0)
    assert monitor.state(now=T0) == "DEGRADED"


def test_health_degraded_on_queue_depth():
    monitor = ScannerHealthMonitor()
    monitor.tick(queue_depth=50_000, heartbeat=True, now=T0)
    assert monitor.state(now=T0) == "DEGRADED"


def test_health_failed_on_stale_heartbeat():
    monitor = ScannerHealthMonitor()
    monitor.heartbeat(now=T0)
    assert monitor.state(now=T0 + timedelta(minutes=3)) == "FAILED"
    assert monitor.state(now=T0 + timedelta(minutes=20)) == "UNREACHABLE"


def test_health_maintenance():
    monitor = ScannerHealthMonitor()
    monitor.heartbeat(now=T0)
    monitor.mark_maintenance(on=True)
    assert monitor.state(now=T0) == "MAINTENANCE"


def test_health_scan_success_sets_heartbeat():
    monitor = ScannerHealthMonitor()
    monitor.mark_scan_success(now=T0)
    assert monitor.report(now=T0)["last_successful_scan"] == T0.isoformat()


def test_health_report_shape():
    monitor = ScannerHealthMonitor(agent_id="agent-1")
    monitor.tick(cpu=10, memory=20, heartbeat=True, now=T0)
    report = monitor.report(now=T0)
    assert report["agent_id"] == "agent-1"
    assert report["state"] == "HEALTHY"
    assert report["sample"]["cpu"] == 10
    assert report["history_len"] == 1


# ---------------------------------------------------------------- agent

def test_local_queue_bounded():
    queue = LocalQueue(max_items=3)
    assert queue.put({"a": 1}) is True
    assert queue.put({"a": 2}) is True
    assert queue.put({"a": 3}) is True
    assert queue.put({"a": 4}) is False  # full
    assert queue.pending() == 3
    assert len(queue.get_many(10)) == 3


def test_local_queue_fifo():
    queue = LocalQueue()
    queue.put_many([{"n": 1}, {"n": 2}, {"n": 3}])
    assert queue.get_many(2) == [{"n": 1}, {"n": 2}]
    assert queue.pending() == 1


def test_evidence_cache_bounded_and_store():
    cache = EvidenceCache(max_items=2)
    cache.store("a", {"v": 1})
    cache.store("b", {"v": 2})
    cache.store("c", {"v": 3})  # full — dropped
    assert cache.size() == 2
    assert cache.get("a")["v"] == 1
    # overwriting an existing key is allowed even when full
    cache.store("a", {"v": 9})
    assert cache.get("a")["v"] == 9


def test_secure_sync_online_upload():
    uploaded = []

    def uploader(batch):
        uploaded.extend(batch)
        return {"ok": True}

    sync = SecureSyncEngine(uploader=uploader)
    sync.enqueue({"id": 1})
    sync.enqueue({"id": 2})
    result = sync.sync()
    assert result["online"] is True
    assert result["synced"] == 2
    assert uploaded == [{"id": 1}, {"id": 2}]
    assert sync.queue.pending() == 0


def test_secure_sync_offline_buffers():
    sync = SecureSyncEngine(is_online=lambda: False, uploader=lambda b: {})
    sync.enqueue({"id": 1})
    result = sync.sync()
    assert result["online"] is False
    assert sync.queue.pending() == 1


def test_secure_sync_failed_requeues():
    sync = SecureSyncEngine(uploader=lambda batch: (_ for _ in ()).throw(RuntimeError("down")))
    sync.enqueue({"id": 1})
    result = sync.sync()
    assert result["failed"] == 1
    assert sync.queue.pending() == 1  # re-queued


def test_edge_agent_collect_and_status():
    agent = EdgeAgent(
        region="UAE",
        collector=lambda: [{"kind": "observation", "asset": "rtr-1"}],
    )
    agent.collect()
    assert agent.queue.pending() == 1
    status = agent.status()
    assert status["region"] == "UAE"
    assert status["queue_depth"] == 1
    assert status["health"]["state"] in HEALTH_STATES


def test_edge_agent_agent_id_default():
    assert EdgeAgent(region="EU").agent_id == "eu-agent"
    assert EdgeAgent(region="USA", agent_id="us-1").agent_id == "us-1"


def test_control_plane_registers_and_summarizes():
    plane = ControlPlane()
    plane.register(EdgeAgent(region="UAE", agent_id="uae-1"))
    plane.register(EdgeAgent(region="EU", agent_id="eu-1"))
    assert len(plane.agents()) == 2
    summary = plane.summary()
    assert summary["agents"] == 2
    assert summary["regions"] == ["EU", "UAE"]
    assert "UNREACHABLE" in summary["health_states"]  # no heartbeats yet


def test_control_plane_orchestrates_sync():
    synced = []
    plane = ControlPlane()
    plane.register(EdgeAgent(
        region="USA", agent_id="us-1",
        sync=SecureSyncEngine(uploader=lambda batch: synced.extend(batch) or {})))
    plane.get("us-1").queue.put({"id": 1})
    results = plane.orchestrate_sync()
    assert results[0]["synced"] == 1
    assert synced == [{"id": 1}]
