"""24/7 live engine — LiveVendorEngine end-to-end loop test."""

from __future__ import annotations

from universal_vendor.live.engine import LiveVendorEngine
from universal_vendor.live.monitoring import LiveConnector, MonitorMode
from universal_vendor.live.vendor_monitors import CiscoLiveMonitor


def _engine():
    return LiveVendorEngine()


def test_engine_collects_and_applies():
    engine = _engine()
    engine.monitor.register(CiscoLiveMonitor(asset_id="r1", events=[
        {"domain": "ipsec", "action": "modified", "detail": "esp-aes-256"},
    ]))
    outcome = engine.tick()
    assert outcome["events_processed"] >= 1
    assert outcome["state_assets"] == 1
    assert engine.gateway.__len__() >= 1
    assert engine.state.get("r1").vendor == "Cisco"


def test_engine_cbom_and_graph():
    engine = _engine()
    engine.monitor.register(CiscoLiveMonitor(asset_id="r1", events=[
        {"domain": "tls", "action": "modified"},
        {"domain": "certificate", "action": "replaced"},
    ]))
    outcome = engine.tick()
    assert outcome["cbom_components"] >= 2
    assert outcome["graph_nodes"] >= 1


def test_engine_identity_resolution():
    engine = _engine()
    engine.monitor.register(CiscoLiveMonitor(asset_id="r1", events=[
        {"domain": "config", "action": "modified"},
    ]))
    engine.tick()
    assert engine.identity.count() >= 1
    record = engine.identity.resolve(vendor_asset="r1")
    assert record is not None
    assert record.vendor == "Cisco"


def test_engine_repeated_ticks_incremental():
    """24/7: ticks are cheap and repeatable — no duplicate component build-up."""
    engine = _engine()
    monitor = CiscoLiveMonitor(asset_id="r1", events=[
        {"domain": "crypto", "action": "modified"},
    ])
    engine.monitor.register(monitor)
    first = engine.tick()
    second = engine.tick()   # no new events
    assert first["events_processed"] == 1
    assert second["events_processed"] == 0
    # the first event is still re-applied through the gateway (idempotent-ish)
    assert second["cbom_version"] > first["cbom_version"]


def test_engine_drift_pass():
    engine = _engine()

    class SnapshotConnector(LiveConnector):
        vendor = "Cisco"
        product = "IOS-XE"
        mechanism = "netconf"
        modes = [MonitorMode.LIGHTWEIGHT_PERIODIC_POLLING]

        def snapshot(self):
            return {"ssh": "version 2", "crypto": "ike policy 10"}

    engine.monitor.register(SnapshotConnector(asset_id="r1"))
    engine.drift.set_baseline("r1", {"ssh": "version 2", "crypto": "ike policy 10"})
    outcome = engine.tick()
    assert outcome["drift_results"]
    assert outcome["drift_results"][0]["state"] == "NO_CHANGE"
