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


def test_a_surface_event_records_the_surface_without_inventing_an_algorithm():
    """A changed TLS or certificate surface is a real observation; its
    algorithm is not.

    _EVENT_SURFACE_TYPES in live/cbom.py draws this line deliberately: a
    TLS_CHANGED or CERTIFICATE_REPLACED event proves a cryptographic surface
    exists and changed, even when the source never reported which algorithm
    is on it. So the component is materialized, and every algorithm property
    stays absent until evidence supplies one.

    Asserting the component *count* alone cannot tell those apart -- a
    fabricated "unknown algorithm" row would count the same. The assertion
    that matters is algorithm is None, which is the rule update.md section 3
    states: a finding must not become a CBOM algorithm without an explicit
    crypto field.
    """
    engine = _engine()
    engine.monitor.register(CiscoLiveMonitor(asset_id="r1", events=[
        {"domain": "tls", "action": "modified"},
        {"domain": "certificate", "action": "replaced"},
    ]))
    outcome = engine.tick()

    assert outcome["cbom_components"] == 2
    assert outcome["graph_nodes"] >= 1

    kinds = set()
    for component in engine.cbom.components():
        crypto = component.get("cryptoProperties") or {}
        kinds.add(crypto.get("assetType"))
        algorithm = (crypto.get("algorithmProperties") or {}).get("algorithm")
        assert algorithm is None, (
            f"{component.get('name')} reports algorithm {algorithm!r} from an "
            "event that carried no algorithm — that is a fabricated finding"
        )
    assert kinds == {"protocol", "certificate"}


def test_an_explicit_crypto_observation_does_become_a_cbom_component():
    """The other half of the rule: a real observation must still land.

    Without this the test above could be satisfied by a CBOM that never
    materializes anything.
    """
    engine = _engine()
    engine.monitor.register(CiscoLiveMonitor(asset_id="r2", events=[
        {
            "domain": "tls",
            "action": "modified",
            "observation": {"algorithm": "RSA-2048", "protocol": "TLS1.2"},
        },
    ]))
    outcome = engine.tick()

    assert outcome["cbom_components"] >= 1
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
    # The property this test is named for: no duplicate component build-up.
    assert second["cbom_components"] == first["cbom_components"]
    # A quiet tick still re-materializes the known events to record liveness
    # in the append-only history, so the version advances. That is the
    # documented intent at engine.py's "records liveness without building
    # duplicates" — see test_quiet_ticks_grow_the_event_log for the cost.
    assert second["cbom_version"] > first["cbom_version"]


def test_quiet_ticks_grow_the_event_log_without_new_events():
    """Records a real cost of the liveness re-materialization, unresolved.

    engine.tick() re-applies every known gateway event when none are
    pending, which keeps components idempotent (asserted above) but appends
    one row to LiveCbom._event_log and bumps the version on every tick.

    Measured: one real event followed by 50 quiet ticks leaves version 53
    and 52 log entries for a single observation. A 24/7 loop on a two-second
    interval therefore accumulates ~43k duplicate entries a day and a
    version number that counts ticks rather than changes.

    Two comments in engine.tick() disagree about this: the step-2 block
    promises "no repeated CBOM version bumps" and the block ten lines below
    performs exactly that. This test pins the behaviour that actually ships
    so the contradiction is visible in CI rather than in a reading of the
    source; it is a product decision whether liveness belongs in the
    version, in a separate heartbeat, or in a bounded log.
    """
    engine = _engine()
    engine.monitor.register(CiscoLiveMonitor(asset_id="r1", events=[
        {"domain": "tls", "action": "modified"},
    ]))
    first = engine.tick()
    for _ in range(10):
        engine.tick()
    last = engine.tick()

    assert last["cbom_components"] == first["cbom_components"]  # still idempotent
    assert last["cbom_version"] == first["cbom_version"] + 11
    assert len(engine.cbom._event_log) == 12  # 1 real + 11 re-materializations


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
