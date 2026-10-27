"""Live layer — the 24/7 LiveNetworkMonitor orchestrator + wiring."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from network_scanner.core.scanner import NetworkTlsScanner
from network_scanner.enterprise.live.loop import (
    LiveNetworkMonitor,
)

T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


def _report(assets=("web-1", "db-1"), tls=None, certs=None, topology=None,
            tls_version="TLSv1.3"):
    report = {
        "assets": [{"asset_id": aid, "hostname": aid, "ip": f"10.0.0.{i+1}",
                    "device_type": "server", "criticality": 10.0,
                    "internet_exposed": True, "crypto_risk": 10.0,
                    "change_frequency": 10.0, "compliance_importance": 10.0,
                    "tls_version": tls_version, "public_key_size": 3072}
                   for i, aid in enumerate(assets)],
        "tls_intelligence": tls or [],
        "certificates": certs or [],
        "evidence": {"certificates": certs or []},
        "topology": topology,
    }
    return report


def _monitor(scan_fn, *, scope=None, events=(), **kwargs):
    return LiveNetworkMonitor(
        scope_specs=scope or ["10.0.0.0/24"],
        scan_fn=scan_fn,
        options={"events": list(events)},
        clock=lambda: T0,
        **kwargs,
    )


# ------------------------------------------------------------- first cycle

def test_first_cycle_full_scan_populates_state():
    calls = []

    def scan(specs, mode):
        calls.append((list(specs), mode))
        return _report()

    monitor = _monitor(scan)
    result = monitor.cycle(now=T0)
    assert calls[0] == (["10.0.0.0/24"], "SAFE")  # LIGHTWEIGHT → SAFE
    assert result.scanned_assets == ["web-1", "db-1"]
    assert len(result.transitions) == 2
    assert all(t["kind"] == "FIRST_SEEN" for t in result.transitions)
    assert monitor.state.count() == 2
    # CBOM events recorded
    assert len(result.cbom_events) == 2


def test_second_cycle_no_full_restart():
    calls = []

    def scan(specs, mode):
        calls.append((list(specs), mode))
        return _report()

    monitor = _monitor(scan)
    monitor.cycle(now=T0)
    monitor.cycle(now=T0 + timedelta(seconds=30))
    # second cycle: assets not due yet (CRITICAL interval 60s) → no rescans
    assert len(calls) == 1


def test_periodic_lightweight_rescan_when_due():
    calls = []

    def scan(specs, mode):
        calls.append((list(specs), mode))
        return _report()

    monitor = _monitor(scan)
    monitor.cycle(now=T0)
    monitor.cycle(now=T0 + timedelta(seconds=61))
    assert len(calls) == 3  # full scan + 2 lightweight rescans (web-1, db-1)
    assert calls[1] == (["web-1"], "SAFE")  # LIGHTWEIGHT → SAFE
    assert calls[2] == (["db-1"], "SAFE")  # LIGHTWEIGHT → SAFE


def test_deep_scan_due_weekly():
    calls = []

    def scan(specs, mode):
        calls.append((list(specs), mode))
        return _report()

    monitor = _monitor(scan)
    monitor.cycle(now=T0)
    monitor.cycle(now=T0 + timedelta(days=8))
    modes = [mode for _, mode in calls[1:]]
    assert "DEEP" in modes
    assert "SAFE" in modes  # LIGHTWEIGHT → SAFE


# ------------------------------------------------------------- events

def test_event_triggers_targeted_rescan_only():
    calls = []

    def scan(specs, mode):
        calls.append((list(specs), mode))
        return _report(assets=("web-1",))

    monitor = _monitor(scan, events=[
        {"kind": "CERTIFICATE_REPLACED", "hostname": "web-1",
         "observed_at": "2026-08-30T12:00:00Z"},
    ])
    result = monitor.cycle(now=T0)
    assert result.targeted_rescans == ["web-1"]
    assert len(calls) == 2  # full scan + targeted
    assert calls[1] == (["web-1"], "DEEP")  # crypto event → DEEP


def test_event_impact_includes_dependents():
    calls = []

    def scan(specs, mode):
        calls.append((list(specs), mode))
        return _report(assets=("web-1",))

    monitor = LiveNetworkMonitor(
        scope_specs=["10.0.0.0/24"],
        scan_fn=scan,
        options={"events": [{"kind": "TLS_POLICY_CHANGED", "hostname": "web-1",
                             "observed_at": "2026-08-30T12:00:00Z"}]},
        clock=lambda: T0,
    )
    monitor.impact = _DependentsImpact({"web-1": ["lb-1"]})
    result = monitor.cycle(now=T0)
    # web-1 + dependent lb-1 rescanned
    assert set(result.targeted_rescans) == {"web-1", "lb-1"}


class _DependentsImpact:
    def __init__(self, deps):
        self._deps = deps

    def analyze(self, event):
        impacted = list(event.asset_ids)
        for asset in event.asset_ids:
            impacted.extend(self._deps.get(asset, []))
        return {"event": event.kind, "impacted_assets": impacted,
                "primary_assets": list(event.asset_ids),
                "targeted_scan_mode": "DEEP",
                "severity": event.severity}


def test_event_normalizer_skips_unknown_events():
    calls = []

    def scan(specs, mode):
        calls.append((list(specs), mode))
        return _report()

    monitor = _monitor(scan, events=[{"kind": "NOT_A_REAL_EVENT"}])
    result = monitor.cycle(now=T0)
    assert result.events == []
    assert len(calls) == 1


def test_events_write_evidence():
    def scan(specs, mode):
        return _report()

    monitor = _monitor(scan, events=[{"kind": "NEW_DEVICE_CONNECTED",
                                      "hostname": "web-1",
                                      "observed_at": "2026-08-30T12:00:00Z"}])
    monitor.cycle(now=T0)
    assert len(monitor.evidence) >= 1
    assert monitor.evidence.verify() is True


# ------------------------------------------------------------- watchers

def test_tls_change_detected_across_cycles():
    def scan(specs, mode):
        if monitor._cycle == 1:
            return _report(tls=[{"endpoint": "web-1:443",
                                 "tls_version": "TLSv1.3"}])
        return _report(tls=[{"endpoint": "web-1:443",
                             "tls_version": "TLSv1.0"}])

    monitor = _monitor(scan)
    r1 = monitor.cycle(now=T0)
    assert r1.tls_changes == []  # first observation
    r2 = monitor.cycle(now=T0 + timedelta(seconds=61))
    assert len(r2.tls_changes) == 1
    assert r2.tls_changes[0]["alert"] is True
    assert r2.tls_changes[0]["changed_fields"] == ["tls_version"]


def test_cert_change_detected():
    def scan(specs, mode):
        if monitor._cycle == 1:
            return _report(certs=[{"fingerprint_sha256": "fp-1",
                                   "subject": "CN=web-1",
                                   "serial_number": "111",
                                   "not_valid_after": "2030-01-01T00:00:00Z"}])
        return _report(certs=[{"fingerprint_sha256": "fp-1",
                               "subject": "CN=web-1",
                               "serial_number": "222",
                               "not_valid_after": "2030-01-01T00:00:00Z"}])

    monitor = _monitor(scan)
    r1 = monitor.cycle(now=T0)
    assert [c["kind"] for c in r1.cert_changes] == ["NEW_CERTIFICATE"]
    r2 = monitor.cycle(now=T0 + timedelta(seconds=61))
    assert any(c["kind"] == "CERTIFICATE_RENEWED" for c in r2.cert_changes)


def test_topology_baseline_then_change():
    def scan(specs, mode):
        if monitor._cycle == 1:
            return _report(topology={"edges": [
                {"source": "web-1", "target": "lb-1", "relationship": "CONNECTED_TO"}]})
        return _report(topology={"edges": [
            {"source": "web-1", "target": "lb-1", "relationship": "CONNECTED_TO"},
            {"source": "db-1", "target": "app-1", "relationship": "CONNECTED_TO"}]})

    monitor = _monitor(scan)
    r1 = monitor.cycle(now=T0)
    assert r1.topology_changes == []  # baseline
    r2 = monitor.cycle(now=T0 + timedelta(seconds=61))
    assert any(c["kind"] == "NEW_CONNECTION" for c in r2.topology_changes)


# ------------------------------------------------------------- PQC

def test_pqc_reevaluation_on_crypto_change():
    evaluated = []

    def pqc(snapshot):
        evaluated.append(snapshot)
        return {"pqc_status": "MIGRATION_REQUIRED"}

    def scan(specs, mode):
        if monitor._cycle == 1:
            return _report(assets=("web-1",))  # TLSv1.3
        return _report(assets=("web-1",), tls_version="TLSv1.2")

    monitor = _monitor(scan, pqc_evaluator=pqc)
    r1 = monitor.cycle(now=T0)
    assert r1.pqc_re_evaluations == []
    r2 = monitor.cycle(now=T0 + timedelta(seconds=61))
    assert any(e["asset_id"] == "web-1" and e["pqc_status"] == "MIGRATION_REQUIRED"
               for e in r2.pqc_re_evaluations)


# ------------------------------------------------------------- alerts

def test_drift_alert_raised():
    def scan(specs, mode):
        if monitor._cycle == 1:
            return _report(tls=[{"endpoint": "web-1:443",
                                 "tls_version": "TLSv1.3"}])
        return _report(tls=[{"endpoint": "web-1:443",
                             "tls_version": "TLSv1.0"}])

    monitor = _monitor(scan)
    monitor.cycle(now=T0)
    monitor.cycle(now=T0 + timedelta(seconds=61))
    alerts = monitor.alerts.history()
    assert any(a.title.startswith("CRYPTO DRIFT") and a.severity == "CRITICAL"
               for a in alerts)


def test_passive_observations_ingested():
    from network_scanner.enterprise.live.passive_monitor import PassiveSensor

    sensor = PassiveSensor("TLS_HANDSHAKE_METADATA",
                           records=[{"host": "web-1", "tls_version": "TLSv1.3"}])

    def scan(specs, mode):
        return _report()

    monitor = _monitor(scan)
    monitor.passive.add_sensor(sensor)
    result = monitor.cycle(now=T0)
    assert len(result.passive_observations) == 1
    assert result.passive_observations[0]["asset"] == "web-1"


# ------------------------------------------------------------- run/report

def test_run_cycles_and_stop():
    def scan(specs, mode):
        return _report()

    monitor = _monitor(scan)
    results = monitor.run(cycles=3, now=T0)
    assert len(results) == 3
    assert monitor.report()["monitoring"]["cycles_run"] == 3


def test_run_stop_callback():
    def scan(specs, mode):
        return _report()

    monitor = _monitor(scan)
    results = monitor.run(cycles=10, stop=lambda: True, now=T0)
    assert len(results) == 0  # stopped before first cycle


def test_report_shape():
    def scan(specs, mode):
        return _report()

    monitor = _monitor(scan)
    monitor.cycle(now=T0)
    report = monitor.report()
    assert report["monitoring"]["modes"] == [
        "REALTIME_EVENT", "PASSIVE", "PERIODIC_LIGHTWEIGHT",
        "SCHEDULED_DEEP", "CHANGE_TRIGGERED"]
    assert report["assets"]
    assert report["scheduler"]["assets"] == 2
    assert report["evidence_verified"] is True
    assert report["cbom"]["component_count"] == 2
    assert report["health"]["state"] == "HEALTHY"


def test_report_serializable():
    def scan(specs, mode):
        return _report()

    monitor = _monitor(scan)
    monitor.cycle(now=T0)
    json.dumps(monitor.report())


# ------------------------------------------------------------- scanner wiring

def test_scanner_live_monitor_wiring():
    scanner = NetworkTlsScanner(live=False)

    def fake_scan(specs, mode):
        return _report(assets=("web-1",))

    monitor = scanner.live_monitor(["10.0.0.0/24"], mode="SAFE")
    monitor._scan_fn = fake_scan  # offline
    result = monitor.cycle(now=T0)
    assert result.scanned_assets == ["web-1"]
    assert monitor.report()["monitoring"]["scope_specs"] == ["10.0.0.0/24"]


def test_scanner_live_monitor_defaults_safe():
    scanner = NetworkTlsScanner(live=False)
    monitor = scanner.live_monitor(["10.0.0.0/24"])
    assert monitor.scope_specs == ["10.0.0.0/24"]
    # DEEP is refused by discover_network without authorization — wired scan fn
    # passes authorization_scope through
    assert callable(monitor._scan_fn)


def test_cli_live_monitor_flag_runs_cycles(tmp_path):
    """CLI --live-monitor requires --scope and emits a monitor report."""
    from network_scanner.main import main

    out = tmp_path / "live.json"
    # --scope localhost with mode safe: localhost refuses live TLS so the
    # first scan returns probe-error findings; the loop must still produce a
    # report with monitoring + health sections instead of crashing.
    argv = ["--live-monitor", "--live-cycles", "1",
            "--scope", "localhost", "--mode", "safe", "-o", str(out)]
    try:
        code = main(argv)
    except SystemExit as exc:
        code = exc.code
    assert code in (0, 1)
    report = json.loads(out.read_text())
    assert report["scan_context"]["mode"] == "live-monitor"
    assert report["monitoring"]["modes"]
    assert report["health"]["state"] in ("HEALTHY", "DEGRADED", "FAILED",
                                         "UNREACHABLE", "MAINTENANCE")
    assert report["evidence_verified"] is True


def test_cli_live_monitor_requires_scope():
    from network_scanner.main import main

    with pytest.raises(SystemExit) as exc:
        main(["--live-monitor"])
    assert exc.value.code == 2  # argparse error


# ------------------------------------------------------------- no scope

def test_no_scope_skips_scheduled_scans_but_processes_events():
    events = []

    def scan(specs, mode):
        events.append(specs)
        return _report()

    monitor = LiveNetworkMonitor(scan_fn=scan, options={"events": []},
                                 clock=lambda: T0)
    result = monitor.cycle(now=T0)
    assert events == []
    assert result.scanned_assets == []
