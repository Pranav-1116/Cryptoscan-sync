"""§18/§19/§20 tests — platform event bus, state engine, change detection,
targeted rescan dispatch, drift detection."""

from __future__ import annotations

from universal_platform.drift import DriftEngine, evaluate_drift
from universal_platform.events import (
    EVENT_DOMAIN,
    PlatformEvent,
    PlatformEventBus,
    PlatformEventType,
)


def test_event_domain_catalog():
    assert EVENT_DOMAIN[PlatformEventType.NEW_DEVICE] == "network"
    assert EVENT_DOMAIN[PlatformEventType.FIRMWARE_CHANGED] == "hardware"
    assert EVENT_DOMAIN[PlatformEventType.CERTIFICATE_CHANGED] == "crypto"
    assert EVENT_DOMAIN[PlatformEventType.CLOUD_RESOURCE_CHANGED] == "cloud"
    assert EVENT_DOMAIN[PlatformEventType.VENDOR_CONFIGURATION_CHANGED] == "vendor"


def test_bus_detects_change_and_dispatches_targeted_analysis():
    bus = PlatformEventBus()
    handled = []
    bus.register("crypto", lambda e: handled.append(e.event_type.value))

    first = bus.dispatch(PlatformEventType.NEW_CERTIFICATE, "cert-1",
                         {"subject": "svc", "signature_algorithm": "RSA-PSS"})
    assert first["changed"] is True
    assert first["targeted_analysis"] == ["algorithm_reclassify",
                                          "quantum_recheck", "cbom_update"]
    assert handled == ["NEW_CERTIFICATE"]

    # same payload again → no change, no handler dispatch
    second = bus.dispatch(PlatformEventType.NEW_CERTIFICATE, "cert-1",
                          {"subject": "svc", "signature_algorithm": "RSA-PSS"})
    assert second["changed"] is False
    assert handled == ["NEW_CERTIFICATE"]

    # real change detected
    third = bus.dispatch(PlatformEventType.CERTIFICATE_CHANGED, "cert-1",
                         {"subject": "svc",
                          "signature_algorithm": "ML-DSA-65"})
    assert third["changed"] is True


def test_bus_replay_and_journal():
    bus = PlatformEventBus()
    bus.dispatch(PlatformEventType.NEW_DEVICE, "sw-1", {"ip": "10.1.1.1"})
    bus.dispatch(PlatformEventType.DEVICE_REMOVED, "sw-1", {})
    journal = bus.replay()
    assert len(journal) == 2
    assert journal[0]["event"]["event_type"] == "NEW_DEVICE"
    assert journal[0]["event"]["domain"] == "network"


def test_bus_forwards_to_domain_scanner_engine():
    calls = []
    bus = PlatformEventBus(scanner_engines={
        "hardware": lambda e: calls.append(e.event_type.value)})
    bus.dispatch(PlatformEventType.HSM_CHANGED, "hsm-1",
                 {"firmware": "8.0"})
    assert calls == ["HSM_CHANGED"]


def test_drift_detects_added_removed_changed():
    baseline = {
        "network": {"rtr-1": "1.0", "sw-1": "1.0"},
        "crypto": ["RSA-2048", "AES-256"],
        "firmware": {"rtr-1": "17.1"},
        "pqc": {"readiness": "QUANTUM_VULNERABLE"},
    }
    live = {
        "network": {"rtr-1": "1.1", "sw-1": "1.0", "fw-2": "1.0"},
        "crypto": ["RSA-2048", "ML-KEM-768"],
        "firmware": {"rtr-1": "17.1"},
        "pqc": {"readiness": "PQC_READY"},
    }
    result = evaluate_drift(baseline, live)
    assert result["drift_detected"] is True
    net = result["categories"]["network"]
    changes = {c["change"] for c in net["changes"]}
    assert changes == {"changed", "added"}
    crypto = {c["change"] for c in result["categories"]["crypto"]["changes"]}
    assert "removed" in crypto and "added" in crypto
    assert result["categories"]["firmware"]["drift"] is False
    assert result["categories"]["pqc"]["drift"] is True


def test_drift_no_change_is_clean():
    baseline = {"protocol": {"TLS": "1.3"}}
    result = DriftEngine(baseline).evaluate({"protocol": {"TLS": "1.3"}})
    assert result["drift_detected"] is False
    assert result["total_changes"] == 0
