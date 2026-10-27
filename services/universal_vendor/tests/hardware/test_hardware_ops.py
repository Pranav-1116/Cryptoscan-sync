"""Hardware scanner tests — HBOM, alert correlation, OT/ICS mode, safety,
distributed edges (§19, §21–§24)."""

from __future__ import annotations

import pytest

from universal_vendor.hardware.models import (
    HardwareObservation,
)


def _obs(asset_id: str = "srv-1", device_type: str = "server",
         manufacturer: str = "Dell", model: str = "R740",
         firmware: str = "2.10", **extra) -> HardwareObservation:
    return HardwareObservation(
        asset_id=asset_id, manufacturer=manufacturer, model=model,
        device_type=device_type, firmware=firmware, **extra)


# ── §19 HBOM ───────────────────────────────────────────────────────────

def test_hbom_add_hardware_firmware_security():
    from universal_vendor.hardware.hbom import HbomGenerator

    hbom = HbomGenerator()
    hbom.add(_obs(asset_id="srv-1", firmware_components={"BIOS": "2.10",
                                                         "BMC": "5.0"}))
    hbom.add(_obs(asset_id="hsm-1", device_type="hsm",
                  manufacturer="Thales", model="Luna",
                  tpm=None))
    hbom.add(_obs(asset_id="tpm-1", device_type="tpm",
                  manufacturer="Intel", model="PTT",
                  tpm={"present": True, "version": "2.0"}))

    doc = hbom.to_document()
    assert len(doc["hardware"]) == 3
    assert len(doc["firmware"]) == 2
    assert {h["type"] for h in doc["security_hardware"]} >= {"hsm", "tpm"}


def test_hbom_cyclonedx_serializable():
    from universal_vendor.hardware.hbom import HbomGenerator

    hbom = HbomGenerator()
    hbom.add(_obs())
    doc = hbom.to_cyclonedx()
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["components"][0]["type"] == "device"
    assert doc["components"][0]["bom-ref"] == "hw:srv-1"


def test_hbom_combined_inventory_with_cbom_sbom():
    from universal_vendor.hardware.hbom import HbomGenerator

    hbom = HbomGenerator()
    hbom.add(_obs())
    combined = hbom.combined_inventory(
        cbom_components=[{"name": "tls"}, {"name": "cert"}],
        sbom_components=[{"name": "openssl"}])
    assert combined["hbom_hardware"] == 1
    assert combined["cbom_components"] == 2
    assert combined["sbom_components"] == 1


# ── §21 alert correlation ──────────────────────────────────────────────

def test_one_root_hardware_change_not_four_incidents():
    from universal_vendor.hardware.alert import HardwareAlertCorrelator

    correlator = HardwareAlertCorrelator()
    correlator.report(root_asset_id="srv-1", event_type="FIRMWARE_CHANGED",
                      detail={"component": "BIOS"})
    correlator.report(root_asset_id="srv-1", event_type="TPM_STATE_CHANGED",
                      detail={"tpm": "unavailable"})
    correlator.report(root_asset_id="srv-1",
                      event_type="CRYPTO_CAPABILITY_RE_EVALUATED")
    incidents = correlator.incidents()
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["root_asset_id"] == "srv-1"
    assert incident["child_event_count"] == 3
    assert "FIRMWARE_CHANGED" in incident["child_types"]
    assert "ONE ROOT" in incident["summary"]


def test_alert_correlator_distinct_assets_distinct_incidents():
    from universal_vendor.hardware.alert import HardwareAlertCorrelator

    correlator = HardwareAlertCorrelator()
    correlator.report(root_asset_id="srv-1", event_type="FIRMWARE_CHANGED")
    correlator.report(root_asset_id="srv-2", event_type="FIRMWARE_CHANGED")
    assert correlator.count() == 2


def test_alert_correlator_root_events_tracked():
    from universal_vendor.hardware.alert import HardwareAlertCorrelator

    correlator = HardwareAlertCorrelator()
    correlator.report(root_asset_id="hsm-1", root_type="HSM_CHANGE",
                      event_type="FIRMWARE_CHANGED")
    correlator.report(root_asset_id="hsm-1", root_type="HSM_CHANGE",
                      event_type="CONFIGURATION_CHANGED")
    incident = correlator.incidents()[0]
    assert incident["child_event_count"] == 2
    assert incident["child_types"] == ["CONFIGURATION_CHANGED",
                                       "FIRMWARE_CHANGED"]


# ── §22 OT/ICS passive-first ───────────────────────────────────────────

def test_ot_passive_first_by_default():
    from universal_vendor.hardware.ot import OtScanMode, PassiveFirstOtScanner

    scanner = PassiveFirstOtScanner()
    result = scanner.run(scope_id="plant-1", mode=OtScanMode.SAFE,
                         targets=["10.0.0.0/24"])
    assert result["blocked"] is False
    assert result["passive_first"] is True
    assert result["mode"] == "SAFE"


def test_ot_active_deep_require_approval():
    from universal_vendor.hardware.ot import (
        OtScopeApproval,
        OtScanMode,
        PassiveFirstOtScanner,
    )

    scanner = PassiveFirstOtScanner()
    blocked = scanner.run(scope_id="plant-1", mode=OtScanMode.ACTIVE,
                          targets=["10.0.0.5"])
    assert blocked["blocked"] is True

    scanner.approve_scope(OtScopeApproval(
        scope_id="plant-1", approved_modes=["ACTIVE"],
        approved_by="OT-SOC-lead"))
    allowed = scanner.run(scope_id="plant-1", mode=OtScanMode.ACTIVE,
                          targets=["10.0.0.5"])
    assert allowed["blocked"] is False
    # DEEP still not approved for this scope
    deep = scanner.run(scope_id="plant-1", mode=OtScanMode.DEEP,
                       targets=["10.0.0.5"])
    assert deep["blocked"] is True


def test_ot_requires_approval_rule():
    from universal_vendor.hardware.ot import OtScanMode

    assert OtScanMode.requires_approval("ACTIVE") is True
    assert OtScanMode.requires_approval("DEEP") is True
    assert OtScanMode.requires_approval("SAFE") is False
    assert OtScanMode.requires_approval("CAUTIOUS") is False


def test_ot_passive_observation_logged():
    from universal_vendor.hardware.ot import PassiveFirstOtScanner

    scanner = PassiveFirstOtScanner()
    scanner.passive_observe(scope_id="plant-1",
                            observation={"mac": "00:1B:44:11:3A:B7",
                                         "protocol": "modbus"})
    log = scanner.passive_log()
    assert log and log[0]["observation"]["protocol"] == "modbus"
    assert log[0]["mode"] == "SAFE"


# ── §23 mandatory safety controls ──────────────────────────────────────

def test_safety_scope_and_exclusions():
    from universal_vendor.hardware.safety import SafetyController

    safety = SafetyController()
    safety.authorize("srv-1")
    assert safety.in_scope("srv-1") is True
    assert safety.in_scope("srv-2") is False
    safety.exclude("srv-1")
    assert safety.in_scope("srv-1") is False


def test_safety_can_scan_gates():
    from universal_vendor.hardware.safety import (
        SafetyController,
        SafetyProfile,
    )

    safety = SafetyController()
    allowed, reason = safety.can_scan(asset_id="srv-1")
    assert allowed is False and "scope" in reason
    safety.authorize("srv-1")
    safety.set_profile(SafetyProfile(vendor="*", max_rate_per_second=3.0))
    allowed, reason = safety.can_scan(asset_id="srv-1")
    assert allowed is True and reason == "allowed"
    # rate limiting kicks in once the per-asset budget is consumed
    safety._rate_remaining["srv-1"] = 0.0
    allowed, reason = safety.can_scan(asset_id="srv-1")
    assert allowed is False and "rate" in reason


def test_safety_kill_switch():
    from universal_vendor.hardware.safety import SafetyController

    safety = SafetyController()
    safety.authorize("srv-1")
    safety.engage_kill_switch()
    allowed, reason = safety.can_scan(asset_id="srv-1")
    assert allowed is False and "kill switch" in reason
    assert safety.in_scope("srv-1") is False
    assert any(e["outcome"] == "KILL_SWITCH" for e in safety.audit())


def test_safety_read_only_required():
    from universal_vendor.hardware.safety import SafetyController

    safety = SafetyController()
    safety.authorize("srv-1")
    safety.read_only = False
    allowed, reason = safety.can_scan(asset_id="srv-1")
    assert allowed is False and "read-only" in reason


def test_safety_never_rules_enforced():
    from universal_vendor.hardware.safety import SafetyController

    safety = SafetyController()
    with pytest.raises(AssertionError):
        safety.assert_never("extract private keys")
    with pytest.raises(AssertionError):
        safety.assert_never("bypass authentication")
    with pytest.raises(AssertionError):
        safety.assert_never("modify configurations")
    safety.assert_never("read DMI metadata")  # benign action fine


def test_safety_vendor_profile_and_audit():
    from universal_vendor.hardware.safety import (
        SafetyController,
        SafetyProfile,
    )

    safety = SafetyController()
    safety.set_profile(SafetyProfile(vendor="Cisco", max_rate_per_second=0.5,
                                     max_connections=2,
                                     scan_timeout_seconds=60))
    profile = safety.profile_for("cisco")
    assert profile.max_connections == 2
    assert profile.scan_timeout_seconds == 60
    # default profile for unknown vendors
    assert safety.profile_for("nobody").max_rate_per_second == 1.0
    safety.authorize("sw-1")
    safety.can_scan(asset_id="sw-1", vendor="Cisco")
    assert any(e["outcome"] == "ALLOWED" for e in safety.audit())


def test_safety_maintenance_window():
    from universal_vendor.hardware.safety import (
        SafetyController,
        SafetyProfile,
    )

    safety = SafetyController()
    safety.set_profile(SafetyProfile(vendor="Dell",
                                     maintenance_windows=["2026-09-05"]))
    assert safety.in_maintenance_window("Dell", now="2026-09-05T02:00:00") is True
    assert safety.in_maintenance_window("Dell", now="2026-09-06T02:00:00") is False


# ── §24 distributed edges ──────────────────────────────────────────────

def test_control_plane_regions():
    from universal_vendor.hardware.regions import HardwareControlPlane

    plane = HardwareControlPlane()
    plane.add_edge("UAE", online=True, control_plane_url="https://cp.zelinx")
    plane.add_edge("EU", online=True)
    plane.add_edge("USA", online=False)
    assert plane.regions() == ["EU", "UAE", "USA"]
    summary = plane.summary()
    assert summary["total_edges"] == 3
    assert summary["online_edges"] == 2


def test_edge_offline_sync_short_circuits():
    from universal_vendor.hardware.regions import HardwareControlPlane

    plane = HardwareControlPlane()
    plane.add_edge("USA", online=False)
    results = plane.sync_all()
    assert len(results) == 1
    assert results[0]["synced"] is False
    assert results[0]["reason"] == "offline"


def test_edge_online_sync_uses_durable_queue():
    from universal_vendor.live.events import UniversalVendorEvent
    from universal_vendor.live.offline import LocalEventQueue
    from universal_vendor.hardware.regions import HardwareControlPlane

    queue = LocalEventQueue(path="/tmp/zelinx-hw-tests/events.jsonl")
    queue.enqueue(UniversalVendorEvent(vendor="Dell", product="R740",
                                       asset_id="srv-1"))
    plane = HardwareControlPlane()
    edge = plane.add_edge("UAE", online=True, control_plane_url="https://cp")
    edge.event_queue = queue
    result = edge.sync()
    assert result["synced"] is True
    assert result["events_sent"] >= 1


def test_edge_local_evidence_offline_collection():
    """Offline edges keep a local evidence store; sync happens when the
    control plane is reachable again (§24)."""
    from universal_vendor.live.events import UniversalVendorEvent
    from universal_vendor.live.offline import (
        LocalEvidenceStore,
        LocalEventQueue,
    )
    from universal_vendor.hardware.regions import HardwareEdge

    queue = LocalEventQueue(path="/tmp/zelinx-hw-tests/events2.jsonl")
    evidence = LocalEvidenceStore(path="/tmp/zelinx-hw-tests/evidence.jsonl")
    edge = HardwareEdge(region="EU", online=False, event_queue=queue,
                        evidence_store=evidence)
    result = edge.sync()
    assert result["synced"] is False
    assert result["reason"] == "offline"
    # bring the edge online → durable queue drains to the control plane
    edge.online = True
    edge.control_plane_url = "https://cp"
    queue.enqueue(UniversalVendorEvent(vendor="Dell", product="R740",
                                       asset_id="srv-9"))
    result = edge.sync()
    assert result["synced"] is True
