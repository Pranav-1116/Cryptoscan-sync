"""Hardware scanner tests — capabilities, correlation, lifecycle, live
monitoring/drift, risk (§10–§18)."""

from __future__ import annotations

from universal_vendor.hardware.models import (
    CryptoCapability,
    HardwareDriftType,
)


# ── §10 capability engine ──────────────────────────────────────────────

def test_supported_vs_used_strictly_separate():
    from universal_vendor.hardware.capabilities import CryptoCapabilityEngine

    engine = CryptoCapabilityEngine()
    engine.record_hardware_from_dict("srv-1", {
        "aes": True, "rsa": True, "ecc": True,
        "supported_algorithms": ["AES", "RSA", "ECC", "SHA-256"],
        "used_algorithms": ["AES"],
    })
    # usage must come from software evidence, not the hardware claim
    engine.record_usage("srv-1", ["AES"])
    summary = engine.summary("srv-1")
    assert summary["hardware_supported"]["aes"] is True
    assert summary["software_used"] == ["AES"]
    assert summary["supported_but_unused"] == ["ECC", "RSA", "SHA-256"]
    # hardware capability alone is NOT evidence of use
    assert engine.supported_but_unused("srv-1")


def test_record_usage_from_software_evidence():
    from universal_vendor.hardware.capabilities import CryptoCapabilityEngine

    engine = CryptoCapabilityEngine()
    engine.record_hardware("srv-1", CryptoCapability(
        aes=True, supported_algorithms=["AES", "SHA-256"]))
    assert engine.supported_but_unused("srv-1") == ["AES", "SHA-256"]
    engine.record_usage("srv-1", ["AES"])
    assert engine.supported_but_unused("srv-1") == ["SHA-256"]


def test_capability_registry_by_model():
    from universal_vendor.hardware.capabilities import CapabilityRegistry

    registry = CapabilityRegistry()
    registry.register("intel xeon 8380",
                      {"aes": True, "sha": True, "rng": True})
    entry = registry.lookup("Intel Xeon 8380")
    assert entry and entry["aes"] is True
    assert registry.lookup("unknown chip") is None


# ── §11–§13 correlation ────────────────────────────────────────────────

def test_hardware_to_software_chain():
    from universal_vendor.hardware.correlation import HardwareCorrelationEngine

    engine = HardwareCorrelationEngine()
    engine.link_hardware_to_software(
        server="srv-1", component="TPM", operating_system="RHEL 9",
        crypto_library="OpenSSL", application="payment-app",
        certificate="cert-payment-2026")
    hardware = engine.underlying_hardware("cert-payment-2026")
    assert "srv-1" in hardware


def test_hardware_to_network_chain():
    from universal_vendor.hardware.correlation import HardwareCorrelationEngine

    engine = HardwareCorrelationEngine()
    engine.link_hardware_to_network(
        server="srv-1", nic="nic-1", switch="sw-1", firewall="fw-1",
        load_balancer="lb-1", application="banking-app")
    # the full path server→NIC→switch→FW→LB→app is present in the graph
    for pair in (("srv-1", "nic-1"), ("nic-1", "sw-1"),
                 ("sw-1", "fw-1"), ("fw-1", "lb-1"), ("lb-1", "banking-app")):
        assert engine.graph.paths(pair[0], pair[1], max_depth=2)


def test_cloud_visibility_ladder():
    from universal_vendor.hardware.correlation import HardwareCorrelationEngine
    from universal_vendor.hardware.models import CloudVisibility

    engine = HardwareCorrelationEngine()
    assert engine.cloud_visibility({"observed": True}) == CloudVisibility.OBSERVED.value
    assert engine.cloud_visibility(
        {"provider_declared": True}) == CloudVisibility.PROVIDER_DECLARED.value
    assert engine.cloud_visibility({"instance_type": "m5.large"}) == CloudVisibility.INFERRED.value
    assert engine.cloud_visibility({}) == CloudVisibility.UNKNOWN.value


def test_cloud_vm_links_no_physical_host_claim():
    from universal_vendor.hardware.correlation import HardwareCorrelationEngine

    engine = HardwareCorrelationEngine()
    engine.link_cloud_resource(
        cloud_vm="vm-1", instance_type="m5.large",
        provider_capability="aws-nitro-aes",
        virtual_capability="aes-ni-virtual")
    node_ids = [n["id"] for n in engine.graph.nodes()]
    assert "vm-1" in node_ids
    # the graph must NOT contain a physical host node we can't observe
    assert not any("physical-host" in n for n in node_ids)


# ── §14 lifecycle ──────────────────────────────────────────────────────

def test_lifecycle_unknown_by_default():
    from universal_vendor.hardware.lifecycle import HardwareLifecycleDatabase

    db = HardwareLifecycleDatabase()
    status = db.status("Acme", "Mystery Box 3000")
    assert status["support_status"] == "UNKNOWN"
    assert "NOT inferred" in status["reason"]


def test_lifecycle_seeded_entries():
    from universal_vendor.hardware.lifecycle import HardwareLifecycleDatabase

    db = HardwareLifecycleDatabase()
    gen9 = db.status("HPE", "ProLiant Gen9")
    assert gen9["support_status"] == "END_OF_SUPPORT"
    assert gen9["evidence_source"]
    dell13 = db.status("Dell", "PowerEdge 13G")
    assert dell13["support_status"] == "END_OF_SUPPORT"


def test_migration_candidate_legacy_hsm_no_pqc_eos():
    from universal_vendor.hardware.lifecycle import (
        HardwareLifecycleDatabase,
        HardwareLifecycleEntry,
    )
    from universal_vendor.models import LifecycleStatus

    db = HardwareLifecycleDatabase()
    # evidence-backed entry: legacy HSM, no PQC, end of support
    db.add(HardwareLifecycleEntry(
        manufacturer="LegacyVault", model="HSM-2000",
        support_status=LifecycleStatus.END_OF_SUPPORT.value,
        end_of_support="2025-06-30", end_of_life="2026-06-30",
        pqc_capability="NOT_SUPPORTED",
        evidence_source="vendor lifecycle notice", confidence=0.9))
    result = db.migration_candidate("LegacyVault", "HSM-2000",
                                    pqc_required=True)
    assert result["candidate"] == "CRITICAL"
    assert result["lifecycle"]["support_status"] == "END_OF_SUPPORT"


def test_migration_candidate_eos_alone_is_high():
    from universal_vendor.hardware.lifecycle import HardwareLifecycleDatabase

    db = HardwareLifecycleDatabase()
    # seeded Dell PowerEdge 13G is END_OF_SUPPORT — even without a PQC
    # requirement it is still a migration candidate
    result = db.migration_candidate("Dell", "PowerEdge 13G",
                                    pqc_required=False)
    assert result["candidate"] == "HIGH"


def test_migration_candidate_unverified_is_standard():
    """Never inferred from a product name — an unverified device is STANDARD."""
    from universal_vendor.hardware.lifecycle import HardwareLifecycleDatabase

    db = HardwareLifecycleDatabase()
    result = db.migration_candidate("Acme", "Mystery Box 3000",
                                    pqc_required=True)
    assert result["candidate"] == "STANDARD"


# ── §15–§17 live monitoring / state / drift ────────────────────────────

def test_live_monitor_collects_from_sources():
    from universal_vendor.hardware.live import LiveHardwareMonitor

    class Source:
        def collect(self):
            return [{"event_type": "DEVICE_ADDED", "asset_id": "srv-1",
                     "manufacturer": "Dell", "model": "R740"}]

    monitor = LiveHardwareMonitor()
    monitor.register(Source())
    events = monitor.collect()
    assert events and events[0]["event_type"] == "DEVICE_ADDED"


def test_live_monitor_broken_source_does_not_kill_loop():
    from universal_vendor.hardware.live import LiveHardwareMonitor

    class Broken:
        def collect(self):
            raise RuntimeError("boom")

    class Good:
        def collect(self):
            return [{"event_type": "DEVICE_ADDED", "asset_id": "srv-2"}]

    monitor = LiveHardwareMonitor()
    monitor.register(Broken())
    monitor.register(Good())
    events = monitor.collect()
    assert len(events) == 2
    assert events[1]["asset_id"] == "srv-2"
    assert "error" in events[0]["detail"]


def test_state_engine_new_changed_removed():
    from universal_vendor.hardware.live import HardwareStateEngine

    engine = HardwareStateEngine()
    assert engine.apply_event({"event_type": "DEVICE_ADDED",
                               "asset_id": "srv-1",
                               "manufacturer": "Dell",
                               "model": "R740"}) == "NEW"
    assert engine.apply_event({"event_type": "FIRMWARE_CHANGED",
                               "asset_id": "srv-1",
                               "component": "BIOS",
                               "version": "2.10"}) == "CHANGED"
    state = engine.get("srv-1")
    assert state is not None
    assert state.firmware.get("BIOS") == "2.10"
    assert state.last_firmware_check is not None
    assert engine.apply_event({"event_type": "DEVICE_REMOVED",
                               "asset_id": "srv-1"}) == "REMOVED"


def test_state_engine_24_7_fields():
    from universal_vendor.hardware.live import HardwareStateEngine

    engine = HardwareStateEngine()
    engine.apply_event({"event_type": "DEVICE_ADDED", "asset_id": "srv-1"})
    engine.mark_verified("srv-1")
    engine.update_fingerprint("srv-1", "abc123")
    engine.update_fingerprint("srv-1", "def456")
    engine.record_evidence("srv-1", "ev-1")
    state = engine.get("srv-1")
    assert state.last_verified is not None
    assert state.current_fingerprint == "def456"
    assert state.previous_fingerprint == "abc123"
    assert state.evidence_history == ["ev-1"]
    assert state.first_seen == state.last_seen


def test_drift_tpm_expected_unavailable():
    from universal_vendor.hardware.live import HardwareDriftEngine

    engine = HardwareDriftEngine()
    engine.set_expected("srv-1", {"tpm": {"present": True, "version": "2.0"}})
    result = engine.evaluate("srv-1", {"tpm": {"present": False}})
    assert result["state"] == HardwareDriftType.SECURITY_HARDWARE_DRIFT.value


def test_drift_firmware_and_replacement():
    from universal_vendor.hardware.live import HardwareDriftEngine

    engine = HardwareDriftEngine()
    engine.set_expected("srv-1", {"firmware": {"BIOS": "2.10"},
                                  "model": "R740"})
    result = engine.evaluate("srv-1", {"firmware": {"BIOS": "2.00"},
                                       "model": "R750"})
    assert HardwareDriftType.BIOS_DRIFT.value in result["drift_types"]
    assert HardwareDriftType.UNEXPECTED_REPLACEMENT.value in result["drift_types"]
    assert result["state"] == HardwareDriftType.BIOS_DRIFT.value


def test_drift_no_change():
    from universal_vendor.hardware.live import HardwareDriftEngine

    engine = HardwareDriftEngine()
    engine.set_expected("srv-1", {"firmware": {"BIOS": "2.10"}})
    result = engine.evaluate("srv-1", {"firmware": {"BIOS": "2.10"}})
    assert result["state"] == HardwareDriftType.NO_CHANGE.value


def test_drift_no_expected_state():
    from universal_vendor.hardware.live import HardwareDriftEngine

    engine = HardwareDriftEngine()
    result = engine.evaluate("srv-1", {})
    assert result["state"] == HardwareDriftType.NO_CHANGE.value


# ── §18 risk ───────────────────────────────────────────────────────────

def test_risk_critical_threshold():
    from universal_vendor.hardware.risk import HardwareRiskEngine

    engine = HardwareRiskEngine()
    result = engine.assess(
        asset_id="hsm-1",
        hardware_criticality="critical",
        crypto_dependency_count=5,
        age_years=9,
        firmware_state="legacy",
        pqc_capability="NOT_SUPPORTED",
        network_exposure="internet",
        replacement_difficulty="high",
    )
    assert result.score >= 12
    assert result.level == "CRITICAL"


def test_risk_low_threshold():
    from universal_vendor.hardware.risk import HardwareRiskEngine

    engine = HardwareRiskEngine()
    result = engine.assess(
        asset_id="printer-1",
        hardware_criticality="low",
        crypto_dependency_count=0,
        age_years=1,
        firmware_state="current",
        pqc_capability="SUPPORTED",
        network_exposure="isolated",
        replacement_difficulty="low",
    )
    assert result.score < 6
    assert result.level == "LOW"


def test_risk_components_recorded():
    from universal_vendor.hardware.risk import HardwareRiskEngine

    result = HardwareRiskEngine().assess(
        asset_id="srv-1", pqc_capability="UNKNOWN")
    assert result.components["pqc_capability"] == "UNKNOWN"
    assert result.asset_id == "srv-1"


def test_empty_plugin_capability_container_does_not_claim_known_hardware():
    from universal_vendor.hardware.capabilities import CryptoCapabilityEngine

    engine = CryptoCapabilityEngine()
    engine.record_hardware_from_dict("host-empty", {"supported_algorithms": []})
    assert engine.summary("host-empty") == {"asset_id": "host-empty", "known": False}


def test_scanner_reports_capability_evidence_even_without_identity_claim():
    from universal_vendor.hardware.scanner import UniversalHardwareScanner

    result = UniversalHardwareScanner().scan({
        "asset_id": "cap-only", "capabilities": {"aes": True},
        "used_algorithms": ["AES"],
    })
    assert result["observations"] == []
    assert result["capabilities"] == [{
        "asset_id": "cap-only", "known": True,
        "hardware_supported": {
            "aes": True, "sha2": False, "sha3": False, "rsa": False,
            "ecc": False, "ecdsa": False, "ecdh": False, "rng": False,
            "secure_key_storage": False, "pqc_hybrid": False,
            "supported_algorithms": [], "used_algorithms": [],
        },
        "software_used": ["AES"], "supported_but_unused": [],
    }]
