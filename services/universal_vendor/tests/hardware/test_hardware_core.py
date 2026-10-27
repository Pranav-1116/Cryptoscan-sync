"""Hardware scanner tests — models, identity, fingerprinting, CPU/TPM/HSM/
smart-card discovery, firmware intelligence (§1–§10)."""

from __future__ import annotations


import pytest

from universal_vendor.hardware.models import (
    CloudVisibility,
    CryptoCapability,
    CpuInfo,
    DiscoveryMethod,
    FirmwareComponent,
    HardwareConfidence,
    HardwareIdentity,
    HardwareObservation,
    HardwareType,
    TpmInfo,
)


# ── §1 model surface ───────────────────────────────────────────────────

def test_hardware_type_categories_cover_spec():
    assert HardwareType.SERVER.value == "server"
    assert HardwareType.GPU.value == "gpu"
    assert HardwareType.FIREWALL.value == "firewall"
    assert HardwareType.HSM.value == "hsm"
    assert HardwareType.TPM.value == "tpm"
    assert HardwareType.SAN.value == "san"
    assert HardwareType.PLC.value == "plc"
    assert HardwareType.IOT_GATEWAY.value == "iot_gateway"
    assert HardwareType.HYPERVISOR_HOST.value == "hypervisor_host"


def test_discovery_methods_three_kinds():
    assert DiscoveryMethod.AGENT.value == "agent"
    assert DiscoveryMethod.NETWORK.value == "network"
    assert DiscoveryMethod.API.value == "api"


def test_hardware_observation_canonical_roundtrip():
    obs = HardwareObservation(
        asset_id="srv-001", manufacturer="Dell", model="PowerEdge R740",
        serial_reference="SN123", device_type="server", firmware="2.10",
        environment="production", source="agent",
        confidence=HardwareConfidence.HIGH.value,
        cpu=CpuInfo(vendor="Intel", architecture="x86_64",
                    instruction_extensions=["aes", "sha"]).to_dict(),
        tpm=TpmInfo(present=True, version="2.0",
                    supported_algorithms=["SHA-256", "RSA"]).to_dict(),
    )
    data = obs.to_dict()
    assert data["asset_id"] == "srv-001"
    assert data["device_type"] == "server"
    assert data["cpu"]["instruction_extensions"] == ["aes", "sha"]
    assert data["tpm"]["version"] == "2.0"
    assert data["confidence"] == "HIGH"
    assert data["visibility"] == CloudVisibility.OBSERVED.value


def test_crypto_capability_supported_vs_used():
    cap = CryptoCapability(aes=True, rsa=True, ecdsa=True,
                           supported_algorithms=["AES", "RSA", "ECDSA", "SHA-256"],
                           used_algorithms=["AES"])
    assert cap.supported("aes") and cap.supported("rsa")
    assert cap.used("aes") and not cap.used("rsa")
    assert sorted(set(cap.supported_algorithms) - set(cap.used_algorithms)) == [
        "ECDSA", "RSA", "SHA-256"]


def test_cpu_info_to_dict_carries_capability_flags():
    cpu = CpuInfo(vendor="Intel", architecture="x86_64",
                  instruction_extensions=["aes", "sha_ni", "rdrand"],
                  core_count=16, thread_count=32, microcode_version="0x200",
                  aes_acceleration=True, sha_acceleration=True,
                  hardware_rng=True)
    d = cpu.to_dict()
    assert d["aes_acceleration"] is True
    assert d["sha_acceleration"] is True
    assert d["hardware_rng"] is True


def test_hardware_identity_multi_signal():
    identity = HardwareIdentity(
        asset_id="hw-1", manufacturer="Cisco", model="Catalyst 9300",
        serial_reference="FOC123", device_type="switch",
        source="network", confidence="HIGH")
    assert identity.serial_reference == "FOC123"
    assert identity.device_type == "switch"


# ── §4 fingerprinting ──────────────────────────────────────────────────

def test_fingerprint_high_medium_low_confidence():
    from universal_vendor.hardware.fingerprint import fingerprint_hardware

    high = fingerprint_hardware({"dmi": {"serial": "A", "product": "B"},
                                 "serial": "A", "bmc": "1.2",
                                 "firmware": "2.0", "mac_oui": "00:11:22"})
    assert high.confidence == HardwareConfidence.HIGH.value
    assert high.score >= 1.8

    medium = fingerprint_hardware({"serial": "A", "firmware": "2.0"})
    assert medium.confidence == HardwareConfidence.MEDIUM.value
    assert 0.9 <= medium.score < 1.8

    low = fingerprint_hardware({"serial": "A"})
    assert low.confidence == HardwareConfidence.LOW.value
    assert low.score < 0.9


def test_fingerprint_tracker_change_detection():
    from universal_vendor.hardware.fingerprint import (
        FingerprintTracker,
        fingerprint_hardware,
    )

    tracker = FingerprintTracker()
    fp1 = fingerprint_hardware({"serial": "A", "dmi": {"product": "R740"}})
    first = tracker.observe("srv-1", fp1)
    assert first["first_seen"] is True
    assert first["changed"] is False
    same = tracker.observe("srv-1", fp1)
    assert same["changed"] is False
    fp2 = fingerprint_hardware({"serial": "A", "dmi": {"product": "R750"},
                                "firmware": "2.1"})
    changed = tracker.observe("srv-1", fp2)
    assert changed["changed"] is True


def test_fingerprint_evidence_sources_recorded():
    from universal_vendor.hardware.fingerprint import fingerprint_hardware

    fp = fingerprint_hardware({"dmi": "x", "snmp": "y", "lldp": "z"})
    assert set(fp.evidence_sources) == {"dmi", "snmp", "lldp"}


# ── §3 identity resolution ─────────────────────────────────────────────

def test_identity_never_serial_only():
    from universal_vendor.hardware.identity import (
        HardwareIdentityResolver,
        IdentitySignal,
    )

    resolver = HardwareIdentityResolver()
    identity = resolver.build_identity(
        signals=[IdentitySignal("serial", "SN-123", "agent")],
        manufacturer="Dell", model="R740", device_type="server",
        source="agent")
    # a single serial signal alone never yields HIGH confidence
    assert identity.confidence == HardwareConfidence.MEDIUM.value
    assert identity.confidence != HardwareConfidence.HIGH.value


def test_identity_two_kinds_high_confidence():
    from universal_vendor.hardware.identity import (
        HardwareIdentityResolver,
        IdentitySignal,
    )

    resolver = HardwareIdentityResolver()
    identity = resolver.build_identity(
        signals=[IdentitySignal("serial", "SN-123", "agent"),
                 IdentitySignal("mac", "00:11:22:33:44:55", "agent")],
        manufacturer="Dell", model="R740", device_type="server",
        source="agent")
    assert identity.confidence == HardwareConfidence.HIGH.value


def test_identity_resolve_by_any_signal():
    from universal_vendor.hardware.identity import (
        HardwareIdentityResolver,
        IdentitySignal,
    )

    resolver = HardwareIdentityResolver()
    signals = [IdentitySignal("serial", "SN-ABC", "agent"),
               IdentitySignal("mac", "aa:bb:cc:dd:ee:ff", "agent")]
    identity = resolver.build_identity(
        signals=signals, manufacturer="HPE", model="ProLiant",
        device_type="server", source="agent")
    resolver.register(identity, signals=signals)
    found = resolver.resolve(mac="AA:BB:CC:DD:EE:FF")
    assert found is not None and found.asset_id == identity.asset_id
    found2 = resolver.resolve(serial="SN-ABC")
    assert found2 is not None


def test_identity_virtualized_environment_multiple_signals():
    """Virtualized environments expose incomplete identifiers — the resolver
    must not collapse on one duplicated signal."""
    from universal_vendor.hardware.identity import (
        HardwareIdentityResolver,
        IdentitySignal,
    )

    resolver = HardwareIdentityResolver()
    vm_a = resolver.build_identity(
        signals=[IdentitySignal("hostname", "vm-a", "api"),
                 IdentitySignal("cloud_resource", "arn:aws:ec2:us-east-1:1:instance/i-abc", "api")],
        manufacturer="", model="", device_type="virtualization", source="api")
    vm_b = resolver.build_identity(
        signals=[IdentitySignal("hostname", "vm-b", "api"),
                 IdentitySignal("cloud_resource", "arn:aws:ec2:us-east-1:1:instance/i-def", "api")],
        manufacturer="", model="", device_type="virtualization", source="api")
    assert vm_a.asset_id != vm_b.asset_id


# ── §5 CPU ─────────────────────────────────────────────────────────────

def test_cpu_parse_and_aliases():
    from universal_vendor.hardware.cpu import CpuDiscovery

    cpu = CpuDiscovery().parse({
        "vendor": "GenuineIntel",
        "family": "6", "model": "85",
        "architecture": "x86_64",
        "instruction_extensions": ["aes", "pclmulqdq", "sha_ni",
                                   "ssse3", "sse4_2", "rdrand"],
        "cores": 8, "threads": 16, "microcode_version": "0x200",
    })
    assert cpu.aes_acceleration is True
    assert cpu.sha_acceleration is True
    assert cpu.hardware_rng is True
    assert "AES" in cpu.instruction_extensions   # alias normalized
    assert cpu.core_count == 8 and cpu.thread_count == 16
    assert cpu.microcode_version == "0x200"


def test_cpu_parse_text_proc_cpuinfo():
    from universal_vendor.hardware.cpu import CpuDiscovery

    cpu = CpuDiscovery().parse_text(
        "vendor_id : GenuineIntel\nmodel name : Intel Xeon 8380\n"
        "flags : fpu vme aes pclmulqdq rdrand sha_ni\ncpu cores : 16")
    assert cpu.vendor == "GenuineIntel"
    assert cpu.aes_acceleration is True
    assert cpu.core_count == 16


def test_cpu_capability_not_usage():
    from universal_vendor.hardware.cpu import CpuDiscovery

    cpu = CpuDiscovery().parse({"vendor": "GenuineIntel",
                                "instruction_extensions": ["aes"]})
    observation = CpuDiscovery().to_observation(cpu)
    # capability-only: the observation must not claim software uses AES
    assert observation.get("capability_only") is True
    assert "used_algorithms" not in observation


def test_cpu_trusted_execution_recorded_as_capability():
    from universal_vendor.hardware.cpu import CpuDiscovery

    cpu = CpuDiscovery().parse({"vendor": "GenuineIntel",
                                "instruction_extensions": ["aes", "sgx", "tdx"]})
    assert cpu.trusted_execution is True
    obs = CpuDiscovery().to_observation(cpu)
    assert obs["cpu"]["trusted_execution"] is True
    assert obs["capability_only"] is True


# ── §6 TPM ─────────────────────────────────────────────────────────────

def test_tpm_parse_metadata():
    from universal_vendor.hardware.tpm import TpmScanner

    tpm = TpmScanner().parse({
        "present": True, "version": "2.0",
        "manufacturer": "STMicroelectronics", "firmware": "8.63.5152",
        "supported_algorithms": ["SHA-256", "RSA", "ECC"],
        "pcr_capabilities": ["PCR0-SHA256", "PCR7-SHA256"],
        "secure_boot_relationship": "enabled",
    })
    assert tpm.present is True
    assert tpm.version == "2.0"
    assert "SHA-256" in tpm.supported_algorithms
    assert tpm.secure_boot_relationship == "enabled"


def test_tpm_never_extract_secret_material():
    from universal_vendor.hardware.tpm import TpmScanner

    with pytest.raises(AssertionError):
        TpmScanner().parse({"present": True,
                            "owner_auth": "hunter2-secret"})


def test_tpm_drift_to_security_hardware_drift():
    from universal_vendor.hardware.tpm import TpmScanner

    scanner = TpmScanner()
    expected = scanner.parse({"present": True, "version": "2.0"})
    current = scanner.parse({"present": False, "version": "2.0"})
    assert scanner.drift(expected, current) == "SECURITY_HARDWARE_DRIFT"


# ── §7 HSM ─────────────────────────────────────────────────────────────

def test_hsm_scan_metadata_only():
    from universal_vendor.hardware.hsm_hw import HsmHardwareScanner

    scanner = HsmHardwareScanner()
    obs = scanner.scan({
        "manufacturer": "Thales", "model": "Luna Network HSM",
        "firmware": "7.10", "crypto_capabilities": ["FIPS 140-2 L3"],
        "supported_algorithms": ["RSA", "ECDSA", "AES"],
        "partition_metadata": {"partitions": 4},
    })
    assert obs["device_type"] == "hsm"
    assert obs["model"] == "Luna Network HSM"
    assert obs["partition_metadata"] == {"partitions": 4}


def test_hsm_never_keys_or_secrets():
    from universal_vendor.hardware.hsm_hw import HsmHardwareScanner

    scanner = HsmHardwareScanner()
    with pytest.raises(AssertionError):
        scanner.scan({"manufacturer": "Thales", "model": "Luna",
                      "private_key": "top-secret"})
    with pytest.raises(AssertionError):
        scanner.scan({"manufacturer": "Thales", "model": "Luna",
                      "master_key": "mk-123"})


def test_hsm_event_types():
    from universal_vendor.hardware.hsm_hw import HsmHardwareScanner

    scanner = HsmHardwareScanner()
    for event_type in ("HSM_CAPABILITY_CHANGED", "FIRMWARE_CHANGED",
                       "CRYPTO_SUPPORT_CHANGED", "CONFIGURATION_CHANGED"):
        scanner.track_event(asset_id="hsm-1", event_type=event_type)
    assert len(scanner.events()) == 4
    assert {e["event_type"] for e in scanner.events()} == {
        "HSM_CAPABILITY_CHANGED", "FIRMWARE_CHANGED",
        "CRYPTO_SUPPORT_CHANGED", "CONFIGURATION_CHANGED"}


def test_hsm_vendor_plugin_metadata():
    from universal_vendor.hardware.hsm_hw import HsmHardwareScanner

    scanner = HsmHardwareScanner()
    meta = scanner.vendor_plugin_metadata("thales")
    assert meta is not None and meta["vendor"].lower() == "thales"
    assert scanner.vendor_plugin_metadata("nobody") is None


# ── §8 smart card ──────────────────────────────────────────────────────

def test_smartcard_metadata_only():
    from universal_vendor.hardware.smartcard import SmartCardScanner

    scanner = SmartCardScanner()
    obs = scanner.parse({
        "vendor": "Gemalto", "model": "IDPrime MD",
        "interface": "contactless", "firmware": "2.1",
        "supported_algorithms": ["RSA", "ECC"],
        "certificate_references": ["CN=Employee Card"],
        "application_dependencies": ["PIV"],
    })
    assert obs["vendor"] == "Gemalto"
    assert obs["model"] == "IDPrime MD"
    assert obs["supported_algorithms"] == ["RSA", "ECC"]
    assert obs["certificate_references"] == ["CN=Employee Card"]
    # no secret material appears anywhere in the parsed record
    assert "private_key" not in obs
    assert "pin" not in {str(k).lower() for k in obs}


def test_smartcard_never_extract_keys():
    from universal_vendor.hardware.smartcard import SmartCardScanner

    with pytest.raises(AssertionError):
        SmartCardScanner().parse({"vendor": "Gemalto", "model": "IDPrime",
                                  "private_key": "k1"})


# ── §9 firmware intelligence ───────────────────────────────────────────

def test_firmware_change_triggers_crypto_reassessment():
    from universal_vendor.hardware.firmware import FirmwareIntelligence

    reassessments = []
    fw = FirmwareIntelligence(
        reassessment_hook=lambda event: reassessments.append(event))
    assert fw.observe(asset_id="srv-1", component="BIOS", version="1.0") is None
    change = fw.observe(asset_id="srv-1", component="BIOS", version="2.0")
    assert change is not None
    assert change.previous == "1.0" and change.current == "2.0"
    assert change.reassessment_triggered is True
    assert reassessments and reassessments[0]["type"] == "firmware_change"
    # identical version → no change
    assert fw.observe(asset_id="srv-1", component="BIOS", version="2.0") is None


def test_firmware_monitored_components():
    from universal_vendor.hardware.firmware import FirmwareIntelligence

    fw = FirmwareIntelligence()
    components = [FirmwareComponent.BIOS, FirmwareComponent.UEFI,
                  FirmwareComponent.BMC, FirmwareComponent.NIC,
                  FirmwareComponent.RAID, FirmwareComponent.HBA,
                  FirmwareComponent.TPM, FirmwareComponent.HSM,
                  FirmwareComponent.STORAGE, FirmwareComponent.NETWORK_APPLIANCE,
                  FirmwareComponent.GPU]
    for i, component in enumerate(components):
        fw.observe(asset_id="srv-1", component=component.value, version=str(i))
    assert len(fw.asset_firmware("srv-1")) == len(components)


def test_firmware_state_per_component():
    from universal_vendor.hardware.firmware import FirmwareIntelligence

    fw = FirmwareIntelligence()
    fw.observe(asset_id="srv-1", component="BMC", version="1.5")
    fw.observe(asset_id="srv-1", component="BMC", version="1.6")
    state = fw.state("srv-1", "BMC")
    assert state is not None
    assert state.previous == "1.5" and state.current == "1.6"


def test_fingerprint_ignores_placeholder_evidence_and_tracker_has_no_previous_baseline():
    from universal_vendor.hardware.fingerprint import FingerprintTracker, fingerprint_hardware

    fingerprint = fingerprint_hardware({"dmi": {"serial": "unknown"},
                                        "serial": "N/A", "bmc": {}})
    assert fingerprint.evidence_sources == []
    assert fingerprint.confidence == "LOW"

    tracker = FingerprintTracker()
    first = tracker.observe("host-1", fingerprint)
    assert first["first_seen"] is True
    assert first["previous_hash"] is None
    second = tracker.observe("host-1", fingerprint)
    assert second["first_seen"] is False
    assert second["previous_hash"] == first["fingerprint_hash"]


def test_discovery_preserves_lower_confidence_provenance_and_identity_conflict():
    from universal_vendor.hardware.discovery import HardwareDiscoveryOrchestrator

    class Sources:
        def __init__(self, records):
            self.records = records

        def collect(self, context):
            return self.records

    observation = HardwareDiscoveryOrchestrator(
        Sources([{
            "asset_id": "asset-1", "manufacturer": "Acme", "model": "A1",
            "serial_reference": "S1", "device_type": "server", "source": "agent",
            "confidence": "HIGH", "vendor_specific": {"serial_source": "dmi"},
        }]),
        Sources([{
            "asset_id": "asset-1", "manufacturer": "Other", "model": "A1",
            "serial_reference": "S1", "device_type": "server", "source": "network",
            "confidence": "LOW", "vendor_specific": {"banner": "Other A1"},
        }]),
    ).discover([{}])[0]
    assert observation.manufacturer == "Acme"
    assert observation.source == "agent"
    assert observation.discovery_sources == ["agent", "network"]
    assert observation.identity_conflicts["manufacturer"] == [
        {"source": "agent", "value": "Acme"},
        {"source": "network", "value": "Other"},
    ]
    assert observation.vendor_specific["banner"] == "Other A1"


def test_hardware_scanner_uses_unambiguous_plugin_and_keeps_ambiguous_tpm_unknown():
    from universal_vendor.hardware.plugins import build_registry
    from universal_vendor.hardware.scanner import UniversalHardwareScanner

    result = UniversalHardwareScanner(plugins=build_registry()).scan({
        "asset_id": "srv-1",
        "dmi": {"serial": "S1", "product": "PowerEdge R740"},
        "tpm": {"present": True, "version": "2.0"},
        "cpu": {"vendor": "Intel", "flags": "aes sha_ni"},
    })
    observation = result["observations"][0]
    assert observation["manufacturer"] == "Dell"
    assert "plugin:hw_dell_poweredge" in observation["discovery_sources"]
    assert any(row["category"] == "tpm" for row in result["plugin_detection"]["ambiguous"])
    assert result["capabilities"][0]["hardware_supported"]["aes"] is True
    assert result["capabilities"][0]["software_used"] == []


def test_anonymous_event_fallback_identity_is_stable_and_event_specific():
    from universal_vendor.hardware.live.events import HardwareEvent, HardwareEventPipeline

    pipeline = HardwareEventPipeline()
    first = pipeline.resolve_identity(HardwareEvent(
        event_type="HARDWARE_DISCOVERED", source="agent",
        observed_at="2026-01-01T00:00:00+00:00", payload={"hostname": "hidden"}))
    repeat = pipeline.resolve_identity(HardwareEvent(
        event_type="HARDWARE_DISCOVERED", source="agent",
        observed_at="2026-01-01T00:00:00+00:00", payload={"hostname": "hidden"}))
    different = pipeline.resolve_identity(HardwareEvent(
        event_type="FIRMWARE_CHANGED", source="agent",
        observed_at="2026-01-01T00:00:00+00:00", payload={"hostname": "hidden"}))
    assert first[0] == repeat[0]
    assert first[0] != different[0]
