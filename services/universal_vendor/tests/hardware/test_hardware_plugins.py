"""Hardware scanner tests — discovery, plugins, scanner pipeline (§2, §20, §25)."""

from __future__ import annotations

import pytest

from universal_vendor.hardware.models import (
    HardwareConfidence,
    HardwareObservation,
    HardwareType,
)


# ── §2 three discovery methods ─────────────────────────────────────────

def test_agent_based_discovery_dmi():
    from universal_vendor.hardware.discovery import AgentBasedDiscovery

    collector = AgentBasedDiscovery()
    raw = collector.collect({"dmi": {"serial": "SN1", "product": "PowerEdge",
                                     "bios_version": "2.1",
                                     "manufacturer": "Dell Inc."}})
    assert raw and raw[0]["source"] == "agent"
    assert raw[0]["manufacturer"] == "Dell Inc."
    assert raw[0]["model"] == "PowerEdge"


def test_network_based_discovery_snmp():
    from universal_vendor.hardware.discovery import NetworkBasedDiscovery

    collector = NetworkBasedDiscovery()
    raw = collector.collect({"snmp": {"sysname": "core-sw1",
                                      "serial": "FOC123",
                                      "sysdescr": "Cisco IOS",
                                      "manufacturer": "Cisco"}})
    assert raw and raw[0]["source"] == "network"
    assert raw[0]["asset_id"] == "core-sw1"
    assert raw[0]["manufacturer"] == "Cisco"


def test_api_based_discovery_cloud():
    from universal_vendor.hardware.discovery import ApiBasedDiscovery

    collector = ApiBasedDiscovery()
    raw = collector.collect({"api_metadata": {
        "devices": [{"asset_id": "i-123", "instance_type": "m5.large",
                     "region": "us-east-1", "manufacturer": "AWS",
                     "model": "m5.large", "device_type": "server",
                     "visibility": "provider_declared"}]}})
    assert raw and raw[0]["source"] == "api"
    assert raw[0]["asset_id"] == "i-123"
    assert raw[0]["region"] == "us-east-1"
    assert raw[0]["visibility"] == "provider_declared"


def test_discovery_orchestrator_merges_higher_confidence_wins():
    from universal_vendor.hardware.discovery import (
        AgentBasedDiscovery,
        HardwareDiscoveryOrchestrator,
        NetworkBasedDiscovery,
    )

    orchestrator = HardwareDiscoveryOrchestrator(
        AgentBasedDiscovery(), NetworkBasedDiscovery())
    observations = orchestrator.discover([{
        "asset_id": "srv-9",
        "dmi": {"serial": "SN-9", "product": "R740", "bios_version": "2.10"},
        "passive_observation": {"mac": "00:11:22:33:44:55"},
    }])
    # agent (HIGH) and passive (LOW) describe the same asset_id — one merged
    # observation keeps the higher-confidence source
    assert len(observations) == 1
    obs = observations[0]
    assert obs.asset_id == "srv-9"
    assert obs.source == "agent"
    assert obs.confidence == HardwareConfidence.HIGH.value
    # passive evidence preserved in vendor_specific
    assert obs.vendor_specific["passive"] == {"mac": "00:11:22:33:44:55"}


def test_discovery_orchestrator_never_depends_on_one_source():
    """A context that only carries API metadata must still yield an
    observation — the orchestrator runs all three collectors."""
    from universal_vendor.hardware.discovery import (
        AgentBasedDiscovery,
        ApiBasedDiscovery,
        HardwareDiscoveryOrchestrator,
        NetworkBasedDiscovery,
    )

    orchestrator = HardwareDiscoveryOrchestrator(
        AgentBasedDiscovery(), NetworkBasedDiscovery(), ApiBasedDiscovery())
    observations = orchestrator.discover([{
        "api_metadata": {"devices": [{
            "asset_id": "vm-7", "manufacturer": "VMware",
            "model": "ESXi guest", "device_type": "virtualization",
            "region": "us-east-1"}]}}])
    assert len(observations) == 1
    assert observations[0].asset_id == "vm-7"
    assert observations[0].source == "api"


# ── §25 plugin framework ───────────────────────────────────────────────

def test_plugin_registry_counts_and_categories():
    from universal_vendor.hardware.plugins import build_registry

    registry = build_registry()
    assert registry.count() >= 25
    categories = {cls.category.value for cls in registry.all()}
    for wanted in ("server", "switch", "firewall", "hsm", "tpm",
                   "storage" if False else "san", "gpu",
                   "hypervisor_host", "iot_gateway", "plc"):
        assert wanted in categories
    # by-manufacturer lookup
    assert registry.by_manufacturer("Cisco")
    assert registry.by_manufacturer("Thales")


def test_plugin_duplicate_id_rejected():
    from universal_vendor.hardware.plugin import HardwarePluginRegistry
    from universal_vendor.hardware.plugins.server import DellServerPlugin

    registry = HardwarePluginRegistry()
    registry.register(DellServerPlugin)
    with pytest.raises(ValueError):
        registry.register(DellServerPlugin)


def test_plugin_detect_banner_server():
    from universal_vendor.hardware.plugins.server import DellServerPlugin

    plugin = DellServerPlugin()
    result = plugin.detect({"banner": "PowerEdge R740 iDRAC"})
    assert result["detected"] is True
    assert result["manufacturer"] == "Dell"
    assert result["confidence"] == HardwareConfidence.HIGH.value
    assert plugin.detect({"banner": "some random thing"})["detected"] is False


def test_plugin_detect_banner_network():
    from universal_vendor.hardware.plugins.network import CiscoHwPlugin

    plugin = CiscoHwPlugin()
    assert plugin.detect({"snmp_sysdescr": "Cisco IOS XE Catalyst 9300"})[
        "detected"] is True


def test_plugin_identify_multi_signal():
    from universal_vendor.hardware.plugins.server import HpeServerPlugin

    plugin = HpeServerPlugin()
    identity = plugin.identify({
        "dmi": {"serial": "CZ123", "product": "ProLiant DL380"},
        "asset_id": "srv-hpe-1",
    })
    assert identity.manufacturer == "HPE"
    assert identity.confidence == HardwareConfidence.HIGH.value


def test_plugin_inventory_firmware_crypto():
    from universal_vendor.hardware.plugins.server import DellServerPlugin

    plugin = DellServerPlugin()
    context = {"asset_id": "srv-1",
               "dmi": {"serial": "SN-1", "product": "R740",
                       "bios_version": "2.10"},
               "bmc": {"firmware": "5.0"},
               "cpu": {"vendor": "GenuineIntel", "flags": "aes sha_ni"},
               "tpm": {"present": True, "version": "2.0"}}
    inventory = plugin.inventory(context)
    assert inventory and inventory[0]["serial_reference"] == "SN-1"
    firmware = plugin.discover_firmware(context)
    assert {f["firmware_component"] for f in firmware} == {"BIOS", "BMC"}
    crypto = plugin.discover_crypto(context)
    assert any(r["algorithm"] == "CPU" for r in crypto)
    assert any(r["algorithm"] == "TPM" for r in crypto)


def test_plugin_collect_evidence_and_normalize():
    from universal_vendor.hardware.plugins.server import DellServerPlugin

    plugin = DellServerPlugin()
    context = {"asset_id": "srv-1", "dmi": {"serial": "SN-1",
                                            "product": "R740"}}
    evidence = plugin.collect_evidence(context)
    assert evidence
    raw = plugin.inventory(context)[0]
    obs = plugin.normalize(raw)
    assert isinstance(obs, HardwareObservation)
    assert obs.manufacturer == "Dell"
    assert obs.device_type == HardwareType.SERVER.value


def test_plugin_health_check_read_only():
    from universal_vendor.hardware.plugins.hsm import ThalesLunaHwPlugin

    plugin = ThalesLunaHwPlugin()
    health = plugin.health_check({})
    assert health["ok"] is True
    assert health["read_only"] is True


def test_hsm_plugin_metadata_only_normalize():
    from universal_vendor.hardware.plugins.hsm import UtimacoHwPlugin

    plugin = UtimacoHwPlugin()
    obs = plugin.normalize(plugin.inventory({
        "asset_id": "hsm-2", "serial": "U-1", "firmware": "4.5",
        "model": "SecurityServer",
        "supported_algorithms": ["RSA", "ECC"],
        "partition_metadata": {"partitions": 8},
    })[0])
    assert obs.device_type == HardwareType.HSM.value
    assert obs.hsm["supported_algorithms"] == ["RSA", "ECC"]
    # no key material ever lands in the canonical record
    assert "private_key" not in obs.to_dict()


def test_tpm_plugin_parse():
    from universal_vendor.hardware.plugins.tpm import TpmGenericPlugin

    plugin = TpmGenericPlugin()
    result = plugin.detect({"tpm_present": True})
    assert result["detected"] is True
    obs = plugin.normalize(plugin.inventory({
        "asset_id": "tpm-1",
        "tpm": {"present": True, "version": "2.0",
                "supported_algorithms": ["SHA-256"]}})[0])
    assert obs.tpm["version"] == "2.0"


def test_plc_plugin_passive_first():
    from universal_vendor.hardware.plugins.industrial import SiemensPlcPlugin

    plugin = SiemensPlcPlugin()
    assert getattr(plugin, "passive_first", False) is True
    result = plugin.detect({"banner": "SIMATIC S7-1500"})
    assert result["detected"] is True
    assert result["manufacturer"] == "Siemens"


def test_plugin_scrubs_credentials_from_vendor_specific():
    from universal_vendor.hardware.plugins.storage import NetappStoragePlugin

    plugin = NetappStoragePlugin()
    obs = plugin.normalize(plugin.inventory({
        "asset_id": "netapp-1", "serial": "NA-1", "firmware": "9.10",
        "controllers": {"a": {"status": "ok"}},
    })[0])
    assert obs.vendor_specific["controllers"] == {"a": {"status": "ok"}}
    # injecting a password-shaped field must be redacted, never stored in clear
    raw = plugin._raw(asset_id="netapp-1", api_password="hunter2")
    assert plugin._scrubbed(raw)["api_password"] == "<REDACTED>"


# ── §20 end-to-end scanner pipeline ────────────────────────────────────

def test_scanner_full_pipeline_with_evidence_chain():
    from universal_vendor.hardware.plugins import build_registry
    from universal_vendor.hardware.scanner import UniversalHardwareScanner

    scanner = UniversalHardwareScanner(plugins=build_registry())
    result = scanner.scan({
        "dmi": {"serial": "SN-E2E", "product": "PowerEdge R740",
                "bios_version": "2.10"},
        "bmc": {"firmware": "5.2"},
        "cpu": {"vendor": "GenuineIntel", "flags": "aes sha_ni rdrand"},
        "tpm": {"present": True, "version": "2.0",
                "supported_algorithms": ["SHA-256", "RSA"]},
        "snmp": {"sysname": "srv-e2e", "serial": "SN-E2E",
                 "sysdescr": "Dell PowerEdge"},
        "asset_id": "srv-e2e",
    }, scan_id="scan-e2e")
    assert result["scan_id"] == "scan-e2e"
    assert result["observations"]
    assert result["evidence"]
    assert result["evidence_verification"]["valid"] is True
    assert result["hbom"]["hardware"]
    assert result["graph"] is not None
    assert result["pqc"]
    assert result["risks"]


def test_scanner_evidence_chain_tamper_detection():
    from universal_vendor.hardware.plugins import build_registry
    from universal_vendor.hardware.scanner import UniversalHardwareScanner

    scanner = UniversalHardwareScanner(plugins=build_registry())
    result = scanner.scan({"dmi": {"serial": "SN-T", "product": "R740"}},
                          scan_id="scan-t")
    tampered = result["evidence"][0].copy()
    tampered["observation"] = {"asset_id": "evil"}
    from universal_vendor.evidence import verify_evidence_chain

    check = verify_evidence_chain([tampered] + result["evidence"][1:],
                                  scan_id="scan-t")
    assert check["valid"] is False
    assert check["errors"]


def test_scanner_carries_plugin_firmware_and_hsm_capability_evidence():
    from universal_vendor.hardware.plugins import build_registry
    from universal_vendor.hardware.scanner import UniversalHardwareScanner

    result = UniversalHardwareScanner(plugins=build_registry()).scan({
        "asset_id": "hsm-1", "manufacturer": "Thales", "model": "Luna",
        "firmware": "7.10", "supported_algorithms": ["RSA", "AES"],
        "crypto_capabilities": ["FIPS 140-3"],
        "partition_metadata": {"partitions": 2},
    })
    observation = result["observations"][0]
    assert observation["device_type"] == "hsm"
    assert observation["firmware_components"] == {"HSM": "7.10"}
    assert observation["hsm"]["supported_algorithms"] == ["AES", "RSA"]
    assert observation["hsm"]["crypto_capabilities"] == ["FIPS 140-3"]
    assert result["capabilities"][0]["supported_but_unused"] == ["AES", "RSA"]
