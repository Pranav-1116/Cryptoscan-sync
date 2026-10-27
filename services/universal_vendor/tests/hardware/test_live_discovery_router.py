"""§5 discovery mechanism router + §6 targeted re-discovery execution +
§12 NIC → network relationships + monitor bridge."""

from __future__ import annotations


from universal_vendor.hardware.correlation import HardwareCorrelationEngine
from universal_vendor.hardware.live import (
    HardwareEvent,
    HardwareEventType,
    LiveDiscoveryRouter,
    LiveHardwareController,
    discovery_mechanism,
)
from universal_vendor.hardware.models import HardwareType
from universal_vendor.hardware.safety import SafetyController


# ── §5 catalog ─────────────────────────────────────────────────────────

def test_every_hardware_type_has_a_mechanism():
    for member in HardwareType:
        mechanism = discovery_mechanism(member.value)
        assert mechanism, member
        assert mechanism in (
            "agent_dmi_smbios_pci", "telemetry_snmpv3_management_api",
            "authorized_hsm_management_interface", "local_os_tpm_interface",
            "local_os_smart_card_interface", "local_os_secure_element_interface",
            "os_storage_management_api", "hypervisor_api", "passive_first",
        )


def test_mechanism_catalog_spec_examples():
    assert discovery_mechanism("server") == "agent_dmi_smbios_pci"
    assert discovery_mechanism("switch") == "telemetry_snmpv3_management_api"
    assert discovery_mechanism("hsm") == "authorized_hsm_management_interface"
    assert discovery_mechanism("tpm") == "local_os_tpm_interface"
    assert discovery_mechanism("san") == "os_storage_management_api"
    assert discovery_mechanism("hypervisor_host") == "hypervisor_api"
    # OT/ICS + IoT: passive-first is the default (§22)
    assert discovery_mechanism("plc") == "passive_first"
    assert discovery_mechanism("iot_gateway") == "passive_first"
    assert discovery_mechanism("industrial_controller") == "passive_first"


# ── §5 execution ───────────────────────────────────────────────────────

def test_server_discovery_uses_agent_mechanism():
    router = LiveDiscoveryRouter()
    result = router.execute(
        device_type="server", asset_id="srv-1",
        context={"dmi": {"manufacturer": "Dell", "product": "R760",
                         "serial": "SN-1", "bios_version": "2.18"}},
    )
    assert result["mechanism"] == "agent_dmi_smbios_pci"
    assert result["blocked"] is False
    assert result["observations"], "DMI context must produce observations"
    assert result["observations"][0]["manufacturer"] == "Dell"


def test_ot_ics_passive_first_never_probes():
    """§22: passive-first for OT — active context (SNMP creds, SSH) must be
    ignored even if the caller passes it."""
    router = LiveDiscoveryRouter()
    result = router.execute(
        device_type="plc", asset_id="plc-1",
        context={
            "snmp": {"sysname": "plc-1", "community": "public"},
            "ssh": {"host": "plc-1", "username": "root"},
            "passive_observation": {"tcp_syn": "ack", "mac": "00:11:22:33:44:55"},
        },
    )
    assert result["passive_only"] is True
    assert result["mechanism"] == "passive_first"
    obs = result["observations"]
    assert obs, "passive observation must be captured"
    assert "community" not in str(obs)
    assert "root" not in str(obs)
    assert obs[0]["vendor_specific"]["passive"]["mac"] == "00:11:22:33:44:55"


def test_safety_gating_blocks_out_of_scope():
    safety = SafetyController()
    safety.authorize("srv-1")
    router = LiveDiscoveryRouter(safety=safety)
    result = router.execute(device_type="server", asset_id="srv-2",
                            context={"dmi": {"serial": "X"}})
    assert result["blocked"] is True
    assert result["observations"] == []
    assert any(a["outcome"] == "BLOCKED" for a in router.audit())
    # authorized asset proceeds
    ok = router.execute(device_type="server", asset_id="srv-1",
                        context={"dmi": {"serial": "X", "manufacturer": "Dell"}})
    assert ok["blocked"] is False
    assert any(a["outcome"] == "ALLOWED" for a in router.audit())


# ── §6 targeted re-discovery through the controller ────────────────────

def test_controller_rediscover_runs_only_required_mechanism():
    ctl = LiveHardwareController()
    ctl.ingest(HardwareEvent(event_type=HardwareEventType.HARDWARE_DISCOVERED,
                             asset_id="srv-1", device_type="server",
                             manufacturer="Dell", model="R760"))
    result = ctl.rediscover(
        asset_id="srv-1", device_type="server",
        event_type="BIOS_CHANGED",
        context={"dmi": {"manufacturer": "Dell", "product": "R760",
                         "serial": "SN-1", "bios_version": "2.19"}},
    )
    assert result["blocked"] is False
    assert result["mechanism"] == "agent_dmi_smbios_pci"
    assert result["plan"]["event_type"] == "BIOS_CHANGED"
    assert "bios_verification" in result["plan"]["required_actions"]
    assert result["ingested"], "rediscovery observations must be ingested"
    state = ctl.live_state("srv-1")[0]
    assert state["firmware"]["BIOS"] == "2.19"


def test_controller_rediscover_ot_passive_only():
    ctl = LiveHardwareController()
    result = ctl.rediscover(
        asset_id="plc-7", device_type="plc", event_type="HARDWARE_CHANGED",
        context={"snmp": {"community": "public"},
                 "passive_observation": {"mac": "aa:bb:cc:dd:ee:ff"}},
    )
    assert result["passive_only"] is True
    assert result["mechanism"] == "passive_first"


# ── monitor bridge (diagram: Agent Telemetry / APIs / Passive → bus) ───

def test_run_monitor_bridges_sources_into_controller():
    class FakeSource:
        def collect(self):
            return [
                {"event_type": "HARDWARE_DISCOVERED", "asset_id": "srv-1",
                 "manufacturer": "Dell", "model": "R760"},
                {"event_type": "BIOS_CHANGED", "asset_id": "srv-1",
                 "component": "BIOS", "version": "2.19"},
                {"event_type": "NOT_VALID", "asset_id": "srv-1"},  # skipped
            ]

    from universal_vendor.hardware.live.state import LiveHardwareMonitor

    monitor = LiveHardwareMonitor()
    monitor.register(FakeSource())
    ctl = LiveHardwareController()
    results = ctl.run_monitor(monitor)
    assert len(results) == 2  # invalid event skipped
    assert ctl.live_state("srv-1")[0]["firmware"]["BIOS"] == "2.19"
    assert ctl.event_count() == 2


# ── §12 NIC change → affected network relationships ────────────────────

def test_nic_change_reports_affected_network_relationships():
    correlation = HardwareCorrelationEngine()
    correlation.link_hardware_to_network(
        server="srv-1", nic="nic-1", switch="sw-1", firewall="fw-1",
        load_balancer="lb-1", application="payments",
    )
    ctl = LiveHardwareController(correlation=correlation)
    ctl.ingest(HardwareEvent(event_type=HardwareEventType.HARDWARE_DISCOVERED,
                             asset_id="srv-1", device_type="server"))
    result = ctl.ingest(HardwareEvent(event_type=HardwareEventType.NIC_CHANGED,
                                      asset_id="srv-1", component="nic-1",
                                      version="fw-2.1"))
    rels = result["network_relationships"]
    nodes = {r["node"] for r in rels}
    assert {"sw-1", "fw-1", "lb-1", "payments"} <= nodes
    assert result["targeted_plan"]["required_actions"] == [
        "nic_verification", "network_relationship_analysis", "capability_verification"]


def test_nic_change_without_correlation_is_none():
    ctl = LiveHardwareController()
    ctl.ingest(HardwareEvent(event_type=HardwareEventType.HARDWARE_DISCOVERED,
                             asset_id="srv-1"))
    result = ctl.ingest(HardwareEvent(event_type=HardwareEventType.NIC_CHANGED,
                                      asset_id="srv-1"))
    assert result["network_relationships"] is None
