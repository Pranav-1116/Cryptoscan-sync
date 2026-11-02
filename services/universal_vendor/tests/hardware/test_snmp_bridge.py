"""The SNMP bridge: what it carries across, and what it refuses to carry.

The bridge is the seam between the network scanner and the hardware estate. Two
things can go wrong at a seam — a fact gets dropped, or a credential gets
carried — so the tests here check both directions, with the network scanner's
own ``SnmpDeviceInfo`` where possible rather than a lookalike.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from universal_vendor.hardware.host.snmp_bridge import (
    CredentialLeakRefused,
    SnmpHardwareBridge,
    SnmpUnavailable,
)
from universal_vendor.hardware.models import HardwareObservation


@dataclass
class FakeDevice:
    """The shape the bridge consumes — deliberately not the real class."""

    host: str = "core-sw-01"
    reachable: bool = True
    sys_descr: str | None = "Cisco IOS XE Software, Version 17.09.04a"
    sys_object_id: str | None = "1.3.6.1.4.1.9.1.1222"
    sys_name: str | None = "core-sw-01.dxb.example.com"
    sys_location: str | None = "DXB-DC1-ROW3"
    interfaces: list[dict[str, Any]] = field(default_factory=lambda: [
        {"ifDescr": "Gi1/0/1", "ifOperStatus": 1, "ifSpeed": 1000000000,
         "ifPhysAddress": "aa:bb:cc:00:11:22"},
        {"ifDescr": "Gi1/0/2", "ifOperStatus": 2, "ifSpeed": 1000000000},
    ])
    routes: list[dict[str, Any]] = field(default_factory=lambda: [{"routeDest": "10.0.0.0"}])
    entities: list[dict[str, Any]] = field(default_factory=lambda: [
        {"entPhysicalClass": 3, "entPhysicalName": "Chassis",
         "entPhysicalSerialNum": "FDO2140A1B2", "entPhysicalModelName": "C9300-48P",
         "entPhysicalFirmwareRev": "17.9.4a"},
        {"entPhysicalClass": 7, "entPhysicalName": "Fan tray 1",
         "entPhysicalSerialNum": "FAN-0001"},
    ])
    security_mode: str = "SNMPv2c-community"
    vendor_name: str | None = "Cisco"


def discover_with(device: FakeDevice):
    def discover(host, **kwargs):
        return device

    return discover


def test_a_switch_arrives_with_identity_not_a_marketing_sentence():
    bridge = SnmpHardwareBridge(discover=discover_with(FakeDevice()))
    facts = bridge.collect("core-sw-01", community="s3cret-community")

    assert facts.reachable is True
    assert facts.vendor == "Cisco"
    assert facts.model == "C9300-48P"
    assert facts.serial_reference == "FDO2140A1B2"
    assert facts.firmware == "17.9.4a"
    assert facts.sources["chassis"] == "ENTITY-MIB"
    assert facts.context["asset_id"] == "core-sw-01.dxb.example.com"
    assert facts.context["manufacturer"] == "Cisco"


def test_the_context_feeds_network_discovery():
    from universal_vendor.hardware.discovery import NetworkBasedDiscovery

    bridge = SnmpHardwareBridge(discover=discover_with(FakeDevice()))
    facts = bridge.collect("core-sw-01", community="s3cret-community")
    records = NetworkBasedDiscovery().collect(facts.context)

    assert len(records) == 1
    assert records[0]["serial_reference"] == "FDO2140A1B2"
    assert records[0]["firmware"] == "17.9.4a"
    assert records[0]["vendor_specific"]["snmp_sysdescr"].startswith("Cisco IOS XE")


def test_the_observation_is_a_switch_not_a_mystery_box():
    bridge = SnmpHardwareBridge(discover=discover_with(FakeDevice()))
    facts = bridge.collect("core-sw-01", community="s3cret-community")
    observation = bridge.to_observation(facts)

    assert isinstance(observation, HardwareObservation)
    assert observation.device_type == "switch"
    assert observation.serial_reference == "FDO2140A1B2"
    assert observation.source == "network"
    assert observation.confidence == "HIGH"


def test_the_crypto_seam_states_what_snmp_cannot_answer():
    bridge = SnmpHardwareBridge(discover=discover_with(FakeDevice()))
    facts = bridge.collect("core-sw-01", community="s3cret-community")
    crypto = facts.context["crypto"]
    assert crypto["tls_terminator"] is True
    assert crypto["interfaces_up"] == 1
    assert "not from SNMP" in crypto["note"]


def test_the_community_string_never_survives_the_call():
    bridge = SnmpHardwareBridge(discover=discover_with(FakeDevice()))
    facts = bridge.collect("core-sw-01", community="s3cret-community")
    payload = facts.to_dict()
    assert "s3cret-community" not in str(payload)
    assert payload["credential_ref"] is None
    assert "community" not in payload


def test_a_device_that_echoes_the_credential_is_refused():
    """If the community comes back in sysDescr, something is wrong on that box."""
    device = FakeDevice(sys_descr="Cisco IOS XE (community s3cret-community)")
    bridge = SnmpHardwareBridge(discover=discover_with(device))
    with pytest.raises(CredentialLeakRefused):
        bridge.collect("core-sw-01", community="s3cret-community")


def test_an_unreachable_device_is_a_reason_not_an_empty_inventory():
    device = FakeDevice(reachable=False, interfaces=[], entities=[])
    bridge = SnmpHardwareBridge(discover=discover_with(device))
    facts = bridge.collect("10.0.0.99", community="public")

    assert facts.reachable is False
    assert facts.context == {}
    assert "no response" in facts.unavailable[0]
    assert "empty inventory" in facts.unavailable[0]
    assert bridge.to_observation(facts) is None


def test_a_discovery_error_is_a_fact_not_a_crash():
    def broken(host, **kwargs):
        raise TimeoutError("no route to host")

    facts = SnmpHardwareBridge(discover=broken).collect("10.0.0.99", community="public")
    assert facts.reachable is False
    assert "no route to host" in facts.unavailable[0]


def test_a_deployment_without_the_network_scanner_says_so():
    def unavailable(host, **kwargs):
        raise SnmpUnavailable("no SNMP client is importable")

    facts = SnmpHardwareBridge(discover=unavailable).collect("10.0.0.99", community="public")
    assert facts.unavailable == ["no SNMP client is importable"]


def test_chassis_wins_over_a_part_with_its_own_serial():
    device = FakeDevice(entities=[
        {"entPhysicalClass": 7, "entPhysicalSerialNum": "FAN-0001"},
        {"entPhysicalClass": 3, "entPhysicalSerialNum": "FDO2140A1B2",
         "entPhysicalModelName": "C9300-48P"},
    ])
    facts = SnmpHardwareBridge(discover=discover_with(device)).collect(
        "core-sw-01", community="public")
    assert facts.serial_reference == "FDO2140A1B2"


def test_no_entities_means_no_invented_serial():
    device = FakeDevice(entities=[])
    facts = SnmpHardwareBridge(discover=discover_with(device)).collect(
        "core-sw-01", community="public")
    assert facts.serial_reference is None
    assert facts.model is None
    assert facts.host == "core-sw-01"


def test_works_with_the_real_network_scanner_object():
    """Not a lookalike: the production dataclass and its real chassis property."""
    from network_scanner.enterprise.vendors.snmp import SnmpDeviceInfo

    device = SnmpDeviceInfo(
        host="core-sw-01", sys_descr="Arista EOS", sys_object_id="1.3.6.1.4.1.30065.1",
        sys_name="core-sw-01", reachable=True, security_mode="SNMPv2c-community",
        entities=[
            {"entPhysicalClass": 3, "entPhysicalSerialNum": "AR-1",
             "entPhysicalModelName": "DCS-7050SX3"},
            {"entPhysicalClass": 7, "entPhysicalSerialNum": "FAN-2"},
        ],
        interfaces=[{"ifDescr": "Ethernet1", "ifOperStatus": 1}],
    )
    facts = SnmpHardwareBridge(
        discover=lambda host, **kwargs: device).collect("core-sw-01", community="public")
    assert facts.serial_reference == "AR-1"
    assert facts.model == "DCS-7050SX3"
    assert facts.context["manufacturer"] == "Arista"


def test_facts_are_json_serialisable():
    import json

    bridge = SnmpHardwareBridge(discover=discover_with(FakeDevice()))
    facts = bridge.collect("core-sw-01", community="public")
    payload = json.loads(json.dumps(facts.to_dict()))
    assert payload["schema"] == "cryptoscan.snmp-hardware/1"
    assert payload["serial_reference"] == "FDO2140A1B2"
