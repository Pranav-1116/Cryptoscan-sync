from __future__ import annotations

import pytest

from network_scanner.inventory.network_inventory import (
    NetworkInventoryDocument,
    inventory_completeness,
    inventory_hash,
    inventory_risk,
    parse_inventory,
)
from network_scanner.inventory_adapter import inventory_from_discovery


def test_empty_inventory_is_explicitly_incomplete_and_risky() -> None:
    document = NetworkInventoryDocument(inventory_id="tenant-a")
    completeness = inventory_completeness(document)
    risk = inventory_risk(document)

    assert completeness["status"] == "INCOMPLETE"
    assert set(completeness["missing_sections"]) == {
        "devices", "topology", "configuration", "network_services",
        "security_controls", "wan_connectivity", "monitoring",
        "wireless_networks", "firmware_software", "documentation", "evidence",
    }
    assert risk["posture"] == "RED"
    assert "management identity is missing" in risk["reasons"]


def test_secret_bearing_inventory_fields_are_rejected() -> None:
    with pytest.raises(ValueError, match="secret-bearing field"):
        parse_inventory({"devices": [{"device_id": "r1", "device_type": "router", "password": "no"}]})

    with pytest.raises(ValueError, match="secret value"):
        parse_inventory({"documentation": {"ip_plan_reference": "https://x.test/export?token=abcdefghijklmnopqrst"}})

    allowed = parse_inventory({"network_services": {"authentication": {"credential_reference": "vault://network/r1"}}})
    assert allowed.network_services.authentication.credential_reference == "vault://network/r1"


def test_inventory_hash_is_deterministic_and_schema_alias_is_preserved() -> None:
    payload = {"inventory_id": "net-a", "source": "NMAP"}
    one = parse_inventory(payload)
    two = parse_inventory(payload)
    assert inventory_hash(one) == inventory_hash(two)
    assert one.model_dump(by_alias=True)["schema"] == "cryptoscan.network-inventory/1"


def test_discovery_adapter_keeps_unknown_areas_unknown() -> None:
    document = inventory_from_discovery({
        "assets": [{
            "asset_identity": "router-a",
            "ip_addresses": ["10.0.0.1"],
            "device_type": "router",
            "last_seen": "2026-10-02T00:00:00Z",
        }],
        "scan_metadata": {},
    }, inventory_id="net-a")

    assert document.devices[0].device_id == "router-a"
    assert document.devices[0].management_ip == "10.0.0.1"
    assert document.topology.physical_connections == []
    assert document.evidence[0].status == "UNVERIFIED"
    assert "topology" in inventory_completeness(document)["missing_sections"]
