from __future__ import annotations

import pytest

from network_scanner.inventory.network_inventory import (
    NetworkInventoryDocument,
    configuration_drift,
    inventory_completeness,
    inventory_hash,
    inventory_risk,
    parse_inventory,
    topology_graph,
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


def test_discovery_adapter_uses_scrubbed_plugin_observations_for_interfaces() -> None:
    document = inventory_from_discovery({
        "assets": [{"asset_identity": "r1", "ip_addresses": ["10.0.0.1"], "device_type": "router", "source": "snmp"}],
        "inventory_observations": [{
            "asset_identity": "r1", "ip": "10.0.0.1", "vendor": "Example", "interfaces": [{"ifDescr": "Gi0/1", "ifOperStatus": "up"}],
        }],
        "scan_metadata": {},
    })
    assert document.devices[0].discovery_source == "SNMP"
    assert document.devices[0].interfaces[-1].name == "Gi0/1"


def test_discovery_adapter_promotes_only_observed_graph_edges() -> None:
    document = inventory_from_discovery({
        "assets": [
            {"asset_identity": "r1", "ip_addresses": ["10.0.0.1"], "device_type": "router"},
            {"asset_identity": "r2", "ip_addresses": ["10.0.0.2"], "device_type": "router"},
        ],
        "topology": {"edges": [{"source": "r1", "target": "r2", "relationship": "CONNECTED_TO"}]},
        "scan_metadata": {},
    })
    assert len(document.topology.graph_edges) == 1
    assert document.topology.graph_edges[0].observation.status == "OBSERVED"
    assert topology_graph(document)["unknown_endpoints"] == []


def test_configuration_artifacts_must_be_secret_free() -> None:
    with pytest.raises(ValueError, match="raw or secret-bearing"):
        parse_inventory({"configuration": {"snapshots": [{"snapshot_id": "s", "device_id": "r1", "kind": "RUNNING", "secret_free": False}]}})


def test_configuration_drift_requires_hashes_and_detects_differences() -> None:
    document = parse_inventory({
        "devices": [{"device_id": "r1", "device_type": "router", "management_ip": "10.0.0.1"}],
        "configuration": {
            "snapshots": [
                {"snapshot_id": "base", "device_id": "r1", "kind": "BASELINE", "content_sha256": "a" * 64},
                {"snapshot_id": "run", "device_id": "r1", "kind": "RUNNING", "content_sha256": "b" * 64},
            ]
        },
    })
    result = configuration_drift(document)
    assert result["status"] == "DRIFTED"
    assert result["drifted_comparisons"] == 1
    assert result["raw_configuration_stored"] is False


def test_topology_graph_reports_unknown_endpoints_and_unverified_edges() -> None:
    document = parse_inventory({
        "devices": [{"device_id": "r1", "device_type": "router"}],
        "topology": {"graph_edges": [{
            "source": "r1", "target": "not-in-inventory", "relationship": "ROUTES_TO",
        }]},
    })
    result = topology_graph(document)
    assert result["unknown_endpoints"] == ["not-in-inventory"]
    assert result["unverified_edges"] == 1
