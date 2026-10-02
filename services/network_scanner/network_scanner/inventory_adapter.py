"""Translate observed scanner output into the structured inventory contract.

The adapter only promotes facts already present in the discovery report. It
never guesses a device role, topology link, firmware version, or security
posture. Missing areas remain empty and are reported by inventory_completeness.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from network_scanner.inventory.network_inventory import (
    InventoryEvidence,
    NetworkDevice,
    NetworkInventoryDocument,
    NetworkInterface,
    ObservationMetadata,
    TopologyGraphEdge,
    inventory_completeness,
)


_DEVICE_TYPES = {
    "router": "router",
    "switch": "switch",
    "firewall": "firewall",
    "load_balancer": "load_balancer",
    "wireless_controller": "wireless_controller",
    "dns_server": "dns_server",
    "vpn_gateway": "vpn_concentrator",
    "proxy": "proxy",
    "ids_ips": "ids_ips",
    "ddos": "ddos",
    "dhcp_server": "dhcp_server",
    "nac": "nac",
}


def inventory_from_discovery(
    report: dict[str, Any],
    *,
    inventory_id: str | None = None,
    captured_at: datetime | None = None,
) -> NetworkInventoryDocument:
    """Create an incomplete, evidence-linked inventory from a scan report."""
    assets = report.get("assets") or []
    raw_observations = report.get("inventory_observations") or []
    observations_by_identity: dict[str, dict[str, Any]] = {}
    for observation in raw_observations:
        if not isinstance(observation, dict):
            continue
        identity = str(observation.get("asset_identity") or observation.get("ip") or "").strip()
        if identity:
            observations_by_identity[identity] = observation
    devices: list[NetworkDevice] = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        identity = str(asset.get("asset_identity") or "").strip()
        if not identity:
            continue
        ip_addresses = [str(value) for value in (asset.get("ip_addresses") or [])]
        raw = observations_by_identity.get(identity) or {}
        device_type = _DEVICE_TYPES.get(str(asset.get("device_type") or raw.get("device_type") or "").lower(), "other")
        interfaces = [
            NetworkInterface(name=f"observed-{index + 1}", ip_addresses=[ip])
            for index, ip in enumerate(ip_addresses)
        ]
        for index, interface in enumerate(raw.get("interfaces") or []):
            if not isinstance(interface, dict):
                continue
            name = str(interface.get("ifDescr") or interface.get("ifName") or interface.get("name") or interface.get("ifIndex") or f"interface-{index + 1}")
            raw_status = str(interface.get("ifOperStatus") or interface.get("status") or "unknown").lower()
            status = "up" if raw_status in {"up", "1", "up(1)"} else "down" if raw_status in {"down", "2", "down(2)"} else "unknown"
            interfaces.append(NetworkInterface(
                name=name,
                interface_type=str(interface.get("ifType") or interface.get("type") or "") or None,
                speed=str(interface.get("ifSpeed") or interface.get("speed") or "") or None,
                status=status,
                mac_address=interface.get("ifPhysAddress") or interface.get("mac_address"),
            ))
        raw_source = str(asset.get("source") or "").upper()
        discovery_source = raw_source if raw_source in {"SNMP", "SSH", "API", "NMAP", "CONFIG_IMPORT", "MANUAL"} else "NMAP" if raw_source in {"SWEEP", "PROBE", "SCOPE-SPEC"} else "OTHER"
        devices.append(NetworkDevice(
            device_id=identity,
            device_type=device_type,
            manufacturer=asset.get("manufacturer") or raw.get("vendor"),
            model=asset.get("model") or raw.get("model") or raw.get("sys_descr"),
            management_ip=ip_addresses[0] if ip_addresses else str(raw.get("ip") or "") or None,
            management_fqdn=asset.get("fqdn") or asset.get("hostname") or raw.get("sys_name"),
            role=asset.get("device_type") or raw.get("device_type") or None,
            criticality=str(asset.get("criticality") or "unknown").lower()
            if str(asset.get("criticality") or "unknown").lower() in {"critical", "high", "medium", "low"}
            else "unknown",
            firmware={
                "os": asset.get("os"),
                "version": asset.get("os_version"),
            },
            interfaces=interfaces,
            discovery_source=discovery_source,
            last_seen=_parse_datetime(asset.get("last_seen")),
            observation=ObservationMetadata(
                status="OBSERVED",
                observed_at=_parse_datetime(asset.get("last_seen")),
                source="network_scanner",
                limitation="Discovery establishes reachability/identity hints only; it does not establish configuration or control effectiveness.",
            ),
        ))

    graph_edges: list[TopologyGraphEdge] = []
    raw_edges = ((report.get("topology") or {}).get("edges") or [])
    allowed_relationships = {"CONNECTED_TO", "ROUTES_TO", "PROTECTS", "TERMINATES_TLS_FOR", "DEPENDS_ON", "AUTHENTICATES_TO", "USES_CERTIFICATE", "USES_VPN", "USES_IPSEC", "USES_TLS"}
    for index, raw_edge in enumerate(raw_edges):
        if not isinstance(raw_edge, dict) or not raw_edge.get("source") or not raw_edge.get("target"):
            continue
        relationship = str(raw_edge.get("relationship") or "CONNECTED_TO")
        if relationship not in allowed_relationships:
            relationship = "CONNECTED_TO"
        metadata = raw_edge.get("metadata") if isinstance(raw_edge.get("metadata"), dict) else {}
        graph_edges.append(TopologyGraphEdge(
            source=str(raw_edge["source"]),
            target=str(raw_edge["target"]),
            relationship=relationship,
            metadata={str(key): str(value) for key, value in metadata.items() if value is not None},
            observation=ObservationMetadata(status="OBSERVED", source="network_scanner"),
        ))

    scan_time = captured_at or _parse_datetime((report.get("scan_metadata") or {}).get("finished_at")) or datetime.now(timezone.utc)
    reference_id = inventory_id or "discovery"
    evidence = InventoryEvidence(
        evidence_id=f"discovery-{reference_id}-{scan_time.strftime('%Y%m%dT%H%M%SZ')}",
        evidence_type="DISCOVERY",
        reference=f"scanner-report:{reference_id}",
        status="UNVERIFIED",
        captured_at=scan_time,
        source_system="network_scanner",
        collector="GlobalNetworkDiscoveryEngine",
        limitations=[
            "Discovery output does not establish configuration, topology, ownership, firmware currency, or security control effectiveness.",
            "Credentials and secret-bearing artifacts are intentionally excluded.",
        ],
    )
    for device in devices:
        device.observation.evidence_ids = [evidence.evidence_id]
    for edge in graph_edges:
        edge.observation.evidence_ids = [evidence.evidence_id]
    return NetworkInventoryDocument(
        inventory_id=inventory_id,
        captured_at=scan_time,
        source="MIXED",
        devices=devices,
        topology={"graph_edges": graph_edges},
        evidence=[evidence],
        limitations=[
            "Scanner output does not establish a physical cable, patch-panel, VLAN, routing, bandwidth, or redundancy relationship unless explicitly observed and evidenced.",
        ],
    )


def discovery_inventory_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Return a safe summary suitable for scan logs and API responses."""
    document = inventory_from_discovery(report)
    return {
        "device_count": len(document.devices),
        "inventory_completeness": inventory_completeness(document),
        "evidence_count": len(document.evidence),
        "secret_free": True,
    }


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
