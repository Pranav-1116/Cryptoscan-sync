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
    devices: list[NetworkDevice] = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        identity = str(asset.get("asset_identity") or "").strip()
        if not identity:
            continue
        ip_addresses = [str(value) for value in (asset.get("ip_addresses") or [])]
        device_type = _DEVICE_TYPES.get(str(asset.get("device_type") or "").lower(), "other")
        interfaces = [
            NetworkInterface(name=f"observed-{index + 1}", ip_addresses=[ip])
            for index, ip in enumerate(ip_addresses)
        ]
        devices.append(NetworkDevice(
            device_id=identity,
            device_type=device_type,
            manufacturer=asset.get("manufacturer"),
            model=asset.get("model"),
            management_ip=ip_addresses[0] if ip_addresses else None,
            management_fqdn=asset.get("fqdn") or asset.get("hostname"),
            role=asset.get("device_type") or None,
            criticality=str(asset.get("criticality") or "unknown").lower()
            if str(asset.get("criticality") or "unknown").lower() in {"critical", "high", "medium", "low"}
            else "unknown",
            firmware={
                "os": asset.get("os"),
                "version": asset.get("os_version"),
            },
            interfaces=interfaces,
            discovery_source="OTHER",
            last_seen=_parse_datetime(asset.get("last_seen")),
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
    return NetworkInventoryDocument(
        inventory_id=inventory_id,
        captured_at=scan_time,
        source="MIXED",
        devices=devices,
        evidence=[evidence],
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
