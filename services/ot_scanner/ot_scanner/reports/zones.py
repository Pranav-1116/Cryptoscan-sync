"""IEC 62443 zone & conduit approximation from passive flow observations.

Zones are /24 heuristics derived from observed src/dst addresses — an
approximation an engineer can correct, never a claim about the real network
diagram.  Broadcast and multicast destinations are not conduits.
"""

from __future__ import annotations

from typing import Any


def _octets(ip: str) -> list[int] | None:
    parts = str(ip).split(".")
    if len(parts) != 4:
        return None
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    return nums if all(0 <= n <= 255 for n in nums) else None


def _zone_of(ip: str) -> str | None:
    nums = _octets(ip)
    return f"{nums[0]}.{nums[1]}.{nums[2]}.0/24" if nums else None


def _is_broadcast_or_multicast(ip: str) -> bool:
    nums = _octets(ip)
    return bool(nums) and (nums[3] == 255 or 224 <= nums[0] <= 239)


def _flow_endpoints(finding: dict[str, Any]) -> tuple[str | None, str | None]:
    source = finding.get("source") if isinstance(finding.get("source"), dict) else {}
    return source.get("src_ip") or (finding.get("device") or {}).get("ip_address"), source.get("dst_ip")


def cross_zone_flows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Unencrypted flows whose src and dst land in different /24 zones."""
    out: list[dict[str, Any]] = []
    for finding in findings:
        if finding.get("has_crypto"):
            continue
        src, dst = _flow_endpoints(finding)
        if not src or not dst or _is_broadcast_or_multicast(dst):
            continue
        src_zone, dst_zone = _zone_of(src), _zone_of(dst)
        if src_zone and dst_zone and src_zone != dst_zone:
            out.append(
                {
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_zone": src_zone,
                    "dst_zone": dst_zone,
                    "protocol": finding.get("protocol"),
                }
            )
    return out


def derive_zones(findings: list[dict[str, Any]]) -> dict[str, Any]:
    zones: dict[str, dict[str, Any]] = {}
    for finding in findings:
        src, dst = _flow_endpoints(finding)
        src_zone = _zone_of(src) if src and not _is_broadcast_or_multicast(src) else None
        for ip, zone in ((src, src_zone), (dst, _zone_of(dst) if dst and not _is_broadcast_or_multicast(dst) else None)):
            if not zone:
                continue
            entry = zones.setdefault(
                zone, {"zone": zone, "devices": set(), "protocols": set(), "unencrypted_flows": 0}
            )
            if ip:
                entry["devices"].add(str(ip))
            entry["protocols"].add(str(finding.get("protocol") or "UNKNOWN"))
        if not finding.get("has_crypto") and src_zone:
            # count each unencrypted flow once, against the source zone
            zones[src_zone]["unencrypted_flows"] += 1
    crossing = cross_zone_flows(findings)
    zone_rows = [
        {
            "zone": zone,
            "devices": sorted(data["devices"]),
            "device_count": len(data["devices"]),
            "protocols": sorted(data["protocols"]),
            "unencrypted_flows": data["unencrypted_flows"],
        }
        for zone, data in sorted(zones.items())
    ]
    return {
        "zones": zone_rows,
        "zone_count": len(zone_rows),
        "cross_zone_flows": len(crossing),
        "cross_zone_unencrypted": len(crossing),
        "cross_zone_examples": crossing[:10],
        "semantics": "zones are /24 approximations derived from observed traffic, not a network diagram",
    }
