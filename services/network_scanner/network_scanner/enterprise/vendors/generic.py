"""Generic / SNMP vendor plugin + minimal multi-vendor plugin classes.

The GenericSNMPPlugin is the workhorse for environments without a vendor
controller: it discovers via SNMPv2c (identity, interfaces, routes) and
reports agent security mode as metadata. The other plugin classes are thin
adapters so `REGISTRY.names()` reflects the full multi-vendor surface; each
delegates to the generic plugin unless a controller client is injected.
"""

from __future__ import annotations

from typing import Any

from network_scanner.enterprise.vendors.base import NetworkVendorPlugin, register_plugin
from network_scanner.enterprise.vendors.snmp import SnmpClient, SnmpError, snmp_discover, vendor_from_sys_object_id


class GenericSNMPPlugin(NetworkVendorPlugin):
    """SNMPv2c discovery: device identity + interfaces + routes + topology hints."""

    vendor = "snmp"
    device_types = ("router", "switch", "firewall", "server", "unknown")

    def discover_devices(self, targets: list[str], **kw: Any) -> list[dict[str, Any]]:
        community = str(kw.get("community") or self.options.get("community") or "public")
        timeout = float(kw.get("timeout") or self.options.get("timeout") or 2.0)
        sock_factory = kw.get("sock_factory")
        devices: list[dict[str, Any]] = []
        for target in targets:
            info = snmp_discover(target, community=community, timeout=timeout, sock_factory=sock_factory)
            if not info.reachable:
                devices.append({"ip": target, "vendor": None, "reachable": False,
                                "security_mode": info.security_mode})
                continue
            devices.append({
                "ip": target,
                "vendor": vendor_from_sys_object_id(info.sys_object_id),
                "sys_descr": info.sys_descr,
                "sys_object_id": info.sys_object_id,
                "sys_name": info.sys_name,
                "sys_location": info.sys_location,
                "sys_uptime": info.sys_uptime,
                "interfaces": info.interfaces,
                "routes": info.routes,
                "security_mode": info.security_mode,
                "reachable": True,
            })
        return devices

    def collect_inventory(self, device: dict[str, Any], **kw: Any) -> dict[str, Any]:
        vendor = device.get("vendor")
        return {
            "asset_identity": device.get("asset_identity") or device.get("ip"),
            "ip_addresses": [device.get("ip")] if device.get("ip") else [],
            "hostname": device.get("sys_name") or device.get("hostname"),
            "manufacturer": vendor,
            "model": device.get("model"),
            "os": device.get("os"),
            "os_version": device.get("os_version"),
            "device_type": _device_type_from_descr(device.get("sys_descr") or ""),
            "interfaces": device.get("interfaces") or [],
            "routes": device.get("routes") or [],
            "location": device.get("sys_location"),
            "security_mode": device.get("security_mode"),
        }

    def collect_crypto_configuration(self, device: dict[str, Any], **kw: Any) -> dict[str, Any]:
        return {"config_available": False,
                "security_mode": device.get("security_mode"),
                "note": "SNMP exposes security *mode* metadata, never secrets"}

    def collect_certificates(self, device: dict[str, Any], **kw: Any) -> list[dict[str, Any]]:
        return []

    def collect_protocols(self, device: dict[str, Any], **kw: Any) -> list[dict[str, Any]]:
        services = []
        for interface in device.get("interfaces") or []:
            if _if_type_suggests_crypto(int(interface.get("ifType") or 0)):
                services.append({"protocol": _IF_TYPE_NAMES.get(int(interface.get("ifType")), "UNKNOWN"),
                                 "status": "PROTOCOL_PRESENT", "interface": interface.get("ifDescr")})
        return services

    def collect_topology(self, devices: list[dict[str, Any]], **kw: Any) -> list[dict[str, Any]]:
        edges = []
        for device in devices:
            source = device.get("asset_identity") or device.get("ip")
            for route in device.get("routes") or []:
                next_hop = route.get("routeNextHop")
                if next_hop:
                    edges.append({"from": source, "to": next_hop, "relationship": "ROUTES_TO",
                                  "source": "snmp-route-table"})
        return edges

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        inventory = self.collect_inventory(raw)
        return {
            "asset_identity": inventory["asset_identity"],
            "ip_addresses": inventory["ip_addresses"],
            "hostname": inventory["hostname"],
            "device_type": inventory["device_type"],
            "manufacturer": inventory["manufacturer"],
            "location": inventory["location"],
            "discovery_confidence": 0.8 if raw.get("reachable") else 0.2,
            "source": "snmp",
            "extra": {"security_mode": inventory["security_mode"],
                      "sys_object_id": raw.get("sys_object_id")},
        }


register_plugin(GenericSNMPPlugin)


_IF_TYPE_NAMES = {
    1: "ETHERNET", 6: "ETHERNET", 23: "PPP", 24: "SOFTWARE_LOOPBACK",
    53: "PROP_VIRTUAL", 131: "TUNNEL", 135: "L2VLAN", 161: "IEEE80211",
    117: "GRE", 131: "TUNNEL", 150: "MPLS_TUNNEL",
}


def _if_type_suggests_crypto(if_type: int) -> bool:
    return if_type in (23, 117, 131, 150)  # PPP/GRE/tunnel/MPLS carry VPN traffic


def _device_type_from_descr(descr: str) -> str:
    text = (descr or "").lower()
    if "router" in text or "routing" in text:
        return "router"
    if "switch" in text:
        return "switch"
    if "firewall" in text or "asa" in text:
        return "firewall"
    if "controller" in text and "wireless" in text:
        return "wireless_controller"
    if "server" in text:
        return "server"
    return "unknown"


class _GenericVendorPlugin(GenericSNMPPlugin):
    """Template for vendor-specific plugins that delegate to SNMP discovery."""

    vendor = "generic-vendor"
    device_types = ("unknown",)


def _make_vendor(vendor_name: str, device_types: tuple[str, ...]) -> type[GenericSNMPPlugin]:
    return type(
        f"{vendor_name.title().replace('-', '')}Plugin",
        (GenericSNMPPlugin,),
        {"vendor": vendor_name.lower(), "device_types": device_types},
    )


for _name, _types in {
    "juniper": ("router", "switch", "firewall"),
    "paloalto": ("firewall", "vpn_gateway"),
    "fortinet": ("firewall", "vpn_gateway"),
    "checkpoint": ("firewall", "vpn_gateway"),
    "f5": ("load_balancer", "vpn_gateway"),
    "arista": ("switch",),
    "huawei": ("router", "switch"),
    "mikrotik": ("router", "switch", "wireless_controller"),
    "ubiquiti": ("wireless_controller", "router"),
    "vmware": ("server", "switch"),
}.items():
    register_plugin(_make_vendor(_name, _types))
