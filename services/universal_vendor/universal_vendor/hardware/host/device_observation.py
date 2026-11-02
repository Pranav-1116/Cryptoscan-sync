"""One projection from network facts to a canonical observation.

Three transports (SNMP, NETCONF, RESTCONF) produce the same
:class:`~universal_vendor.hardware.host.snmp_bridge.NetworkDeviceFacts`. They
must also produce the *same* observation, or the estate ends up with three
subtly different switch records depending on which protocol reached it. This
module is the single place that projection happens.
"""

from __future__ import annotations

from typing import Any

from universal_vendor.hardware.models import (
    HardwareConfidence,
    HardwareObservation,
    HardwareType,
)

#: Plugin categories that describe a network box rather than a server.
NETWORK_CATEGORIES = frozenset({"switch", "firewall", "router", "load_balancer",
                                "network_appliance"})


def device_type(value: Any) -> str:
    try:
        return HardwareType(str(value)).value
    except ValueError:
        return HardwareType.OTHER.value


def vendor_plugin(vendor: str | None) -> Any:
    """The vendor plugin for this network box, if one exists."""
    if not vendor:
        return None
    from universal_vendor.hardware import plugins as hardware_plugins  # noqa: PLC0415

    for plugin_cls in hardware_plugins.ALL_HARDWARE_PLUGINS:
        if plugin_cls.manufacturer.lower() == vendor.lower() and \
                plugin_cls.category.value in NETWORK_CATEGORIES:
            return plugin_cls()
    return None


def to_observation(facts: Any) -> HardwareObservation | None:
    """Project network facts into the estate's canonical shape."""
    if not getattr(facts, "reachable", False):
        return None
    context = getattr(facts, "context", {}) or {}
    transport = getattr(facts, "transport", "network")
    record: dict[str, Any] = {
        "asset_id": context.get("asset_id") or facts.host,
        "manufacturer": facts.vendor or "",
        "model": facts.model or "",
        "serial_reference": facts.serial_reference,
        "firmware": facts.firmware,
        "source": "network",
        "confidence": HardwareConfidence.HIGH.value,
        "vendor_specific": {
            "transport": transport,
            "sys_descr": facts.sys_descr,
            "security_mode": facts.security_mode,
            "interfaces": list(facts.interfaces or []),
            "route_count": facts.route_count,
        },
    }
    plugin = vendor_plugin(facts.vendor)
    if plugin is not None:
        normalised = plugin.normalize({**record, "device_type": plugin.category.value})
        if isinstance(normalised, HardwareObservation):
            return normalised
    return HardwareObservation(
        asset_id=record["asset_id"],
        manufacturer=record["manufacturer"],
        model=record["model"],
        serial_reference=facts.serial_reference,
        device_type=device_type(context.get("device_type", "switch")),
        firmware=facts.firmware,
        source="network",
        confidence=HardwareConfidence.HIGH.value,
        vendor_specific=record["vendor_specific"],
    )
