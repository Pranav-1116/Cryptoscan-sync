"""SNMP -> hardware facts (phase H5): a switch is a box and a TLS endpoint.

The network scanner already speaks SNMPv2c — it has a BER codec, a GET_NEXT
walk, and it reads sysDescr, the interface table, the route table and, as of
this pass, ENTITY-MIB. What it never did was hand any of that to the hardware
estate: a switch discovered by the network scanner stayed in the network
scanner, and the NBOM never heard about it.

This module is that hand-off, and only that hand-off. It does not implement
SNMP, does not open a socket, and does not know what a community string is
*beyond using it once and dropping it*. Duplicating the client here would put
two SNMP stacks in the tree and two answers to "what firmware is this switch
running"; the bridge exists so there is one.

Two rules the code enforces rather than documents:

* **The credential does not survive the call.** The community string is a
  credential. It is passed in, used, and never stored on the result; the
  finished payload is checked for it and the bridge refuses to return a payload
  that echoes it (:class:`CredentialLeakRefused`). A device whose sysDescr
  contains the community is a device to investigate, not one to inventory.
* **The chassis is named, not an arbitrary part.** ENTITY-MIB indexes fans and
  transceivers with their own serials. :attr:`SnmpDeviceInfo.chassis` picks the
  chassis, and this bridge reports ``None`` rather than a fan tray's serial.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from universal_vendor.hardware.host.credentials import (
    CredentialLeakRefused,
    refuse_credential_echo,
    refuse_secret_shapes,
)
from universal_vendor.hardware.host.device_observation import to_observation

SCHEMA = "cryptoscan.snmp-hardware/1"

#: Attribute names read from the discovery result. Duck-typed on purpose: the
#: network scanner's ``SnmpDeviceInfo``, a test double, and a future SNMPv3
#: client all satisfy it.
_DISCOVERY_ATTRIBUTES = ("sys_descr", "sys_object_id", "sys_name", "sys_location",
                         "interfaces", "routes", "entities", "security_mode", "reachable")


__all__ = [
    "CredentialLeakRefused",
    "NetworkDeviceFacts",
    "SnmpHardwareBridge",
    "SnmpUnavailable",
]


class SnmpUnavailable(RuntimeError):
    """No SNMP client is importable in this deployment."""


@dataclass
class NetworkDeviceFacts:
    """Normalised identity for one network device, plus what the caller needs."""

    host: str
    reachable: bool = False
    transport: str = "snmp"
    vendor: str | None = None
    model: str | None = None
    serial_reference: str | None = None
    firmware: str | None = None
    software_version: str | None = None
    sys_descr: str | None = None
    sys_name: str | None = None
    sys_location: str | None = None
    security_mode: str = "SNMPv2c-community"
    interfaces: list[dict[str, Any]] = field(default_factory=list)
    route_count: int = 0
    context: dict[str, Any] = field(default_factory=dict)
    sources: dict[str, str] = field(default_factory=dict)
    unavailable: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "host": self.host,
            "reachable": self.reachable,
            "transport": self.transport,
            "vendor": self.vendor,
            "model": self.model,
            "serial_reference": self.serial_reference,
            "firmware": self.firmware,
            "software_version": self.software_version,
            "sys_descr": self.sys_descr,
            "sys_name": self.sys_name,
            "sys_location": self.sys_location,
            "security_mode": self.security_mode,
            "interfaces": list(self.interfaces),
            "route_count": self.route_count,
            # Never the community string, never a credential reference that
            # could be resolved back to one.
            "credential_ref": None,
        }


def _default_discover() -> Callable[..., Any]:
    """Resolve the network scanner's SNMP client lazily.

    Lazy because the hardware package must not depend on the network scanner to
    import, and explicit because a deployment without the scanner should get a
    stated reason rather than an ImportError from deep inside a collector.
    """
    try:
        from network_scanner.enterprise.vendors.snmp import (  # noqa: PLC0415
            snmp_discover,
            vendor_from_sys_object_id,
        )
    except ImportError as exc:  # pragma: no cover - depends on deployment layout
        raise SnmpUnavailable(
            "no SNMP client is importable: install services/network_scanner, or inject "
            f"a discover callable ({exc})") from exc

    def discover(host: str, **kwargs: Any) -> Any:
        result = snmp_discover(host, **kwargs)
        result.vendor_name = vendor_from_sys_object_id(result.sys_object_id)
        return result

    return discover


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


class SnmpHardwareBridge:
    """Turn one SNMP discovery result into a hardware context and an observation."""

    def __init__(self, discover: Callable[..., Any] | None = None) -> None:
        self._discover = discover

    def _resolve(self) -> Callable[..., Any]:
        return self._discover or _default_discover()

    def collect(self, host: str, *, community: str, device_type: str = "switch",
                port: int = 161, timeout: float = 2.0,
                sock_factory: Any = None) -> NetworkDeviceFacts:
        """Read one device. ``community`` is used and then dropped."""
        facts = NetworkDeviceFacts(host=host)
        discover = self._resolve()
        try:
            device = discover(host, community=community, port=port, timeout=timeout,
                              sock_factory=sock_factory)
        except SnmpUnavailable as exc:
            facts.unavailable.append(str(exc))
            return facts
        except Exception as exc:  # noqa: BLE001 - a hung device is a fact, not a crash
            facts.unavailable.append(f"snmp {host}:{port}: {exc}")
            return facts

        facts.reachable = bool(getattr(device, "reachable", False))
        facts.security_mode = _text(getattr(device, "security_mode", None)) or \
            "SNMPv2c-community"
        facts.sys_descr = _text(getattr(device, "sys_descr", None))
        facts.sys_name = _text(getattr(device, "sys_name", None))
        facts.sys_location = _text(getattr(device, "sys_location", None))
        facts.interfaces = list(getattr(device, "interfaces", []) or [])
        facts.route_count = len(getattr(device, "routes", []) or [])

        if not facts.reachable:
            facts.unavailable.append(
                f"snmp {host}:{port}: no response — the device may be down, filtered, or "
                "the community may be wrong; none of those is an empty inventory")
            return facts

        vendor = _text(getattr(device, "vendor_name", None))
        if vendor is None:
            vendor = self._vendor_from_oid(_text(getattr(device, "sys_object_id", None)))
        facts.vendor = vendor

        chassis = self._chassis(device)
        if chassis is not None:
            facts.sources["chassis"] = "ENTITY-MIB"
            facts.serial_reference = _text(chassis.get("entPhysicalSerialNum"))
            facts.model = _text(chassis.get("entPhysicalModelName"))
            facts.firmware = _text(chassis.get("entPhysicalFirmwareRev"))
            facts.software_version = _text(chassis.get("entPhysicalSoftwareRev"))
        if facts.firmware is None and facts.software_version is not None:
            facts.firmware = facts.software_version
            facts.sources["firmware"] = "ENTITY-MIB entPhysicalSoftwareRev"
        if facts.sys_descr:
            facts.sources["sys_descr"] = "SNMP sysDescr.0"

        facts.context = {
            "asset_id": facts.sys_name or host,
            "device_type": device_type,
            "manufacturer": facts.vendor or "",
            "model": facts.model or "",
            "serial_reference": facts.serial_reference,
            "firmware": facts.firmware,
            "snmp": {
                "sysname": facts.sys_name,
                "sysdescr": facts.sys_descr,
                "location": facts.sys_location,
                "security_mode": facts.security_mode,
                "manufacturer": facts.vendor,
                "model": facts.model,
                "serial": facts.serial_reference,
                "firmware": facts.firmware,
                "interfaces": facts.interfaces,
            },
            # A switch terminates TLS, so its crypto posture belongs in the same
            # observation as its serial number — that is the NBOM/CBOM seam.
            "crypto": self._crypto_from_interfaces(facts.interfaces),
        }
        refuse_credential_echo(facts.context, community, host=host,
                               kind="SNMP community string")
        refuse_secret_shapes(facts.context, host=host)
        return facts

    # -- helpers --------------------------------------------------------- #

    @staticmethod
    def _vendor_from_oid(object_id: str | None) -> str | None:
        if not object_id:
            return None
        try:
            from network_scanner.enterprise.vendors.snmp import (  # noqa: PLC0415
                vendor_from_sys_object_id,
            )
        except ImportError:  # pragma: no cover - deployment without the scanner
            return None
        return vendor_from_sys_object_id(object_id)

    @staticmethod
    def _chassis(device: Any) -> dict[str, Any] | None:
        chassis = getattr(device, "chassis", None)
        if callable(chassis):  # a property on a mock, or a method on a stub
            chassis = chassis()
        if isinstance(chassis, dict):
            return chassis
        for entity in getattr(device, "entities", []) or []:
            if entity.get("entPhysicalClass") == 3:
                return entity
        return None

    @staticmethod
    def _crypto_from_interfaces(interfaces: list[dict[str, Any]]) -> dict[str, Any]:
        """Interface facts a TLS inventory can use — nothing invented.

        SNMP will not tell us which cipher suites an appliance offers; that is
        the certificate probe's job. What it does tell us is which interfaces
        are up, their speed and their MAC, and claiming more than that would be
        the kind of guess this review exists to stop.
        """
        up = [iface for iface in interfaces if iface.get("ifOperStatus") == 1]
        return {
            "tls_terminator": bool(up),
            "interface_count": len(interfaces),
            "interfaces_up": len(up),
            "note": "cipher suites and TLS versions come from the TLS probe, not from SNMP",
        }

    # -- projection ------------------------------------------------------ #

    def to_observation(self, facts: NetworkDeviceFacts) -> Any:
        """Project network facts into the estate — one implementation, shared."""
        return to_observation(facts)
