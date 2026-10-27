"""Pure-python SNMPv2c client + device discovery (stdlib only).

Implements just enough BER/ASN.1 to GET and WALK an SNMP agent over UDP:
- BER TLV encode/decode for the message types a responder actually uses
  (INTEGER, OCTET STRING, NULL, OID, SEQUENCE, IpAddress, Counter/Gauge,
  TimeTicks, Counter64, Opaque, bits)
- SNMPv2c GET / GET_NEXT walk with community string, timeout and retries
- device identity, interface table, route table, topology hints

Security posture is *reported as metadata* (auth/privacy mode of the agent),
never as secret material. No third-party dependency, so it runs everywhere
the scanner runs; inject ``sock_factory`` to unit-test against a local
responder without touching the network.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Callable

SNMP_PORT = 161

# OIDs
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
SYS_SERVICES = "1.3.6.1.2.1.1.7.0"
IF_TABLE = "1.3.6.1.2.1.2.2.1"
IP_ROUTE_TABLE = "1.3.6.1.2.1.4.21.1"

# BER tags
_TAG_INTEGER = 0x02
_TAG_OCTET = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_TAG_IPADDR = 0x40
_TAG_COUNTER32 = 0x41
_TAG_GAUGE32 = 0x42
_TAG_TIMETICKS = 0x43
_TAG_OPAQUE = 0x44
_TAG_COUNTER64 = 0x46

PDU_GET = 0xA0
PDU_GET_NEXT = 0xA1
PDU_RESPONSE = 0xA2


class SnmpError(Exception):
    pass


# ------------------------------------------------------------------ BER


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    out = bytearray()
    while length:
        out.insert(0, length & 0xFF)
        length >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _encode_tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(payload)) + payload


def encode_integer(value: int) -> bytes:
    if value < 0:
        # signed two's complement, minimal bytes (BER allows extra length)
        length = max(1, (value.bit_length() + 8) // 8)
        return _encode_tlv(_TAG_INTEGER, value.to_bytes(length, "big", signed=True))
    if value == 0:
        return _encode_tlv(_TAG_INTEGER, b"\x00")
    out = bytearray()
    while value:
        out.insert(0, value & 0xFF)
        value >>= 8
    if out[0] & 0x80:
        out.insert(0, 0x00)
    return _encode_tlv(_TAG_INTEGER, bytes(out))


def encode_octet_string(value: bytes) -> bytes:
    return _encode_tlv(_TAG_OCTET, value)


def encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.strip(".").split(".")]
    if len(parts) < 2:
        raise SnmpError(f"OID too short: {oid}")
    payload = bytearray([(parts[0] * 40) + parts[1]])
    for part in parts[2:]:
        if part < 0x80:
            payload.append(part)
            continue
        chunks = []
        while part:
            chunks.insert(0, part & 0x7F)
            part >>= 7
        for idx, chunk in enumerate(chunks):
            if idx < len(chunks) - 1:
                payload.append(chunk | 0x80)
            else:
                payload.append(chunk)
    return _encode_tlv(_TAG_OID, bytes(payload))


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise SnmpError("truncated TLV")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise SnmpError("truncated length")
    length = data[offset]
    offset += 1
    if length & 0x80:
        num = length & 0x7F
        if offset + num > len(data):
            raise SnmpError("truncated long length")
        length = int.from_bytes(data[offset:offset + num], "big")
        offset += num
    if offset + length > len(data):
        raise SnmpError("value runs past packet")
    return tag, data[offset:offset + length], offset + length


def decode_oid(payload: bytes) -> str:
    if not payload:
        raise SnmpError("empty OID")
    first = payload[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in payload[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _decode_value(tag: int, payload: bytes) -> Any:
    if tag == _TAG_INTEGER:
        return int.from_bytes(payload, "big", signed=payload and payload[0] & 0x80)
    if tag == _TAG_OCTET:
        return payload.decode("utf-8", "replace")
    if tag == _TAG_OID:
        return decode_oid(payload)
    if tag == _TAG_NULL:
        return None
    if tag == _TAG_IPADDR:
        return socket.inet_ntoa(payload)
    if tag in (_TAG_COUNTER32, _TAG_GAUGE32, _TAG_TIMETICKS, _TAG_COUNTER64):
        return int.from_bytes(payload, "big")
    if tag == _TAG_OPAQUE:
        return payload.hex()
    return payload.hex()


# ------------------------------------------------------------------ messages


def build_get(oid: str, community: str, request_id: int) -> bytes:
    varbind = _encode_tlv(_TAG_SEQUENCE, encode_oid(oid) + _encode_tlv(_TAG_NULL, b""))
    varbinds = _encode_tlv(_TAG_SEQUENCE, varbind)
    pdu = _encode_tlv(PDU_GET, encode_integer(request_id) + encode_integer(0) + encode_integer(0) + varbinds)
    return _encode_tlv(_TAG_SEQUENCE, encode_integer(1) + encode_octet_string(community.encode()) + pdu)


def build_get_next(oid: str, community: str, request_id: int) -> bytes:
    varbind = _encode_tlv(_TAG_SEQUENCE, encode_oid(oid) + _encode_tlv(_TAG_NULL, b""))
    varbinds = _encode_tlv(_TAG_SEQUENCE, varbind)
    pdu = _encode_tlv(PDU_GET_NEXT, encode_integer(request_id) + encode_integer(0) + encode_integer(0) + varbinds)
    return _encode_tlv(_TAG_SEQUENCE, encode_integer(1) + encode_octet_string(community.encode()) + pdu)


def parse_response(packet: bytes) -> list[tuple[str, Any]]:
    """Return [(oid, value), ...] from an SNMPv2c response message."""
    tag, payload, _ = _read_tlv(packet, 0)
    if tag != _TAG_SEQUENCE:
        raise SnmpError("not an SNMP message")
    _version, _, pos = _read_tlv(payload, 0)
    _community, _, pos = _read_tlv(payload, pos)
    pdu_tag, pdu_payload, _ = _read_tlv(payload, pos)
    if pdu_tag != PDU_RESPONSE:
        raise SnmpError(f"unexpected PDU tag 0x{pdu_tag:02x}")
    _reqid, _, pos = _read_tlv(pdu_payload, 0)
    _status, _, pos = _read_tlv(pdu_payload, pos)
    _index, _, pos = _read_tlv(pdu_payload, pos)
    _varbinds_tag, varbinds, _ = _read_tlv(pdu_payload, pos)
    out: list[tuple[str, Any]] = []
    pos = 0
    while pos < len(varbinds):
        _vb_tag, vb, pos = _read_tlv(varbinds, pos)
        oid_tag, oid_payload, vpos = _read_tlv(vb, 0)
        oid = decode_oid(oid_payload)
        value_tag, value_payload, _ = _read_tlv(vb, vpos)
        out.append((oid, _decode_value(value_tag, value_payload)))
    return out


# ------------------------------------------------------------------ client


@dataclass
class SnmpClient:
    host: str
    community: str = "public"
    port: int = SNMP_PORT
    timeout: float = 2.0
    retries: int = 1
    sock_factory: Callable[[], socket.socket] | None = None
    request_id: int = 0x10203

    def _send(self, packet: bytes) -> bytes:
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            sock = (self.sock_factory or socket.socket)(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(self.timeout)
                sock.sendto(packet, (self.host, self.port))
                data, _addr = sock.recvfrom(65535)
                return data
            except OSError as exc:
                last_error = exc
            finally:
                sock.close()
        raise SnmpError(f"no response from {self.host}:{self.port}: {last_error}")

    def get(self, oid: str) -> Any:
        data = self._send(build_get(oid, self.community, self.request_id))
        self.request_id += 1
        rows = parse_response(data)
        if not rows:
            raise SnmpError("empty response")
        return rows[0][1]

    def walk(self, base_oid: str, *, limit: int = 512) -> dict[str, Any]:
        """GET_NEXT walk until we leave the base subtree or hit the limit."""
        results: dict[str, Any] = {}
        cursor = base_oid
        for _ in range(limit):
            data = self._send(build_get_next(cursor, self.community, self.request_id))
            self.request_id += 1
            rows = parse_response(data)
            if not rows:
                break
            oid, value = rows[0]
            if not _oid_below(oid, base_oid):
                break
            if oid == cursor and value is None:
                break  # endOfMibView / noSuchName — table exhausted
            results[oid] = value
            cursor = oid
        return results


def _oid_below(oid: str, base: str) -> bool:
    if oid == base:
        return True
    return oid.startswith(base + ".")


# ------------------------------------------------------------------ discovery


@dataclass
class SnmpDeviceInfo:
    host: str
    sys_descr: str | None = None
    sys_object_id: str | None = None
    sys_uptime: int | None = None
    sys_name: str | None = None
    sys_location: str | None = None
    sys_services: int | None = None
    interfaces: list[dict[str, Any]] = field(default_factory=list)
    routes: list[dict[str, Any]] = field(default_factory=list)
    security_mode: str = "SNMPv2c-community"  # auth/privacy *mode* metadata only
    reachable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "sys_descr": self.sys_descr,
            "sys_object_id": self.sys_object_id,
            "sys_uptime_ticks": self.sys_uptime,
            "sys_name": self.sys_name,
            "sys_location": self.sys_location,
            "sys_services": self.sys_services,
            "interfaces": list(self.interfaces),
            "routes": list(self.routes),
            "security_mode": self.security_mode,
            "reachable": self.reachable,
            "credential_ref": None,  # community string is never persisted
        }


def vendor_from_sys_object_id(object_id: str | None) -> str | None:
    if not object_id:
        return None
    prefixes = {
        "1.3.6.1.4.1.9": "Cisco",
        "1.3.6.1.4.1.2636": "Juniper",
        "1.3.6.1.4.1.25461": "Palo Alto",
        "1.3.6.1.4.1.12356": "Fortinet",
        "1.3.6.1.4.1.2620": "Check Point",
        "1.3.6.1.4.1.3375": "F5",
        "1.3.6.1.4.1.30065": "Arista",
        "1.3.6.1.4.1.2011": "Huawei",
        "1.3.6.1.4.1.14988": "MikroTik",
        "1.3.6.1.4.1.41112": "Ubiquiti",
        "1.3.6.1.4.1.6876": "VMware",
    }
    for prefix, vendor in prefixes.items():
        if object_id.startswith(prefix + ".") or object_id == prefix:
            return vendor
    return "Generic"


def snmp_discover(
    host: str,
    *,
    community: str = "public",
    port: int = SNMP_PORT,
    timeout: float = 2.0,
    sock_factory: Callable[[], socket.socket] | None = None,
) -> SnmpDeviceInfo:
    """Discover device identity, interfaces and routes via SNMPv2c."""
    info = SnmpDeviceInfo(host=host, security_mode="SNMPv2c-community")
    client = SnmpClient(host, community=community, port=port, timeout=timeout, sock_factory=sock_factory)
    try:
        info.sys_descr = client.get(SYS_DESCR)
        info.sys_object_id = client.get(SYS_OBJECT_ID)
        info.sys_uptime = client.get(SYS_UPTIME)
        info.sys_name = client.get(SYS_NAME)
        info.sys_location = client.get(SYS_LOCATION)
        info.sys_services = client.get(SYS_SERVICES)
        info.reachable = True
    except SnmpError:
        return info
    try:
        table = client.walk(IF_TABLE)
        per_index: dict[str, dict[str, Any]] = {}
        for oid, value in table.items():
            suffix = oid[len(IF_TABLE) + 1:]
            if "." not in suffix:
                continue
            column, index = suffix.split(".", 1)
            entry = per_index.setdefault(index, {})
            entry[_IF_COLUMNS.get(int(column), f"col_{column}")] = value
        info.interfaces = list(per_index.values())
    except SnmpError:
        pass
    try:
        table = client.walk(IP_ROUTE_TABLE)
        per_dest: dict[str, dict[str, Any]] = {}
        for oid, value in table.items():
            suffix = oid[len(IP_ROUTE_TABLE) + 1:]
            if "." not in suffix:
                continue
            column, dest = suffix.split(".", 1)
            dest_ip = ".".join(dest.split(".")[:4])
            entry = per_dest.setdefault(dest_ip, {})
            entry[_ROUTE_COLUMNS.get(int(column), f"col_{column}")] = value
        info.routes = list(per_dest.values())
    except SnmpError:
        pass
    return info


_IF_COLUMNS = {1: "ifIndex", 2: "ifDescr", 3: "ifType", 4: "ifMtu", 5: "ifSpeed",
               6: "ifPhysAddress", 7: "ifAdminStatus", 8: "ifOperStatus"}
_ROUTE_COLUMNS = {1: "routeDest", 2: "routeIfIndex", 3: "routeMetric1", 7: "routeNextHop", 8: "routeType"}
