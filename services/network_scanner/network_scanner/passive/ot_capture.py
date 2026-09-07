"""Offline passive OT capture ingestion (feature 27 last mile).

Reads a standard **libpcap/pcap** capture file (magic 0xa1b2c3d4 or the
nanosecond/byte-swapped variants) WITHOUT scapy or any third-party dependency,
extracts TCP/UDP payloads for the OT ports (S7comm/102, EtherNet-IP/44818,
OPC-UA/4840, BACnet/47808), and runs the deterministic `ot_protocols` decoders.

This is strictly passive: it parses bytes handed to it and never opens a socket
or sends a packet. It returns decoded frames + cleartext-engineering findings
suitable for persisting to the findings/alerts store.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field, asdict
from typing import Any, Iterator

from . import ot_protocols as ot

# Ethernet ethertypes
_ETHERTYPE_IPV4 = 0x0800
_IP_PROTO_TCP = 6
_IP_PROTO_UDP = 17

# OT port map (destination ports we decode)
OT_PORTS = {102: "s7comm", 44818: "enip", 4840: "opcua", 47808: "bacnet"}


@dataclass
class CaptureStats:
    packets: int = 0
    ipv4: int = 0
    tcp: int = 0
    udp: int = 0
    ot_packets: int = 0
    decode_errors: int = 0


class PcapError(ValueError):
    pass


def _iter_records(blob: bytes) -> Iterator[tuple[bytes, int, int]]:
    """Yield (link_payload, dport, ip_proto) from a classic pcap blob.

    Supports the two magic layouts (micro/nanosecond) and both endiannesses.
    Link-layer type 1 (Ethernet) is supported; Linux cooked (113) is tolerated
    for IP extraction.
    """
    if len(blob) < 24:
        raise PcapError("file too short to be a pcap")
    magic = blob[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic == b"\x4d\x3c\xb2\xa1" or magic == b"\xa1\xb2\x3c\x4d":
        # nanosecond-resolution variant; record layout is identical
        endian = "<" if magic[0] == 0x4D else ">"
    else:
        raise PcapError("not a classic pcap file (pcapng not supported in this decoder)")
    _major, _minor, _thiszone, _sigfigs, snaplen, network = struct.unpack(endian + "HHiIII", blob[4:24])
    off = 24
    n = len(blob)
    while off + 16 <= n:
        _ts_sec, _ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", blob[off:off + 16])
        off += 16
        pkt = blob[off:off + incl_len]
        off += incl_len
        if len(pkt) < incl_len:
            pkt = blob[off - len(pkt): off]  # truncated last record
        yield pkt, network
        if off >= n:
            break


def _parse_ethernet_ip(pkt: bytes, network: int) -> tuple[int, int, bytes] | None:
    """Return (ip_proto, dport, transport_payload) or None."""
    if network == 1:  # Ethernet
        if len(pkt) < 14:
            return None
        ethertype = struct.unpack(">H", pkt[12:14])[0]
        # VLAN tags
        if ethertype in (0x8100, 0x88A8):
            ethertype = struct.unpack(">H", pkt[16:18])[0]
            l3 = pkt[18:]
        else:
            l3 = pkt[14:]
        if ethertype != _ETHERTYPE_IPV4:
            return None
    elif network == 113:  # Linux cooked capture (SLL)
        if len(pkt) < 16:
            return None
        ethertype = struct.unpack(">H", pkt[14:16])[0]
        if ethertype != _ETHERTYPE_IPV4:
            return None
        l3 = pkt[16:]
    else:
        return None

    if len(l3) < 20:
        return None
    ihl = (l3[0] & 0x0F) * 4
    proto = l3[9]
    l4 = l3[ihl:]
    if proto == _IP_PROTO_TCP and len(l4) >= 20:
        sport, dport = struct.unpack(">HH", l4[0:4])
        data_off = (l4[12] >> 4) * 4
        payload = l4[data_off:]
        return (6, dport if dport in OT_PORTS else sport, payload)
    if proto == _IP_PROTO_UDP and len(l4) >= 8:
        sport, dport, ulen = struct.unpack(">HHH", l4[0:6])
        payload = l4[8:8 + max(0, ulen - 8)]
        return (17, dport if dport in OT_PORTS else sport, payload)
    return None


def analyze_pcap(blob: bytes) -> dict[str, Any]:
    """Parse a pcap capture and decode every OT frame. Passive; zero probes."""
    stats = CaptureStats()
    decoded_frames = []
    findings = []
    for pkt, network in _iter_records(blob):
        stats.packets += 1
        try:
            parsed = _parse_ethernet_ip(pkt, network)
        except Exception:  # noqa: BLE001 - never let one bad frame abort a capture
            stats.decode_errors += 1
            continue
        if not parsed:
            continue
        stats.ipv4 += 1
        proto, port, payload = parsed
        if proto == 6:
            stats.tcp += 1
        elif proto == 17:
            stats.udp += 1
        if port not in OT_PORTS:
            continue
        stats.ot_packets += 1
        kw = {"dport": port}
        if proto == 6:
            kw["tcp_payload"] = payload
        else:
            kw["udp_payload"] = payload
        frames = ot.decode_frame(**kw)
        for f in frames:
            d = asdict(f)
            decoded_frames.append(d)
            if f.flags:
                findings.append({
                    "rule_id": f"OT-{f.protocol}-CLEARTEXT",
                    "severity": f.risk,
                    "protocol": f.protocol,
                    "port": port,
                    "service": f.detail.get("service") or f.detail.get("cip_service")
                    or f.detail.get("service_choice") or f.detail.get("security_mode"),
                    "flags": f.flags,
                    "detail": f.detail,
                    "source": "passive_capture",
                    "active_probes_sent": 0,
                })
    return {
        "capture_stats": asdict(stats),
        "frames_decoded": len(decoded_frames),
        "frames_flagged": len(findings),
        "protocols": sorted({f["protocol"] for f in decoded_frames}),
        "cleartext_engineering_detected": bool(findings),
        "active_probes_sent": 0,
        "findings": findings,
        "decoded": decoded_frames,
    }
