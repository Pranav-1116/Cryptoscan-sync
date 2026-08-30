"""DNS/DNSSEC crypto posture checker.

Every public zone should be signed (DNSSEC) with strong algorithms. This
module checks, over the wire with no third-party dependencies:

- **zone existence** (SOA) and **signing status**: does the zone publish
  ``DNSKEY`` records (type 48) / ``DS`` (type 43)?
- **weak algorithms**: RSAMD5 / DSA / RSASHA1 / RSASHA1-NSEC3 are deprecated;
  RSA key sizes under 1024 bits are broken-by-today's-standards;
- **zone-transfer exposure**: a successful ``AXFR`` (type 252, TCP) means the
  whole zone (including DNSSEC key tags, hostnames, internal names) is
  readable by anyone — a real crypto-adjacent finding.

Resolver selection: explicit ``resolver`` config wins; otherwise the first
nameserver in ``/etc/resolv.conf`` (i.e. what the host itself uses), never a
hardcoded third-party resolver.
"""

from __future__ import annotations

import os
import socket
import struct
from typing import Any, Iterable

DNS_SERVER_PORT = 53
AXFR = 252
SOA = 6
DNSKEY = 48
DS = 43

DNS_ALGORITHMS = {
    1: "RSAMD5",
    2: "DH",
    3: "DSA",
    5: "RSASHA1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSASHA256",
    10: "RSASHA512",
    13: "ECDSA-P256-SHA256",
    14: "ECDSA-P384-SHA384",
    15: "ED25519",
    16: "ED448",
}
WEAK_ALGORITHMS = {"RSAMD5", "DSA", "RSASHA1", "DSA-NSEC3-SHA1", "RSASHA1-NSEC3-SHA1"}

UDP_TIMEOUT = 3.0
MAX_AXFR_BYTES = 1_048_576  # 1 MiB cap on zone transfer reads


class DnsError(Exception):
    """Transport or parse failure — reported as UNKNOWN, never fatal."""


# ------------------------------------------------------------------ wire code

def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in str(name).rstrip(".").split("."):
        if not label:
            continue
        out.append(len(label))
        out.extend(label.encode("ascii", "ignore"))
    out.append(0)
    return bytes(out)


def _read_name(raw: bytes, offset: int) -> tuple[str, int]:
    """Decode a possibly-compressed DNS name; returns (name, next_offset)."""
    labels: list[str] = []
    pos = offset
    jumped = False
    end = offset
    while True:
        if pos >= len(raw):
            raise DnsError("name runs past packet")
        length = raw[pos]
        if length == 0:
            pos += 1
            if not jumped:
                end = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(raw):
                raise DnsError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | raw[pos + 1]
            if not jumped:
                end = pos + 2
            pos = pointer
            jumped = True
            continue
        pos += 1
        if pos + length > len(raw):
            raise DnsError("label runs past packet")
        labels.append(raw[pos:pos + length].decode("ascii", "ignore"))
        pos += length
    return ".".join(labels), end


def _build_query(domain: str, qtype: int, *, rd: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100 | rd, 1, 0, 0, 0)
    question = _encode_name(domain) + struct.pack("!HH", qtype, 1)
    return header + question


def _parse_records(raw: bytes, qtype: int | None) -> list[dict[str, Any]]:
    """Parse the answer/authority section; ``qtype=None`` collects every RR (AXFR)."""
    if len(raw) < 12:
        raise DnsError("short DNS header")
    ancount = struct.unpack("!H", raw[6:8])[0]
    nscount = struct.unpack("!H", raw[8:10])[0]
    pos = 12
    _qname, pos = _read_name(raw, pos)
    pos += 4  # qtype + qclass
    records: list[dict[str, Any]] = []

    def _section(count: int) -> None:
        nonlocal pos
        for _ in range(count):
            _owner, pos = _read_name(raw, pos)
            if pos + 10 > len(raw):
                raise DnsError("truncated RR header")
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", raw[pos:pos + 10])
            pos += 10
            rdata = raw[pos:pos + rdlength]
            pos += rdlength
            if qtype is None or rtype == qtype:
                records.append(_parse_rdata(rtype, rdata))

    _section(ancount)
    _section(nscount)
    return records


def _parse_rdata(rtype: int, rdata: bytes) -> dict[str, Any]:
    if rtype == DNSKEY:
        # DNSKEY RDATA: flags(2), protocol(1), algorithm(1), public key
        flags, protocol, algorithm = struct.unpack("!HBB", rdata[:4])
        rest = rdata[4:]
        key_size: int | None = None
        if algorithm in (1, 5, 7, 8, 10):  # RSA family — key size from modulus
            # public key: exponent length byte, exponent, modulus
            try:
                exp_len = rest[0]
                modulus_len = len(rest) - 1 - exp_len
                key_size = modulus_len * 8
            except Exception:
                key_size = None
        elif algorithm == 13:  # ECDSA P-256
            key_size = 256
        elif algorithm == 14:  # ECDSA P-384
            key_size = 384
        return {
            "key_tag": ((flags & 0xFF) << 8) | (protocol & 0xFF),  # computed tag (approximate)
            "flags": flags,
            "zone_key": bool(flags & 0x0100),  # bit 8 = zone key (KSK)
            "algorithm": algorithm,
            "algorithm_name": DNS_ALGORITHMS.get(algorithm, f"ALG-{algorithm}"),
            "key_size": key_size,
            "rdata_len": len(rdata),
        }
    if rtype == DS:
        # DS RDATA: key_tag(2), algorithm(1), digest_type(1), digest
        key_tag, algorithm, digest_type = struct.unpack("!HBB", rdata[:4])
        return {
            "key_tag": key_tag,
            "algorithm": algorithm,
            "algorithm_name": DNS_ALGORITHMS.get(algorithm, f"ALG-{algorithm}"),
            "digest_type": digest_type,
            "key_size": None,
            "rdata_len": len(rdata),
        }
    if rtype == SOA:
        return {"rtype": "SOA", "rdata_len": len(rdata)}
    return {"rtype": rtype, "rdata_len": len(rdata)}


def _default_resolver() -> str:
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1]
    except OSError:
        pass
    return "127.0.0.1"


def _split_resolver(resolver: str) -> tuple[str, int]:
    """'host' or 'host:port' -> (host, port)."""
    if ":" in resolver and not resolver.startswith("["):
        host, _, port = resolver.rpartition(":")
        try:
            return host or "127.0.0.1", int(port)
        except ValueError:
            return resolver, DNS_SERVER_PORT
    return resolver, DNS_SERVER_PORT


def _query_udp(domain: str, qtype: int, resolver: str, timeout: float = UDP_TIMEOUT) -> list[dict[str, Any]]:
    host, port = _split_resolver(resolver)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(_build_query(domain, qtype), (host, port))
        data, _ = sock.recvfrom(65535)
    finally:
        sock.close()
    return _parse_records(data, qtype)


def _query_axfr(domain: str, resolver: str, timeout: float = UDP_TIMEOUT) -> list[dict[str, Any]]:
    """Zone transfer over TCP. Returns [] when refused (the good case)."""
    host, port = _split_resolver(resolver)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, port))
        query = _build_query(domain, AXFR, rd=0)
        sock.sendall(struct.pack("!H", len(query)) + query)
        received = bytearray()
        while len(received) < MAX_AXFR_BYTES:
            chunk = sock.recv(65536)
            if not chunk:
                break
            received.extend(chunk)
        if len(received) < 2:
            return []
        msglen = struct.unpack("!H", received[:2])[0]
        # AXFR answers carry the zone's real records (SOA, DNSKEY, …), so
        # collect every RR type present in the response.
        return _parse_records(bytes(received[2:2 + msglen]), None)
    except (ConnectionRefusedError, socket.timeout, OSError):
        return []
    finally:
        sock.close()


# ------------------------------------------------------------- orchestration

def scan_dnssec(
    zone: str,
    *,
    resolver: str | None = None,
    timeout: float = UDP_TIMEOUT,
    check_transfer: bool = True,
) -> dict[str, Any]:
    """One zone's DNS/DNSSEC posture. Returns status + findings + issues."""
    resolver = resolver or os.environ.get("CRYPTOSCAN_DNS_RESOLVER") or _default_resolver()
    zone = str(zone).strip().lower().rstrip(".")
    if not zone:
        return {"zone": zone, "status": "ERROR", "issues": ["NO_ZONE_NAME"]}

    try:
        soa = _query_udp(zone, SOA, resolver, timeout=timeout)
    except (DnsError, OSError) as exc:
        return {"zone": zone, "status": "UNKNOWN", "issues": [f"DNS_ERROR:{type(exc).__name__}"], "detail": str(exc)}

    if not soa:
        return {"zone": zone, "status": "NO_ZONE", "issues": []}

    issues: list[str] = []
    dnskey = ds = []
    try:
        dnskey = _query_udp(zone, DNSKEY, resolver, timeout=timeout)
    except (DnsError, OSError):
        pass
    try:
        ds = _query_udp(zone, DS, resolver, timeout=timeout)
    except (DnsError, OSError):
        pass

    if not dnskey and not ds:
        issues.append("UNSIGNED_ZONE")
        status = "UNSIGNED"
    else:
        status = "SIGNED"
        for key in dnskey:
            algo = key.get("algorithm_name") or ""
            if algo in WEAK_ALGORITHMS:
                issues.append(f"WEAK_DNSSEC_ALGORITHM:{algo}")
            size = key.get("key_size")
            if size is not None and size < 1024:
                issues.append(f"WEAK_DNSSEC_KEY_SIZE:{size}")

    transfer = []
    if check_transfer:
        try:
            transfer = _query_axfr(zone, resolver, timeout=timeout)
        except (DnsError, OSError):
            transfer = []
    if transfer:
        issues.append("ZONE_TRANSFER_EXPOSED")

    return {
        "zone": zone,
        "resolver": resolver,
        "status": status,
        "signed": status == "SIGNED",
        "dnskey_count": len(dnskey),
        "ds_count": len(ds),
        "algorithms": sorted({k.get("algorithm_name") for k in dnskey} - {None}),
        "transfer_exposed": bool(transfer),
        "issues": sorted(set(issues)),
    }
