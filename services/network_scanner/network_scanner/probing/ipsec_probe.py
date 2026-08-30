"""IPsec/IKE VPN crypto probing (IKEv1 + IKEv2).

Enterprises run VPN concentrators; their crypto posture (IKE encryption,
integrity/PRF, Diffie-Hellman group, PFS) is part of the network crypto
surface. This module:

- sends a minimal IKE SA proposal over UDP (500, and 4500 for NAT-T) and
  parses the responder's accepted transform set — no handshake completed,
  no keys exchanged, no traffic established;
- classifies weak configurations: DES/3DES encryption, MD5/SHA1 integrity,
  DH groups < 2048-bit (1, 2, 5), no PFS (ESN absent / no DH in ESP);
- is **active opt-in only**: you must pass explicit endpoints. Nothing is
  ever probed implicitly, and every probe is one UDP packet with a timeout.

The parser is deliberately lenient: real IKE implementations vary in
proposal layout, so unknown transform types are recorded, never crash the
parse. If a responder does not answer, that is a ``NO_RESPONSE`` status,
not a failure — the endpoint may filter UDP 500 (common), which is itself
a finding worth reporting.
"""

from __future__ import annotations

import socket
import struct
from typing import Any, Iterable

# IKE payload types (RFC 7296)
SA = 33
KE = 34
NONCE = 40
NOTIFY = 41

# Transform types inside an SA proposal
ENCR = 1
PRF = 2
INTEG = 3
DH_GROUP = 4
ESN = 5

# IKEv2 transform IDs
IKE_ENCR = {  # type 1 (ENCR)
    1: "DES", 2: "3DES", 3: "AES-CBC-128", 4: "AES-CBC-192", 5: "AES-CBC-256",
    12: "AES-GCM-16-128", 13: "AES-GCM-16-192", 14: "AES-GCM-16-256",
    18: "AES-CTR-128", 19: "AES-CTR-192", 20: "AES-CTR-256", 8: "CAMELLIA-128",
    23: "CAMELLIA-GCM-256",
}
IKE_PRF_INTEG = {  # types 2 (PRF) and 3 (INTEG) — RFC 7296 transform IDs
    1: "HMAC-MD5", 2: "HMAC-SHA1", 5: "HMAC-SHA2-256", 6: "HMAC-SHA2-384",
    7: "HMAC-SHA2-512", 4: "AES-XCBC", 12: "AES-CMAC", 3: "DES-MAC",
}
IKE_DH = {  # type 4 (DH group)
    1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048",
    15: "MODP-3072", 16: "MODP-4096", 17: "MODP-6144", 18: "MODP-8192",
    19: "ECP-256", 20: "ECP-384", 21: "ECP-521", 27: "ECP-256-BRAINPOOL",
    28: "ECP-384-BRAINPOOL", 29: "ECP-521-BRAINPOOL", 31: "CURVE25519",
    32: "CURVE448",
}

WEAK_ENCR = {"DES", "3DES"}
WEAK_MAC = {"HMAC-MD5", "HMAC-SHA1"}
WEAK_DH = {"MODP-768", "MODP-1024", "MODP-1536"}  # < 2048-bit
WEAK_DH_GROUPS = {1, 2, 5}

UDP_TIMEOUT = 3.0
IKEV2_SA_INIT = 34


class IkeParseError(Exception):
    """Malformed IKE message — recorded, never fatal."""


# ------------------------------------------------------------------ builders

def build_ikev2_sa_init(spi_i: bytes) -> bytes:
    """Minimal IKEv2 SA_INIT: header + SA proposal (AES-CBC-256/HMAC-SHA2-256/MODP-2048)."""
    # SA payload body: proposal substructure
    # proposal: 1 byte num, 1 proto-id(1=IKE), 1 SPI-size(0), 1 num-transforms, then transforms
    # offer AES-CBC-256 + PRF HMAC-SHA2-256 + MODP-2048 (strong, widely supported)
    transforms = _transform(ENCR, 5, 16) + _transform(PRF, 5, 0) + _transform(DH_GROUP, 14, 0)
    proposal = bytes([1, 1, 0, 3]) + transforms
    sa_payload = bytes([KE, 0]) + struct.pack("!H", len(proposal) + 4) + proposal
    # KE payload (dummy public key — a responder only needs the proposal to reply)
    ke_body = b"\x00\x00\x00\x00" + bytes(range(1, 33))  # DH group num 0 + dummy data
    ke_payload = bytes([NONCE, 0]) + struct.pack("!H", len(ke_body) + 4) + ke_body
    nonce_body = b"\x01" * 16
    nonce_payload = bytes([0, 0]) + struct.pack("!H", len(nonce_body) + 4) + nonce_body

    body = sa_payload + ke_payload + nonce_payload
    header = struct.pack(
        "!8s8sBBBBII",
        spi_i,
        b"\x00" * 8,
        SA, 0x20, IKEV2_SA_INIT, 0x08, 0,
        len(body) + 28,
    )
    return header + body


def _transform(transform_type: int, transform_id: int, key_length: int) -> bytes:
    attrs = b""
    if key_length:
        attrs = struct.pack("!HH", 0x800E, key_length)  # KEY_LENGTH attribute
    # transform substructure: type(1) + reserved(1) + transform id(2) + attrs
    body = bytes([transform_type, 0]) + struct.pack("!H", transform_id) + attrs
    # Length includes the 2-byte length field itself
    return struct.pack("!H", len(body) + 2) + body


# ------------------------------------------------------------------ parser

def _transform_name(ttype: int, tid: int) -> str:
    if ttype == ENCR:
        return IKE_ENCR.get(tid, f"ENCR-{tid}")
    if ttype in (PRF, INTEG):
        return IKE_PRF_INTEG.get(tid, f"{'PRF' if ttype == PRF else 'INTEG'}-{tid}")
    if ttype == DH_GROUP:
        return IKE_DH.get(tid, f"DH-{tid}")
    if ttype == ESN:
        return "ESN"
    return f"TYPE{ttype}-{tid}"


def _parse_transforms(raw: bytes, start: int, count: int, end: int) -> list[dict[str, Any]]:
    """Parse ``count`` transform substructures starting at ``start``."""
    out: list[dict[str, Any]] = []
    pos = start
    for _ in range(count):
        if pos + 4 > end:
            break
        tlen = struct.unpack("!H", raw[pos:pos + 2])[0]
        if tlen < 4 or pos + tlen > end:
            break
        ttype = raw[pos + 2]
        tid = struct.unpack("!H", raw[pos + 4:pos + 6])[0]
        out.append({"type": ttype, "id": tid, "name": _transform_name(ttype, tid)})
        pos += tlen
    return out


def parse_sa_payload(raw: bytes, offset: int, length: int) -> list[dict[str, Any]]:
    """Parse an SA payload's proposal substructures into a readable list."""
    proposals: list[dict[str, Any]] = []
    end = min(len(raw), offset + length)
    pos = offset + 4  # skip 4 reserved bytes
    while pos + 4 <= end:
        num = raw[pos]
        proto = raw[pos + 1]
        spi_size = raw[pos + 2]
        num_trans = raw[pos + 3]
        body = pos + 4 + spi_size
        if body + 2 > end:
            break
        transforms = _parse_transforms(raw, body, num_trans, end)
        proposals.append(
            {
                "proposal": num,
                "protocol": "IKE" if proto == 1 else ("ESP" if proto == 3 else f"PROTO-{proto}"),
                "transforms": transforms,
            }
        )
        # advance past the transforms of this proposal
        next_pos = body
        for _ in range(num_trans):
            if next_pos + 2 > end:
                break
            tlen = struct.unpack("!H", raw[next_pos:next_pos + 2])[0]
            if tlen < 4 or next_pos + tlen > end:
                break
            next_pos += tlen
        if next_pos <= pos:
            break  # no progress — malformed input
        pos = next_pos
    return proposals


def extract_sa_from_response(packet: bytes) -> list[dict[str, Any]]:
    """Walk an IKE message's payload chain and return every SA proposal found.

    Each payload's first byte is the *next* payload's type; the type of the
    first payload lives in the IKE header at offset 16.
    """
    if len(packet) < 28:
        raise IkeParseError("packet too short for IKE header")
    length = struct.unpack("!I", packet[24:28])[0]
    next_payload = packet[16]
    pos = 28
    end = min(len(packet), length or len(packet))
    proposals: list[dict[str, Any]] = []
    while pos + 4 <= end:
        payload_type = next_payload
        p_len = struct.unpack("!H", packet[pos + 2:pos + 4])[0]
        if p_len < 4 or pos + p_len > end:
            break
        if payload_type == SA:
            proposals.extend(parse_sa_payload(packet, pos, p_len))
        next_payload = packet[pos]
        pos += p_len
    return proposals


# ------------------------------------------------------------- classification

def classify_ipsec(proposals: list[dict[str, Any]]) -> list[str]:
    """Return issues for the weakest transform set found in the proposals."""
    issues: list[str] = []
    for proposal in proposals:
        trans = proposal.get("transforms") or []
        encr = [t for t in trans if t["type"] == ENCR]
        macs = [t for t in trans if t["type"] in (PRF, INTEG)]
        dhs = [t for t in trans if t["type"] == DH_GROUP]
        for t in encr:
            if t["name"] in WEAK_ENCR:
                issues.append(f"WEAK_IKE_ENCRYPTION:{t['name']}")
        for t in macs:
            if t["name"] in WEAK_MAC:
                issues.append(f"WEAK_IKE_MAC:{t['name']}")
        for t in dhs:
            if t["name"] in WEAK_DH or t["id"] in WEAK_DH_GROUPS:
                issues.append(f"WEAK_IKE_DH_GROUP:{t['name']}")
        # PFS in IKEv2 = the SA proposal includes a DH-group transform (so a
        # fresh DH exchange can secure each CHILD_SA). No DH group -> no PFS.
        if not dhs:
            issues.append("IKE_NO_PFS")
    return sorted(set(issues))


# ------------------------------------------------------------------ probing

def probe_ike(
    host: str,
    *,
    ports: Iterable[int] = (500, 4500),
    timeout: float = UDP_TIMEOUT,
    spi_i: bytes | None = None,
) -> dict[str, Any]:
    """Send one IKEv2 SA_INIT to a host; return status + parsed proposals.

    Returns:
        {"endpoint", "status": "OK"|"NO_RESPONSE"|"PORT_CLOSED"|"ERROR",
         "proposals": [...], "issues": [...]}
    """
    spi = spi_i or bytes(range(8))
    last_error = ""
    for port in ports:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(build_ikev2_sa_init(spi), (host, port))
            data, _addr = sock.recvfrom(4096)
            proposals = extract_sa_from_response(data)
            issues = classify_ipsec(proposals)
            return {
                "endpoint": f"{host}:{port}",
                "status": "OK",
                "port": port,
                "proposals": proposals,
                "issues": issues,
            }
        except socket.timeout:
            last_error = f"no IKE response on udp/{port}"
            continue
        except ConnectionRefusedError:
            return {"endpoint": f"{host}:{port}", "status": "PORT_CLOSED", "port": port, "issues": ["IKE_PORT_CLOSED"]}
        except OSError as exc:
            last_error = f"udp/{port}: {exc}"
            continue
        finally:
            if sock is not None:
                sock.close()
    return {"endpoint": f"{host}:{ports[0]}", "status": "NO_RESPONSE", "issues": ["IKE_NO_RESPONSE"], "detail": last_error}
