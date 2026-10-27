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
    11: "NULL", 12: "AES-GCM-16-128", 13: "AES-GCM-16-192", 14: "AES-GCM-16-256",
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

#: IKEv2 notify message types worth reporting (§13): a responder that refuses
#: our proposal tells us something real — it is not a "no crypto" verdict.
NOTIFY_TYPES = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD",
    14: "NO_PROPOSAL_CHOSEN",
    17: "INVALID_KE_PAYLOAD",
    24: "AUTHENTICATION_FAILED",
    34: "INVALID_SYNTAX",
    35: "NO_ADDITIONAL_SAS",
    40: "SINGLE_PAIR_REQUIRED",
    13868: "COOKIE",
    16404: "INVALID_SELECTORS",
    16421: "TEMPORARY_FAILURE",
}

WEAK_ENCR = {"DES", "3DES", "NULL"}
WEAK_MAC = {"HMAC-MD5", "HMAC-SHA1"}
WEAK_DH = {"MODP-768", "MODP-1024", "MODP-1536"}  # < 2048-bit
WEAK_DH_GROUPS = {1, 2, 5}

UDP_TIMEOUT = 3.0
IKEV2_SA_INIT = 34
#: exchange type 34 = IKE_SA_INIT, 35 = IKE_AUTH (never sent by us)
EXCHANGE_TYPES = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL"}


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
    """Parse an SA payload's proposal substructures into a readable list.

    RFC 7296 §3.3 layout: four reserved bytes after the generic payload header,
    then proposals, each of which starts with its own two-byte length. Some lab
    fixtures and a few appliance quirks omit those length prefixes, so the
    layout is detected (a proposal number is never 0 and the length must fit the
    remaining payload) rather than assumed — neither form is silently mis-read.
    """
    proposals: list[dict[str, Any]] = []
    end = min(len(raw), offset + length)
    pos = offset + 4  # skip the generic payload header
    if raw[pos:pos + 4] == b"\x00\x00\x00\x00":
        pos += 4  # RFC reserved field
    while pos + 4 <= end:
        remaining = end - pos
        declared = struct.unpack("!H", raw[pos:pos + 2])[0]
        has_length = 8 <= declared <= remaining and raw[pos + 2] != 0
        if has_length:
            num, proto, spi_size, num_trans = raw[pos + 2], raw[pos + 3], raw[pos + 4], raw[pos + 5]
            body = pos + 6 + spi_size
            proposal_end = pos + declared
            advance = pos + declared
        else:
            num, proto, spi_size, num_trans = raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]
            body = pos + 4 + spi_size
            proposal_end = end
            advance = None  # computed from the transform lengths below
        if body + 2 > proposal_end:
            break
        transforms = _parse_transforms(raw, body, num_trans, proposal_end)
        proposals.append(
            {
                "proposal": num,
                "protocol": "IKE" if proto == 1 else ("ESP" if proto == 3 else f"PROTO-{proto}"),
                "transforms": transforms,
            }
        )
        if advance is not None:
            pos = advance
            continue
        # legacy layout: walk past this proposal's transforms to find the next one
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


# ------------------------------------------------------------------ header

def parse_ike_header(packet: bytes) -> dict[str, Any]:
    """Read the IKEv2 header: version, exchange, SPIs, message id, flags."""
    if len(packet) < 28:
        raise IkeParseError("packet too short for IKE header")
    spi_i, spi_r, next_payload, version, exchange, flags, message_id, length = struct.unpack(
        "!8s8sBBBBII", packet[:28]
    )
    major = version >> 4
    minor = version & 0x0F
    return {
        "spi_initiator": spi_i.hex(),
        "spi_responder": spi_r.hex(),
        "next_payload": next_payload,
        "version": f"IKEv{major}" if major == 2 else f"IKEv{major}.{minor}",
        "major": major,
        "minor": minor,
        "exchange": EXCHANGE_TYPES.get(exchange, f"EXCHANGE-{exchange}"),
        "exchange_type": exchange,
        "initiator": bool(flags & 0x08),
        "response": bool(flags & 0x20),
        "message_id": message_id,
        "length": length or len(packet),
    }


def _walk_payloads(packet: bytes):
    """Yield ``(payload_type, body_offset, payload_length)`` for one IKE message."""
    if len(packet) < 28:
        raise IkeParseError("packet too short for IKE header")
    length = struct.unpack("!I", packet[24:28])[0]
    next_payload = packet[16]
    pos = 28
    end = min(len(packet), length or len(packet))
    while pos + 4 <= end:
        p_len = struct.unpack("!H", packet[pos + 2:pos + 4])[0]
        if p_len < 4 or pos + p_len > end:
            break
        yield next_payload, pos, p_len
        next_payload = packet[pos]
        pos += p_len


def extract_notifies(packet: bytes) -> list[dict[str, Any]]:
    """Parse NOTIFY payloads — the responder's explicit refusal reason."""
    notifies: list[dict[str, Any]] = []
    for payload_type, offset, length in _walk_payloads(packet):
        if payload_type != NOTIFY:
            continue
        body = packet[offset:offset + length]
        if len(body) < 8:
            continue
        protocol_id, spi_size, notify_type = struct.unpack("!BBH", body[4:8])
        data = body[8 + spi_size:]
        entry: dict[str, Any] = {
            "type": notify_type,
            "name": NOTIFY_TYPES.get(notify_type, f"NOTIFY-{notify_type}"),
            "protocol_id": protocol_id,
        }
        if notify_type == 17 and len(data) >= 2:  # INVALID_KE_PAYLOAD carries the wanted group
            group = struct.unpack("!H", data[:2])[0]
            entry["suggested_dh_group"] = _transform_name(DH_GROUP, group)
        notifies.append(entry)
    return notifies


def extract_ke(packet: bytes) -> dict[str, Any] | None:
    """Parse the KE payload's DH group and public-key length (§13)."""
    for payload_type, offset, length in _walk_payloads(packet):
        if payload_type != KE:
            continue
        body = packet[offset:offset + length]
        if len(body) < 8:
            continue
        group = struct.unpack("!H", body[4:6])[0]
        return {
            "dh_group": _transform_name(DH_GROUP, group),
            "dh_group_id": group,
            "public_key_bytes": max(0, len(body) - 8),
        }
    return None


# ------------------------------------------------------------- classification

def _names(transforms: list[dict[str, Any]], ttype: int) -> list[str]:
    return [t["name"] for t in transforms if t.get("type") == ttype]


def summarize_proposals(proposals: list[dict[str, Any]]) -> dict[str, Any]:
    """Collapse raw proposals into the readable IKE/ESP decomposition of §13.

    Only what the responder actually put in its SA payload is reported. A
    missing ESP proposal is *not* evidence that ESP is unencrypted — IKEv2
    negotiates the CHILD_SA inside IKE_AUTH, which needs an authenticated SA we
    never establish, so ``esp.status`` stays ``NOT_OBSERVED``.
    """
    ike = next((p for p in proposals if p.get("protocol") == "IKE"), None)
    esp = next((p for p in proposals if p.get("protocol") == "ESP"), None)

    summary: dict[str, Any] = {"ike": None, "esp": None}
    if ike:
        transforms = ike.get("transforms") or []
        encryption = _names(transforms, ENCR)
        prf = _names(transforms, PRF)
        integrity = _names(transforms, INTEG)
        dh = _names(transforms, DH_GROUP)
        aead = any("GCM" in name for name in encryption)
        summary["ike"] = {
            "protocol": "IKE",
            "encryption": encryption[0] if encryption else None,
            "prf": prf[0] if prf else None,
            # AEAD suites (GCM) authenticate the payload themselves: an absent
            # integrity transform is *implied* AEAD, not missing integrity.
            "integrity": integrity[0] if integrity else ("AEAD" if aead else None),
            "dh_group": dh[0] if dh else None,
            "esn": any(t.get("type") == ESN for t in transforms),
            "transform_count": len(transforms),
        }
    if esp:
        transforms = esp.get("transforms") or []
        encryption = _names(transforms, ENCR)
        integrity = _names(transforms, INTEG)
        dh = _names(transforms, DH_GROUP)
        summary["esp"] = {
            "protocol": "ESP",
            "status": "DECLARED_IN_SA_INIT",
            "encryption": encryption[0] if encryption else None,
            "integrity": integrity[0] if integrity else None,
            "dh_group": dh[0] if dh else None,
            "pfs": "OFFERED" if dh else "NOT_OFFERED",
            "transform_count": len(transforms),
        }
    else:
        summary["esp"] = {
            "protocol": "ESP",
            "status": "NOT_OBSERVED",
            "encryption": None,
            "integrity": None,
            "dh_group": None,
            "pfs": "UNKNOWN",
            "reason": (
                "ESP/CHILD_SA transforms are negotiated inside IKE_AUTH, which requires an "
                "authenticated SA — CryptoScan never completes IKE_AUTH, so the ESP suite "
                "is NOT_OBSERVED, not absent"
            ),
        }
    return summary


def classify_esp(proposals: list[dict[str, Any]]) -> list[str]:
    """Weak-transform issues for ESP proposals a responder volunteered."""
    issues: list[str] = []
    for proposal in proposals:
        if proposal.get("protocol") != "ESP":
            continue
        trans = proposal.get("transforms") or []
        for name in _names(trans, ENCR):
            if name in {"DES", "3DES", "NULL"}:
                issues.append(f"WEAK_ESP_ENCRYPTION:{name}")
        for name in _names(trans, INTEG):
            if name in WEAK_MAC:
                issues.append(f"WEAK_ESP_INTEGRITY:{name}")
        for name in _names(trans, DH_GROUP):
            if name in WEAK_DH:
                issues.append(f"WEAK_ESP_DH_GROUP:{name}")
        # An ESP proposal without a DH transform cannot offer PFS for that
        # CHILD_SA (IKEv2 re-keys without a fresh DH exchange).
        if not _names(trans, DH_GROUP):
            issues.append("ESP_NO_PFS")
    return issues


def classify_ipsec(proposals: list[dict[str, Any]]) -> list[str]:
    """Return issues for the weakest transform set found in the proposals."""
    issues: list[str] = []
    for proposal in proposals:
        if proposal.get("protocol") != "IKE":
            continue
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
    """Send one IKEv2 SA_INIT to a host; return status + parsed transforms.

    Status vocabulary (never a "no crypto" verdict):

    * ``OK`` — responder returned an SA proposal; transforms are parsed
    * ``NO_PROPOSAL_CHOSEN`` — responder answered but refused our suite
    * ``INVALID_KE`` — responder asked for a different DH group
    * ``NO_RESPONSE`` — nothing came back (filtered UDP, offline, or wrong port)
    * ``PORT_CLOSED`` / ``ERROR`` — reachability/transport failure

    Returns:
        {"endpoint", "status", "port", "proposals", "ike", "esp", "notifies",
         "issues", "detail"}
    """
    spi = spi_i or bytes(range(8))
    port_list = [int(port) for port in (ports or (500, 4500))]
    if not port_list:
        port_list = [500, 4500]
    last_error = ""
    for port in port_list:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(build_ikev2_sa_init(spi), (host, port))
            data, _addr = sock.recvfrom(4096)
            header = parse_ike_header(data)
            proposals = extract_sa_from_response(data)
            notifies = extract_notifies(data)
            ke = extract_ke(data)
            summary = summarize_proposals(proposals)
            issues = sorted(set(classify_ipsec(proposals) + classify_esp(proposals)))
            refusal = next(
                (n for n in notifies if n["name"] in {"NO_PROPOSAL_CHOSEN", "INVALID_KE_PAYLOAD"}),
                None,
            )
            if summary["ike"]:
                status = "OK"
            elif refusal and refusal["name"] == "INVALID_KE_PAYLOAD":
                status = "INVALID_KE"
                issues = sorted(set(issues + ["IKE_DH_GROUP_REFUSED"]))
            elif refusal:
                status = "NO_PROPOSAL_CHOSEN"
                issues = sorted(set(issues + ["IKE_PROPOSAL_REFUSED"]))
            else:
                status = "NO_PROPOSAL"
            return {
                "endpoint": f"{host}:{port}",
                "status": status,
                "port": port,
                "transport": "UDP",
                "header": header,
                "ike": summary["ike"],
                "esp": summary["esp"],
                "ke": ke,
                "notifies": notifies,
                "proposals": proposals,
                "issues": issues,
                "detail": refusal["name"] if refusal else None,
            }
        except socket.timeout:
            last_error = f"no IKE response on udp/{port}"
            continue
        except ConnectionRefusedError:
            return {
                "endpoint": f"{host}:{port}",
                "status": "PORT_CLOSED",
                "port": port,
                "transport": "UDP",
                "ike": None,
                "esp": summarize_proposals([])["esp"],
                "notifies": [],
                "proposals": [],
                "issues": ["IKE_PORT_CLOSED"],
                "detail": "ICMP port unreachable",
            }
        except IkeParseError as exc:
            return {
                "endpoint": f"{host}:{port}",
                "status": "MALFORMED_RESPONSE",
                "port": port,
                "transport": "UDP",
                "ike": None,
                "esp": summarize_proposals([])["esp"],
                "notifies": [],
                "proposals": [],
                "issues": ["IKE_MALFORMED_RESPONSE"],
                "detail": str(exc),
            }
        except OSError as exc:
            last_error = f"udp/{port}: {exc}"
            continue
        finally:
            if sock is not None:
                sock.close()
    return {
        "endpoint": f"{host}:{port_list[0]}",
        "status": "NO_RESPONSE",
        "port": port_list[0],
        "transport": "UDP",
        "ike": None,
        "esp": summarize_proposals([])["esp"],
        "notifies": [],
        "proposals": [],
        "issues": ["IKE_NO_RESPONSE"],
        "detail": last_error,
    }
