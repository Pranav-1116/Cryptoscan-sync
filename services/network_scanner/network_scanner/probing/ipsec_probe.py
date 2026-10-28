"""IPsec/IKE VPN crypto probing (IKEv1 + IKEv2).

Enterprises run VPN concentrators; their crypto posture (IKE encryption,
integrity/PRF, Diffie-Hellman group, PFS) is part of the network crypto
surface. This module:

- sends a minimal IKE SA proposal over UDP (500, and 4500 for NAT-T) and
  parses the responder's returned transform set — no handshake completed,
  no keys exchanged, no traffic established. **Both versions are spoken**:
  IKEv2 IKE_SA_INIT first, then IKEv1 Main Mode, because a concentrator that
  only answers IKEv1 is still part of the estate and would otherwise be
  silently missing from the inventory;
- classifies weak configurations: DES/3DES encryption, MD5/SHA1 integrity,
  DH groups < 2048-bit (1, 2, 5), and no PFS where we can *see* the CHILD_SA
  proposal;
- is **active opt-in only**: you must pass explicit endpoints. Nothing is
  ever probed implicitly, and every probe is one UDP packet with a timeout.

What "ESP in use" and "PFS on" may mean here, and no more:

* ``DECLARED_IN_SA_INIT`` — the responder volunteered an ESP proposal in its
  reply; that is its offer, read out of the packet;
* ``CONFIGURED`` — a caller supplied the transform set from configuration or
  inventory (:func:`esp_from_config`); nobody has seen it negotiated;
* ``NOT_OBSERVED`` — the normal case: the CHILD_SA is negotiated only after
  IKE_AUTH / Quick Mode, which needs an authenticated peer. CryptoScan never
  authenticates, so the ESP suite and the PFS actually in use stay
  ``UNKNOWN``. This is a boundary, not a finding of "no ESP" or "no PFS".

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

# IKEv1 transform ids (RFC 2409 / 2407 / 2451): a *different* table from
# IKEv2's — id 2 is 3DES in v1 (ENCR) but HMAC-SHA1 in v2, so the two are
# never mixed up.
IKEV1_ENCR = {
    1: "DES", 2: "IDEA", 3: "BLOWFISH", 4: "RC5", 5: "3DES", 6: "CAST", 7: "AES-CBC",
    8: "CAMELLIA-CBC",
}
IKEV1_HASH = {1: "HMAC-MD5", 2: "HMAC-SHA1", 3: "TIGER", 4: "HMAC-SHA2-256",
              5: "HMAC-SHA2-384", 6: "HMAC-SHA2-512"}
IKEV1_AUTH = {
    1: "PRE-SHARED-KEY", 2: "DSS-SIGNATURES", 3: "RSA-SIGNATURES", 4: "RSA-SIGNATURES-LONG",
    5: "RSA-SIGNATURES-REVISED", 64221: "XAUTH-INIT", 64222: "HYBRID", 64223: "XAUTH-RESP",
    65001: "GSSAPI",
}

#: IKEv1 transform types, and the IKEv2 slot each one is reported in
IKEV1_T_HASH = 2
IKEV1_T_AUTH = 3
#: a v1 authentication method is neither a v2 PRF nor a v2 INTEG transform —
#: it gets its own type so it can never be mistaken for a MAC
AUTH_METHOD = 6
#: IKEv1 attribute types
ATTR_LIFE_DURATION = 12
ATTR_KEY_LENGTH = 14
ATTR_GROUP_DESCRIPTION = 10

#: IKEv1 exchange types (RFC 2408)
IKEV1_EXCHANGES = {
    1: "BASE", 2: "MAIN_MODE", 3: "AUTH_ONLY", 4: "AGGRESSIVE_MODE", 5: "INFORMATIONAL",
    32: "QUICK_MODE", 37: "NEW_GROUP_MODE",
}

WEAK_ENCR = {"DES", "3DES", "NULL"}
WEAK_MAC = {"HMAC-MD5", "HMAC-SHA1"}
WEAK_DH = {"MODP-768", "MODP-1024", "MODP-1536"}  # < 2048-bit
WEAK_DH_GROUPS = {1, 2, 5}

UDP_TIMEOUT = 3.0
IKEV2_SA_INIT = 34
IKEV1_MAIN_MODE = 2
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


def build_ikev1_main_mode(spi_i: bytes, *, encryption: int = 7, hash_id: int = 2, auth: int = 3,
                          group: int = 14, key_length: int = 256, lifetime: int = 28800) -> bytes:
    """Minimal IKEv1 Main Mode SA proposal: AES-CBC-256 / HMAC-SHA1 / RSA-sig / MODP-2048.

    One packet, no cookies exchange, no key exchange, no authentication. An
    IKEv1 responder that answers this replies with the proposal it accepts —
    the same information an IKEv2 responder gives, in the v1 wire format.
    """
    transforms = (
        _v1_transform(1, ENCR, encryption, {ATTR_KEY_LENGTH: key_length})
        + _v1_transform(2, IKEV1_T_HASH, hash_id)
        + _v1_transform(3, IKEV1_T_AUTH, auth)
        + _v1_transform(4, DH_GROUP, group, {ATTR_LIFE_DURATION: lifetime})
    )
    # proposal: number, protocol-id (1 = ISAKMP), SPI size 0, transform count
    proposal = bytes([1, 1, 0, 4]) + transforms
    # SA body: DOI (1 = IPsec) + situation (1 = SIT_IDENTITY_ONLY), then proposals
    sa_body = struct.pack("!II", 1, 1) + proposal
    sa_payload = bytes([0, 0]) + struct.pack("!H", len(sa_body) + 4) + sa_body
    header = struct.pack(
        "!8s8sBBBBII",
        spi_i,
        b"\x00" * 8,
        SA,
        0x10,  # version 1.0
        IKEV1_MAIN_MODE,
        0x00,  # no encryption, no commit, not auth-only
        0,
        len(sa_payload) + 28,
    )
    return header + sa_payload


def _v1_transform(number: int, transform_type: int, transform_id: int,
                  attributes: dict[int, int] | None = None) -> bytes:
    """IKEv1 transform: number, type id, length (incl. header), then attributes.

    Unlike IKEv2 — where the algorithm sits in the transform id — IKEv1 carries
    the type in byte 1 and the *algorithm* in the first attribute, whose class
    equals the transform type. Getting this wrong yields a packet an appliance
    rejects, which would look exactly like "not listening".
    """
    attrs = struct.pack("!HH", transform_type, transform_id)  # class, algorithm
    attrs += b"".join(struct.pack("!HH", atype, value) for atype, value in (attributes or {}).items())
    body = bytes([number, transform_type]) + struct.pack("!H", 4 + len(attrs)) + attrs
    return body


def _transform(transform_type: int, transform_id: int, key_length: int) -> bytes:
    attrs = b""
    if key_length:
        attrs = struct.pack("!HH", 0x800E, key_length)  # KEY_LENGTH attribute
    # transform substructure: type(1) + reserved(1) + transform id(2) + attrs
    body = bytes([transform_type, 0]) + struct.pack("!H", transform_id) + attrs
    # Length includes the 2-byte length field itself
    return struct.pack("!H", len(body) + 2) + body


# ------------------------------------------------------------------ parser

def _transform_name(ttype: int, tid: int, version: int = 2, key_length: int | None = None) -> str:
    if version == 1:
        if ttype == ENCR:
            name = IKEV1_ENCR.get(tid, f"IKEv1-ENCR-{tid}")
            return f"{name}-{key_length}" if name == "AES-CBC" and key_length else name
        if ttype == PRF:
            return IKEV1_HASH.get(tid, f"IKEv1-HASH-{tid}")
        if ttype == AUTH_METHOD:
            return IKEV1_AUTH.get(tid, f"IKEv1-AUTH-{tid}")
        if ttype == DH_GROUP:
            return IKE_DH.get(tid, f"DH-{tid}")
        return f"TYPE{ttype}-{tid}"
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


def _parse_transforms_v1(raw: bytes, start: int, count: int, end: int) -> list[dict[str, Any]]:
    """Parse IKEv1 transform substructures, keeping their attributes.

    v1 attributes are 2-byte class/value pairs (short form) or class, length and
    value (long form). The algorithm is the first attribute whose class equals
    the transform type; KEY_LENGTH and LIFE_DURATION decide whether an AES entry
    says 128, 192 or 256 bits — or nothing at all.
    """
    out: list[dict[str, Any]] = []
    pos = start
    for _ in range(count):
        if pos + 4 > end:
            break
        number, v1_type = raw[pos], raw[pos + 1]
        tlen = struct.unpack("!H", raw[pos + 2:pos + 4])[0]
        if tlen < 4 or pos + tlen > end:
            break
        attributes: list[tuple[int, int]] = []
        attr_pos = pos + 4
        while attr_pos + 4 <= pos + tlen:
            aclass = struct.unpack("!H", raw[attr_pos:attr_pos + 2])[0]
            if aclass & 0x8000:  # long form: class, length, value
                length = struct.unpack("!H", raw[attr_pos + 2:attr_pos + 4])[0]
                value = int.from_bytes(raw[attr_pos + 4:attr_pos + 4 + length], "big")
                attr_pos += 4 + length
            else:
                value = struct.unpack("!H", raw[attr_pos + 2:attr_pos + 4])[0]
                attr_pos += 4
            attributes.append((aclass & 0x7FFF, value))
        algorithm = next((value for aclass, value in attributes if aclass == v1_type), None)
        extras = {aclass: value for aclass, value in attributes if aclass != v1_type}
        mapped = {
            ENCR: ENCR,
            IKEV1_T_HASH: PRF,
            IKEV1_T_AUTH: AUTH_METHOD,
            DH_GROUP: DH_GROUP,
        }.get(v1_type, v1_type)
        out.append({
            "type": mapped,
            "v1_type": v1_type,
            "id": algorithm,
            "number": number,
            "name": _transform_name(mapped, algorithm if algorithm is not None else -1, 1,
                                    extras.get(ATTR_KEY_LENGTH)),
            "attributes": {str(key): value for key, value in sorted(extras.items())},
        })
        pos += tlen
    return out


def parse_sa_payload_v1(raw: bytes, offset: int, length: int) -> list[dict[str, Any]]:
    """Parse an IKEv1 SA payload: DOI + situation, then length-less proposals."""
    proposals: list[dict[str, Any]] = []
    end = min(len(raw), offset + length)
    pos = offset + 4  # generic payload header
    if pos + 8 <= end:
        doi = struct.unpack("!I", raw[pos:pos + 4])[0]
        if doi in (0, 1):  # IPsec DOI
            pos += 8  # DOI + situation
    while pos + 4 <= end:
        num, proto, spi_size, num_trans = raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]
        body = pos + 4 + spi_size
        if body > end:
            break
        transforms = _parse_transforms_v1(raw, body, num_trans, end)
        proposals.append({
            "proposal": num,
            "protocol": {1: "IKE", 3: "ESP", 2: "AH"}.get(proto, f"PROTO-{proto}"),
            "ike_version": 1,
            "transforms": transforms,
        })
        if not transforms:
            break
        pos = body
        for _ in range(num_trans):
            if pos + 4 > end:
                return proposals
            tlen = struct.unpack("!H", raw[pos + 2:pos + 4])[0]
            if tlen < 4 or pos + tlen > end:
                return proposals
            pos += tlen
    return proposals


def _packet_version(packet: bytes) -> int:
    return packet[17] >> 4 if len(packet) > 17 else 2


def extract_sa_from_response(packet: bytes, *, version: int | None = None) -> list[dict[str, Any]]:
    """Walk an IKE message's payload chain and return every SA proposal found.

    Each payload's first byte is the *next* payload's type; the type of the
    first payload lives in the IKE header at offset 16. The version is read
    from the header, so an IKEv1 reply is parsed with the v1 layout instead of
    being mis-read as v2 and reported as a malformed proposal.
    """
    if len(packet) < 28:
        raise IkeParseError("packet too short for IKE header")
    major = version or _packet_version(packet)
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
            if major == 1:
                proposals.extend(parse_sa_payload_v1(packet, pos, p_len))
            else:
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
        "exchange": (
            IKEV1_EXCHANGES.get(exchange, f"EXCHANGE-{exchange}") if major == 1
            else EXCHANGE_TYPES.get(exchange, f"EXCHANGE-{exchange}")
        ),
        "exchange_type": exchange,
        # v2: 0x08 initiator, 0x20 response; v1: 0x01 encrypted, 0x02 commit, 0x04 auth-only
        "initiator": bool(flags & 0x08) if major != 1 else bool(flags & 0x20),
        "response": bool(flags & 0x20) if major != 1 else bool(flags & 0x01),
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


#: what an ESP report is allowed to rest on
ESP_BASES = {
    "RESPONDER_OFFERED": "the responder put this ESP proposal in its own reply; read out of the packet",
    "CONFIGURATION": "an operator supplied this transform set from configuration or inventory; nobody has seen "
                     "it negotiated",
    "NOT_OBSERVED": "the CHILD_SA is negotiated only after IKE_AUTH / Quick Mode succeeds, which CryptoScan "
                    "never completes",
}


def esp_from_config(record: dict[str, Any]) -> dict[str, Any]:
    """ESP suite as *configured* (device config, vendor export, CMDB row).

    This is the only honest way to say "ESP/PFS is in use" without performing
    IKE_AUTH: the suite is declared, so the report says ``CONFIGURED`` and
    carries its reference. It never claims the SA was negotiated.
    """
    encryption = record.get("encryption") or record.get("esp_encryption")
    integrity = record.get("integrity") or record.get("esp_integrity") or record.get("authentication")
    dh_group = record.get("dh_group") or record.get("pfs_group")
    declared_pfs = record.get("pfs")
    if isinstance(declared_pfs, str):
        state = {"ON": "ON", "TRUE": "ON", "OFF": "OFF", "FALSE": "OFF", "UNKNOWN": "UNKNOWN"}.get(
            declared_pfs.upper(), "UNKNOWN"
        )
    elif isinstance(declared_pfs, bool):
        state = "ON" if declared_pfs else "OFF"
    else:
        state = "ON" if dh_group else "UNKNOWN"
    return {
        "protocol": "ESP",
        "status": "CONFIGURED",
        "basis": "CONFIGURATION",
        "claim": "CONFIGURED",
        "encryption": encryption,
        "integrity": integrity,
        "dh_group": dh_group,
        "pfs": state,
        "pfs_state": state,
        "pfs_basis": "CONFIGURATION",
        "reference": record.get("reference") or record.get("source"),
        "transform_count": len([item for item in (encryption, integrity, dh_group) if item]),
        "reason": ESP_BASES["CONFIGURATION"],
    }


def summarize_proposals(proposals: list[dict[str, Any]], *, ike_version: int | None = None,
                        esp_config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Collapse raw proposals into the readable IKE/ESP decomposition of §13.

    Only what the responder actually put in its SA payload is reported. A
    missing ESP proposal is *not* evidence that ESP is unencrypted: the
    CHILD_SA is negotiated inside IKE_AUTH (v2) or Quick Mode after phase-1
    authentication (v1), neither of which CryptoScan performs, so
    ``esp.status`` stays ``NOT_OBSERVED`` and PFS stays ``UNKNOWN`` unless a
    caller supplies a configuration basis.
    """
    version = ike_version or next((p.get("ike_version") for p in proposals if p.get("ike_version")), 2)
    ike = next((p for p in proposals if p.get("protocol") == "IKE"), None)
    esp = next((p for p in proposals if p.get("protocol") == "ESP"), None)

    summary: dict[str, Any] = {"ike": None, "esp": None, "ike_version": version}
    if ike:
        transforms = ike.get("transforms") or []
        encryption = _names(transforms, ENCR)
        prf = _names(transforms, PRF)
        integrity = _names(transforms, INTEG)
        dh = _names(transforms, DH_GROUP)
        aead = any("GCM" in name for name in encryption)
        summary["ike"] = {
            "protocol": "IKE",
            "version": f"IKEv{version}",
            "encryption": encryption[0] if encryption else None,
            "prf": prf[0] if prf else None,
            # AEAD suites (GCM) authenticate the payload themselves: an absent
            # integrity transform is *implied* AEAD, not missing integrity.
            "integrity": integrity[0] if integrity else ("AEAD" if aead else None),
            "dh_group": dh[0] if dh else None,
            "esn": any(t.get("type") == ESN for t in transforms),
            # v1 offers its authentication method in the proposal; which one won
            # is only settled in phase 2, so this is *offered*, not observed
            "auth_methods_offered": _names(transforms, AUTH_METHOD) or None,
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
            "basis": "RESPONDER_OFFERED",
            "claim": "OFFERED",
            "encryption": encryption[0] if encryption else None,
            "integrity": integrity[0] if integrity else None,
            "dh_group": dh[0] if dh else None,
            "pfs": "OFFERED" if dh else "NOT_OFFERED",
            "pfs_state": "ON" if dh else "OFF",
            "pfs_basis": "RESPONDER_OFFERED",
            "transform_count": len(transforms),
            "reason": ESP_BASES["RESPONDER_OFFERED"],
        }
    elif esp_config:
        summary["esp"] = esp_from_config(esp_config)
    else:
        summary["esp"] = {
            "protocol": "ESP",
            "status": "NOT_OBSERVED",
            "basis": "NOT_OBSERVED",
            "claim": "NOT_OBSERVED",
            "encryption": None,
            "integrity": None,
            "dh_group": None,
            "pfs": "UNKNOWN",
            "pfs_state": "UNKNOWN",
            "pfs_basis": "NOT_OBSERVED",
            "reason": (
                "ESP/CHILD_SA transforms are negotiated "
                + ("in Quick Mode after the phase-1 SA is authenticated" if version == 1
                   else "inside IKE_AUTH, which requires an authenticated SA")
                + " — CryptoScan never authenticates, so the ESP suite and the PFS in use are "
                "NOT_OBSERVED, not absent"
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
        # In IKEv1 the phase-1 group only protects the IKE SA itself — PFS is a
        # Quick Mode property we never see — so no IKE_NO_PFS is claimed there.
        if not dhs and proposal.get("ike_version") != 1:
            issues.append("IKE_NO_PFS")
    return sorted(set(issues))


# ------------------------------------------------------------------ probing

def _empty_esp(version: int = 2) -> dict[str, Any]:
    return summarize_proposals([], ike_version=version)["esp"]


def _probe_once(host: str, port: int, timeout: float, spi: bytes, version: int,
                esp_config: dict[str, Any] | None) -> dict[str, Any]:
    """One packet, one reply window, for a single IKE version."""
    packet = build_ikev1_main_mode(spi) if version == 1 else build_ikev2_sa_init(spi)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (host, port))
        data, _addr = sock.recvfrom(4096)
        header = parse_ike_header(data)
        ike_version = int(header.get("major") or version)
        proposals = extract_sa_from_response(data, version=ike_version)
        notifies = extract_notifies(data)
        ke = extract_ke(data)
        summary = summarize_proposals(proposals, ike_version=ike_version, esp_config=esp_config)
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
            "ike_version": f"IKEv{ike_version}",
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
        return {
            "endpoint": f"{host}:{port}", "status": "NO_RESPONSE", "port": port, "transport": "UDP",
            "ike_version": f"IKEv{version}", "ike": None, "esp": _empty_esp(version),
            "notifies": [], "proposals": [], "issues": ["IKE_NO_RESPONSE"],
            "detail": f"no IKEv{version} response on udp/{port}",
        }
    except ConnectionRefusedError:
        return {
            "endpoint": f"{host}:{port}", "status": "PORT_CLOSED", "port": port, "transport": "UDP",
            "ike_version": f"IKEv{version}", "ike": None, "esp": _empty_esp(version),
            "notifies": [], "proposals": [], "issues": ["IKE_PORT_CLOSED"],
            "detail": "ICMP port unreachable",
        }
    except IkeParseError as exc:
        return {
            "endpoint": f"{host}:{port}", "status": "MALFORMED_RESPONSE", "port": port, "transport": "UDP",
            "ike_version": f"IKEv{version}", "ike": None, "esp": _empty_esp(version),
            "notifies": [], "proposals": [], "issues": ["IKE_MALFORMED_RESPONSE"], "detail": str(exc),
        }
    except OSError as exc:
        return {
            "endpoint": f"{host}:{port}", "status": "ERROR", "port": port, "transport": "UDP",
            "ike_version": f"IKEv{version}", "ike": None, "esp": _empty_esp(version),
            "notifies": [], "proposals": [], "issues": ["IKE_PROBE_ERROR"],
            "detail": f"udp/{port}: {exc}",
        }
    finally:
        if sock is not None:
            sock.close()


#: statuses where the endpoint answered — trying another version would only add noise
_ANSWERED = frozenset({"OK", "NO_PROPOSAL_CHOSEN", "INVALID_KE", "NO_PROPOSAL", "MALFORMED_RESPONSE",
                       "PORT_CLOSED"})


def probe_ike(
    host: str,
    *,
    ports: Iterable[int] = (500, 4500),
    timeout: float = UDP_TIMEOUT,
    spi_i: bytes | None = None,
    versions: Iterable[int] = (2, 1),
    esp_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Probe a host with an IKE SA proposal and return status + parsed transforms.

    IKEv2 SA_INIT is sent first, then IKEv1 Main Mode: a concentrator that only
    speaks IKEv1 would otherwise look like "no VPN here", which is a coverage
    lie rather than a finding. Each attempt is one UDP packet; the loop stops as
    soon as the endpoint answers, and every attempt is recorded in ``attempts``.

    Status vocabulary (never a "no crypto" verdict):

    * ``OK`` — responder returned an SA proposal; transforms are parsed
    * ``NO_PROPOSAL_CHOSEN`` — responder answered but refused our suite
    * ``INVALID_KE`` — responder asked for a different DH group
    * ``NO_RESPONSE`` — nothing came back on any port for any version
    * ``PORT_CLOSED`` / ``MALFORMED_RESPONSE`` / ``ERROR`` — transport-level outcome

    ``esp_config`` is optional and, when given, describes the ESP suite from
    configuration (see :func:`esp_from_config`): the report then says
    ``CONFIGURED``, never "observed".

    Returns:
        {"endpoint", "status", "port", "ike_version", "proposals", "ike", "esp",
         "notifies", "issues", "detail", "attempts"}
    """
    spi = spi_i or bytes(range(8))
    port_list = [int(port) for port in (ports or (500, 4500))]
    if not port_list:
        port_list = [500, 4500]
    version_list = [int(version) for version in (versions or (2,)) if int(version) in (1, 2)] or [2]
    attempts: list[dict[str, Any]] = []
    last: dict[str, Any] | None = None
    for version in version_list:
        for port in port_list:
            result = _probe_once(host, port, timeout, spi, version, esp_config)
            attempts.append({"version": f"IKEv{version}", "port": port, "status": result["status"],
                             "detail": result.get("detail")})
            last = result
            if result["status"] in _ANSWERED:
                result["attempts"] = attempts
                return result
    fallback = last or {
        "endpoint": f"{host}:{port_list[0]}", "status": "NO_RESPONSE", "port": port_list[0],
        "transport": "UDP", "ike_version": f"IKEv{version_list[0]}", "ike": None,
        "esp": _empty_esp(version_list[0]), "notifies": [], "proposals": [],
        "issues": ["IKE_NO_RESPONSE"], "detail": "no attempt was made",
    }
    fallback["status"] = "NO_RESPONSE"
    fallback["issues"] = sorted(set(list(fallback.get("issues") or []) + ["IKE_NO_RESPONSE"]))
    fallback["detail"] = "; ".join(
        f"{item['version']} udp/{item['port']}: {item['status']}" for item in attempts
    )
    fallback["attempts"] = attempts
    return fallback
