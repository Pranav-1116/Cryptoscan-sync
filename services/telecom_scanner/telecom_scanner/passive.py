"""Passive telecom protocol parsers (read-only, line-rate friendly).

Decode crypto-relevant fields from captured control-plane bytes — the same
safety model as the OT/ICS scanner: passive TAP output, never injected.
Parsers are pure functions over bytes; identical capture -> identical record.

Covered (initial set, extends the active 5G SBA scanner):
- Diameter (RFC 6733): header + AVP walk; origin-host/realm extraction;
  command codes mapped to the 3GPP interfaces they carry (S6a=316, Gx=1672,
  Gy=1673, Rx=1678, Cx=601, Sh=628) — security rides below Diameter
  (TCP/TLS or IPsec per TS 33.210).
- GTP-C v2 (TS 29.274): header + IE walk; message types mapped
  (Echo=1, Create Session=32, Modify Bearer=34, Delete Session=36,
  Bearer Resource Cmd=68).
- SIP / IMS security headers (TS 33.203): Security-Server / Security-Verify
  — ipsec-3gpp parameters (alg, spi-c/spi-s, port-c/port-s) and the TLS
  mechanism's advertised algorithms -> IMS security posture per NF.
"""

from __future__ import annotations

from typing import Any

# Diameter command codes worth naming for telecom ops (3GPP-mapped)
DIAMETER_COMMANDS = {
    257: "Capabilities-Exchange", 258: "Device-Watchdog", 280: "Diameter-Echo",
    316: "S6a-Update-Location", 318: "Purge-UE", 1672: "Gx-Credit-Control",
    1673: "Gy-Credit-Control", 1678: "Rx-AA-Request", 601: "Cx-User-Authorization",
    628: "Sh-Data",
}
DIAMETER_AVP_NAMES = {
    264: "Origin-Host", 263: "Session-Id", 266: "Origin-Realm", 267: "Firmware-Revision",
    257: "Auth-Application-Id", 258: "Auth-Session-State", 296: "Destination-Realm",
    283: "Destination-Host", 293: "Host-IP-Address", 299: "Result-Code",
}

GTPV2_MESSAGES = {
    1: "Echo-Request", 2: "Echo-Response", 32: "Create-Session-Request",
    33: "Create-Session-Response", 34: "Modify-Bearer-Request",
    35: "Modify-Bearer-Response", 36: "Delete-Session-Request",
    37: "Delete-Session-Response", 68: "Bearer-Resource-Command",
    130: "S5/S8-C-Create-Bearer",
}


def parse_diameter(buf: bytes) -> dict[str, Any] | None:
    """Decode a Diameter PDU: header, command mapping, and a bounded AVP walk."""
    if len(buf) < 20:
        return None
    version = buf[0]
    length = int.from_bytes(buf[1:4], "big")
    flags = buf[4]
    command_code = int.from_bytes(buf[5:8], "big")
    app_id = int.from_bytes(buf[8:12], "big")
    hop_id = int.from_bytes(buf[12:16], "big")
    end_id = int.from_bytes(buf[16:20], "big")
    record: dict[str, Any] = {
        "kind": "diameter", "proto": "diameter",
        "version": version, "length": length, "flags": hex(flags),
        "command_code": command_code,
        "command": DIAMETER_COMMANDS.get(command_code, f"code-{command_code}"),
        "application_id": app_id, "hop_by_hop": hop_id, "end_to_end": end_id,
        "avps": [], "origin_host": None, "origin_realm": None,
    }
    pos = 20
    while pos + 4 <= min(length, len(buf)):
        avp_code = int.from_bytes(buf[pos:pos + 4], "big")
        avp_flags = buf[pos + 4]
        avp_len = int.from_bytes(buf[pos + 5:pos + 8], "big")
        if avp_len < 8 or pos + avp_len > len(buf):
            break  # malformed tail — keep what decoded, honestly
        data_start = pos + 8
        if avp_flags & 0x80:  # Vendor-ID present
            data_start += 4
        if avp_code == 264 and avp_len > data_start - pos:
            raw = buf[data_start:pos + avp_len]
            record["origin_host"] = raw.rstrip(b"\x00").decode("utf-8", "replace")
        elif avp_code == 266 and avp_len > data_start - pos:
            raw = buf[data_start:pos + avp_len]
            record["origin_realm"] = raw.rstrip(b"\x00").decode("utf-8", "replace")
        record["avps"].append({
            "code": avp_code,
            "name": DIAMETER_AVP_NAMES.get(avp_code, f"avp-{avp_code}"),
            "length": avp_len, "vendor": bool(avp_flags & 0x80),
        })
        pos += avp_len + ((4 - avp_len % 4) % 4)  # 32-bit alignment padding
    return record


def parse_gtpc_v2(buf: bytes) -> dict[str, Any] | None:
    """Decode a GTP-C v2 PDU: header (TEID present unless Echo) + IE walk."""
    if len(buf) < 4:
        return None
    flags = buf[0]
    msg_type = buf[1]
    length = int.from_bytes(buf[2:4], "big")
    has_teid = bool(flags & 0x08)
    record: dict[str, Any] = {
        "kind": "gtpc", "proto": "gtpc-v2",
        "flags": hex(flags), "message_type": msg_type,
        "message": GTPV2_MESSAGES.get(msg_type, f"type-{msg_type}"),
        "length": length, "teid": None, "sequence": None, "ies": [],
    }
    pos = 4
    if has_teid:
        if len(buf) < 12:
            return record
        record["teid"] = int.from_bytes(buf[4:8], "big")
        record["sequence"] = int.from_bytes(buf[8:11], "big")
        pos = 12
    else:
        if len(buf) < 8:
            return record
        record["sequence"] = int.from_bytes(buf[4:7], "big")
        pos = 8
    # GTPv2 IE: 1-byte type + 2-byte length (top bit = CR flag) -> 3-byte header
    while pos + 3 <= min(4 + length, len(buf)):
        ie_type = buf[pos]
        raw_len = int.from_bytes(buf[pos + 1:pos + 3], "big")
        ie_len = raw_len & 0x7FFF
        if pos + 3 + ie_len > len(buf):
            break
        record["ies"].append({"type": ie_type, "length": ie_len,
                              "cr_flag": bool(raw_len & 0x8000)})
        pos += 3 + ie_len
    return record


def _parse_security_value(value: str) -> dict[str, Any]:
    """Parse one Security-Server mechanism value (TS 33.203 §7.2)."""
    parts = [p.strip() for p in value.split(";")]
    mech = parts[0].lower()
    params: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, _, v = p.partition("=")
            params[k.strip().lower()] = v.strip().strip('"')
    out: dict[str, Any] = {"mechanism": mech, "params": params}
    if mech == "ipsec-3gpp":
        out["algorithm"] = params.get("alg")
        spi_c, spi_s = params.get("spi-c"), params.get("spi-s")
        if spi_c and spi_s:
            out["key_size"] = 96 * 2 if "sha-1-96" in str(params.get("alg", "")) else None
        out["endpoint"] = (f"{params.get('port-c', '?')}/{params.get('port-s', '?')}"
                           if params.get("port-c") else None)
    elif mech == "tls":
        algs = params.get("algs", "")
        out["algorithm"] = algs or None
        out["extra_algs"] = [a for a in algs.split(",") if a] if algs else []
    return out


def parse_sip_security(buf: bytes) -> dict[str, Any] | None:
    """Extract crypto posture from SIP Security-Server / Security-Verify."""
    text = buf.decode("utf-8", "replace")
    headers: dict[str, list[str]] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        if key in {"security-server", "security-verify"}:
            headers.setdefault(key, []).append(value.strip())
    if not headers:
        return None
    mechanisms: list[dict[str, Any]] = []
    for values in headers.values():
        for v in values:
            # comma-separated mechanism list; quoted params may contain commas
            chunk, quote = "", False
            for ch in v + ",":
                if ch == '"':
                    quote = not quote
                    chunk += ch
                elif ch == "," and not quote:
                    if chunk.strip():
                        mechanisms.append(_parse_security_value(chunk.strip()))
                    chunk = ""
                else:
                    chunk += ch
    if not mechanisms:
        return None
    algs = [m.get("algorithm") for m in mechanisms if m.get("algorithm")]
    return {
        "kind": "sip", "proto": "sip/ims",
        "mechanisms": mechanisms,
        "algorithm": algs[0] if algs else None,
        "ipsec_present": any(m["mechanism"] == "ipsec-3gpp" for m in mechanisms),
        "tls_present": any(m["mechanism"] == "tls" for m in mechanisms),
    }
