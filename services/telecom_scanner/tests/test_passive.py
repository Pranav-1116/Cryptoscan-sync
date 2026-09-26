"""Passive telecom parsers: crafted wire bytes -> decoded crypto posture."""

from __future__ import annotations

import struct

from telecom_scanner.passive import parse_diameter, parse_gtpc_v2, parse_sip_security


def _diameter_pdu(command_code: int, app_id: int, avps: list[tuple[int, bytes]]) -> bytes:
    body = b""
    for code, data in avps:
        avp = struct.pack("!IB", code, 0) + (len(data) + 8).to_bytes(3, "big") + data
        pad = (4 - len(avp) % 4) % 4
        body += avp + b"\x00" * pad
    total = 20 + len(body)
    return (struct.pack("!B3sB", 1, total.to_bytes(3, "big"), 0b11000000)
            + command_code.to_bytes(3, "big")          # 24-bit command code
            + struct.pack("!III", app_id, 0x11223344, 0x55667788) + body)


def test_diameter_s6a_decode():
    pdu = _diameter_pdu(316, 16777251, [
        (264, b"amf01.mnc001.mcc310.3gppnetwork.org"),
        (266, b"mnc001.mcc310.3gppnetwork.org"),
    ])
    rec = parse_diameter(pdu)
    assert rec is not None
    assert rec["command"] == "S6a-Update-Location"
    assert rec["origin_host"] == "amf01.mnc001.mcc310.3gppnetwork.org"
    assert rec["origin_realm"] == "mnc001.mcc310.3gppnetwork.org"
    assert [a["name"] for a in rec["avps"]] == ["Origin-Host", "Origin-Realm"]
    # security note: Diameter rides below on TLS/IPsec (TS 33.210) — recorded
    assert rec["proto"] == "diameter"


def test_diameter_short_buffer_is_none():
    assert parse_diameter(b"\x01\x00") is None


def test_gtpc_v2_create_session():
    flags = 0x48  # version 2 + TEID present
    teid = 0xDEADBEEF
    seq = 0x0A0B0C
    ie = struct.pack("!BH", 71, 2) + b"PG"  # APN-ish IE
    body = ie
    total = 12 + len(body)
    pdu = struct.pack("!BBH", flags, 32, total - 4) + struct.pack("!I", teid) \
        + struct.pack("!I", seq)[1:4] + b"\x00" + body  # 24-bit sequence
    rec = parse_gtpc_v2(pdu)
    assert rec is not None
    assert rec["message"] == "Create-Session-Request"
    assert rec["teid"] == teid and rec["sequence"] == seq
    assert rec["ies"][0]["type"] == 71


def test_gtpc_echo_without_teid():
    pdu = struct.pack("!BBH", 0x40, 1, 4) + struct.pack("!I", 1)[1:4] + b"\x00"
    rec = parse_gtpc_v2(pdu)
    assert rec["message"] == "Echo-Request" and rec["teid"] is None


def test_sip_security_server_ipsec_and_tls():
    sip = (
        "Security-Server: ipsec-3gpp;alg=hmac-sha-1-96;spi-c=1111;spi-s=2222;"
        "port-c=5555;port-s=6666\r\n"
        "Security-Server: tls;algs=\"aes-gcm,aes-cm\"\r\n"
    )
    rec = parse_sip_security(sip.encode())
    assert rec is not None
    assert rec["ipsec_present"] and rec["tls_present"]
    ipsec = next(m for m in rec["mechanisms"] if m["mechanism"] == "ipsec-3gpp")
    assert ipsec["algorithm"] == "hmac-sha-1-96"
    assert ipsec["endpoint"] == "5555/6666"
    tls = next(m for m in rec["mechanisms"] if m["mechanism"] == "tls")
    assert tls["extra_algs"] == ["aes-gcm", "aes-cm"]
    assert rec["algorithm"] == "hmac-sha-1-96"


def test_sip_without_security_headers_is_none():
    assert parse_sip_security(b"INVITE sip:x SIP/2.0\r\n\r\n") is None
