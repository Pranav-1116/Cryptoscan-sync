"""TLS record/handshake parser fixtures and tests.

Fixture records are hand-built per RFC 5246 — no network or real certs
needed. Structure helpers build valid ClientHello/ServerHello/Certificate
wire bytes the way a tap would see them.
"""

from __future__ import annotations

import struct

from runtime.agent.tls_record_parser import (
    HT_CERTIFICATE,
    HT_CLIENT_HELLO,
    HT_SERVER_HELLO,
    RecordBuffer,
    cipher_name,
    handshake_messages,
    parse_certificate,
    parse_client_hello,
    parse_server_hello,
)


# --------------------------------------------------------------------------- #
# fixture builders
# --------------------------------------------------------------------------- #


def hs_message(htype: int, body: bytes) -> bytes:
    return bytes([htype]) + len(body).to_bytes(3, "big") + body


def record(ctype: int, version: int, payload: bytes) -> bytes:
    return struct.pack(">BHH", ctype, version, len(payload)) + payload


def build_client_hello(
    *,
    version: int = 0x0303,
    suites: list[int] | None = None,
    sni: bytes = b"payments.internal",
    alpn: list[bytes] | None = None,
    supported_versions: list[int] | None = None,
) -> bytes:
    suites = suites if suites is not None else [0x1301, 0xC02F, 0x002F]
    body = bytearray()
    body += struct.pack(">H", version)
    body += b"\x00" * 32  # random
    body += b"\x00"  # empty session id
    body += struct.pack(">H", len(suites) * 2) + b"".join(struct.pack(">H", s) for s in suites)
    body += b"\x01\x00"  # null compression
    extensions = bytearray()
    if sni:
        name_block = bytes([0x00]) + struct.pack(">H", len(sni)) + sni
        ext_body = struct.pack(">H", len(name_block)) + name_block
        extensions += struct.pack(">HH", 0x00, len(ext_body)) + ext_body
    if supported_versions:
        sv = bytes([len(supported_versions) * 2]) + b"".join(struct.pack(">H", v) for v in supported_versions)
        extensions += struct.pack(">HH", 0x002B, len(sv)) + sv
    if alpn:
        proto_list = b"".join(bytes([len(p)]) + p for p in alpn)
        ext_body = struct.pack(">H", len(proto_list)) + proto_list
        extensions += struct.pack(">HH", 0x0010, len(ext_body)) + ext_body
    body += struct.pack(">H", len(extensions)) + extensions
    return record(22, 0x0301, hs_message(HT_CLIENT_HELLO, bytes(body)))


def build_server_hello(*, suite: int = 0xC02F, version: int = 0x0303, negotiated_version: int | None = 0x0304) -> bytes:
    body = bytearray()
    body += struct.pack(">H", version)
    body += b"\x11" * 32  # random
    body += b"\x20" + b"\x33" * 32  # session id
    body += struct.pack(">H", suite)
    body += b"\x00"  # compression
    extensions = bytearray()
    if negotiated_version:
        extensions += struct.pack(">HH", 0x002B, 2) + struct.pack(">H", negotiated_version)
    body += struct.pack(">H", len(extensions)) + extensions
    return record(22, 0x0303, hs_message(HT_SERVER_HELLO, bytes(body)))


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value


def build_certificate(cn: bytes = b"payments.internal") -> bytes:
    """A syntactically-scannable pseudo-DER cert containing a commonName."""
    cn_oid = b"\x06\x03\x55\x04\x03"
    rdn = cn_oid + _tlv(0x0C, cn)
    name = _tlv(0x30, rdn)
    tbs = name + b"\x17\x0d" + b"250101000000Z"  # UTCTime-ish
    der = _tlv(0x30, tbs + name)
    entry = len(der).to_bytes(3, "big") + der
    chain = len(entry).to_bytes(3, "big") + entry
    body = len(chain).to_bytes(3, "big") + chain
    return record(22, 0x0303, hs_message(HT_CERTIFICATE, body))


# --------------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------------- #


def test_record_buffer_reassembles_split_records():
    payload = build_client_hello(sni=b"api.local")
    buf = RecordBuffer()
    assert buf.feed(payload[:7]) == []
    records = buf.feed(payload[7:])
    assert len(records) == 1
    ctype, body = records[0]
    assert ctype == 22
    assert handshake_messages(body)[0][0] == HT_CLIENT_HELLO


def test_record_buffer_rejects_garbage_cleanly():
    buf = RecordBuffer()
    assert buf.feed(b"GET /health HTTP/1.1\r\n\r\nnot tls at all") == []


def test_parse_client_hello_full_contract():
    hello_bytes = build_client_hello(
        suites=[0x1301, 0xC02F, 0x000A, 0x0005],
        sni=b"payments.internal",
        alpn=[b"h2", b"http/1.1"],
        supported_versions=[0x0304, 0x0303],
    )
    _ctype, payload = RecordBuffer().feed(hello_bytes)[0]
    hello = parse_client_hello(handshake_messages(payload)[0][1])
    assert hello["client_version"] == "TLSv1.2"
    assert hello["sni"] == "payments.internal"
    assert hello["cipher_suites"] == [
        "TLS_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_RC4_128_SHA",
    ]
    assert hello["supported_versions"] == ["TLSv1.3", "TLSv1.2"]
    assert hello["alpn"] == ["h2", "http/1.1"]


def test_parse_server_hello_negotiated_suite_and_tls13():
    _c, payload = RecordBuffer().feed(build_server_hello(suite=0x1302))[0]
    hello = parse_server_hello(handshake_messages(payload)[0][1])
    assert hello["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    assert hello["negotiated_version"] == "TLSv1.3"  # via supported_versions ext


def test_parse_certificate_chain_fingerprint_and_cn():
    _c, payload = RecordBuffer().feed(build_certificate())[0]
    cert = parse_certificate(handshake_messages(payload)[0][1])
    chain = cert["chain"]
    assert len(chain) == 1
    assert len(chain[0]["sha256_fingerprint"]) == 64
    assert "payments.internal" in chain[0]["common_names"]


def test_unknown_cipher_id_degrades_to_hex():
    assert cipher_name(0xFFFF) == "0xFFFF"
