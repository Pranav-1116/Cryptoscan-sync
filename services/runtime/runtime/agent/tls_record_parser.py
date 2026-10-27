"""Minimal TLS record + handshake parser (read-only, no decryption).

Parses just enough of RFC 5246 / RFC 8446 handshake messages to inventory
what production traffic actually negotiates:

- ClientHello: client version, offered cipher suites, SNI, ALPN,
  supported_versions (TLS 1.3), signature algorithms, elliptic curves
- ServerHello: negotiated version + cipher suite + ALPN
- Certificate: DER chain -> SHA-256 fingerprints + CN heuristics

Everything runs on bytes already observed on the wire; the tap never
terminates TLS, so no key material is ever touched.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any

# content types
CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

# handshake types
HT_CLIENT_HELLO = 1
HT_SERVER_HELLO = 2
HT_CERTIFICATE = 11

RECORD_HEADER = 5

# cipher suite IDs (IANA) the platform commonly sees; unknown IDs degrade
# to "0x%04X" instead of silence.
CIPHER_SUITE_NAMES: dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC02A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",  # alias guard
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0x008C: "TLS_PSK_WITH_AES_128_CBC_SHA",
    0x00A8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
    0xC0AE: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
}

TLS_VERSION_NAMES: dict[int, str] = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}


def cipher_name(suite_id: int) -> str:
    return CIPHER_SUITE_NAMES.get(suite_id, f"0x{suite_id:04X}")


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0]


def _vector8(data: bytes, offset: int) -> tuple[bytes, int]:
    """length-prefixed (1 byte) vector -> (payload, next_offset)."""
    length = data[offset]
    return data[offset + 1 : offset + 1 + length], offset + 1 + length


def _vector16(data: bytes, offset: int) -> tuple[bytes, int]:
    """length-prefixed (2 byte) vector -> (payload, next_offset)."""
    length = _u16(data, offset)
    return data[offset + 2 : offset + 2 + length], offset + 2 + length


def parse_record_header(header: bytes) -> tuple[int, int, int]:
    """(content_type, legacy_version, length) from a 5-byte record header."""
    if len(header) < RECORD_HEADER:
        raise ValueError("short record header")
    return header[0], _u16(header, 1), _u16(header, 3)


class RecordBuffer:
    """Accumulate a byte stream into complete TLS records.

    ``track_raw`` additionally retains every byte seen (the tap replays the
    exact original bytes upstream after peeking at the ClientHello).
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self.raw_consumed = bytearray()

    def track_raw(self, data: bytes) -> None:
        self.raw_consumed.extend(data)

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        """Feed raw bytes; return any complete (content_type, payload) records."""
        self._buf.extend(data)
        emitted: list[tuple[int, bytes]] = []
        while len(self._buf) >= RECORD_HEADER:
            content_type, _version, length = parse_record_header(bytes(self._buf[:RECORD_HEADER]))
            if length == 0 or length > 1 << 17:
                # not TLS (or corrupt) — drop the buffer, stop parsing
                self._buf.clear()
                break
            if len(self._buf) < RECORD_HEADER + length:
                break
            payload = bytes(self._buf[RECORD_HEADER : RECORD_HEADER + length])
            del self._buf[: RECORD_HEADER + length]
            emitted.append((content_type, payload))
        return emitted


def handshake_messages(payload: bytes) -> list[tuple[int, bytes]]:
    """Split a handshake record payload into (handshake_type, body) messages."""
    messages: list[tuple[int, bytes]] = []
    offset = 0
    while offset + 4 <= len(payload):
        htype = payload[offset]
        length = int.from_bytes(payload[offset + 1 : offset + 4], "big")
        body = payload[offset + 4 : offset + 4 + length]
        if len(body) < length:
            break
        messages.append((htype, body))
        offset += 4 + length
    return messages


def parse_client_hello(body: bytes) -> dict[str, Any]:
    """ClientHello body (after the 4-byte handshake header)."""
    if len(body) < 34:
        return {"error": "short ClientHello"}
    client_version = _u16(body, 0)
    offset = 34  # version + random(32) ... 2+32 = 34
    session_id, offset = _vector8(body, offset)
    cipher_bytes, offset = _vector16(body, offset)
    suites = [_u16(cipher_bytes, i) for i in range(0, len(cipher_bytes) - 1, 2)] if len(cipher_bytes) % 2 == 0 else []
    compression, offset = _vector8(body, offset)
    hello: dict[str, Any] = {
        "client_version": TLS_VERSION_NAMES.get(client_version, f"0x{client_version:04X}"),
        "session_id_len": len(session_id),
        "cipher_suites": [cipher_name(s) for s in suites],
        "cipher_suite_ids": suites,
        "compression": list(compression),
    }
    if offset + 2 <= len(body):
        ext_bytes, offset = _vector16(body, offset)
        hello.update(_parse_extensions(ext_bytes))
    return hello


def parse_server_hello(body: bytes) -> dict[str, Any]:
    """ServerHello body (after the 4-byte handshake header)."""
    if len(body) < 35:
        return {"error": "short ServerHello"}
    server_version = _u16(body, 0)
    offset = 34
    session_id, offset = _vector8(body, offset)
    suite_id = _u16(body, offset)
    offset += 2
    compression = body[offset]
    offset += 1
    hello: dict[str, Any] = {
        "server_version": TLS_VERSION_NAMES.get(server_version, f"0x{server_version:04X}"),
        "session_id_len": len(session_id),
        "cipher_suite": cipher_name(suite_id),
        "cipher_suite_id": suite_id,
        "compression": compression,
    }
    if offset + 2 <= len(body):
        ext_bytes, offset = _vector16(body, offset)
        hello.update(_parse_extensions(ext_bytes))
    supported = hello.get("supported_versions")
    if supported:
        hello["negotiated_version"] = supported[0]
    else:
        hello["negotiated_version"] = hello["server_version"]
    return hello


# extension type constants we care about
EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_SUPPORTED_VERSIONS = 43

EXTENSION_NAMES = {
    EXT_SERVER_NAME: "server_name",
    EXT_SUPPORTED_GROUPS: "supported_groups",
    EXT_SIGNATURE_ALGORITHMS: "signature_algorithms",
    EXT_ALPN: "alpn",
    EXT_SUPPORTED_VERSIONS: "supported_versions",
}

_SIG_ALGO_NAMES: dict[int, str] = {
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0201: "rsa_pkcs1_sha1",
    0x0203: "ecdsa_sha1",
}

_GROUP_NAMES: dict[int, str] = {
    0x001D: "x25519",
    0x001E: "x448",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x00FF: "ffdhe8192",
}


def _parse_extensions(ext_bytes: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    offset = 0
    while offset + 4 <= len(ext_bytes):
        ext_type = _u16(ext_bytes, offset)
        length = _u16(ext_bytes, offset + 2)
        data = ext_bytes[offset + 4 : offset + 4 + length]
        offset += 4 + length
        name = EXTENSION_NAMES.get(ext_type)
        if name == "server_name" and data:
            try:
                list_bytes, _ = _vector16(data, 0)
                # first entry: type byte + name
                if list_bytes:
                    host, _ = _vector16(list_bytes, 1)
                    try:
                        out["sni"] = host.decode("idna")
                    except UnicodeError:
                        out["sni"] = host.decode("utf-8", errors="replace")
            except Exception:
                pass
        elif name == "alpn" and data:
            try:
                proto, _ = _vector16(data, 0)
                # sequence of (1-byte len + bytes)
                protocols = []
                i = 0
                while i < len(proto):
                    plen = proto[i]
                    protocols.append(proto[i + 1 : i + 1 + plen].decode("ascii", errors="replace"))
                    i += 1 + plen
                out["alpn"] = protocols
            except Exception:
                pass
        elif name == "supported_versions":
            if ext_type == EXT_SUPPORTED_VERSIONS:
                # client: 1-byte byte-length + version list; server: single version
                if data and data[0] == len(data) - 1 and data[0] % 2 == 0:
                    versions = [_u16(data, 1 + 2 * i) for i in range(data[0] // 2)]
                    out["supported_versions"] = [TLS_VERSION_NAMES.get(v, f"0x{v:04X}") for v in versions]
                elif len(data) >= 2:
                    out["supported_versions"] = [TLS_VERSION_NAMES.get(_u16(data, 0), "unknown")]
        elif name == "signature_algorithms":
            try:
                sig_bytes, _ = _vector16(data, 0)
                algos = [_u16(sig_bytes, i) for i in range(0, len(sig_bytes) - 1, 2)]
                out["signature_algorithms"] = [_SIG_ALGO_NAMES.get(a, f"0x{a:04X}") for a in algos]
            except Exception:
                pass
        elif name == "supported_groups":
            try:
                group_bytes, _ = _vector16(data, 0)
                groups = [_u16(group_bytes, i) for i in range(0, len(group_bytes) - 1, 2)]
                out["supported_groups"] = [_GROUP_NAMES.get(g, f"0x{g:04X}") for g in groups]
            except Exception:
                pass
    return out


def parse_certificate(body: bytes) -> dict[str, Any]:
    """Certificate handshake body -> chain inventory (fingerprints + CNs)."""
    if len(body) < 3:
        return {"chain": []}
    list_length = int.from_bytes(body[0:3], "big")
    chain_bytes = body[3 : 3 + list_length]
    chain: list[dict[str, Any]] = []
    offset = 0
    while offset + 3 <= len(chain_bytes):
        length = int.from_bytes(chain_bytes[offset : offset + 3], "big")
        der = chain_bytes[offset + 3 : offset + 3 + length]
        offset += 3 + length
        if not der:
            continue
        entry = {
            "length": len(der),
            "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
        }
        entry.update(_der_common_names(der))
        chain.append(entry)
    return {"chain": chain}


_CN_OID = b"\x06\x03\x55\x04\x03"  # 2.5.4.3 commonName


def _der_common_names(der: bytes) -> dict[str, Any]:
    """Heuristic CN extraction from a DER certificate (no ASN.1 parser dep).

    Scans for the commonName OID followed by a PrintableString/UTF8String/
    IA5String/TeletexString value. Good enough for inventory labels; the
    authoritative identity is the SHA-256 fingerprint.
    """
    subject: list[str] = []
    start = 0
    while True:
        idx = der.find(_CN_OID, start)
        if idx < 0:
            break
        start = idx + 5
        cursor = idx + len(_CN_OID)
        if cursor + 2 > len(der):
            continue
        tag = der[cursor]
        # tag values: 0x0C UTF8String, 0x13 PrintableString, 0x16 IA5String, 0x14 TeletexString
        if tag in (0x0C, 0x13, 0x16, 0x14) and cursor + 1 < len(der):
            length = der[cursor + 1]
            if 0 < length <= 128 and cursor + 2 + length <= len(der):
                value = der[cursor + 2 : cursor + 2 + length].decode("utf-8", errors="replace")
                if value.strip():
                    subject.append(value)
    return {"common_names": subject[:4]}
