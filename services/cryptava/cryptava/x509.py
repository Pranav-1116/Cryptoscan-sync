"""A small, strict X.509 reader — public facts only, standard library only.

Cryptava must run on hardened bank servers where installing a crypto library just for
the agent is a change request of its own. Reading a certificate's *public* facts needs
no cryptography: it is DER parsing. This module extracts subject, issuer, serial,
validity, public-key algorithm and size, signature algorithm, SANs and the CA flag.
Anything malformed raises :class:`CertificateError`; nothing here touches a private key.
"""

from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone
from typing import Any

PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----\s+(.+?)\s+-----END CERTIFICATE-----", re.S)

OIDS = {
    # public-key algorithms
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.10": "RSA-PSS",
    "1.2.840.10045.2.1": "EC",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.3.101.110": "X25519",
    "1.2.840.10040.4.1": "DSA",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    # curves
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
    "1.3.132.0.10": "secp256k1",
    "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
    "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
    # signature algorithms
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "2.16.840.1.101.3.4.3.2": "dsa-with-sha256",
    # name attributes
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O",
    "2.5.4.11": "OU", "1.2.840.113549.1.9.1": "emailAddress",
}
CURVE_BITS = {"P-256": 256, "P-384": 384, "P-521": 521, "secp256k1": 256,
              "brainpoolP256r1": 256, "brainpoolP384r1": 384}
FIXED_BITS = {"Ed25519": 256, "Ed448": 456, "X25519": 256}


class CertificateError(ValueError):
    pass


def _tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    """``(tag, content_start, content_end, next_offset)`` for the TLV at ``offset``."""
    if offset + 2 > len(data):
        raise CertificateError("truncated DER")
    tag = data[offset]
    length = data[offset + 1]
    cursor = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or cursor + count > len(data):
            raise CertificateError("unsupported DER length")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        cursor += count
    end = cursor + length
    if end > len(data):
        raise CertificateError("DER length beyond buffer")
    return tag, cursor, end, end


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    cursor = start
    while cursor < end:
        tag, cstart, cend, cursor = _tlv(data, cursor)
        out.append((tag, cstart, cend))
    return out


def _oid(raw: bytes) -> str:
    if not raw:
        raise CertificateError("empty OID")
    first = raw[0]
    parts = [str(first // 40 if first < 80 else 2), str(first % 40 if first < 80 else first - 80)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _text(tag: int, raw: bytes) -> str:
    if tag == 0x1E:  # BMPString
        return raw.decode("utf-16-be", "replace")
    return raw.decode("utf-8", "replace")


def _name(data: bytes, start: int, end: int) -> dict[str, str]:
    out: dict[str, str] = {}
    for _set_tag, sstart, send in _children(data, start, end):
        for _seq_tag, qstart, qend in _children(data, sstart, send):
            parts = _children(data, qstart, qend)
            if len(parts) < 2:
                continue
            oid = _oid(data[parts[0][1]:parts[0][2]])
            key = OIDS.get(oid, oid)
            value = _text(parts[1][0], data[parts[1][1]:parts[1][2]])
            out[key] = f"{out[key]}, {value}" if key in out else value
    return out


def _dn(name: dict[str, str]) -> str:
    order = ["CN", "OU", "O", "L", "ST", "C", "emailAddress"]
    keys = [k for k in order if k in name] + sorted(k for k in name if k not in order)
    return ", ".join(f"{k}={name[k]}" for k in keys)


def _time(tag: int, raw: bytes) -> str:
    text = raw.decode("ascii", "replace").rstrip("Z")
    try:
        if tag == 0x17:  # UTCTime YYMMDDHHMM[SS]
            year = int(text[:2])
            year += 2000 if year < 50 else 1900
            stamp = datetime(year, int(text[2:4]), int(text[4:6]), int(text[6:8]), int(text[8:10]),
                             int(text[10:12] or 0), tzinfo=timezone.utc)
        else:  # GeneralizedTime YYYYMMDDHHMM[SS]
            stamp = datetime(int(text[:4]), int(text[4:6]), int(text[6:8]), int(text[8:10]),
                             int(text[10:12]), int(text[12:14] or 0), tzinfo=timezone.utc)
    except (ValueError, IndexError) as exc:
        raise CertificateError(f"bad time {text!r}") from exc
    return stamp.isoformat()


def _algorithm(data: bytes, start: int, end: int) -> tuple[str, str | None]:
    parts = _children(data, start, end)
    if not parts or parts[0][0] != 0x06:
        raise CertificateError("AlgorithmIdentifier without OID")
    oid = _oid(data[parts[0][1]:parts[0][2]])
    param = None
    if len(parts) > 1 and parts[1][0] == 0x06:
        param = _oid(data[parts[1][1]:parts[1][2]])
    return oid, param


def parse_der(der: bytes) -> dict[str, Any]:
    """Public facts of one DER certificate."""
    tag, start, end, _ = _tlv(der, 0)
    if tag != 0x30:
        raise CertificateError("not a certificate SEQUENCE")
    top = _children(der, start, end)
    if len(top) < 3:
        raise CertificateError("certificate needs tbs, algorithm, signature")
    tbs = _children(der, top[0][1], top[0][2])
    index = 0
    version = 1
    if tbs and tbs[0][0] == 0xA0:
        inner = _children(der, tbs[0][1], tbs[0][2])
        if inner:
            version = int.from_bytes(der[inner[0][1]:inner[0][2]], "big") + 1
        index = 1
    try:
        serial_t, issuer_t, validity_t, subject_t, spki_t = (
            tbs[index], tbs[index + 2], tbs[index + 3], tbs[index + 4], tbs[index + 5])
    except IndexError as exc:
        raise CertificateError("tbsCertificate is missing fields") from exc
    serial = der[serial_t[1]:serial_t[2]].hex().lstrip("0") or "0"
    issuer = _name(der, issuer_t[1], issuer_t[2])
    subject = _name(der, subject_t[1], subject_t[2])
    validity = _children(der, validity_t[1], validity_t[2])
    not_before = _time(validity[0][0], der[validity[0][1]:validity[0][2]])
    not_after = _time(validity[1][0], der[validity[1][1]:validity[1][2]])

    spki = _children(der, spki_t[1], spki_t[2])
    key_oid, key_param = _algorithm(der, spki[0][1], spki[0][2])
    key_algorithm = OIDS.get(key_oid, key_oid)
    curve = OIDS.get(key_param) if key_param else None
    key_bits: int | None = FIXED_BITS.get(key_algorithm)
    if key_algorithm in {"RSA", "RSA-PSS"}:
        bits = der[spki[1][1] + 1:spki[1][2]]  # skip the unused-bits byte
        _t, rstart, rend, _ = _tlv(bits, 0)
        numbers = _children(bits, rstart, rend)
        if numbers:
            modulus = int.from_bytes(bits[numbers[0][1]:numbers[0][2]], "big")
            key_bits = modulus.bit_length()
    elif key_algorithm == "EC" and curve:
        key_bits = CURVE_BITS.get(curve)
    elif key_algorithm == "DSA":
        key_bits = None

    sig_oid, _ = _algorithm(der, top[1][1], top[1][2])
    signature_algorithm = OIDS.get(sig_oid, sig_oid)

    san: list[str] = []
    is_ca = False
    for item in tbs[index + 6:]:
        if item[0] != 0xA3:
            continue
        for _seq_tag, estart, eend in _children(der, item[1], item[2]):
            for _ext_tag, xstart, xend in _children(der, estart, eend):
                fields = _children(der, xstart, xend)
                if not fields:
                    continue
                ext_oid = _oid(der[fields[0][1]:fields[0][2]])
                value = fields[-1]
                if value[0] != 0x04:
                    continue
                body = der[value[1]:value[2]]
                try:
                    if ext_oid == "2.5.29.17":
                        _t, nstart, nend, _ = _tlv(body, 0)
                        for name_tag, vstart, vend in _children(body, nstart, nend):
                            if name_tag == 0x82:
                                san.append(body[vstart:vend].decode("ascii", "replace"))
                            elif name_tag == 0x87 and vend - vstart == 4:
                                san.append(".".join(str(b) for b in body[vstart:vend]))
                    elif ext_oid == "2.5.29.19":
                        _t, bstart, bend, _ = _tlv(body, 0)
                        for flag_tag, vstart, vend in _children(body, bstart, bend):
                            if flag_tag == 0x01:
                                is_ca = body[vstart:vend] != b"\x00"
                except CertificateError:
                    continue

    algorithm_label = {"EC": "ECDSA"}.get(key_algorithm, key_algorithm)
    return {
        "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
        "serial_number": serial,
        "version": version,
        "subject": _dn(subject),
        "subject_cn": subject.get("CN"),
        "subject_o": subject.get("O"),
        "issuer": _dn(issuer),
        "issuer_cn": issuer.get("CN"),
        "issuer_o": issuer.get("O"),
        "self_signed": _dn(subject) == _dn(issuer),
        "not_before": not_before,
        "not_after": not_after,
        "public_key_algorithm": algorithm_label,
        "public_key_bits": key_bits,
        "curve": curve,
        "signature_algorithm": signature_algorithm,
        "san": sorted(set(san))[:50],
        "is_ca": is_ca,
    }


def certificates_in(data: bytes) -> list[bytes]:
    """DER certificates in a PEM bundle or a single DER file. Never returns key blocks."""
    if b"-----BEGIN" in data:
        out = []
        for match in PEM_CERT.finditer(data):
            try:
                out.append(base64.b64decode(b"".join(match.group(1).split()), validate=False))
            except ValueError:
                continue
        return out
    if data[:1] == b"\x30":
        return [data]
    return []
