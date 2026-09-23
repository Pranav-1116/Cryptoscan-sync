"""Embedded key material in compiled binaries — spec §2.3 component 8.

Real binaries carry key material far more often than teams expect: a test
certificate baked into a firmware image, an OpenSSH host key in an initramfs, an
OpenPGP secret key inside a vendor agent, a JKS keystore in a Java installer.
``universal_crypto.hardcoded`` answers a different question — *is an algorithm
hard-coded in source* — so key **material** is read here, from the bytes, with the
same evidence discipline as the rest of the binary scanner.

Detectors, each deterministic and offline:

``pem``            ``-----BEGIN … KEY-----`` armoured blocks: label → kind, plus the
                   legacy ``Proc-Type: 4,ENCRYPTED`` / ``DEK-Info`` header read as
                   "encrypted with <cipher>" — never decrypted.
``der``            ASN.1 read by hand (no third-party parsers): PKCS#1 RSA/DSA, SEC1
                   EC, PKCS#8 (clear and ``EncryptedPrivateKeyInfo``),
                   SubjectPublicKeyInfo, X.509 certificates, PKCS#7/CMS, PKCS#12.
``base64``/``hex`` encoded runs decoded and handed to the same ASN.1 reader, so an
                   encoded key is found wherever it is embedded.
``openssh``/``putty``  OpenSSH private-key container (``openssh-key-v1``) and PuTTY
                   ``User-Key-File`` records: cipher, KDF, key type, comment. The
                   private section is read only when the container says it is in the
                   clear, and then only for its comment.
``ssh-public``     ``ssh-rsa AAAA…``/``ecdsa-sha2-…``/``ssh-ed25519`` host-key lines —
                   firmware shipping fleet-wide host keys is a real defect.
``pgp``            OpenPGP packet headers inside ASCII armour: key version, public-key
                   algorithm, S2K usage, and the armour CRC-24 verified.
``jks``            Java KeyStore / JCEKS entries: aliases, entry types, and whether
                   protected private keys are present.

Two rules are absolute:

1. **Key material is never emitted.** Only a SHA-256 of the material, its kind,
   type, size, curve, offset and container. A test asserts the modulus and prime
   factors of a fixture key appear nowhere in the output.
2. **Nothing is guessed.** A key is reported as a key only when a *named* structure
   parsed. Symmetric key bytes with no encoding wrapper are not claimed at all, and
   "looks familiar" is not evidence: a value is reclassified as a *test vector* only
   when it is a named published vector, carries an explicit test label, or is a
   degenerate placeholder.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any

# --------------------------------------------------------------- limits ---- #
MAX_KEY_WINDOW = 64 * 1024 * 1024      # bytes of the file searched for armour/DER
BLOB_WINDOW = 32 * 1024 * 1024         # encoded-run search window (regex is the cost)
MAX_ASN1_DEPTH = 8                     # nesting we are willing to follow
MAX_ASN1_ELEMENT = 1 << 20             # one ASN.1 element may not exceed 1 MiB
MAX_PEM_BLOCKS = 64                    # armour blocks read per file
MAX_BLOB_ATTEMPTS = 2000               # encoded runs decoded per class per file
MAX_BLOB_CANDIDATES = 48               # encoded runs that turn out to be structures
MAX_BLOB_BYTES = 64 * 1024             # decoded size of a candidate blob
MAX_CERT_SANS = 8                      # subjectAltName entries reported
MAX_PGP_PACKETS = 8
MAX_PGP_BODY = 2048                     # enough to skip an RSA-4096 public key and see the S2K octet
MAX_KEY_OCCURRENCES = 6                # offsets listed per unique material
MAX_ROWS = 64                          # key rows returned per file
MAX_DER_OFFSET_ATTEMPTS = 512          # 0x30 bytes tried when hunting a structure at an offset

# ------------------------------------------------------------------ OIDs --- #
OID_NAMES: dict[str, str] = {
    # public-key and signature algorithms
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10040.4.1": "dsa",
    "1.2.840.10040.4.3": "dsaWithSHA1",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.110": "X25519",
    "1.3.101.111": "X448",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    # post-quantum (NIST CSOR assignments)
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    # named curves
    "1.2.840.10045.3.1.1": "prime192v1",
    "1.2.840.10045.3.1.7": "prime256v1",
    "1.3.132.0.10": "secp256k1",
    "1.3.132.0.33": "secp224r1",
    "1.3.132.0.34": "secp384r1",
    "1.3.132.0.35": "secp521r1",
    "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
    "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
    "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
    # symmetric and derivation algorithms seen inside encrypted key containers
    "1.2.840.113549.1.5.3": "pbeWithMD5AndDES-CBC",
    "1.2.840.113549.1.5.12": "PBKDF2",
    "1.2.840.113549.1.5.13": "PBES2",
    "1.2.840.113549.3.7": "des-ede3-cbc",
    "1.2.840.113549.1.12.1.1": "pbeWithSHAAnd128BitRC4",
    "1.2.840.113549.1.12.1.2": "pbeWithSHAAnd40BitRC4",
    "1.2.840.113549.1.12.1.3": "pbeWithSHAAnd3-KeyTripleDES-CBC",
    "1.2.840.113549.1.12.1.4": "pbeWithSHAAnd2-KeyTripleDES-CBC",
    "1.2.840.113549.1.12.1.5": "pbeWithSHAAnd128BitRC2-CBC",
    "1.2.840.113549.1.12.1.6": "pbeWithSHAAnd40BitRC2-CBC",
    "2.16.840.1.101.3.4.1.2": "aes128-CBC",
    "2.16.840.1.101.3.4.1.22": "aes192-CBC",
    "2.16.840.1.101.3.4.1.42": "aes256-CBC",
    "2.16.840.1.101.3.4.1.46": "aes256-GCM",
    # content and container types
    "1.2.840.113549.1.7.1": "pkcs7-data",
    "1.2.840.113549.1.7.2": "pkcs7-signedData",
    "1.2.840.113549.1.7.6": "pkcs7-encryptedData",
    "1.2.840.113549.1.12.10.1.1": "pkcs12-keyBag",
    "1.2.840.113549.1.12.10.1.2": "pkcs12-shroudedKeyBag",
    "1.2.840.113549.1.12.10.1.3": "pkcs12-certBag",
    "1.2.840.113549.1.12.10.1.6": "pkcs12-safeContents",
    "1.2.840.113549.1.9.20": "friendlyName",
    "1.2.840.113549.1.9.21": "localKeyID",
    # attribute types (RDN) and certificate extensions
    "2.5.4.3": "commonName",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "1.2.840.113549.1.9.1": "emailAddress",
    "2.5.29.14": "subjectKeyIdentifier",
    "2.5.29.15": "keyUsage",
    "2.5.29.17": "subjectAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.37": "extKeyUsage",
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "ocspSigning",
    "1.3.14.3.2.26": "sha1",
    "1.2.840.113549.2.5": "md5",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}

#: named curve → field size in bits
CURVE_BITS = {
    "prime192v1": 192, "secp224r1": 224, "prime256v1": 256, "secp256k1": 256,
    "secp384r1": 384, "secp521r1": 521, "brainpoolP256r1": 256,
    "brainpoolP384r1": 384, "brainpoolP512r1": 512,
}

#: fixed-size algorithms → bits
ALGORITHM_BITS = {"Ed25519": 256, "Ed448": 456, "X25519": 256, "X448": 448}

#: algorithm name → key type reported to the caller
ALGORITHM_KEY_TYPE = {
    "rsaEncryption": "rsa", "RSASSA-PSS": "rsa", "md5WithRSAEncryption": "rsa",
    "sha1WithRSAEncryption": "rsa", "sha256WithRSAEncryption": "rsa",
    "sha384WithRSAEncryption": "rsa", "sha512WithRSAEncryption": "rsa",
    "dsa": "dsa", "dsaWithSHA1": "dsa", "id-ecPublicKey": "ec",
    "ecdsa-with-SHA1": "ec", "ecdsa-with-SHA256": "ec", "ecdsa-with-SHA384": "ec",
    "ecdsa-with-SHA512": "ec", "Ed25519": "ed25519", "Ed448": "ed448",
    "X25519": "x25519", "X448": "x448",
    "ML-KEM-512": "ml-kem", "ML-KEM-768": "ml-kem", "ML-KEM-1024": "ml-kem",
    "ML-DSA-44": "ml-dsa", "ML-DSA-65": "ml-dsa", "ML-DSA-87": "ml-dsa",
}

#: PEM armour label → (kind, key type)
PEM_LABELS: dict[str, tuple[str, str | None]] = {
    "PRIVATE KEY": ("private-key", None),
    "ENCRYPTED PRIVATE KEY": ("private-key", None),
    "RSA PRIVATE KEY": ("private-key", "rsa"),
    "DSA PRIVATE KEY": ("private-key", "dsa"),
    "EC PRIVATE KEY": ("private-key", "ec"),
    "OPENSSH PRIVATE KEY": ("private-key", "openssh"),
    "SSH2 PRIVATE KEY": ("private-key", "openssh"),
    "PUBLIC KEY": ("public-key", None),
    "RSA PUBLIC KEY": ("public-key", "rsa"),
    "DSA PUBLIC KEY": ("public-key", "dsa"),
    "EC PUBLIC KEY": ("public-key", "ec"),
    "SSH2 PUBLIC KEY": ("public-key", "openssh"),
    "CERTIFICATE": ("certificate", None),
    "TRUSTED CERTIFICATE": ("certificate", None),
    "X509 CRL": ("crl", None),
    "CERTIFICATE REQUEST": ("csr", None),
    "NEW CERTIFICATE REQUEST": ("csr", None),
    "PKCS7": ("pkcs7", None),
    "DH PARAMETERS": ("parameters", "dh"),
    "DSA PARAMETERS": ("parameters", "dsa"),
    "PGP PRIVATE KEY BLOCK": ("private-key", "openpgp"),
    "PGP PUBLIC KEY BLOCK": ("public-key", "openpgp"),
    "PGP MESSAGE": ("pgp-message", "openpgp"),
    "PGP SIGNATURE": ("pgp-signature", "openpgp"),
}

_PEM_BEGIN_RE = re.compile(rb"-----BEGIN ([A-Z0-9][A-Z0-9 ]{0,58})-----")
#: at least 64 base64 characters, with the optional padded final group kept —
#: cutting it off would hand a truncated DER to the classifier
_BASE64_BLOB_RE = re.compile(rb"(?:[A-Za-z0-9+/]{4}){16,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_HEX_BLOB_RE = re.compile(rb"(?<![0-9a-fA-Fx])(?:[0-9a-fA-F]{2}){32,}(?![0-9a-fA-F])")
_SSH_KEY_LINE_RE = re.compile(
    rb"\b(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|"
    rb"rsa-sha2-256|rsa-sha2-512|sk-ssh-ed25519@openssh\.com|"
    rb"sk-ecdsa-sha2-nistp256@openssh\.com)\s+([A-Za-z0-9+/=]{60,})")
_PUTTY_RE = re.compile(rb"PuTTY-User-Key-File-(\d):\s*([A-Za-z0-9@.-]+)")
_OPENSSH_MAGIC = b"openssh-key-v1\x00"
_JKS_MAGICS = {b"\xfe\xed\xfe\xed": "jks", b"\xce\xce\xce\xce": "jceks"}
_KEY_USAGE_BITS = ("digitalSignature", "contentCommitment", "keyEncipherment",
                   "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
                   "encipherOnly", "decipherOnly")

#: OpenPGP public-key algorithm identifiers (RFC 4880 §9.1, RFC 9580 §9.1)
PGP_ALGORITHMS = {
    1: "RSA", 2: "RSA-encrypt-only", 3: "RSA-sign-only", 16: "ElGamal",
    17: "DSA", 18: "ECDH", 19: "ECDSA", 20: "ElGamal-sign-only",
    21: "Diffie-Hellman (X9.42)", 22: "EdDSA", 23: "AEDH", 24: "AEDSA",
    25: "X25519", 26: "X448", 27: "Ed25519", 28: "Ed448",
}

#: named published test vectors — the only byte strings reclassified as not-a-secret
KNOWN_TEST_VECTORS: tuple[tuple[str, str], ...] = (
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "RFC 8032 Ed25519 test 1 seed"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "RFC 8032 Ed25519 test 2 seed"),
)

#: labels that say out loud the material is not a real secret
_PLACEHOLDER_RE = re.compile(
    rb"do[-_ ]?not[-_ ]?use|not[-_ ]?a[-_ ]?real|example[-_ ]?(?:key|only)|"
    rb"test[-_ ]?(?:key|only|cert)|placeholder|dummy[-_ ]?key|changeme|"
    rb"sample[-_ ]?key|fake[-_ ]?key", re.IGNORECASE)


#: a long run of one byte never occurs in real key material
_REPEAT_RE = re.compile(rb"(.)\1{31,}", re.DOTALL)


#: bytes allowed after a DER structure before it stops looking like the content
DER_TRAILING_SLACK = 16


def _der_offsets(window: bytes) -> list[int]:
    """Offsets worth trying when hunting for a DER structure inside a blob.

    ``0x30`` is far too common to trust on its own, so callers must confirm the
    candidate: the structure has to reach the end of the window *and* describe
    something concrete. Bounded, so this stays cheap on a large file.
    """
    offsets = [0] if window[:1] == b"\x30" else []
    cursor = window.find(b"\x30", 1)
    while cursor >= 0 and len(offsets) < MAX_DER_OFFSET_ATTEMPTS:
        offsets.append(cursor)
        cursor = window.find(b"\x30", cursor + 1)
    return offsets


def _concrete(classified: dict[str, Any]) -> bool:
    """Does this classification actually say something about key material?"""
    if classified.get("kind") == "keystore":
        detail = classified.get("detail") or {}
        return bool(detail.get("entries") or detail.get("content_types"))
    if classified.get("kind") == "certificate":
        detail = classified.get("detail") or {}
        return bool(detail.get("subject") or detail.get("not_after") or detail.get("serial"))
    return bool(classified.get("key_bits") or classified.get("curve")
                or (classified.get("detail") or {}).get("key_type"))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- ASN.1 ---- #
class _Asn1Error(ValueError):
    """The bytes are not a structure we can read — never a reason to guess."""


def _tlv(data: bytes, offset: int, end: int, *, depth: int = 0) -> tuple[int, int, int]:
    """Return ``(tag, content_start, content_end)`` for one definite-length TLV."""
    if depth > MAX_ASN1_DEPTH:
        raise _Asn1Error("nesting too deep")
    if offset + 2 > end:
        raise _Asn1Error("truncated header")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise _Asn1Error("multi-byte tag numbers are not used here")
    length_byte = data[offset + 1]
    cursor = offset + 2
    if length_byte < 0x80:
        length = length_byte
    else:
        count = length_byte & 0x7F
        if count == 0:
            raise _Asn1Error("indefinite lengths are not DER")
        if count > 4 or cursor + count > end:
            raise _Asn1Error("bad length field")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        cursor += count
    if length > MAX_ASN1_ELEMENT:
        raise _Asn1Error("element too large")
    stop = cursor + length
    if stop > end or stop > len(data):
        raise _Asn1Error("content runs past the end")
    return tag, cursor, stop


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out: list[tuple[int, int, int]] = []
    cursor = start
    while cursor < end:
        tag, cstart, cend = _tlv(data, cursor, end)
        out.append((tag, cstart, cend))
        cursor = cend
    return out


def _integer(data: bytes, cstart: int, cend: int) -> int:
    if cend <= cstart:
        raise _Asn1Error("empty INTEGER")
    return int.from_bytes(data[cstart:cend], "big", signed=bool(data[cstart] & 0x80))


def _decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    if first < 40:
        parts = [0, first]
    elif first < 80:
        parts = [1, first - 40]
    else:
        parts = [2, first - 80]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    if value:
        parts.append(value)                 # truncated continuation: report what parsed
    return ".".join(str(part) for part in parts)


def _oid_name(oid: str) -> str:
    return OID_NAMES.get(oid, oid or "unknown")


def _read_algorithm(data: bytes, cstart: int, cend: int) -> dict[str, Any]:
    """Read an ``AlgorithmIdentifier``: OID, resolved name, and parameter name/span."""
    kids = _children(data, cstart, cend)
    if not kids or kids[0][0] != 0x06:
        raise _Asn1Error("AlgorithmIdentifier does not start with an OID")
    oid = _decode_oid(data[kids[0][1]:kids[0][2]])
    out: dict[str, Any] = {"oid": oid, "algorithm": _oid_name(oid), "parameters": None,
                           "params_span": None}
    if len(kids) > 1:
        ptag, pstart, pend = kids[1]
        if ptag == 0x06:
            out["parameters"] = _oid_name(_decode_oid(data[pstart:pend]))
        elif ptag == 0x05:
            out["parameters"] = "NULL"
        elif ptag == 0x30:
            out["parameters"] = "SEQUENCE"
            out["params_span"] = (pstart, pend)
    return out


def _bit_string_bits(data: bytes, cstart: int, cend: int) -> int:
    if cend <= cstart:
        return 0
    return max(0, (cend - cstart - 1) * 8 - data[cstart])


def _read_spki(data: bytes, cstart: int, cend: int) -> dict[str, Any]:
    """``SubjectPublicKeyInfo`` → algorithm, key type, size, curve (never the key)."""
    kids = _children(data, cstart, cend)
    if len(kids) != 2 or kids[1][0] != 0x03:
        raise _Asn1Error("not a SubjectPublicKeyInfo")
    algorithm = _read_algorithm(data, kids[0][1], kids[0][2])
    out: dict[str, Any] = {"algorithm": algorithm["algorithm"], "oid": algorithm["oid"],
                           "key_type": ALGORITHM_KEY_TYPE.get(algorithm["algorithm"]),
                           "key_bits": None, "curve": None}
    params = algorithm["parameters"]
    if params and params in CURVE_BITS:
        out["curve"] = params
        out["key_bits"] = CURVE_BITS[params]
    elif algorithm["algorithm"] in ALGORITHM_BITS:
        out["key_bits"] = ALGORITHM_BITS[algorithm["algorithm"]]
    elif algorithm["params_span"]:          # DSA: parameters are SEQUENCE {p, q, g}
        try:
            for tag, s, e in _children(data, *algorithm["params_span"]):
                if tag == 0x02:
                    out["key_bits"] = _integer(data, s, e).bit_length()
                    break
        except _Asn1Error:
            pass
    payload = data[kids[1][1] + 1:kids[1][2]]
    try:
        inner = _children(payload, 0, len(payload))
    except _Asn1Error:
        inner = []
    if len(inner) == 1 and inner[0][0] == 0x30:      # RSAPublicKey ::= SEQUENCE {..}
        try:
            inner = _children(payload, inner[0][1], inner[0][2])
        except _Asn1Error:
            inner = []
    if algorithm["algorithm"] in ("rsaEncryption", "RSASSA-PSS") and len(inner) >= 2:
        out["key_bits"] = _integer(payload, inner[0][1], inner[0][2]).bit_length()
        out["public_exponent_bits"] = _integer(payload, inner[1][1], inner[1][2]).bit_length()
    return out


def _time_string(raw: bytes, tag: int) -> str | None:
    """UTCTime / GeneralizedTime → ``YYYY-MM-DDTHH:MM:SSZ`` (no locale, no tz math)."""
    digits = "".join(ch for ch in raw.decode("ascii", "ignore") if ch.isdigit())
    if tag == 0x17 and len(digits) >= 10:                     # UTCTime: YYMMDDHHMM(SS)
        year = int(digits[0:2])
        year += 2000 if year < 50 else 1900
        rest = digits[2:14].ljust(12, "0")
    elif len(digits) >= 12:                                   # GeneralizedTime: YYYYMMDD…
        year = int(digits[0:4])
        rest = digits[4:16].ljust(12, "0")
    else:
        return None
    return (f"{year:04d}-{rest[0:2]}-{rest[2:4]}T{rest[4:6]}:{rest[6:8]}:{rest[8:10]}Z")


def _name_from_rdn(data: bytes, cstart: int, cend: int) -> str | None:
    """Read a ``Name`` RDN sequence — public identifiers only."""
    names: list[str] = []
    try:
        for _tag, rstart, rend in _children(data, cstart, cend):
            for _atag, astart, aend in _children(data, rstart, rend):
                pairs = _children(data, astart, aend)
                if len(pairs) != 2 or pairs[0][0] != 0x06:
                    continue
                label = _oid_name(_decode_oid(data[pairs[0][1]:pairs[0][2]]))
                value = data[pairs[1][1]:pairs[1][2]].decode("utf-8", "replace")
                names.append(f"{label}={value}")
    except _Asn1Error:
        return None
    return ", ".join(names) if names else None


def _key_usage_bits(bit_string: bytes) -> list[str]:
    if len(bit_string) < 2:
        return []
    unused, payload = bit_string[0], bit_string[1:]
    total = len(payload) * 8 - unused
    return [name for index, name in enumerate(_KEY_USAGE_BITS)
            if index < total and payload[index // 8] & (0x80 >> (index % 8))]


def _basic_constraints_ca(data: bytes, span: tuple[int, int, int]) -> bool | None:
    if span[0] != 0x30:
        return None
    try:
        for tag, s, _e in _children(data, span[1], span[2]):
            if tag == 0x01:
                return bool(data[s])
    except _Asn1Error:
        return None
    return False                     # extensions present, no cA field → not a CA


def _oid_list(data: bytes, span: tuple[int, int, int]) -> list[str]:
    if span[0] != 0x30:
        return []
    out: list[str] = []
    try:
        for tag, s, e in _children(data, span[1], span[2]):
            if tag == 0x06:
                out.append(_oid_name(_decode_oid(data[s:e])))
    except _Asn1Error:
        return out
    return out


def _extensions(data: bytes, span: tuple[int, int, int]) -> list[tuple[str, tuple[int, int, int]]]:
    """X.509 ``[3] EXPLICIT Extensions`` → ``(oid, inner value span)`` pairs.

    Each ``Extension`` is ``SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
    extnValue OCTET STRING }`` and the OCTET STRING *wraps* the real value, so the
    wrapper is stripped here rather than in every caller.
    """
    out: list[tuple[str, tuple[int, int, int]]] = []
    try:
        for wrapper in _children(data, span[1], span[2]):        # SEQUENCE OF Extension
            for _tag, estart, eend in _children(data, wrapper[1], wrapper[2]):
                parts = _children(data, estart, eend)
                if len(parts) < 2 or parts[0][0] != 0x06:
                    continue
                oid = _decode_oid(data[parts[0][1]:parts[0][2]])
                value = parts[-1]
                if value[0] != 0x04:
                    continue
                out.append((oid, _tlv(data, value[1], value[2])))
    except _Asn1Error:
        return out
    return out


def _san_names(data: bytes, span: tuple[int, int, int]) -> list[str]:
    if span[0] != 0x30:
        return []
    labels = {0x81: "email", 0x82: "dns", 0x87: "ip"}
    out: list[str] = []
    try:
        for tag, s, e in _children(data, span[1], span[2]):
            if tag not in labels:
                continue
            text = (".".join(str(b) for b in data[s:e]) if tag == 0x87
                    else data[s:e].decode("utf-8", "replace"))
            out.append(f"{labels[tag]}:{text}")
    except _Asn1Error:
        return out
    return out[:MAX_CERT_SANS]


def _read_certificate(data: bytes, tbs_start: int, tbs_end: int) -> dict[str, Any]:
    """X.509 ``tbsCertificate`` → the fields an inventory report can cite."""
    out: dict[str, Any] = {"version": None, "serial": None, "signature_algorithm": None,
                           "issuer": None, "subject": None, "not_before": None,
                           "not_after": None, "key_type": None, "key_bits": None,
                           "curve": None, "self_signed": None, "ca": None,
                           "key_usage": [], "extended_key_usage": [], "san": []}
    kids = _children(data, tbs_start, tbs_end)
    index = 0
    if kids and kids[0][0] == 0xA0:                       # [0] EXPLICIT version
        for tag, s, e in _children(data, kids[0][1], kids[0][2]):
            if tag == 0x02:
                out["version"] = _integer(data, s, e) + 1
        index = 1
    if len(kids) > index and kids[index][0] == 0x02:      # serialNumber (public value)
        out["serial"] = data[kids[index][1]:kids[index][2]].hex()
        index += 1
    if len(kids) > index and kids[index][0] == 0x30:      # signature AlgorithmIdentifier
        out["signature_algorithm"] = _read_algorithm(data, kids[index][1], kids[index][2])["algorithm"]
        index += 1
    if len(kids) > index and kids[index][0] == 0x30:      # issuer
        out["issuer"] = _name_from_rdn(data, kids[index][1], kids[index][2])
        index += 1
    if len(kids) > index and kids[index][0] == 0x30:      # validity
        for tag, s, e in _children(data, kids[index][1], kids[index][2]):
            if tag in (0x17, 0x18):
                value = _time_string(data[s:e], tag)
                if out["not_before"] is None:
                    out["not_before"] = value
                else:
                    out["not_after"] = value
        index += 1
    if len(kids) > index and kids[index][0] == 0x30:      # subject
        out["subject"] = _name_from_rdn(data, kids[index][1], kids[index][2])
        index += 1
    if len(kids) > index and kids[index][0] == 0x30:      # subjectPublicKeyInfo
        spki = _read_spki(data, kids[index][1], kids[index][2])
        out.update({"key_type": spki["key_type"], "key_bits": spki["key_bits"],
                    "curve": spki["curve"]})
        index += 1
    out["self_signed"] = bool(out["subject"] and out["subject"] == out["issuer"])
    for tag, s, e in kids[index:]:                        # [3] EXPLICIT extensions
        if tag != 0xA3:
            continue
        for oid, inner in _extensions(data, (tag, s, e)):
            if oid == "2.5.29.15" and inner[0] == 0x03:   # keyUsage is a BIT STRING
                out["key_usage"] = _key_usage_bits(data[inner[1]:inner[2]])
            elif oid == "2.5.29.19":
                out["ca"] = _basic_constraints_ca(data, inner)
            elif oid == "2.5.29.37":
                out["extended_key_usage"] = _oid_list(data, inner)
            elif oid == "2.5.29.17":
                out["san"] = _san_names(data, inner)
    return out


def _read_csr(data: bytes, cri_start: int, cri_end: int,
              sig_span: tuple[int, int]) -> dict[str, Any]:
    """``CertificationRequestInfo`` → subject, requested key, signature algorithm."""
    out: dict[str, Any] = {"version": None, "subject": None, "key_type": None,
                           "key_bits": None, "curve": None, "signature_algorithm": None,
                           "attributes": 0}
    kids = _children(data, cri_start, cri_end)
    index = 0
    if kids and kids[0][0] == 0x02:                       # version (always 0)
        out["version"] = _integer(data, kids[0][1], kids[0][2])
        index = 1
    if len(kids) > index and kids[index][0] == 0x30:      # subject Name
        out["subject"] = _name_from_rdn(data, kids[index][1], kids[index][2])
        index += 1
    if len(kids) > index and kids[index][0] == 0x30:      # requested SubjectPublicKeyInfo
        spki = _read_spki(data, kids[index][1], kids[index][2])
        out.update({"key_type": spki["key_type"], "key_bits": spki["key_bits"],
                    "curve": spki["curve"], "spki_algorithm": spki["algorithm"]})
        index += 1
    for tag, s, e in kids[index:]:                       # [0] attributes
        if tag == 0xA0:
            out["attributes"] = len(_children(data, s, e))
    try:
        out["signature_algorithm"] = _read_algorithm(data, sig_span[0], sig_span[1])["algorithm"]
    except _Asn1Error:
        pass
    return out


def _cert_or_request(data: bytes, body_kids: list[tuple[int, int, int]]) -> bool | None:
    """Is the first element a ``tbsCertificate`` (True) or a PKCS#10 info (False)?

    A certificate and a request share the outer shape
    ``SEQUENCE { SEQUENCE, SEQUENCE, BIT STRING }``, so the outer tags cannot tell
    them apart. The inner layout can: a certificate carries an explicit ``[0]``
    version (v3) or an ``INTEGER`` serial followed by the signature
    ``AlgorithmIdentifier``, while a request carries a version ``INTEGER 0``
    followed by the subject ``Name`` (an RDN SET). ``None`` means "cannot tell",
    and the caller then declines to name the structure.
    """
    if not body_kids:
        return None
    if body_kids[0][0] == 0xA0:                    # [0] EXPLICIT version → certificate
        return True
    if body_kids[0][0] != 0x02 or len(body_kids) < 2:
        return None
    try:
        second = _children(data, body_kids[1][1], body_kids[1][2])
    except _Asn1Error:
        return None
    if not second:
        return None
    if second[0][0] == 0x06:                       # AlgorithmIdentifier → certificate
        return True
    if second[0][0] == 0x31:                       # RDN SET → request subject
        return False
    return None


def _container_oids(data: bytes, cstart: int, cend: int, *, depth: int = 0) -> list[str]:
    """Resolved OID names near the top of a structure — for containers only."""
    found: list[str] = []
    if depth > 4:
        return found
    try:
        for tag, s, e in _children(data, cstart, cend):
            if tag == 0x06:
                name = OID_NAMES.get(_decode_oid(data[s:e]))
                if name:
                    found.append(name)
            elif tag in (0x30, 0xA0, 0xA3, 0x04):
                found.extend(_container_oids(data, s, e, depth=depth + 1))
    except _Asn1Error:
        return found
    return found


def _classify_der(data: bytes, start: int, end: int, *, depth: int = 0) -> dict[str, Any] | None:
    """Read one ASN.1 structure. ``None`` means "not something we are willing to name"."""
    tag, cstart, cend = _tlv(data, start, end, depth=depth)
    if tag == 0x30:
        kids = _children(data, cstart, cend)
        if not kids:
            return None
        kinds = [kid[0] for kid in kids]
        first = kids[0]

        # PKCS#12 PFX: version 3, ContentInfo(id-data), MacData
        if (len(kids) >= 2 and kinds[0] == 0x02 and kinds[1] == 0x30
                and _integer(data, first[1], first[2]) == 3):
            info = _container_oids(data, kids[1][1], kids[1][2])
            bags = [name for name in info if name.startswith("pkcs12-")]
            if "pkcs7-data" in info and (bags or (len(kids) > 2 and kinds[2] == 0x30)):
                return {"kind": "keystore", "format": "pkcs12", "key_type": None,
                        "key_bits": None, "curve": None, "encrypted": True,
                        "readable": False,
                        "detail": {"version": 3, "bags": sorted(set(bags))[:8],
                                   "content_types": sorted(set(info))[:8],
                                   "note": ("PKCS#12 is password-protected by design — the "
                                            "file was identified, the bags were not opened")}}

        # X.509 certificate or PKCS#10 request — same outer shape, inner layout decides
        if len(kids) == 3 and kinds[0] == 0x30 and kinds[1] == 0x30 and kinds[2] == 0x03:
            body_kids = _children(data, first[1], first[2])
            is_certificate = _cert_or_request(data, body_kids)
            if is_certificate is True:
                cert = _read_certificate(data, first[1], first[2])
                return {"kind": "certificate", "format": "der", "key_type": cert["key_type"],
                        "key_bits": cert["key_bits"], "curve": cert["curve"],
                        "encrypted": False, "readable": True, "detail": cert}
            if is_certificate is False:
                csr = _read_csr(data, first[1], first[2], (kids[1][1], kids[1][2]))
                return {"kind": "csr", "format": "pkcs10", "key_type": csr["key_type"],
                        "key_bits": csr["key_bits"], "curve": csr["curve"],
                        "encrypted": False, "readable": True, "detail": csr}

        # PKCS#8 PrivateKeyInfo / OneAsymmetricKey
        if len(kids) >= 3 and kinds[0] == 0x02 and kinds[1] == 0x30 and kinds[2] in (0x04, 0xA0):
            algorithm = _read_algorithm(data, kids[1][1], kids[1][2])
            inner: dict[str, Any] | None = None
            if kinds[2] == 0x04 and depth < MAX_ASN1_DEPTH:
                try:
                    inner = _classify_der(data, kids[2][1], kids[2][2], depth=depth + 1)
                except _Asn1Error:
                    inner = None
            inner = inner or {}
            return {"kind": "private-key", "format": "pkcs8",
                    "key_type": inner.get("key_type")
                    or ALGORITHM_KEY_TYPE.get(algorithm["algorithm"]),
                    # a fixed-size curve algorithm has no size inside it to read
                    "key_bits": inner.get("key_bits")
                    or ALGORITHM_BITS.get(algorithm["algorithm"]),
                    "curve": inner.get("curve") or (
                        algorithm["parameters"] if algorithm["parameters"] in CURVE_BITS else None),
                    "encrypted": False, "readable": True,
                    "detail": {"algorithm": algorithm["algorithm"], "oid": algorithm["oid"],
                               "pkcs8_version": _integer(data, first[1], first[2]),
                               "inner_format": inner.get("format")}}

        # EncryptedPrivateKeyInfo: AlgorithmIdentifier, OCTET STRING
        if len(kids) == 2 and kinds[0] == 0x30 and kinds[1] == 0x04:
            algorithm = _read_algorithm(data, first[1], first[2])
            return {"kind": "private-key", "format": "pkcs8-encrypted", "key_type": None,
                    "key_bits": None, "curve": None, "encrypted": True, "readable": False,
                    "detail": {"algorithm": algorithm["algorithm"], "oid": algorithm["oid"],
                               "note": "password-encrypted PKCS#8 — not decrypted"}}

        # RFC 5915 EC private key: version 1, privateKey OCTET STRING, [0] curve
        if (len(kids) >= 2 and kinds[0] == 0x02 and kinds[1] == 0x04
                and _integer(data, first[1], first[2]) == 1):
            curve = None
            for tag, s, e in kids[2:]:
                if tag == 0xA0:
                    for itag, istart, iend in _children(data, s, e):
                        if itag == 0x06:
                            curve = _oid_name(_decode_oid(data[istart:iend]))
            private_bits = _integer(data, kids[1][1], kids[1][2]).bit_length()
            return {"kind": "private-key", "format": "sec1", "key_type": "ec",
                    "key_bits": CURVE_BITS.get(curve or "", private_bits), "curve": curve,
                    "encrypted": False, "readable": True,
                    "detail": {"curve": curve, "private_key_octets": kids[1][2] - kids[1][1]}}

        # PKCS#1 RSA private key: version 0 then the eight components as INTEGERs
        if (len(kids) >= 9 and kinds[0] == 0x02 and kinds[1] == 0x02
                and _integer(data, first[1], first[2]) == 0
                and all(kind == 0x02 for kind in kinds[1:9])):
            return {"kind": "private-key", "format": "pkcs1", "key_type": "rsa",
                    "key_bits": _integer(data, kids[1][1], kids[1][2]).bit_length(),
                    "curve": None, "encrypted": False, "readable": True,
                    "detail": {"components": len(kids), "algorithm": "rsaEncryption"}}

        # DSA private key (OpenSSL legacy layout): version, p, q, g, y, x
        if (len(kids) == 6 and kinds[0] == 0x02 and _integer(data, first[1], first[2]) == 0
                and all(kind == 0x02 for kind in kinds[1:])):
            return {"kind": "private-key", "format": "pkcs1-dsa", "key_type": "dsa",
                    "key_bits": _integer(data, kids[1][1], kids[1][2]).bit_length(),
                    "curve": None, "encrypted": False, "readable": True,
                    "detail": {"algorithm": "dsa"}}

        # PKCS#1 RSA public key
        if len(kids) == 2 and kinds[0] == 0x02 and kinds[1] == 0x02:
            return {"kind": "public-key", "format": "pkcs1", "key_type": "rsa",
                    "key_bits": _integer(data, first[1], first[2]).bit_length(),
                    "curve": None, "encrypted": False, "readable": True,
                    "detail": {"algorithm": "rsaEncryption",
                               "public_exponent_bits":
                                   _integer(data, kids[1][1], kids[1][2]).bit_length()}}

        # standalone SubjectPublicKeyInfo: AlgorithmIdentifier + BIT STRING
        if len(kids) == 2 and kinds[0] == 0x30 and kinds[1] == 0x03:
            spki = _read_spki(data, cstart, cend)
            return {"kind": "public-key", "format": "spki", "key_type": spki["key_type"],
                    "key_bits": spki["key_bits"], "curve": spki["curve"],
                    "encrypted": False, "readable": True,
                    "detail": {"algorithm": spki["algorithm"], "oid": spki["oid"],
                               "public_der_bits":
                                   _bit_string_bits(data, kids[1][1], kids[1][2])}}

        # ContentInfo (PKCS#7 / CMS): named by its content OID, never unpacked
        if len(kids) >= 2 and kinds[0] == 0x06:
            oid = _decode_oid(data[first[1]:first[2]])
            if oid in OID_NAMES:
                return {"kind": "container", "format": "asn1", "key_type": None,
                        "key_bits": None, "curve": None,
                        "encrypted": oid == "1.2.840.113549.1.7.6", "readable": False,
                        "detail": {"oid": oid, "algorithm": _oid_name(oid),
                                   "note": "certificate/key container identified by OID"}}

        # anything else: only reported when a known algorithm OID is inside it
        oids = _container_oids(data, cstart, cend)
        if oids:
            return {"kind": "structure", "format": "der", "key_type": None, "key_bits": None,
                    "curve": None, "encrypted": False, "readable": False,
                    "detail": {"algorithms": sorted(set(oids))[:8]}}
        return None
    if tag == 0x04 and depth < MAX_ASN1_DEPTH:          # bare OCTET STRING wrapper
        return _classify_der(data, cstart, cend, depth=depth + 1)
    return None


# ------------------------------------------------------------ PEM armour --- #
def _pem_blocks(window: bytes) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for match in _PEM_BEGIN_RE.finditer(window):
        if len(out) >= MAX_PEM_BLOCKS:
            break
        end_marker = b"-----END " + match.group(1) + b"-----"
        stop = window.find(end_marker, match.end())
        truncated = stop < 0
        if truncated:
            stop = min(len(window), match.end() + 64 * 1024)
        out.append({"label": match.group(1).decode("ascii", "replace").strip(),
                    "offset": match.start(), "body": window[match.end():stop],
                    "terminated": not truncated,
                    "context": window[max(0, match.start() - 160):match.start()]})
    return out


def _pem_material(body: bytes) -> tuple[bytes, bytes | None]:
    """Split a PEM body into armour headers (if any) and the base64 payload."""
    text = body.replace(b"\r\n", b"\n").strip(b"\n \t")
    headers = b""
    if b":" in text.split(b"\n", 1)[0]:                 # Proc-Type / DEK-Info style
        split = text.find(b"\n\n")
        if split < 0:
            split = text.find(b"\n")
        if split >= 0:
            headers, text = text[:split], text[split:].strip(b"\n \t")
    # a "=CRC24" line is armour checksum, not payload — it is never base64 content
    payload = b"\n".join(line for line in text.split(b"\n") if not line.startswith(b"="))
    compact = b"".join(payload.split())
    try:
        decoded = base64.b64decode(compact, validate=True) if compact else b""
    except (binascii.Error, ValueError):
        decoded = b""
    return headers, decoded or None


# -------------------------------------------------------------- SSH keys --- #
def _ssh_wire_strings(payload: bytes, *, limit: int = 10) -> list[bytes]:
    """Read length-prefixed SSH wire strings (RFC 4251 §5)."""
    out: list[bytes] = []
    cursor = 0
    while cursor + 4 <= len(payload) and len(out) < limit:
        size = int.from_bytes(payload[cursor:cursor + 4], "big")
        if size > 1 << 16 or cursor + 4 + size > len(payload):
            break
        out.append(payload[cursor + 4:cursor + 4 + size])
        cursor += 4 + size
    return out


def _ssh_key_bits(algorithm: str, payload: bytes) -> int | None:
    """Size of an SSH public key from its wire format (public data only)."""
    if algorithm in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512", "ssh-dss"):
        fields = _ssh_wire_strings(payload)
        if algorithm.startswith("ssh-rsa") or algorithm.startswith("rsa-sha2"):
            # w[0] = algorithm name, w[1] = e, w[2] = n
            if len(fields) >= 3:
                modulus = fields[2].lstrip(b"\x00")
                return len(modulus) * 8
            return None
        if len(fields) >= 2:                            # DSA: p, q, g, y
            return len(fields[1].lstrip(b"\x00")) * 8
        return None
    if algorithm == "ssh-ed25519":
        return 256
    if algorithm.startswith("ecdsa-sha2-nistp"):
        digits = algorithm.rsplit("nistp", 1)[-1]
        return int(digits) if digits.isdigit() else None
    return None


def _openssh_private(blob: bytes) -> dict[str, Any]:
    """Read the OpenSSH private-key container header (never key material)."""
    out: dict[str, Any] = {"encrypted": False, "readable": True, "key_bits": None,
                           "comment": None, "key_type_name": None,
                           "detail": {"format": "openssh-private"}}
    if not blob.startswith(_OPENSSH_MAGIC):
        out["readable"] = False
        out["detail"] = {"format": "openssh-private",
                         "note": "body is not an openssh-key-v1 container"}
        return out
    cursor = len(_OPENSSH_MAGIC)
    fields: list[bytes] = []
    try:
        while len(fields) < 4 and cursor + 4 <= len(blob):
            size = int.from_bytes(blob[cursor:cursor + 4], "big")
            if size > 1 << 16 or cursor + 4 + size > len(blob):
                break
            fields.append(blob[cursor + 4:cursor + 4 + size])
            cursor += 4 + size
        cipher = fields[0].decode("ascii", "replace") if fields else ""
        kdf = fields[1].decode("ascii", "replace") if len(fields) > 1 else ""
        kdf_rounds = None
        if len(fields) > 2 and len(fields[2]) >= 8:
            kdf_rounds = int.from_bytes(fields[2][-4:], "big") or None
        nkeys = int.from_bytes(fields[3], "big") if len(fields) > 3 else None
        out.update({"encrypted": cipher not in ("", "none"), "cipher": cipher, "kdf": kdf})
        out["detail"].update({"cipher": cipher, "kdf": kdf, "kdf_rounds": kdf_rounds,
                              "nkeys": nkeys})
        # the public key blob is the next string; its first field names the algorithm
        if cursor + 4 <= len(blob):
            size = int.from_bytes(blob[cursor:cursor + 4], "big")
            public = blob[cursor + 4:cursor + 4 + size]
            cursor += 4 + size
            name_field = _ssh_wire_strings(public, limit=1)
            name = name_field[0].decode("ascii", "replace") if name_field else ""
            out["key_type_name"] = name or None
            out["key_bits"] = _ssh_key_bits(name, public[4:]) if name else None
            # private section: readable only when the container says it is in the clear
            if not out["encrypted"] and cursor + 4 <= len(blob):
                psize = int.from_bytes(blob[cursor:cursor + 4], "big")
                section = blob[cursor + 4:cursor + 4 + psize]
                inner = _ssh_wire_strings(section[8:], limit=12) if len(section) > 8 else []
                if inner:
                    out["comment"] = inner[-1].decode("utf-8", "replace")[:120]
        out["detail"]["note"] = ("private section is "
                                 + ("passphrase-encrypted" if out["encrypted"] else "in the clear")
                                 + f" ({kdf or 'no kdf'}); key material was not read")
    except (IndexError, ValueError) as exc:                 # pragma: no cover - defensive
        out["readable"] = False
        out["detail"] = {"format": "openssh-private",
                         "note": f"openssh-key-v1 header did not parse: {exc}"}
    return out


# --------------------------------------------------------------- OpenPGP --- #
def _crc24(payload: bytes) -> int:
    """RFC 4880 §6.1 ASCII-armour checksum."""
    crc = 0xB704CE
    for byte in payload:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def _pgp_packets(blob: bytes) -> list[dict[str, Any]]:
    """Walk OpenPGP packet headers (RFC 4880 §4.2/§4.3)."""
    out: list[dict[str, Any]] = []
    cursor = 0
    while cursor < len(blob) and len(out) < MAX_PGP_PACKETS:
        header = blob[cursor]
        if not header & 0x80:
            break
        if header & 0x40:                                   # new-format packet
            tag = header & 0x3F
            if cursor + 2 > len(blob):
                break
            first = blob[cursor + 1]
            if first < 192:
                length, cursor = first, cursor + 2
            elif first < 224:
                if cursor + 3 > len(blob):
                    break
                length = ((first - 192) << 8) + blob[cursor + 2] + 192
                cursor += 3
            elif first == 255:
                if cursor + 6 > len(blob):
                    break
                length = int.from_bytes(blob[cursor + 2:cursor + 6], "big")
                cursor += 6
            else:                                           # partial body length
                length, cursor = 1 << (first & 0x1F), cursor + 2
        else:                                               # old-format packet
            tag = (header & 0x3C) >> 2
            length_type = header & 0x03
            if length_type == 3:
                if cursor + 5 > len(blob):
                    break
                length = int.from_bytes(blob[cursor + 1:cursor + 5], "big")
                cursor += 5
            elif length_type == 0:
                if cursor + 2 > len(blob):
                    break
                length, cursor = blob[cursor + 1], cursor + 2
            elif length_type == 1:
                if cursor + 3 > len(blob):
                    break
                length = int.from_bytes(blob[cursor + 1:cursor + 3], "big")
                cursor += 3
            else:
                length, cursor = max(0, len(blob) - (cursor + 2)), cursor + 2
        body = blob[cursor:cursor + length]
        out.append({"tag": tag, "length": length, "body": body[:MAX_PGP_BODY]})
        cursor += length
    return out


PGP_MPI_ALGORITHMS = {1: 2, 2: 2, 3: 2, 16: 3, 17: 4}       # algorithm → MPI count


def _pgp_mpi(body: bytes, cursor: int) -> tuple[int | None, int]:
    """Read one OpenPGP MPI: two-byte bit count, then the value. Size only."""
    if cursor + 2 > len(body):
        return None, cursor
    bits = int.from_bytes(body[cursor:cursor + 2], "big")
    size = (bits + 7) // 8
    if cursor + 2 + size > len(body):
        return None, cursor
    return bits, cursor + 2 + size


def _pgp_key_fields(body: bytes) -> tuple[int | None, int | None, str | None]:
    """Size of the public key and where the S2K usage octet sits, if it was found.

    A V4 secret-key packet is ``version, created, algorithm, <public key fields>,
    S2K usage`` — the byte after the analysis name is *public key material*, not the
    S2K octet. Reading it as one would be a guess, so the public fields are skipped
    per algorithm and the S2K octet is only reported when it was actually located.
    """
    if len(body) < 7:
        return None, None, "packet too short to locate the S2K octet"
    algorithm = body[5]
    cursor = 6
    bits: int | None = None
    if algorithm in PGP_MPI_ALGORITHMS:
        for index in range(PGP_MPI_ALGORITHMS[algorithm]):
            found, cursor = _pgp_mpi(body, cursor)
            if found is None:
                return None, None, "public key material is truncated"
            if index == 0:
                bits = found
        return bits, cursor, None
    if algorithm in (19, 22):                               # ECDSA / EdDSA: OID + point
        for _ in range(2):
            if cursor >= len(body):
                return None, None, "public key material is truncated"
            size = body[cursor] if cursor == 6 else int.from_bytes(body[cursor:cursor + 2], "big")
            step = 1 if cursor == 6 else 2
            cursor += step + size
            if cursor > len(body):
                return None, None, "public key material is truncated"
        return None, cursor, None
    if algorithm == 18:                                     # ECDH: OID + point + KDF params
        cursor += 1
        if cursor > len(body):
            return None, None, "public key material is truncated"
        size = int.from_bytes(body[cursor:cursor + 2], "big")
        cursor += 2 + size
        cursor += 1 + (body[cursor] if cursor < len(body) else 0) + 4
        return None, (cursor if cursor <= len(body) else None), None
    return None, None, f"public key fields for algorithm {algorithm} are not described here"


def _pgp_report(blob: bytes) -> dict[str, Any]:
    """Public-key algorithm, version, key size and S2K usage from OpenPGP packets."""
    packets = _pgp_packets(blob)
    detail: dict[str, Any] = {"packets": [packet["tag"] for packet in packets]}
    out: dict[str, Any] = {"key_type": "openpgp", "encrypted": False, "readable": False,
                           "key_bits": None, "detail": detail}
    for packet in packets:
        tag, body = packet["tag"], packet["body"]
        if tag not in (5, 6, 7, 14) or len(body) < 6:
            continue
        detail["key_version"] = body[0]
        detail["public_key_algorithm"] = PGP_ALGORITHMS.get(body[5], f"algorithm-{body[5]}")
        detail["secret_key_packet"] = tag == 5
        out["readable"] = True
        if tag in (5, 7):
            bits, s2k_offset, note = _pgp_key_fields(body)
            if bits:
                out["key_bits"] = bits
            if s2k_offset is not None and s2k_offset < len(body):
                usage = body[s2k_offset]
                detail["s2k_usage"] = ("unencrypted" if usage in (0, 255)
                                       else f"string-to-key (usage {usage})")
                out["encrypted"] = usage not in (0, 255)
            elif note:
                detail["s2k_usage"] = None
                detail["note"] = note
        break
    return out


# -------------------------------------------------------------- keystores -- #
def _jks_entries(window: bytes, offset: int) -> dict[str, Any] | None:
    """Java KeyStore / JCEKS entry table — aliases and types, never key bytes."""
    if offset + 12 > len(window):
        return None
    kind = _JKS_MAGICS.get(window[offset:offset + 4])
    if kind is None:
        return None
    version = int.from_bytes(window[offset + 4:offset + 8], "big")
    count = int.from_bytes(window[offset + 8:offset + 12], "big")
    if version not in (1, 2) or count > 4096:
        return None
    cursor = offset + 12
    entries: list[dict[str, Any]] = []
    private_keys = 0
    for _ in range(min(count, 64)):
        if cursor + 4 > len(window):
            break
        tag = int.from_bytes(window[cursor:cursor + 4], "big")
        cursor += 4
        if tag == 1:
            cursor += 8                                    # creation timestamp
        elif tag != 2:
            break
        if cursor + 2 > len(window):
            break
        alias_len = int.from_bytes(window[cursor:cursor + 2], "big")
        cursor += 2
        if alias_len > 512 or cursor + alias_len > len(window):
            break
        alias = window[cursor:cursor + alias_len].decode("utf-8", "replace")
        cursor += alias_len
        if tag == 1:
            private_keys += 1
            if cursor + 4 > len(window):
                break
            size = int.from_bytes(window[cursor:cursor + 4], "big")
            cursor += 4 + min(size, len(window) - cursor)
            entries.append({"type": "private-key", "alias": alias, "protected_bytes": size})
            continue
        if cursor + 2 > len(window):
            break
        type_len = int.from_bytes(window[cursor:cursor + 2], "big")
        cursor += 2
        if cursor + type_len > len(window):
            break
        cert_type = window[cursor:cursor + type_len].decode("ascii", "replace")
        cursor += type_len
        if cursor + 4 > len(window):
            break
        size = int.from_bytes(window[cursor:cursor + 4], "big")
        cursor += 4
        cert = window[cursor:cursor + min(size, 4096)]
        cursor += min(size, len(window) - cursor)
        entry: dict[str, Any] = {"type": "trusted-certificate", "alias": alias,
                                 "certificate_type": cert_type}
        if cert[:1] == b"\x30":                             # read the certificate we located
            try:
                classified = _classify_der(cert, 0, len(cert))
            except _Asn1Error:
                classified = None
            if classified and classified["kind"] == "certificate":
                cert_detail = classified["detail"]
                entry.update({"subject": cert_detail.get("subject"),
                              "issuer": cert_detail.get("issuer"),
                              "not_after": cert_detail.get("not_after")})
        entries.append(entry)
    return {"format": kind, "detail": {"version": version, "entries_declared": count,
                                       "entries": entries, "private_keys": private_keys,
                                       "note": ("JKS private keys are protected only by the "
                                                "store password, not by a KDF")}}


# ------------------------------------------------------------- aggregates -- #
def _placeholder_reason(material: bytes, label: str, context: bytes = b"") -> str | None:
    wording = (label or "").encode("utf-8", "replace") + b" " + (context or b"")
    if _PLACEHOLDER_RE.search(wording):
        hit = _PLACEHOLDER_RE.search(wording)
        return ("the text around it declares it as a test/placeholder key ("
                + hit.group(0).decode("utf-8", "replace") + ")")
    for known, reason in KNOWN_TEST_VECTORS:
        if material == bytes.fromhex(known) or bytes.fromhex(known) in material:
            return reason
    repeat = _REPEAT_RE.search(material)
    if repeat:
        return (f"degenerate value — {len(repeat.group(0))} identical bytes in sequence "
                "(placeholder, not a real secret)")
    return None


def _row(kind: str, key_type: str | None, material: bytes, offset: int, detector: str,
         *, format: str, encrypted: bool, readable: bool = True, bits: int | None = None,
         curve: str | None = None, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {
        "kind": kind, "key_type": key_type, "format": format, "detector": detector,
        "encrypted": bool(encrypted), "readable": bool(readable),
        "material_sha256": _sha256(material), "material_bytes": len(material),
        "offset": offset, "offsets": [offset], "occurrences": 1,
    }
    if bits:
        row["key_bits"] = bits
    if curve:
        row["curve"] = curve
    if detail:
        row["detail"] = {key: value for key, value in detail.items() if value is not None}
    return row


def detect_embedded_keys(data: bytes, *, window: int = MAX_KEY_WINDOW) -> dict[str, Any]:
    """Find key material in a binary image, reporting it without ever returning the key.

    Result: ``keys`` (private keys, public keys, certificates, keystores),
    ``test_vectors`` (values found but explicitly not secrets), per-kind counters,
    ``unencrypted_private_keys``, ``notes`` and ``scanned_bytes``.

    ``private_keys`` counts the keys found plus the private-key entries a keystore
    declares (``keystore_private_keys``); ``private_key_material_rows`` is how many
    of them are key material this reader could read directly.
    """
    scope = data[:window]
    blob_scope = scope[:BLOB_WINDOW]
    rows: list[dict[str, Any]] = []
    test_vectors: list[dict[str, Any]] = []
    notes: list[str] = []

    def add(row: dict[str, Any]) -> None:
        for existing in rows:
            if (existing["material_sha256"] == row["material_sha256"]
                    and existing["kind"] == row["kind"]):
                if len(existing["offsets"]) < MAX_KEY_OCCURRENCES:
                    existing["offsets"].append(row["offset"])
                existing["occurrences"] = len(existing["offsets"])
                return
        rows.append(row)

    def record(row: dict[str, Any], reason: str | None) -> None:
        if reason and row["kind"] != "certificate":
            row["classification"] = "test-vector"
            row["reason"] = reason
            test_vectors.append(row)
        else:
            add(row)

    # 1. PEM armour -------------------------------------------------------- #
    for block in _pem_blocks(scope):
        label = block["label"]
        mapping = PEM_LABELS.get(label)
        if mapping is None:
            notes.append(f"unrecognised PEM label at offset {block['offset']}: {label}")
            continue
        kind, declared_type = mapping
        headers, decoded = _pem_material(block["body"])
        encrypted = "ENCRYPTED" in label.upper() or b"ENCRYPTED" in headers.upper()
        detail: dict[str, Any] = {"pem_label": label}
        dek = re.search(rb"DEK-Info:\s*([A-Za-z0-9-]+)", headers)
        if dek:
            encrypted = True
            detail["dek_info"] = dek.group(1).decode("ascii", "replace")
        if not block["terminated"]:
            notes.append(f"{label} armour at offset {block['offset']} is not terminated")
        material = decoded or block["body"]
        key_type, bits, curve = declared_type, None, None
        readable = True
        if "PGP" in label:
            pgp = _pgp_report(decoded or b"")
            detail.update(pgp["detail"])
            key_type = pgp["key_type"]
            bits = pgp.get("key_bits")
            encrypted = bool(pgp["encrypted"]) or encrypted
            crc_at = block["body"].rfind(b"=")
            if decoded and crc_at >= 0 and len(block["body"]) >= crc_at + 5:
                try:
                    want = int.from_bytes(
                        base64.b64decode(block["body"][crc_at + 1:crc_at + 5], validate=True),
                        "big")
                    detail["crc24_verified"] = want == _crc24(decoded)
                except (binascii.Error, ValueError):
                    detail["crc24_verified"] = None
        elif decoded and "OPENSSH" in label:
            openssh = _openssh_private(decoded)
            key_type, bits = "openssh", openssh.get("key_bits")
            encrypted = bool(openssh["encrypted"]) or encrypted
            detail.update(openssh["detail"])
        elif decoded:
            try:
                classified = _classify_der(decoded, 0, len(decoded))
            except _Asn1Error as exc:
                classified = None
                notes.append(f"{label} at offset {block['offset']} did not parse: {exc}")
            if classified:
                key_type = classified.get("key_type") or key_type
                bits, curve = classified.get("key_bits"), classified.get("curve")
                encrypted = bool(classified.get("encrypted")) or encrypted
                readable = bool(classified.get("readable", True))
                detail.update(classified.get("detail") or {})
        row = _row(kind, key_type, material, block["offset"], "pem", format="pem",
                   encrypted=encrypted, readable=readable, bits=bits, curve=curve, detail=detail)
        record(row, _placeholder_reason(material, label, block["context"]))

    # 2. encoded copies of DER structures ---------------------------------- #
    for detector, pattern, decode in (("base64", _BASE64_BLOB_RE, "base64"),
                                      ("hex", _HEX_BLOB_RE, "hex")):
        attempts = 0
        hits = 0
        for match in pattern.finditer(blob_scope):
            if attempts >= MAX_BLOB_ATTEMPTS or hits >= MAX_BLOB_CANDIDATES:
                break
            raw = match.group(0)
            attempts += 1
            try:
                blob = (base64.b64decode(b"".join(raw.split()), validate=True)
                        if decode == "base64" else bytes.fromhex(raw.decode("ascii")))
            except (binascii.Error, ValueError):
                continue
            if not 32 <= len(blob) <= MAX_BLOB_BYTES or blob[:1] != b"\x30":
                continue
            try:
                classified = _classify_der(blob, 0, len(blob))
            except _Asn1Error:
                continue
            if not classified or classified["kind"] == "structure":
                continue
            hits += 1
            row = _row(classified["kind"], classified.get("key_type"), blob, match.start(),
                       detector, format=f"{decode}-der",
                       encrypted=bool(classified.get("encrypted")),
                       readable=bool(classified.get("readable")),
                       bits=classified.get("key_bits"), curve=classified.get("curve"),
                       detail=classified.get("detail"))
            record(row, _placeholder_reason(blob, ""))

    # 3. SSH public keys, PuTTY private-key files --------------------------- #
    for match in _SSH_KEY_LINE_RE.finditer(blob_scope):
        algorithm = match.group(1).decode("ascii", "replace")
        try:
            blob = base64.b64decode(b"".join(match.group(2).split()), validate=True)
        except (binascii.Error, ValueError):
            continue
        bits = _ssh_key_bits(algorithm, blob[4:]) if len(blob) > 4 else None
        add(_row("public-key", algorithm.split("-")[0], blob, match.start(), "ssh-public",
                 format="ssh", encrypted=False, bits=bits,
                 detail={"wire_format": algorithm, "authorized_keys_style": True,
                         "note": "public key material — not a secret, inventory value only"}))
    for match in _PUTTY_RE.finditer(blob_scope):
        algorithm = match.group(2).decode("ascii", "replace")
        tail = blob_scope[match.start():match.start() + 4096]
        encryption = re.search(rb"Encryption:\s*([A-Za-z0-9-]+)", tail)
        comment = re.search(rb"Comment:\s*([^\r\n]{0,120})", tail)
        add(_row("private-key", algorithm.split("-")[0], tail, match.start(), "putty",
                 format="putty",
                 encrypted=bool(encryption and encryption.group(1).lower() != b"none"),
                 detail={"version": int(match.group(1)),
                         "encryption": (encryption.group(1).decode("ascii", "replace")
                                        if encryption else None),
                         "comment": (comment.group(1).decode("utf-8", "replace")
                                     if comment else None),
                         "note": "PuTTY private-key file embedded in the image"}))

    # 4. Java keystores ---------------------------------------------------- #
    for magic, kind in _JKS_MAGICS.items():
        start = 0
        while True:
            found = blob_scope.find(magic, start)
            if found < 0:
                break
            start = found + 1
            entry = _jks_entries(blob_scope, found)
            if entry:
                add(_row("keystore", None, blob_scope[found:found + 64], found, "jks",
                         format=entry["format"], encrypted=True, detail=entry["detail"]))

    # 5. a bare DER structure in the window (a .der/.p12 upload, or DER embedded
    # in a blob with a header in front of it). Runs last so the formats that
    # describe a whole file (a keystore, an SSH container) keep precedence, and
    # skips a window a keystore was already read out of — its contents are
    # inventoried there, not reported twice. The walk is bounded and a structure
    # only counts when it reaches the end of the window and says something
    # concrete about the key: a stray 0x30 byte proves nothing.
    if not any(row["kind"] == "keystore" for row in rows):
        accepted_spans: list[tuple[int, int]] = []
        for start in _der_offsets(scope):
            try:
                tag, cstart, cend = _tlv(scope, start, len(scope))
                classified = _classify_der(scope, start, len(scope)) if tag == 0x30 else None
            except _Asn1Error:
                continue
            if not classified or classified["kind"] == "structure":
                continue
            if len(scope) - cend > DER_TRAILING_SLACK or not _concrete(classified):
                continue
            # a structure inside one we just read is the same key material, not a
            # second finding: entry is the SPKI, the RSAPublicKey inside it is not
            if any(outer_start <= start < outer_end for outer_start, outer_end in accepted_spans):
                continue
            accepted_spans.append((start, cend))
            row = _row(classified["kind"], classified.get("key_type"),
                       scope[start:start + 64], start, "der",
                       format=classified.get("format") or "der",
                       encrypted=bool(classified.get("encrypted")),
                       readable=bool(classified.get("readable")),
                       bits=classified.get("key_bits"), curve=classified.get("curve"),
                       detail=classified.get("detail"))
            row["note"] = "material hashed over the structure's first 64 bytes"
            record(row, _placeholder_reason(scope[start:start + 64], "",
                                            scope[max(0, start - 160):start]))

    rows.sort(key=lambda row: (row["kind"], row["offset"]))
    private = [row for row in rows if row["kind"] == "private-key"]
    # a JKS entry is a private key, and a keystore that holds one is not "no keys":
    # the entry list is the only honest source, because those bytes are stored
    # encrypted under the store password and are deliberately not decrypted
    keystore_private = sum(int((row.get("detail") or {}).get("private_keys") or 0)
                           for row in rows if row["kind"] == "keystore")
    out: dict[str, Any] = {
        "keys": rows[:MAX_ROWS],
        "private_keys": len(private) + keystore_private,
        "private_key_material_rows": len(private),
        "keystore_private_keys": keystore_private,
        "public_keys": sum(1 for row in rows if row["kind"] == "public-key"),
        "certificates": sum(1 for row in rows if row["kind"] == "certificate"),
        "keystores": sum(1 for row in rows if row["kind"] == "keystore"),
        "unencrypted_private_keys": sum(1 for row in private if not row["encrypted"]),
        "test_vectors": test_vectors[:MAX_ROWS],
        "scanned_bytes": len(scope),
    }
    if notes:
        out["notes"] = sorted(set(notes))[:16]
    return out
