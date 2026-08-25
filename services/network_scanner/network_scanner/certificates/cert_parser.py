"""Parse X.509 PEMs and live SSL peer certs without a hard cryptography dependency.

Field extraction prefers, in order:
1. stdlib ``ssl`` (DER fingerprint + live peer dict)
2. ``openssl x509 -text`` (SAN, key usage, EKU, CA, key size, AIA, CRL)
3. optional ``cryptography`` if the extra is installed
"""

from __future__ import annotations

import hashlib
import re
import ssl
import subprocess
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

PEM_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----",
    re.DOTALL,
)

_OPENSSL_DATE = "%b %d %H:%M:%S %Y %Z"
_SERIAL_LINE = re.compile(r"Serial Number:\s*(?:\n\s*)?(?:([0-9]+)\s+\((0x[0-9a-fA-F]+)\)|([0-9a-fA-F:]+))")
_SIG_ALG = re.compile(r"Signature Algorithm:\s*(\S+)")
_SUBJECT = re.compile(r"^\s*Subject:\s*(.+)$", re.MULTILINE)
_ISSUER = re.compile(r"^\s*Issuer:\s*(.+)$", re.MULTILINE)
_NOT_BEFORE = re.compile(r"Not Before\s*:\s*(.+)")
_NOT_AFTER = re.compile(r"Not After\s*:\s*(.+)")
_PUB_BITS = re.compile(r"Public-Key:\s*\((\d+)\s*bit\)")
_PUB_ALG = re.compile(r"Public Key Algorithm:\s*(\S+)")
_FINGERPRINT = re.compile(r"sha256 Fingerprint=([0-9A-Fa-f:]+)", re.IGNORECASE)
_SAN_BLOCK = re.compile(r"Subject Alternative Name:\s*\n\s*(.+)", re.IGNORECASE)
_KU_BLOCK = re.compile(r"(?<!Extended )Key Usage[^\n]*\n\s*(.+)", re.IGNORECASE)
_EKU_BLOCK = re.compile(r"Extended Key Usage[^\n]*\n\s*(.+)", re.IGNORECASE)
_CA_FLAG = re.compile(r"\bCA\s*:\s*(TRUE|FALSE)\b", re.IGNORECASE)
_OCSP_URI = re.compile(r"OCSP\s*-\s*URI:(\S+)", re.IGNORECASE)
_CRL_URI = re.compile(r"URI:(https?://\S+)", re.IGNORECASE)
_DN_EQ = re.compile(r"\s*=\s*")

_PUBALG_MAP = {
    "rsaencryption": "RSA",
    "rsa": "RSA",
    "id-ecpublickey": "EC",
    "ecpublickey": "EC",
    "id-ecdh": "EC",
    "dsaencryption": "DSA",
    "dsa": "DSA",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
    "x25519": "X25519",
}

_KU_MAP = {
    "digital signature": "digitalSignature",
    "non repudiation": "nonRepudiation",
    "content commitment": "nonRepudiation",
    "key encipherment": "keyEncipherment",
    "data encipherment": "dataEncipherment",
    "key agreement": "keyAgreement",
    "certificate sign": "keyCertSign",
    "key cert sign": "keyCertSign",
    "crl sign": "cRLSign",
    "encipher only": "encipherOnly",
    "decipher only": "decipherOnly",
}

_EKU_MAP = {
    "tls web server authentication": "serverAuth",
    "tls web client authentication": "clientAuth",
    "code signing": "codeSigning",
    "e-mail protection": "emailProtection",
    "time stamping": "timeStamping",
    "ocsp signing": "OCSPSigning",
}


def fingerprint_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def normalize_dn(value: str | None) -> str:
    """Collapse OpenSSL ``CN = foo, O = bar`` spacing so issuer/subject compare."""
    text = (value or "").strip()
    if not text:
        return ""
    return _DN_EQ.sub("=", text)


def _parse_ssl_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).astimezone(timezone.utc)
    except Exception:
        pass
    try:
        return datetime.strptime(value.strip(), _OPENSSL_DATE).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _name_from_tuples(entries) -> str:
    parts = []
    if not entries:
        return ""
    for relative in entries:
        for key, val in relative:
            parts.append(f"{key}={val}")
    return ", ".join(parts)


def _expiry_fields(not_after: datetime | None, not_before: datetime | None) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    days = None
    status = "UNKNOWN"
    if not_after:
        days = int((not_after - now).total_seconds() // 86400)
        if not_before and now < not_before:
            status = "NOT_YET_VALID"
        elif days < 0:
            status = "EXPIRED"
        elif days <= 7:
            status = "EXPIRING_CRITICAL"
        elif days <= 30:
            status = "EXPIRING_SOON"
        else:
            status = "VALID"
    return {
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "days_until_expiry": days,
        "expiry_status": status,
    }


def from_ssl_dict(cert: dict[str, Any] | None, *, der: bytes | None = None) -> dict[str, Any]:
    cert = cert or {}
    not_after = _parse_ssl_date(cert.get("notAfter"))
    not_before = _parse_ssl_date(cert.get("notBefore"))
    sans = []
    for kind, value in cert.get("subjectAltName") or []:
        sans.append(f"{kind}:{value}")
    subject = _name_from_tuples(cert.get("subject"))
    issuer = _name_from_tuples(cert.get("issuer"))
    payload = {
        "fingerprint_sha256": fingerprint_der(der) if der else None,
        "subject": subject,
        "issuer": issuer,
        "serial_number": cert.get("serialNumber"),
        "san": sans,
        "is_self_signed": bool(subject and normalize_dn(subject) == normalize_dn(issuer)),
        "version": cert.get("version"),
        "key_usage": [],
        "extended_key_usage": [],
    }
    payload.update(_expiry_fields(not_after, not_before))
    return payload


def _csv_tokens(raw: str) -> list[str]:
    return [part.strip() for part in (raw or "").split(",") if part.strip()]


def _map_usages(raw: str, table: dict[str, str]) -> list[str]:
    out: list[str] = []
    for token in _csv_tokens(raw):
        mapped = table.get(token.lower())
        out.append(mapped or token)
    return out


def _openssl_text(pem: str) -> str:
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "PEM", "-noout", "-text", "-fingerprint", "-sha256"],
            input=pem,
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return f"{proc.stdout or ''}\n{proc.stderr or ''}"


def _serial_from_text(text: str) -> str | None:
    match = _SERIAL_LINE.search(text)
    if not match:
        return None
    if match.group(2):
        return match.group(2)[2:].lower()
    raw = (match.group(3) or match.group(1) or "").replace(":", "").strip()
    return raw.lower() or None


def openssl_parse(pem: str) -> dict[str, Any]:
    """Best-effort field extract from ``openssl x509 -text``."""
    text = _openssl_text(pem)
    if not text.strip():
        return {}
    subject = normalize_dn((_SUBJECT.search(text).group(1) if _SUBJECT.search(text) else "") or "")
    issuer = normalize_dn((_ISSUER.search(text).group(1) if _ISSUER.search(text) else "") or "")
    not_before = _parse_ssl_date(_NOT_BEFORE.search(text).group(1) if _NOT_BEFORE.search(text) else None)
    not_after = _parse_ssl_date(_NOT_AFTER.search(text).group(1) if _NOT_AFTER.search(text) else None)
    pub_alg_raw = _PUB_ALG.search(text).group(1) if _PUB_ALG.search(text) else ""
    pub_alg = _PUBALG_MAP.get(pub_alg_raw.lower(), pub_alg_raw.upper() if pub_alg_raw else None)
    bits_match = _PUB_BITS.search(text)
    san_match = _SAN_BLOCK.search(text)
    sans = _csv_tokens(san_match.group(1)) if san_match else []
    ku_match = _KU_BLOCK.search(text)
    eku_match = _EKU_BLOCK.search(text)
    ca_match = _CA_FLAG.search(text)
    fp_match = _FINGERPRINT.search(text)
    sig_match = _SIG_ALG.search(text)
    info: dict[str, Any] = {
        "subject": subject or None,
        "issuer": issuer or None,
        "serial_number": _serial_from_text(text),
        "signature_algorithm": sig_match.group(1) if sig_match else None,
        "public_key_algorithm": pub_alg,
        "public_key_size": int(bits_match.group(1)) if bits_match else None,
        "san": sans,
        "key_usage": _map_usages(ku_match.group(1), _KU_MAP) if ku_match else [],
        "extended_key_usage": _map_usages(eku_match.group(1), _EKU_MAP) if eku_match else [],
        "is_ca": bool(ca_match and ca_match.group(1).upper() == "TRUE"),
        "is_self_signed": bool(subject and issuer and subject == issuer),
        "ocsp_url": None,
        "crl_url": None,
    }
    info.update(_expiry_fields(not_after, not_before))
    if fp_match and not info.get("fingerprint_sha256"):
        info["fingerprint_sha256"] = fp_match.group(1).replace(":", "").lower()
    ocsp = _OCSP_URI.search(text)
    if ocsp:
        info["ocsp_url"] = ocsp.group(1).rstrip(";,")
    # Prefer the CRL DP URI over any other http URI in the dump.
    crl_section = re.search(r"CRL Distribution Points:(.+?)(?:\n\s*X509v3 |\n\s*Signature Algorithm:)", text, re.S)
    if crl_section:
        crl = _CRL_URI.search(crl_section.group(1))
        if crl:
            info["crl_url"] = crl.group(1).rstrip(";,")
    return {key: value for key, value in info.items() if value not in (None, "", [])}


def _cryptography_parse(pem: str) -> dict[str, Any]:
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
        from cryptography.x509.oid import ExtensionOID

        parsed = x509.load_pem_x509_certificate(pem.encode("utf-8"), default_backend())
        public = parsed.public_key()
        info: dict[str, Any] = {
            "serial_number": format(parsed.serial_number, "x"),
            "signature_algorithm": parsed.signature_algorithm_oid._name,  # noqa: SLF001
        }
        try:
            info["subject"] = parsed.subject.rfc4514_string()
            info["issuer"] = parsed.issuer.rfc4514_string()
        except Exception:
            pass
        if isinstance(public, rsa.RSAPublicKey):
            info["public_key_algorithm"] = "RSA"
            info["public_key_size"] = public.key_size
        elif isinstance(public, ec.EllipticCurvePublicKey):
            info["public_key_algorithm"] = "EC"
            info["public_key_size"] = public.curve.key_size
        elif isinstance(public, dsa.DSAPublicKey):
            info["public_key_algorithm"] = "DSA"
            info["public_key_size"] = public.key_size
        elif isinstance(public, ed25519.Ed25519PublicKey):
            info["public_key_algorithm"] = "Ed25519"
            info["public_key_size"] = 256
        not_after = getattr(parsed, "not_valid_after_utc", None) or parsed.not_valid_after.replace(
            tzinfo=timezone.utc
        )
        not_before = getattr(parsed, "not_valid_before_utc", None) or parsed.not_valid_before.replace(
            tzinfo=timezone.utc
        )
        info.update(_expiry_fields(not_after, not_before))
        info["is_self_signed"] = normalize_dn(info.get("subject")) == normalize_dn(info.get("issuer"))
        try:
            san = parsed.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            info["san"] = [f"DNS:{name}" if not str(name).startswith(("DNS:", "IP:")) else str(name) for name in san.get_values_for_type(x509.DNSName)]
            info["san"] += [f"IP:{ip}" for ip in san.get_values_for_type(x509.IPAddress)]
        except Exception:
            pass
        try:
            usage = parsed.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            flags = []
            for attr, name in (
                ("digital_signature", "digitalSignature"),
                ("content_commitment", "nonRepudiation"),
                ("key_encipherment", "keyEncipherment"),
                ("data_encipherment", "dataEncipherment"),
                ("key_agreement", "keyAgreement"),
                ("key_cert_sign", "keyCertSign"),
                ("crl_sign", "cRLSign"),
            ):
                if getattr(usage, attr, False):
                    flags.append(name)
            info["key_usage"] = flags
        except Exception:
            pass
        try:
            eku = parsed.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            info["extended_key_usage"] = [item._name for item in eku]  # noqa: SLF001
        except Exception:
            pass
        try:
            basic = parsed.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            info["is_ca"] = bool(basic.ca)
        except Exception:
            pass
        return info
    except Exception:
        return {}


def _merge_cert(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    for key, value in extra.items():
        if value in (None, "", []):
            continue
        current = base.get(key)
        if current in (None, "", [], "UNKNOWN"):
            base[key] = value
    return base


def parse_pem(text: str) -> list[dict[str, Any]]:
    certs: list[dict[str, Any]] = []
    for match in PEM_BLOCK.finditer(text or ""):
        pem = f"-----BEGIN CERTIFICATE-----{match.group(1)}-----END CERTIFICATE-----"
        try:
            der = ssl.PEM_cert_to_DER_cert(pem)
        except Exception:
            continue
        info = from_ssl_dict({}, der=der)
        info["pem"] = pem
        if b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" in der:
            info["public_key_algorithm"] = "RSA"
            info["signature_algorithm"] = info.get("signature_algorithm") or "sha256WithRSAEncryption"
        elif b"\x2a\x86\x48\xce\x3d\x02\x01" in der:
            info["public_key_algorithm"] = "EC"
        _merge_cert(info, openssl_parse(pem))
        _merge_cert(info, _cryptography_parse(pem))
        if info.get("subject") and info.get("issuer"):
            info["is_self_signed"] = normalize_dn(info["subject"]) == normalize_dn(info["issuer"])
        certs.append(info)
    return certs


def parse_der(der: bytes | None) -> dict[str, Any] | None:
    if not der:
        return None
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
    except Exception:
        return None
    parsed = parse_pem(pem)
    return parsed[0] if parsed else None


def hostname_matches(hostname: str, cert: dict[str, Any]) -> bool:
    host = (hostname or "").lower().split(":")[0]
    if not host:
        return False
    subject = normalize_dn(str(cert.get("subject") or "")).lower()
    if f"cn={host}" in subject.replace(" ", ""):
        return True
    for san in cert.get("san") or []:
        value = san.split(":", 1)[-1].lower()
        if value == host:
            return True
        if value.startswith("*.") and host.endswith(value[1:]):
            return True
    return False
