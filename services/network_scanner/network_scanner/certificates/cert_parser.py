"""Parse X.509 PEMs and live SSL peer certs without a hard cryptography dependency."""

from __future__ import annotations

import hashlib
import re
import ssl
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

PEM_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----",
    re.DOTALL,
)

_OPENSSL_DATE = "%b %d %H:%M:%S %Y %Z"


def fingerprint_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _parse_ssl_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).astimezone(timezone.utc)
    except Exception:
        pass
    try:
        return datetime.strptime(value, _OPENSSL_DATE).replace(tzinfo=timezone.utc)
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


def from_ssl_dict(cert: dict[str, Any] | None, *, der: bytes | None = None) -> dict[str, Any]:
    cert = cert or {}
    not_after = _parse_ssl_date(cert.get("notAfter"))
    not_before = _parse_ssl_date(cert.get("notBefore"))
    now = datetime.now(timezone.utc)
    days = None
    if not_after:
        days = int((not_after - now).total_seconds() // 86400)
    sans = []
    for kind, value in cert.get("subjectAltName") or []:
        sans.append(f"{kind}:{value}")
    subject = _name_from_tuples(cert.get("subject"))
    issuer = _name_from_tuples(cert.get("issuer"))
    expiry = "VALID"
    if days is None:
        expiry = "UNKNOWN"
    elif days < 0:
        expiry = "EXPIRED"
    elif days <= 7:
        expiry = "EXPIRING_CRITICAL"
    elif days <= 30:
        expiry = "EXPIRING_SOON"
    return {
        "fingerprint_sha256": fingerprint_der(der) if der else None,
        "subject": subject,
        "issuer": issuer,
        "serial_number": cert.get("serialNumber"),
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "days_until_expiry": days,
        "expiry_status": expiry,
        "san": sans,
        "is_self_signed": bool(subject and subject == issuer),
        "version": cert.get("version"),
    }


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
        # Best-effort algorithm from well-known OIDs in DER
        if b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" in der:
            info["public_key_algorithm"] = "RSA"
            info["signature_algorithm"] = info.get("signature_algorithm") or "sha256WithRSAEncryption"
        elif b"\x2a\x86\x48\xce\x3d\x02\x01" in der:
            info["public_key_algorithm"] = "EC"
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

            parsed = x509.load_pem_x509_certificate(pem.encode("utf-8"), default_backend())
            public = parsed.public_key()
            if isinstance(public, rsa.RSAPublicKey):
                info["public_key_algorithm"] = "RSA"
                info["public_key_size"] = public.key_size
            elif isinstance(public, ec.EllipticCurvePublicKey):
                info["public_key_algorithm"] = "EC"
                info["public_key_size"] = public.curve.key_size
            elif isinstance(public, dsa.DSAPublicKey):
                info["public_key_algorithm"] = "DSA"
                info["public_key_size"] = public.key_size
            not_after = getattr(parsed, "not_valid_after_utc", None) or parsed.not_valid_after.replace(
                tzinfo=timezone.utc
            )
            not_before = getattr(parsed, "not_valid_before_utc", None) or parsed.not_valid_before.replace(
                tzinfo=timezone.utc
            )
            info["not_after"] = not_after.isoformat()
            info["not_before"] = not_before.isoformat()
            info["days_until_expiry"] = int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400)
            days = info["days_until_expiry"]
            info["expiry_status"] = (
                "EXPIRED" if days < 0 else "EXPIRING_CRITICAL" if days <= 7 else "EXPIRING_SOON" if days <= 30 else "VALID"
            )
            try:
                info["subject"] = parsed.subject.rfc4514_string()
                info["issuer"] = parsed.issuer.rfc4514_string()
            except Exception:
                pass
            info["is_self_signed"] = info["subject"] == info["issuer"]
            info["serial_number"] = format(parsed.serial_number, "x")
        except Exception:
            pass
        certs.append(info)
    return certs


def hostname_matches(hostname: str, cert: dict[str, Any]) -> bool:
    host = (hostname or "").lower().split(":")[0]
    if not host:
        return False
    subject = str(cert.get("subject") or "").lower()
    if f"cn={host}" in subject.replace(" ", ""):
        return True
    for san in cert.get("san") or []:
        value = san.split(":", 1)[-1].lower()
        if value == host:
            return True
        if value.startswith("*.") and host.endswith(value[1:]):
            return True
    return False
