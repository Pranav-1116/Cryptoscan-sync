"""Certificate and key-material inspection (§4 Stage 6).

Public certificate metadata is extracted and reported. PRIVATE KEY
handling has a strict boundary: never export, display or store
private-key contents as ordinary findings — only a protected detection
event with location and classification. An arbitrary high-entropy byte
sequence is NEVER interpreted as a key without structural evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_PEM_CERT = re.compile(
    rb"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----")
_PEM_PRIVATE = re.compile(
    rb"-----BEGIN ([A-Z ]*PRIVATE KEY)-----")

_MAX_PEM_SCAN = 32 * 1024 * 1024   # bounded scan
_MAX_CERTS = 64


@dataclass
class CertificateRecord:
    certificate_type: str            # "pem" | "der"
    fingerprint_sha256: str
    subject: str = ""
    issuer: str = ""
    not_valid_before: Optional[str] = None
    not_valid_after: Optional[str] = None
    public_key_algorithm: str = ""
    public_key_bits: Optional[int] = None   # unknown stays None
    signature_algorithm: str = ""
    parse_status: str = "parsed"
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "certificate_type": self.certificate_type,
            "fingerprint_sha256": self.fingerprint_sha256,
            "subject": self.subject, "issuer": self.issuer,
            "not_valid_before": self.not_valid_before,
            "not_valid_after": self.not_valid_after,
            "public_key_algorithm": self.public_key_algorithm,
            "public_key_bits": self.public_key_bits,
            "signature_algorithm": self.signature_algorithm,
            "parse_status": self.parse_status,
            "limitations": self.limitations,
        }


@dataclass
class PrivateKeyDetection:
    """A protected detection event: presence and location only. The
    secret itself is never a finding, never logged, never stored."""
    location: str
    classification: str
    note: str = ("private key material detected — presence and location "
                 "recorded only; contents are never exported, displayed "
                 "or stored as a finding (§6)")

    def as_dict(self) -> Dict[str, Any]:
        return {"location": self.location, "classification": self.classification,
                "note": self.note}


def _cert_metadata(der: bytes, cert_type: str) -> CertificateRecord:
    import hashlib
    fingerprint = hashlib.sha256(der).hexdigest()
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        cert = x509.load_der_x509_certificate(der)
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            algo, bits = "RSA", public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            algo, bits = "EC", public_key.key_size
        else:
            algo, bits = type(public_key).__name__, None
        return CertificateRecord(
            certificate_type=cert_type,
            fingerprint_sha256=fingerprint,
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_valid_before=cert.not_valid_before_utc.isoformat(),
            not_valid_after=cert.not_valid_after_utc.isoformat(),
            public_key_algorithm=algo,
            public_key_bits=bits,
            signature_algorithm=cert.signature_algorithm_oid._name,
        )
    except Exception as exc:                      # pragma: no cover - defensive
        return CertificateRecord(
            certificate_type=cert_type,
            fingerprint_sha256=fingerprint,
            parse_status="unparsable",
            limitations=[f"certificate structure not parsable: {type(exc).__name__} "
                         "— metadata is unknown, never guessed"])


def inspect_certificates(data: bytes) -> Tuple[List[CertificateRecord],
                                               List[PrivateKeyDetection]]:
    """Extract public certificate metadata and PRIVATE-KEY PRESENCE
    events. Key contents are never returned."""
    import base64
    records: List[CertificateRecord] = []
    private_events: List[PrivateKeyDetection] = []
    scan = data[:_MAX_PEM_SCAN]

    for match in _PEM_CERT.finditer(scan):
        if len(records) >= _MAX_CERTS:
            break
        body = re.sub(rb"\s", b"", match.group(1))
        try:
            der = base64.b64decode(body, validate=True)
        except Exception:
            records.append(CertificateRecord(
                certificate_type="pem",
                fingerprint_sha256="unavailable",
                parse_status="unparsable",
                limitations=["PEM body did not decode — unknown, never guessed"]))
            continue
        records.append(_cert_metadata(der, "pem"))

    for match in _PEM_PRIVATE.finditer(scan):
        private_events.append(PrivateKeyDetection(
            location=f"byte offset {match.start()}",
            classification=match.group(1).decode("ascii", "replace")))

    return records, private_events
