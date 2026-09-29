"""Trust-store inventory — parse and audit root CA bundles.

Deterministically parses the trust stores an organization actually relies on:
- PEM bundles (``.crt``/``.pem`` concatenated CAs — container ``ca-certificates.crt``,
  OS ``/etc/ssl/certs``), and raw DER certs.
- Java ``cacerts`` (JKS keystore) — parsed via ``keytool`` if available; if the
  store is PEM/DER it is read directly. JKS binary is never silently guessed —
  we detect the magic header and report NEEDS_KEYTOOL when the JDK tool is
  absent (fail-closed, honest).

For each trust anchor we report subject/issuer/validity/key and flag:
- EXPIRED / EXPIRING roots
- SELF_SIGNED expected (roots are self-signed) but anything NOT self-signed in
  a trust store is anomalous (a leaf was shipped as an anchor)
- EXTRA/ROGUE roots: anchors whose subject+fingerprint are not on the approved
  baseline (pinned Mozilla/company list) — possible injected/rogue CA.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import datetime as dt
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.x509.oid import NameOID

_PEM_MARKER = b"-----BEGIN CERTIFICATE-----"
# Java KeyStore magic (0xFEEDFEED)
_JKS_MAGIC = b"\xfe\xed\xfe\xed"


class TrustStoreError(ValueError):
    pass


@dataclass
class TrustAnchor:
    subject: str
    issuer: str
    sha256_fingerprint: str
    not_before: str
    not_after: str
    days_until_expiry: int | None
    key_type: str
    key_bits: int | None
    self_signed: bool
    source: str
    issues: list[dict] = field(default_factory=list)


def _cn(name) -> str:
    try:
        return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        try:
            return name.rfc4514_string()
        except Exception:
            return "?"


def _cert_to_anchor(cert: x509.Certificate, source: str, now: dt.datetime) -> TrustAnchor:
    pk = cert.public_key()
    key_type = type(pk).__name__.replace("PublicKey", "").replace("EllipticCurve", "EC")
    try:
        bits = pk.key_size
    except Exception:
        bits = None
    days = (cert.not_valid_after_utc - now).days
    self_signed = cert.issuer == cert.subject
    issues: list[dict] = []
    if days < 0:
        issues.append({"severity": "HIGH", "code": "ROOT_EXPIRED",
                       "detail": f"trust anchor expired {-days} days ago"})
    elif days <= 90:
        issues.append({"severity": "MEDIUM", "code": "ROOT_EXPIRING",
                       "detail": f"trust anchor expires in {days} days"})
    if not self_signed:
        issues.append({"severity": "HIGH", "code": "NON_ROOT_ANCHOR",
                       "detail": "certificate in trust store is not self-signed (a leaf shipped as a root?)"})
    if "RSA" in key_type.upper() and (bits or 0) < 2048:
        issues.append({"severity": "HIGH", "code": "WEAK_ROOT_KEY",
                       "detail": f"RSA {bits}-bit root key"})
    fp = cert.fingerprint(__import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()).hex()
    return TrustAnchor(
        subject=_cn(cert.subject), issuer=_cn(cert.issuer), sha256_fingerprint=fp,
        not_before=cert.not_valid_before_utc.isoformat(), not_after=cert.not_valid_after_utc.isoformat(),
        days_until_expiry=days, key_type=key_type, key_bits=bits,
        self_signed=self_signed, source=source, issues=issues)


def parse_pem_bundle(data: bytes, source: str = "pem", now: dt.datetime | None = None) -> list[TrustAnchor]:
    reference = now or dt.datetime.now(dt.timezone.utc)
    anchors: list[TrustAnchor] = []
    # split on PEM blocks so a bundle with many Certs is handled
    for block in data.split(_PEM_MARKER):
        block = block.strip()
        if not block:
            continue
        pem = _PEM_MARKER + block
        if not pem.rstrip().endswith(b"-----END CERTIFICATE-----"):
            # trim any trailing non-cert text
            idx = pem.rfind(b"-----END CERTIFICATE-----")
            if idx != -1:
                pem = pem[: idx + len(b"-----END CERTIFICATE-----")]
        try:
            cert = x509.load_pem_x509_certificate(pem)
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            continue
        anchors.append(_cert_to_anchor(cert, source, reference))
    return anchors


def parse_der(data: bytes, source: str = "der", now: dt.datetime | None = None) -> list[TrustAnchor]:
    reference = now or dt.datetime.now(dt.timezone.utc)
    try:
        cert = x509.load_der_x509_certificate(data)
    except Exception as exc:
        raise TrustStoreError(f"not a valid DER certificate: {exc}") from exc
    return [_cert_to_anchor(cert, source, reference)]


def parse_jks(data: bytes, path: str, now: dt.datetime | None = None) -> list[TrustAnchor]:
    """Parse a Java cacerts JKS via the JDK ``keytool`` (no key material output)."""
    reference = now or dt.datetime.now(dt.timezone.utc)
    try:
        proc = subprocess.run(
            ["keytool", "-list", "-rfc", "-keystore", path, "-storepass", "changeit"],
            capture_output=True, timeout=30, check=False)
    except FileNotFoundError:
        raise TrustStoreError("JKS trust store detected but `keytool` (JDK) is not available")
    out = proc.stdout
    if b"BEGIN CERTIFICATE" not in out:
        # try without password output on stderr
        if proc.returncode != 0:
            raise TrustStoreError(f"keytool could not read JKS (rc={proc.returncode})")
    return parse_pem_bundle(out, source=Path(path).name, now=reference)


def inventory_path(path: str, now: dt.datetime | None = None) -> list[TrustAnchor]:
    """Auto-detect format from file content and parse a trust store."""
    p = Path(path)
    data = p.read_bytes()
    if data[:4] == _JKS_MAGIC:
        return parse_jks(data, path, now=now)
    if _PEM_MARKER in data:
        return parse_pem_bundle(data, source=p.name, now=now)
    # assume DER
    return parse_der(data, source=p.name, now=now)


def baseline_fingerprints(baseline_pem: bytes) -> set[str]:
    """Fingerprints of an approved baseline (e.g. Mozilla/PKIFB or company CA list)."""
    return {a.sha256_fingerprint for a in parse_pem_bundle(baseline_pem, source="baseline")}


def audit(anchors: Iterable[TrustAnchor], *, approved_fingerprints: set[str] | None = None,
          approved_subjects: set[str] | None = None) -> dict:
    """Flag extra/rogue roots and expiry issues across parsed anchors."""
    anchors = list(anchors)
    approved_fp = {f.lower() for f in (approved_fingerprints or set())}
    approved_sj = {s.lower() for s in (approved_subjects or set())}
    extra: list[dict] = []
    expired: list[dict] = []
    weak: list[dict] = []
    seen: set[str] = set()
    duplicates: list[str] = []

    for a in anchors:
        if a.sha256_fingerprint in seen:
            duplicates.append(a.subject)
        seen.add(a.sha256_fingerprint)
        is_approved = (a.sha256_fingerprint.lower() in approved_fp) if approved_fp else None
        if is_approved is False:
            extra.append({"subject": a.subject, "fingerprint": a.sha256_fingerprint,
                          "issuer": a.issuer, "reason": "anchor not present in approved baseline"})
        elif approved_sj and a.subject.lower() not in approved_sj and is_approved is not True:
            extra.append({"subject": a.subject, "fingerprint": a.sha256_fingerprint,
                          "issuer": a.issuer, "reason": "anchor subject not in approved list"})
        for issue in a.issues:
            if issue["code"] in ("ROOT_EXPIRED",):
                expired.append({"subject": a.subject, **issue})
            elif issue["severity"] in ("HIGH", "MEDIUM"):
                weak.append({"subject": a.subject, **issue})

    return {
        "total_anchors": len(anchors),
        "self_signed_roots": sum(1 for a in anchors if a.self_signed),
        "extra_or_rogue_roots": extra,
        "expired_roots": expired,
        "other_issues": weak,
        "duplicate_anchors": duplicates,
        "anchors": [
            {"subject": a.subject, "issuer": a.issuer,
             "sha256_fingerprint": a.sha256_fingerprint, "not_after": a.not_after,
             "days_until_expiry": a.days_until_expiry, "key_type": a.key_type,
             "key_bits": a.key_bits, "self_signed": a.self_signed, "source": a.source,
             "issues": a.issues} for a in anchors],
    }
