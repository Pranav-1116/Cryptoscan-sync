"""Certificate metadata collection
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md — OS-CRYPTO-008's
source, §7).

Certificates are PUBLIC objects: subject, issuer, validity dates,
thumbprint and PUBLIC key metadata are observable facts (evidence
class 'observed'). Private keys are NEVER collected, exported,
displayed or stored (§7) — no PEM private key, no PFX, no key
container content is ever read.

Two input formats normalize into ONE canonical certificate dict:
  - `openssl x509 -noout -subject -issuer -dates -fingerprint
     -sha256` plus an optional 'Public-Key: (N bit)' line  (Linux,
     macOS — the same OpenSSL output on both)
  - `certutil -store` certificate blocks (Windows)

Provenance discipline: a certificate without parseable validity dates
has UNKNOWN validity — 'unknown' is never 'not expired' (§2.1).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

MAX_CERTS = 1024
MAX_LINE = 4096


@dataclass
class CertificateRecord:
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    thumbprint_sha256: str = ""
    public_key_algorithm: str = ""
    public_key_bits: Optional[int] = None
    evidence_class: str = "observed"
    evidence_source: str = ""
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "thumbprint_sha256": self.thumbprint_sha256,
            "public_key_algorithm": self.public_key_algorithm,
            "public_key_bits": self.public_key_bits,
            "evidence_class": self.evidence_class,
            "evidence_source": self.evidence_source,
            "limitations": list(self.limitations),
        }


_STANDARD_LIMITATIONS = [
    "public certificate metadata only — private key material is "
    "NEVER collected, exported, displayed or stored (§7)",
    "a certificate's metadata says nothing about how its private key "
    "is protected or where it is used (§2.2)"]


_OPENSSL_FIELD = {
    "subject": "subject",
    "issuer": "issuer",
    "notbefore": "not_before",
    "notafter": "not_after",
}


def parse_openssl_x509(text: str) -> List[CertificateRecord]:
    """Parse one or more `openssl x509 -noout ...` output blocks.

    Blocks are separated by any line that starts a new subject= or by
    a '---' separator. Malformed fields are left empty — never
    guessed."""
    records: List[CertificateRecord] = []
    current: Optional[CertificateRecord] = None

    def flush() -> None:
        nonlocal current
        if current is not None and (current.subject or current.issuer
                                    or current.thumbprint_sha256):
            if len(records) < MAX_CERTS:
                records.append(current)
        current = None

    for raw in text.splitlines()[:MAX_CERTS * 24]:
        line = raw.strip()[:MAX_LINE]
        if not line or set(line) <= {"-"}:
            continue
        low = line.lower()
        if low.startswith("subject="):
            flush()
            current = CertificateRecord(evidence_source="openssl x509")
            current.subject = line.partition("=")[2].strip()
            continue
        if current is None:
            continue
        if low.startswith("issuer="):
            current.issuer = line.partition("=")[2].strip()
        elif low.startswith("notbefore="):
            current.not_before = line.partition("=")[2].strip()
        elif low.startswith("notafter="):
            current.not_after = line.partition("=")[2].strip()
        elif "fingerprint=" in low:
            value = line.partition("=")[2].strip()
            current.thumbprint_sha256 = value.replace(":", "").upper()
        elif "public-key:" in low:
            m = re.search(r"\((\d+)\s*bit\)", line)
            if m:
                current.public_key_bits = int(m.group(1))
                current.public_key_algorithm = "RSA" \
                    if "rsa" in low else ("unknown")
        elif low.startswith("pub:") or "public key algorithm" in low:
            current.public_key_algorithm = \
                line.partition(":")[2].strip() or "unknown"
    flush()
    for record in records:
        record.limitations = list(_STANDARD_LIMITATIONS)
        if not record.thumbprint_sha256:
            record.limitations.append(
                "no SHA-256 thumbprint in the source — the certificate "
                "identity is UNKNOWN, never guessed")
        if not record.not_after:
            record.limitations.append(
                "validity dates unavailable from this source — "
                "expiration state is UNKNOWN, never 'not expired' "
                "(§2.1)")
    return records


_CERTUTIL_FIELD = {
    "subject": "subject",
    "issuer": "issuer",
    "notbefore": "not_before",
    "notafter": "not_after",
}


def parse_certutil_store(text: str) -> List[CertificateRecord]:
    """Parse `certutil -store` certificate blocks (Windows).

    Each block starts at '================ Certificate N ============'
    and carries Serial Number / Subject / Issuer / NotBefore /
    NotAfter / Cert Hash(sha256) lines. Private key presence flags are
    metadata ONLY — no key content is ever read (§7)."""
    records: List[CertificateRecord] = []
    current: Optional[CertificateRecord] = None
    for raw in text.splitlines()[:MAX_CERTS * 30]:
        line = raw.strip()[:MAX_LINE]
        if re.match(r"^=+\s*Certificate\s+\d+\s*=+$", line):
            if current is not None and len(records) < MAX_CERTS:
                records.append(current)
            current = CertificateRecord(
                evidence_source="certutil -store")
            continue
        if current is None or not line:
            continue
        if ":" not in line:
            if "private key" in line.lower():
                current.limitations.append(
                    f"certificate store reports {line!r} — a presence "
                    "flag only; private key material is NEVER "
                    "collected (§7)")
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key in _CERTUTIL_FIELD:
            setattr(current, _CERTUTIL_FIELD[key], value)
        elif key.startswith("cert hash"):
            current.thumbprint_sha256 = value.replace(":", "").upper()
        elif key == "public key algorithm":
            current.public_key_algorithm = value or "unknown"
        elif key == "public key length":
            m = re.search(r"(\d+)", value)
            if m:
                current.public_key_bits = int(m.group(1))
        elif "private key" in key:
            # a presence FLAG only — never any key content (§7)
            current.limitations.append(
                f"certificate store reports '{key}: {value}' — a "
                "presence flag only; private key material is NEVER "
                "collected (§7)")
    if current is not None and len(records) < MAX_CERTS:
        records.append(current)
    for record in records:
        merged = list(_STANDARD_LIMITATIONS)
        merged.extend(record.limitations)
        record.limitations = merged
        if not record.not_after:
            record.limitations.append(
                "validity dates unavailable from this source — "
                "expiration state is UNKNOWN, never 'not expired' "
                "(§2.1)")
    return records


def build_certificates(source_name: str, text: str
                       ) -> List[Dict[str, Any]]:
    """Dispatch by source name into the canonical list."""
    if source_name == "certutil_store":
        records = parse_certutil_store(text)
    else:
        records = parse_openssl_x509(text)
    return [r.as_dict() for r in records]
