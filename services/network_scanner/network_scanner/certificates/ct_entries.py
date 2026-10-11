"""Certificate-Transparency log entry ingestion (audit 63, round 34).

Certificate Transparency logs (RFC 6962) are the public, append-only
record of every TLS certificate a participating CA issues — the natural
backfill source for certificate inventory. The deployment-scoped part of
the original ask (a live poller pointed at a real log/monitor) stays
open; what ships here is the deterministic ingestion layer that such a
poller — or an operator with a log monitor export — feeds:

* ``parse_leaf_input`` — decode a CT ``get-entries`` ``leaf_input``
  (version 1 byte, entry type 2 bytes, then for ``x509_entry`` a 3-byte
  length + DER certificate, then 2-byte extension length + extensions).
  Precertificate entries (type 1) are reported as unsupported rather
  than half-parsed — their leaf carries only the TBSCertificate, and
  guessing the rest would fabricate inventory.
* ``ct_entry_to_payload`` — DER certificate -> inventory payload with
  SHA-256 fingerprint, subject/issuer/serial/validity, SANs, public key
  identity, and ``extra["ct"]`` provenance (log URL, entry index, entry
  type). Composite/hybrid detection rides along free on ingest.

Failures are explicit: every rejected entry comes back with a reason
(``malformed_leaf``, ``unsupported_precert``, ``not_a_certificate``), so
callers never lose count of what did not import.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
from typing import Any

ENTRY_X509 = 0
ENTRY_PRECERT = 1


class CtEntryError(ValueError):
    """One unparseable CT entry — carries a machine-readable reason."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.reason = reason


def _read_length3(data: bytes, offset: int) -> tuple[int, int]:
    """RFC 6962 3-byte length prefix; returns (length, next_offset)."""
    if offset + 3 > len(data):
        raise CtEntryError("malformed_leaf", "truncated 3-byte length")
    return int.from_bytes(data[offset:offset + 3], "big"), offset + 3


def parse_leaf_input(leaf_input: bytes) -> dict[str, Any]:
    """Decode one CT Merkle tree leaf.

    Returns ``{"version", "entry_type", "der"}`` for x509 entries.
    Precert leaves raise ``CtEntryError(unsupported_precert)``.
    """
    if len(leaf_input) < 3:
        raise CtEntryError("malformed_leaf", "leaf shorter than version+type")
    version = leaf_input[0]
    entry_type = int.from_bytes(leaf_input[1:3], "big")
    if entry_type == ENTRY_PRECERT:
        raise CtEntryError(
            "unsupported_precert",
            "precert leaves carry only the TBSCertificate; not guessed",
        )
    if entry_type != ENTRY_X509:
        raise CtEntryError("malformed_leaf", f"unknown entry_type {entry_type}")
    length, offset = _read_length3(leaf_input, 3)
    if offset + length > len(leaf_input):
        raise CtEntryError("malformed_leaf", "certificate shorter than declared")
    return {
        "version": version,
        "entry_type": entry_type,
        "der": leaf_input[offset:offset + length],
    }


def ct_entry_to_payload(
    entry: dict[str, Any],
    *,
    log_url: str | None = None,
) -> dict[str, Any]:
    """One CT entry (``leaf_input`` b64 + optional index) -> inventory payload.

    ``leaf_input`` may carry a base64 string or raw bytes. Raises
    ``CtEntryError`` with a stable reason for anything that cannot be
    parsed honestly.
    """
    from network_scanner.certificates.cert_parser import fingerprint_der

    leaf = entry.get("leaf_input")
    if isinstance(leaf, str):
        try:
            leaf = base64.b64decode(leaf, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CtEntryError("malformed_leaf", f"leaf_input not base64: {exc}") from exc
    if not leaf:
        raise CtEntryError("malformed_leaf", "empty leaf_input")

    parsed = parse_leaf_input(leaf)
    der = parsed["der"]

    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        raise CtEntryError("not_a_certificate", f"DER did not parse: {exc}") from exc

    def _dn(name: x509.Name | None) -> str | None:
        # a Name from a successfully parsed certificate renders; if parsing
        # had failed, load_der above already rejected the entry
        return name.rfc4514_string() if name is not None else None

    def _dt(value: datetime | None) -> str | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = []
        for name in san_ext.value:
            value = getattr(name, "value", name)  # GeneralName repr is not the value
            sans.append(f"{type(name).__name__.lower()}:{value}")
    except x509.ExtensionNotFound:
        sans = []

    public = cert.public_key()
    key_algorithm = type(public).__name__.replace("_", "").upper()
    key_size = getattr(public, "key_size", None)
    signature_algorithm = None
    try:
        signature_algorithm = cert.signature_algorithm_oid._name  # noqa: SLF001
    except Exception:
        signature_algorithm = None

    payload: dict[str, Any] = {
        "fingerprint_sha256": fingerprint_der(der),
        "subject": _dn(cert.subject),
        "issuer": _dn(cert.issuer),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": _dt(cert.not_valid_before_utc or cert.not_valid_before),
        "not_after": _dt(cert.not_valid_after_utc or cert.not_valid_after),
        "san": sans,
        "public_key_algorithm": key_algorithm if key_algorithm != "NONE" else None,
        "public_key_size": key_size,
        "signature_algorithm": signature_algorithm,
        "is_self_signed": _dn(cert.subject) == _dn(cert.issuer),
        "extra": {
            "ct": {
                "log": log_url,
                "index": entry.get("index"),
                "entry_type": "x509_entry",
                "source": "certificate-transparency",
            },
        },
    }
    return payload


def ingest_ct_entries(entries: list[dict[str, Any]], *, log_url: str | None = None) -> dict[str, Any]:
    """Parse a batch of CT entries; separate payloads from explicit skips.

    Deterministic, no I/O — the caller (API endpoint or a future poller)
    persists the payloads through the certificate repository.
    """
    payloads: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for i, entry in enumerate(entries):
        try:
            payloads.append(ct_entry_to_payload(entry, log_url=log_url))
        except CtEntryError as exc:
            skipped.append({
                "position": i,
                "index": entry.get("index"),
                "reason": exc.reason,
                "detail": str(exc),
            })
    return {"payloads": payloads, "skipped": skipped}
