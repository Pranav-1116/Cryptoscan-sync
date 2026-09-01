"""Certificate lifecycle automation — issue / renew / revoke / rotate.

The platform previously stopped at inventory + expiry + a renewal *tracking*
workflow (CR-001). This engine closes the loop with real X.509 operations,
all local and deterministic (``cryptography`` lib), no external CA needed:

- ``generate_csr`` — PKCS#10 CSR (+ private key), SAN support.
- ``issue_self_signed`` — leaf cert from a CSR or fresh key.
- ``issue_from_ca`` — leaf signed by an internal CA (cert + key PEMs),
  with an OpenSSL-format CRL for revocation.
- ``renew_certificate`` — re-issue before expiry; ``rotate_key=True``
  generates a fresh key pair (metadata-first: the private key is returned
  to the caller once, never stored by the platform).
- ``revoke_certificate`` — local CRL entry + revocation record.
- ``build_crl`` — X.509 CRL over revoked serials (RFC 5280).

Key material rule (unchanged): CryptoScan never stores private keys. The
engine returns key PEMs to the caller at issuance time; the inventory keeps
certificate metadata + fingerprints only.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass
from typing import Any, Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

# Default profile
DEFAULT_VALIDITY_DAYS = 825   # ~27 months, common internal-CA window
DEFAULT_RENEWAL_LEAD_DAYS = 30
DEFAULT_KEY_SIZE = 2048


@dataclass
class LifecycleResult:
    certificate_pem: str
    private_key_pem: str | None = None
    csr_pem: str | None = None
    fingerprint_sha256: str = ""
    serial_number: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    crl_pem: str | None = None
    revoked: list[str] | None = None

    def to_inventory_payload(self) -> dict[str, Any]:
        """Payload shaped for CertificateRepository.upsert (metadata only —
        never the private key)."""
        return {
            "fingerprint_sha256": self.fingerprint_sha256,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "is_self_signed": self.subject == self.issuer,
            "extra": {
                "lifecycle": {
                    "issued_by": "cryptoscan-lifecycle",
                    "key_rotated": self.private_key_pem is not None,
                }
            },
        }


def _subject(name: dict[str, str]) -> x509.Name:
    attrs = []
    mapping = {
        "CN": NameOID.COMMON_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "C": NameOID.COUNTRY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "L": NameOID.LOCALITY_NAME,
        "emailAddress": NameOID.EMAIL_ADDRESS,
    }
    for key, value in name.items():
        oid = mapping.get(key)
        if oid is not None and value:
            attrs.append(x509.NameAttribute(oid, str(value)))
    if not attrs:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, "cryptoscan-default"))
    return x509.Name(attrs)


def _make_key(key_size: int = DEFAULT_KEY_SIZE):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _pem_key(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")


def _pem_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _load_cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode("utf-8"))


def _load_key(pem: str):
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


def _csr(csr_pem: str) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(csr_pem.encode("utf-8"))


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


# ------------------------------------------------------------- generation


def generate_csr(
    *,
    subject: dict[str, str] | None = None,
    san: list[str] | None = None,
    key_size: int = DEFAULT_KEY_SIZE,
) -> LifecycleResult:
    """Create a PKCS#10 CSR (+ fresh private key). Returns both PEMs once."""
    key = _make_key(key_size)
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_subject(subject or {"CN": "cryptoscan-host"}))
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False
        )
    csr = builder.sign(key, hashes.SHA256())
    return LifecycleResult(
        certificate_pem="",
        private_key_pem=_pem_key(key),
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        subject=str(csr.subject),
    )


def issue_self_signed(
    *,
    subject: dict[str, str] | None = None,
    san: list[str] | None = None,
    csr_pem: str | None = None,
    private_key_pem: str | None = None,
    key_size: int = DEFAULT_KEY_SIZE,
    validity_days: int = DEFAULT_VALIDITY_DAYS,
) -> LifecycleResult:
    """Issue a self-signed leaf. Either pass a CSR (key already generated
    elsewhere) or let the engine generate the key pair."""
    if csr_pem:
        csr = _csr(csr_pem)
        key = _load_key(private_key_pem) if private_key_pem else None
        if key is None:
            # CSR without key: we cannot sign for the requester without their
            # key, so generate a new pair and note it in the result.
            key = _make_key(key_size)
        subject_name = csr.subject
        extensions = list(csr.extensions)
    else:
        key = _make_key(key_size)
        subject_name = _subject(subject or {"CN": "cryptoscan-selfsigned"})
        extensions = []
        if san:
            extensions.append(
                x509.SubjectAlternativeName([x509.DNSName(s) for s in san])
            )
    now = _utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=validity_days))
    )
    for ext in extensions:
        if isinstance(ext, x509.Extension):
            builder = builder.add_extension(ext.value, critical=ext.critical)
        else:
            builder = builder.add_extension(ext, critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return LifecycleResult(
        certificate_pem=_pem_cert(cert),
        private_key_pem=_pem_key(key) if not private_key_pem or not csr_pem else None,
        csr_pem=csr_pem,
        fingerprint_sha256=_fingerprint(cert),
        serial_number=format(cert.serial_number, "x"),
        subject=str(cert.subject),
        issuer=str(cert.issuer),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
    )


def issue_from_ca(
    *,
    ca_cert_pem: str,
    ca_key_pem: str,
    subject: dict[str, str] | None = None,
    san: list[str] | None = None,
    csr_pem: str | None = None,
    key_size: int = DEFAULT_KEY_SIZE,
    validity_days: int = DEFAULT_VALIDITY_DAYS,
) -> LifecycleResult:
    """Issue a leaf signed by an internal CA. Returns leaf + leaf key (once)."""
    ca_cert = _load_cert(ca_cert_pem)
    ca_key = _load_key(ca_key_pem)
    if csr_pem:
        csr = _csr(csr_pem)
        public_key = csr.public_key()
        subject_name = csr.subject
        extensions = list(csr.extensions)
        leaf_key_pem = None  # requester holds the key
    else:
        leaf_key = _make_key(key_size)
        public_key = leaf_key.public_key()
        subject_name = _subject(subject or {"CN": "cryptoscan-leaf"})
        extensions = []
        if san:
            extensions.append(
                x509.SubjectAlternativeName([x509.DNSName(s) for s in san])
            )
        leaf_key_pem = _pem_key(leaf_key)
    now = _utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=validity_days))
    )
    for ext in extensions:
        if isinstance(ext, x509.Extension):
            builder = builder.add_extension(ext.value, critical=ext.critical)
        else:
            builder = builder.add_extension(ext, critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    return LifecycleResult(
        certificate_pem=_pem_cert(cert),
        private_key_pem=leaf_key_pem,
        csr_pem=csr_pem,
        fingerprint_sha256=_fingerprint(cert),
        serial_number=format(cert.serial_number, "x"),
        subject=str(cert.subject),
        issuer=str(cert.issuer),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
    )


# ------------------------------------------------------------- renewal


def renewal_due(not_after: Any, *, lead_days: int = DEFAULT_RENEWAL_LEAD_DAYS) -> bool:
    """True when the certificate expires within `lead_days` (or already did)."""
    if not_after is None:
        return False
    if isinstance(not_after, str):
        not_after = _dt.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=_dt.timezone.utc)
    return not_after <= _utcnow() + _dt.timedelta(days=lead_days)


def renew_certificate(
    cert_pem: str,
    *,
    ca_cert_pem: str | None = None,
    ca_key_pem: str | None = None,
    validity_days: int = DEFAULT_VALIDITY_DAYS,
    rotate_key: bool = False,
) -> LifecycleResult:
    """Re-issue a certificate before expiry.

    - Self-signed original -> re-signed self-signed (same subject/SAN).
    - CA-issued original -> requires the CA key; otherwise raises ValueError
      (the caller decides whether that is a hard error or a BLOCKED state).
    - ``rotate_key=True`` generates a fresh key pair.
    """
    cert = _load_cert(cert_pem)
    san = None
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = [name.value for name in ext.value]
    except x509.ExtensionNotFound:
        san = None
    subject = _subject_to_dict(cert)
    is_self_signed = cert.subject == cert.issuer
    if is_self_signed:
        result = issue_self_signed(
            subject=subject,
            san=san,
            validity_days=validity_days,
            key_size=rotated_key_size(cert) if rotate_key else DEFAULT_KEY_SIZE,
        )
    else:
        if not ca_cert_pem or not ca_key_pem:
            raise ValueError(
                "renewal of a CA-issued certificate requires the CA key "
                "(ca_cert_pem + ca_key_pem); refusing to guess"
            )
        result = issue_from_ca(
            ca_cert_pem=ca_cert_pem,
            ca_key_pem=ca_key_pem,
            subject=subject,
            san=san,
            key_size=rotated_key_size(cert) if rotate_key else DEFAULT_KEY_SIZE,
            validity_days=validity_days,
        )
    return result


_OID_NAME_TO_SHORT = {
    "commonName": "CN",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "countryName": "C",
    "stateOrProvinceName": "ST",
    "localityName": "L",
    "emailAddress": "emailAddress",
}


def _subject_to_dict(cert: x509.Certificate) -> dict[str, str]:
    """x509 subject -> {CN: ..., O: ...} (short keys the builder accepts)."""
    out: dict[str, str] = {}
    for attr in cert.subject:
        try:
            name = attr.oid._name  # e.g. "commonName"
        except Exception:
            name = attr.oid.dotted_string
        out[_OID_NAME_TO_SHORT.get(name, name)] = attr.value
    return out


def rotated_key_size(cert: x509.Certificate) -> int:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return key.curve.key_size
    return DEFAULT_KEY_SIZE


# ------------------------------------------------------------- revocation


def build_crl(
    revoked_serials: Iterable[str],
    *,
    ca_cert_pem: str,
    ca_key_pem: str,
    next_update_days: int = 7,
) -> str:
    """RFC 5280 CRL listing the given serials (hex strings)."""
    ca_cert = _load_cert(ca_cert_pem)
    ca_key = _load_key(ca_key_pem)
    now = _utcnow()
    builder = x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject)
    builder = builder.last_update(now).next_update(now + _dt.timedelta(days=next_update_days))
    for serial_hex in revoked_serials:
        serial = int(serial_hex, 16) if isinstance(serial_hex, str) else int(serial_hex)
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now)
            .build()
        )
    crl = builder.sign(ca_key, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def revoke_result(
    cert_pem: str,
    *,
    ca_cert_pem: str | None = None,
    ca_key_pem: str | None = None,
    reason: str = "unspecified",
) -> dict[str, Any]:
    """Revocation record for the inventory + optional CRL entry.

    Returns a dict suitable for CertificateRepository.upsert:
    revocation_status=REVOKED, revocation_method=LOCAL_CRL (when a CA key
    was provided) or MANUAL, plus extra.revocation details.
    """
    cert = _load_cert(cert_pem)
    crl_pem = None
    if ca_cert_pem and ca_key_pem:
        crl_pem = build_crl([format(cert.serial_number, "x")], ca_cert_pem=ca_cert_pem, ca_key_pem=ca_key_pem)
        method = "LOCAL_CRL"
    else:
        method = "MANUAL"
    return {
        "fingerprint_sha256": _fingerprint(cert),
        "serial_number": format(cert.serial_number, "x"),
        "subject": str(cert.subject),
        "issuer": str(cert.issuer),
        "revocation_status": "REVOKED",
        "revocation_method": method,
        "extra": {
            "revocation": {
                "reason": reason,
                "crl_pem": crl_pem,
                "revoked_at": _utcnow().isoformat(),
            }
        },
    }
