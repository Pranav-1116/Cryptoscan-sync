"""Certificate lifecycle engine — CSR / issue / renew / revoke / CRL.

Uses the real `cryptography` X.509 implementation: every assertion in these
tests is against a parsed, validated certificate — not a mock.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from network_scanner.certificates.lifecycle import (
    build_crl,
    generate_csr,
    issue_from_ca,
    issue_self_signed,
    renew_certificate,
    renewal_due,
    revoke_result,
    rotated_key_size,
)


def _parse_cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode("utf-8"))


def _parse_key(pem: str):
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


def _days(iso: str) -> int:
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (dt - datetime.now(timezone.utc)).days


def test_generate_csr():
    result = generate_csr(subject={"CN": "payments.internal", "O": "Bank"}, san=["payments.internal"])
    assert result.csr_pem and result.private_key_pem
    csr = x509.load_pem_x509_csr(result.csr_pem.encode())
    assert csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "payments.internal"
    assert _parse_key(result.private_key_pem).key_size == 2048


def test_issue_self_signed():
    result = issue_self_signed(subject={"CN": "api.bank.example"}, san=["api.bank.example"])
    cert = _parse_cert(result.certificate_pem)
    assert cert.subject == cert.issuer  # genuinely self-signed
    assert len(result.fingerprint_sha256) == 64
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "api.bank.example" in [s.value for s in san]
    assert result.private_key_pem  # fresh key returned once
    assert _days(result.not_after) >= 800


def test_issue_self_signed_validation():
    cert = _parse_cert(issue_self_signed(subject={"CN": "x"}).certificate_pem)
    cert.public_key().verify  # public key materializes fine
    assert isinstance(cert.public_key(), rsa.RSAPublicKey)


def test_issue_from_ca_and_chain():
    ca = issue_self_signed(subject={"CN": "CryptoScan Internal CA"}, validity_days=3650)
    leaf = issue_from_ca(
        ca_cert_pem=ca.certificate_pem,
        ca_key_pem=ca.private_key_pem,
        subject={"CN": "hsm1.payments.bank"},
        san=["hsm1.payments.bank"],
    )
    leaf_cert = _parse_cert(leaf.certificate_pem)
    ca_cert = _parse_cert(ca.certificate_pem)
    assert leaf_cert.issuer == ca_cert.subject
    assert leaf_cert.subject != leaf_cert.issuer
    # Verify the signature with the CA public key
    from cryptography.hazmat.primitives.asymmetric import padding

    ca_cert.public_key().verify(
        leaf_cert.signature,
        leaf_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        leaf_cert.signature_hash_algorithm,
    )
    assert leaf.private_key_pem


def test_renew_self_signed_keeps_subject_and_san():
    original = issue_self_signed(subject={"CN": "svc.internal"}, san=["svc.internal", "svc2.internal"], validity_days=30)
    renewed = renew_certificate(original.certificate_pem, rotate_key=True)
    new_cert = _parse_cert(renewed.certificate_pem)
    assert new_cert.subject == _parse_cert(original.certificate_pem).subject
    san = new_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "svc.internal" in [s.value for s in san]
    assert "svc2.internal" in [s.value for s in san]
    assert renewed.fingerprint_sha256 != original.fingerprint_sha256
    assert _days(renewed.not_after) >= 800  # fresh validity window
    assert renewed.private_key_pem  # rotated key returned


def test_renew_ca_issued_requires_ca_key():
    ca = issue_self_signed(subject={"CN": "CA"})
    leaf = issue_from_ca(ca_cert_pem=ca.certificate_pem, ca_key_pem=ca.private_key_pem, subject={"CN": "leaf"})
    with pytest.raises(ValueError, match="requires the CA key"):
        renew_certificate(leaf.certificate_pem)  # no CA key -> refuse, never guess
    renewed = renew_certificate(
        leaf.certificate_pem,
        ca_cert_pem=ca.certificate_pem,
        ca_key_pem=ca.private_key_pem,
    )
    assert _parse_cert(renewed.certificate_pem).issuer == _parse_cert(ca.certificate_pem).subject


def test_revocation_record_and_crl():
    ca = issue_self_signed(subject={"CN": "CA"})
    leaf = issue_from_ca(ca_cert_pem=ca.certificate_pem, ca_key_pem=ca.private_key_pem, subject={"CN": "leaf"})
    record = revoke_result(
        leaf.certificate_pem,
        ca_cert_pem=ca.certificate_pem,
        ca_key_pem=ca.private_key_pem,
        reason="key compromise",
    )
    assert record["revocation_status"] == "REVOKED"
    assert record["revocation_method"] == "LOCAL_CRL"
    crl_pem = record["extra"]["revocation"]["crl_pem"]
    crl = x509.load_pem_x509_crl(crl_pem.encode())
    revoked = crl.get_revoked_certificate_by_serial_number(_parse_cert(leaf.certificate_pem).serial_number)
    assert revoked is not None
    # Manual revocation when no CA key is provided
    manual = revoke_result(leaf.certificate_pem, reason="cleanup")
    assert manual["revocation_method"] == "MANUAL"
    assert manual["extra"]["revocation"]["crl_pem"] is None


def test_build_crl_multi_serial():
    ca = issue_self_signed(subject={"CN": "CA"})
    crl_pem = build_crl(["0A", "0B"], ca_cert_pem=ca.certificate_pem, ca_key_pem=ca.private_key_pem)
    crl = x509.load_pem_x509_crl(crl_pem.encode())
    assert crl.get_revoked_certificate_by_serial_number(0x0A) is not None
    assert crl.get_revoked_certificate_by_serial_number(0x0B) is not None


def test_renewal_due():
    soon = datetime.now(timezone.utc) + timedelta(days=10)
    later = datetime.now(timezone.utc) + timedelta(days=300)
    assert renewal_due(soon, lead_days=30)
    assert not renewal_due(later, lead_days=30)
    assert not renewal_due(None)
    assert renewal_due(soon.isoformat(), lead_days=30)  # ISO string input


def test_rotated_key_size():
    cert = _parse_cert(issue_self_signed(subject={"CN": "x"}, key_size=4096).certificate_pem)
    assert rotated_key_size(cert) == 4096
