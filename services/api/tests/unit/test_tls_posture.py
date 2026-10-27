"""Serving-TLS posture inspection (deployment set, round 36)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from api.security.tls_posture import (
    inspect_tls_posture,
    production_tls_gate,
)


def _make_cert(key, *, days: int, cn: str = "api.cryproscan.internal",
               self_signed: bool = True, signer_key=None, signer_subject=None,
               not_before_days: int = 1):
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = subject if self_signed else signer_subject
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=not_before_days))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(signer_key or key, hashes.SHA256())
    )
    return builder


def _pem_pair(tmp_path, name, cert, key):
    cert_file = tmp_path / f"{name}.crt"
    key_file = tmp_path / f"{name}.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return str(cert_file), str(key_file)


@pytest.fixture()
def valid_pair(tmp_path):
    """A CA-signed serving pair: site CA + server certificate signed by it."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = _make_cert(ca_key, days=365, cn="site-ca.cryproscan.internal")
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = _make_cert(
        server_key, days=120, self_signed=False, signer_key=ca_key,
        signer_subject=ca_cert.subject)
    cert_file, key_file = _pem_pair(tmp_path, "server", server_cert, server_key)
    return cert_file, key_file, server_cert, server_key, ca_cert, ca_key


def _statuses(result):
    return {c["check"]: c["status"] for c in result["checks"]}


def test_valid_certificate_passes(valid_pair):
    cert_file, key_file, cert, _, ca_cert, _ca_key = valid_pair
    result = inspect_tls_posture(cert_file, key_file)
    assert result["status"] == "PASS"
    assert result["configured"] is True
    assert result["certificate"]["days_until_expiry"] == 119
    assert result["certificate"]["subject_alternative_names"] == [
        "api.cryproscan.internal"]
    assert result["certificate"]["public_key"]["size"] == 2048
    statuses = _statuses(result)
    assert statuses["certificate parses"] == "PASS"
    assert statuses["cert/key pairing"] == "PASS"
    assert statuses["expiry"] == "PASS"
    assert "mTLS" in result["note"]  # honest scope statement
    assert production_tls_gate(result) is None


def test_expired_certificate_fails_and_blocks_boot(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _make_cert(key, days=-3, not_before_days=10)
    cert_file, key_file = _pem_pair(tmp_path, "expired", cert, key)
    result = inspect_tls_posture(cert_file, key_file)
    assert result["status"] == "FAIL"
    expiry = next(c for c in result["checks"] if c["check"] == "expiry")
    assert expiry["status"] == "FAIL" and "EXPIRED" in expiry["detail"]
    error = production_tls_gate(result)
    assert error and "refusing to start" in error


def test_key_mismatch_is_caught(tmp_path):
    key_a = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_b = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _make_cert(key_a, days=90)
    cert_file, key_file = _pem_pair(tmp_path, "a", cert, key_b)
    result = inspect_tls_posture(cert_file, key_file)
    assert result["status"] == "FAIL"
    assert _statuses(result)["cert/key pairing"] == "FAIL"
    assert "does NOT match" in production_tls_gate(result)


def test_weak_key_is_warned(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    cert = _make_cert(key, days=90)
    cert_file, key_file = _pem_pair(tmp_path, "weak", cert, key)
    result = inspect_tls_posture(cert_file, key_file)
    assert _statuses(result)["key strength"] == "WARN"
    assert result["certificate"]["public_key"]["size"] == 1024
    assert result["status"] == "WARN"  # degraded, not broken
    assert production_tls_gate(result) is None  # boots, posture shows it


def test_half_configured_fails_fast(tmp_path):
    result = inspect_tls_posture(str(tmp_path / "x.crt"), "")
    assert result["status"] == "FAIL"
    assert _statuses(result)["cert/key pairing"] == "FAIL"


def test_unconfigured_is_honest_not_an_error():
    result = inspect_tls_posture("", "", "")
    assert result["configured"] is False
    assert result["status"] == "UNCONFIGURED"
    boundary = next(c for c in result["checks"]
                    if c["check"] == "app-boundary TLS")
    assert "reverse proxy" in boundary["detail"]
    assert production_tls_gate(result) is None  # proxy termination is legal


def test_missing_files_fail_cleanly(tmp_path):
    result = inspect_tls_posture(str(tmp_path / "nope.crt"),
                                 str(tmp_path / "nope.key"))
    assert result["status"] == "FAIL"
    assert _statuses(result)["certificate readable"] == "FAIL"
    assert _statuses(result)["private key readable"] == "FAIL"
    assert "not found" in production_tls_gate(result)


def test_trust_bundle_checked(valid_pair, tmp_path):
    cert_file, key_file, cert, _, ca_cert, _ca_key = valid_pair
    # a good bundle: one PEM certificate
    bundle = tmp_path / "ca.pem"
    bundle.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    result = inspect_tls_posture(cert_file, key_file, str(bundle))
    assert _statuses(result)["trust bundle"] == "PASS"
    # a bad bundle: not certificates at all
    junk = tmp_path / "junk.pem"
    junk.write_text("definitely not a certificate")
    result = inspect_tls_posture(cert_file, key_file, str(junk))
    assert _statuses(result)["trust bundle"] == "FAIL"
    # no bundle configured: informational, never a failure
    result = inspect_tls_posture(cert_file, key_file, "")
    assert _statuses(result)["trust bundle"] == "INFO"


def test_no_private_key_material_in_output(valid_pair):
    cert_file, key_file, _, key, _, _ = valid_pair
    result = inspect_tls_posture(cert_file, key_file)
    blob = repr(result)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    assert pem not in blob
    assert "BEGIN" not in blob
