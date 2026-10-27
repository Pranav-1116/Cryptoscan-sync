"""§13/§14/§15 certificate intelligence, key metadata, trust stores."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from universal_crypto.certificate_intel import CertificateIntelligence


@pytest.fixture()
def rsa_cert_der() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "svc.internal")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("svc.internal")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                       critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_certificate_analysis(rsa_cert_der):
    result = CertificateIntelligence().analyze_certificate(
        der=rsa_cert_der, location="tls:svc.internal:443", asset_id="svc")
    assert result["subject"] == "CN=svc.internal"
    assert result["public_key_algorithm"] == "RSA"
    assert result["key_size"] == 2048
    assert result["signature_algorithm"] == "RSA-PSS"
    assert result["signature_hash"] == "SHA-256"
    assert result["expired"] is False
    assert result["is_ca"] is False
    assert result["self_signed"] is True
    assert result["san"] == ["DNS:svc.internal"]
    assert "serverAuth" in str(result["eku"])


def test_trust_anchor_detection(rsa_cert_der):
    result = CertificateIntelligence().analyze_certificate(
        der=rsa_cert_der, trust_anchor=True)
    assert result["trust_anchor"] is True


def test_key_metadata_rejects_secret_material():
    result = CertificateIntelligence().analyze_key_metadata({
        "key_id": "k1", "algorithm": "RSA", "private_key": "-----BEGIN..."})
    assert "error" in result
    assert "private_key" in result.get("fields", [])


def test_key_metadata_never_echoes_secrets():
    intel = CertificateIntelligence()
    result = intel.analyze_key_metadata({
        "key_id": "k1", "algorithm": "AES", "size": 256,
        "usage": "encryption", "location": "hsm-slot-3",
        "owner": "payments", "hardware_backed": True})
    assert result["algorithm"] == "AES"
    assert result["hardware_backed"] is True
    output = str(result)
    assert "hsm-slot-3" in output


def test_trust_store_detects_weak_and_duplicate_anchors():
    result = CertificateIntelligence().analyze_trust_store(
        store_name="system.jks",
        anchors=[
            {"subject": "CN=OldRoot", "expired": True,
             "signature_algorithm": "SHA1WithRSA", "public_key_algorithm": "RSA",
             "key_size": 1024, "application": "auth", "protocol": "TLS"},
            {"subject": "CN=OldRoot", "expired": True,
             "signature_algorithm": "SHA1WithRSA", "public_key_algorithm": "RSA",
             "key_size": 1024},
            {"subject": "CN=MD5Root", "expired": True,
             "signature_algorithm": "MD5WithRSA", "public_key_algorithm": "RSA",
             "key_size": 2048},
            {"subject": "CN=GoodRoot", "expired": False,
             "signature_algorithm": "SHA256WithRSA", "public_key_algorithm": "RSA",
             "key_size": 4096},
        ])
    types = {f["type"] for f in result["findings"]}
    assert {"expired_ca", "weak_signature", "deprecated_algorithm",
            "weak_key", "duplicate_trust_anchor"} <= types
    assert result["anchor_count"] == 4


def test_certificate_sources_discovery():
    sources = {
        "filesystem": [{"location": "/etc/ssl/certs/a.pem"}],
        "tls_endpoints": [{"endpoint": "payments.internal:443"}],
        "kubernetes_secrets": [{"namespace": "prod", "name": "tls-cert"}],
        "bogus_source": [{"x": 1}],  # ignored
    }
    rows = CertificateIntelligence().discover_sources(sources)
    assert len(rows) == 3
    assert {r["source"] for r in rows} == {
        "filesystem", "tls_endpoints", "kubernetes_secrets"}


def test_trust_store_unexpected_ca_and_untrusted_chain():
    result = CertificateIntelligence().analyze_trust_store(
        store_name="system.jks",
        expected_roots=["CN=GoodRoot"],
        anchors=[
            {"subject": "CN=GoodRoot", "expired": False,
             "signature_algorithm": "SHA256WithRSA", "public_key_algorithm": "RSA",
             "key_size": 4096},
            {"subject": "CN=RogueRoot", "expired": False,
             "signature_algorithm": "SHA256WithRSA", "public_key_algorithm": "RSA",
             "key_size": 2048},
            {"subject": "CN=BrokenChain", "expired": False,
             "status": "UNTRUSTED", "signature_algorithm": "SHA256WithRSA",
             "public_key_algorithm": "RSA", "key_size": 2048},
        ])
    types = {f["type"] for f in result["findings"]}
    assert "unexpected_ca" in types
    assert "untrusted_chain" in types
    unexpected = next(f for f in result["findings"] if f["type"] == "unexpected_ca")
    assert unexpected["subject"] == "CN=RogueRoot"


def test_trust_store_legacy_trust_dependency():
    result = CertificateIntelligence().analyze_trust_store(
        store_name="system.jks",
        anchors=[
            {"subject": "CN=OldRoot", "expired": True,
             "signature_algorithm": "SHA1WithRSA", "public_key_algorithm": "RSA",
             "key_size": 2048, "application": "legacy-banking"},
            {"subject": "CN=OldRoot2", "expired": False,
             "signature_algorithm": "MD5WithRSA", "public_key_algorithm": "RSA",
             "key_size": 2048, "protocol": "TLS"},
        ])
    types = {f["type"] for f in result["findings"]}
    assert "legacy_trust_dependency" in types
    dep = [f for f in result["findings"] if f["type"] == "legacy_trust_dependency"]
    assert len(dep) == 2
    assert "legacy-banking" in dep[0]["detail"]
