"""AWS ACM certificate collector — real fingerprints, honest skips.

The PEM in these tests is generated locally with `cryptography` (our own
throwaway test key); the collector must compute the TRUE SHA-256 of the DER —
verified here against an independently computed fingerprint.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from inventory.cloud_kms import collect_aws_acm, normalize_acm_certificate


def _make_cert(cn: str = "api.bank.example", days: int = 90,
               sans: list[str] | None = None) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=days)
    # not_valid_before must always precede not_valid_after, even for
    # already-expired test certs
    not_before = not_after - timedelta(days=abs(days) + 2)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bank CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in (sans or [cn])]),
            critical=False,
        )
    )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(Encoding.PEM).decode()


def _detail(**overrides):
    base = {
        "CertificateArn": "arn:aws:acm:eu-central-1:111122223333:certificate/abc-123",
        "KeyAlgorithm": "EC_prime256v1",
        "SignatureAlgorithm": "SHA256WITHECDSA",
        "Type": "AMAZON_ISSUED",
        "Status": "ISSUED",
        "RenewalEligibility": "ELIGIBLE",
    }
    base.update(overrides)
    return base


def test_normalize_builds_true_fingerprint_and_shape():
    pem = _make_cert(sans=["api.bank.example", "www.bank.example"])
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    expected = x509.load_pem_x509_certificate(pem.encode()).fingerprint(hashes.SHA256()).hex()

    payload = normalize_acm_certificate(_detail(), pem=pem, region="eu-central-1")
    assert payload is not None
    assert payload["fingerprint_sha256"] == expected  # REAL fingerprint, not an id
    assert payload["public_key_algorithm"] == "ECDSA-P256"
    assert payload["public_key_size"] == 256
    assert sorted(payload["san"]) == ["api.bank.example", "www.bank.example"]
    assert payload["expiry_status"] == "valid"
    assert 0 < payload["days_until_expiry"] <= 90
    assert payload["extra"]["collector"] == "aws-acm"
    assert payload["extra"]["acm_type"] == "AMAZON_ISSUED"
    assert payload["usages"] == ["tls"]


def test_normalize_expired_and_self_signed():
    pem = _make_cert(days=-5)
    payload = normalize_acm_certificate(_detail(), pem=pem)
    assert payload["expiry_status"] == "expired"
    assert payload["days_until_expiry"] <= 0


def test_normalize_rejects_unknown_or_broken():
    assert normalize_acm_certificate(_detail(KeyAlgorithm="RSA_1024"),
                                     pem=_make_cert()) is None
    assert normalize_acm_certificate(_detail(CertificateArn=""), pem=_make_cert()) is None
    assert normalize_acm_certificate(_detail(), pem="not a pem") is None


def test_collect_acm_skips_pending_with_reason():
    issued_pem = _make_cert(cn="issued.bank.example")
    pending_arn = "arn:aws:acm:eu-central-1:111122223333:certificate/pending"

    class FakeAcm:
        def list_certificates(self):
            return {"CertificateSummaryList": [
                {"CertificateArn": "arn:issued", "DomainName": "issued.bank.example"},
                {"CertificateArn": pending_arn, "DomainName": "pending.bank.example"},
            ]}

        def describe_certificate(self, CertificateArn):
            if CertificateArn == pending_arn:
                return {"Certificate": _detail(CertificateArn=CertificateArn,
                                               Status="PENDING_VALIDATION")}
            return {"Certificate": _detail(CertificateArn=CertificateArn)}

        def get_certificate(self, CertificateArn):
            if CertificateArn == pending_arn:
                raise RuntimeError("Prohibited: certificate not issued")
            return {"Certificate": issued_pem}

    result = collect_aws_acm(FakeAcm(), region="eu-central-1")
    assert result["provider"] == "aws-acm"
    assert result["seen"] == 2 and result["truncated"] is False
    assert len(result["certificates"]) == 1
    assert result["certificates"][0]["extra"]["arn"] == "arn:issued"
    assert result["skipped"] == [
        {"ref": "pending.bank.example",
         "reason": "describe/pem failed: Prohibited: certificate not issued"}]


def test_collect_acm_denied_and_unsupported():
    class FakeAcm:
        def list_certificates(self):
            return {"CertificateSummaryList": [
                {"CertificateArn": "arn:denied", "DomainName": "denied.bank.example"},
                {"CertificateArn": "arn:weird", "DomainName": "weird.bank.example"},
            ]}

        def describe_certificate(self, CertificateArn):
            if CertificateArn == "arn:denied":
                raise RuntimeError("AccessDeniedException")
            return {"Certificate": _detail(CertificateArn=CertificateArn,
                                           KeyAlgorithm="RSA_1024")}

        def get_certificate(self, CertificateArn):
            return {"Certificate": _make_cert()}

    result = collect_aws_acm(FakeAcm())
    assert result["certificates"] == []
    assert result["skipped"][0]["ref"] == "denied.bank.example"
    assert "AccessDeniedException" in result["skipped"][0]["reason"]
    assert "RSA_1024" in result["skipped"][1]["reason"]


def test_collect_acm_requires_boto3_without_client(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "boto3", None)
    try:
        collect_aws_acm(None)
    except RuntimeError as exc:
        assert "pip install boto3" in str(exc)
