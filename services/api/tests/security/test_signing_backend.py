"""Where the report key lives, and what happens when it cannot be reached.

A bank's signing key belongs in an HSM or a KMS, not in a file beside the
process. The seam in ``api.security.signing_backend`` makes that a configuration
choice — and every backend that cannot work must refuse loudly rather than
quietly fall back to something weaker.

The AWS KMS test drives the real code path with an injected client: no network,
no credentials, but the exact call shape and the refusal handling are exercised.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from api.security.signing_backend import (
    AwsKmsSigner,
    FileSigner,
    SignerRefused,
    build_signer,
    report_signer_from_settings,
    scheme_of,
    signer_status,
)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


@pytest.fixture(scope="module")
def rsa_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def test_references_select_a_backend_by_scheme():
    assert scheme_of("/etc/cryptoscan/report.pem") == "file"
    assert scheme_of("-----BEGIN PRIVATE KEY-----\nabc") == "file"
    assert scheme_of("aws-kms://arn:aws:kms:eu-west-1:1:key/abc") == "aws-kms"
    assert scheme_of("vault://transit/cryptoscan/report") == "vault-transit"
    assert scheme_of("pkcs11:///usr/lib/softhsm/libsofthsm2.so?token=t&label=l") == "pkcs11"


def test_no_reference_means_no_signature_rather_than_a_weaker_one():
    assert build_signer("") is None


def test_a_pem_file_signs_and_verifies_through_the_report_path(rsa_key_pem, tmp_path):
    from reporting.signing import sign_report, verify_report

    key_file = tmp_path / "report.pem"
    key_file.write_text(rsa_key_pem)
    signer = build_signer(str(key_file), key_name="report-2026")

    report = sign_report({"scan": "s-1", "verdict": "FAIL"}, None, signer=signer)
    assert report["signature"]["alg"] == "RS256"
    assert report["signature"]["key_id"] == "report-2026"

    public_pem = (
        serialization.load_pem_private_key(rsa_key_pem.encode(), password=None)
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    assert verify_report(report, public_pem)["ok"] is True

    # and a tampered body no longer verifies
    report["verdict"] = "PASS"
    assert verify_report(report, public_pem)["ok"] is False


def test_aws_kms_signing_uses_the_pkcs1v15_algorithm_and_returns_raw_bytes():
    calls = []

    class FakeKms:
        def sign(self, **kwargs):
            calls.append(kwargs)
            return {"Signature": b"\x01\x02\x03"}

    signer = AwsKmsSigner(key_id_ref="arn:aws:kms:eu-west-1:111:key/abc")
    signer._client = FakeKms()  # injected: no network, real code path

    assert signer.sign(b"payload") == b"\x01\x02\x03"
    assert calls[0]["SigningAlgorithm"] == "RSASSA_PKCS1_V1_5_SHA_256"
    assert calls[0]["MessageType"] == "RAW"
    assert calls[0]["KeyId"] == "arn:aws:kms:eu-west-1:111:key/abc"


def test_aws_kms_refusal_is_a_refusal_not_an_empty_signature():
    class BrokenKms:
        def sign(self, **kwargs):
            raise RuntimeError("AccessDeniedException: not authorized to use this key")

    signer = AwsKmsSigner(key_id_ref="arn:aws:kms:eu-west-1:111:key/abc")
    signer._client = BrokenKms()
    with pytest.raises(SignerRefused, match="AccessDenied"):
        signer.sign(b"payload")


def test_aws_kms_without_a_key_id_is_refused_at_construction():
    with pytest.raises(SignerRefused, match="needs a key id"):
        build_signer("aws-kms://")


def test_vault_transit_without_coordinates_is_refused(monkeypatch):
    settings = SimpleNamespace(VAULT_ADDR="", VAULT_TOKEN="", VAULT_TIMEOUT_SECONDS=2)
    signer = build_signer("vault://transit/cryptoscan/report", settings=settings)
    assert isinstance(signer, object)
    with pytest.raises(SignerRefused, match="VAULT_ADDR and VAULT_TOKEN"):
        signer.sign(b"payload")


def test_pkcs11_without_its_module_refuses_instead_of_signing_elsewhere():
    signer = build_signer(
        "pkcs11:///nonexistent/libpkcs11.so?token=soft&label=report&pin=env:HOME"
    )
    with pytest.raises(SignerRefused, match="python-pkcs11"):
        signer.sign(b"payload")


def test_signer_status_reports_why_a_deployment_cannot_sign(monkeypatch):
    # The PIN is an indirection; an empty one is caught before any device is
    # touched, and the operator is told which variable to fill.
    monkeypatch.delenv("CRYPTOSCAN_HSM_PIN", raising=False)
    missing_pin = SimpleNamespace(
        REPORT_SIGNING_KEY="pkcs11:///nonexistent/lib.so?token=t&label=l&pin=env:CRYPTOSCAN_HSM_PIN"
    )
    status = signer_status(missing_pin)
    assert status["configured"] is True and status["usable"] is False
    assert "CRYPTOSCAN_HSM_PIN" in status["error"]

    # With the PIN present the next honest failure is the missing driver/module.
    monkeypatch.setenv("CRYPTOSCAN_HSM_PIN", "1234")
    status = signer_status(missing_pin)
    assert status["usable"] is False
    assert "python-pkcs11" in status["error"]

    empty = signer_status(SimpleNamespace(REPORT_SIGNING_KEY=""))
    assert empty == {"configured": False, "backend": None, "note": "reports carry no signature"}


def test_signer_status_proves_a_working_key_can_actually_sign(rsa_key_pem, tmp_path):
    key_file = tmp_path / "report.pem"
    key_file.write_text(rsa_key_pem)
    settings = SimpleNamespace(REPORT_SIGNING_KEY=str(key_file), REPORT_SIGNING_KEY_ID="k1")
    status = signer_status(settings)
    assert status["usable"] is True
    assert status["key_id"] == "k1"
    assert status["probe_bytes"] > 0


def test_report_signer_from_settings_reads_the_deployment_reference(rsa_key_pem, tmp_path):
    key_file = tmp_path / "report.pem"
    key_file.write_text(rsa_key_pem)
    settings = SimpleNamespace(REPORT_SIGNING_KEY=str(key_file), REPORT_SIGNING_KEY_ID=None)
    signer = report_signer_from_settings(settings)
    assert isinstance(signer, FileSigner)
    assert signer.key_id() is None
