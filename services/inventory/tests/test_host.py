"""Synthetic Linux collection witnesses; not Windows/production qualification."""

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID

from inventory.host import collect
from shared_models.host_collection import HostInput, HostManifest, HostSnapshot, snapshot_findings, digest


def manifest(tmp_path, inputs=None, **kw):
    return HostManifest(
        approval_reference="change/HOST-17",
        host_id="payments-host-1",
        environment="test",
        platform="linux",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        inputs=inputs or [HostInput(input_id="config", kind="NGINX_TLS_CONFIG", path=str(tmp_path / "tls.conf"))],
        **kw,
    )


def certificate(algorithm="RSA2048"):
    key = (
        ec.generate_private_key(ec.SECP256R1())
        if algorithm == "ECDSA"
        else rsa.generate_private_key(public_exponent=65537, key_size=int(algorithm[3:]))
    )
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic.invalid")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.mark.parametrize("algorithm,size", [("RSA2048", 2048), ("RSA3072", 3072), ("ECDSA", 256)])
def test_public_certificate_is_metadata_not_runtime_or_policy(tmp_path, algorithm, size):
    path = tmp_path / "cert.pem"
    path.write_bytes(certificate(algorithm))
    snap = collect(manifest(tmp_path, [HostInput(input_id="cert", kind="PUBLIC_CERTIFICATE", path=str(path))]))
    fact = snap.receipts[0].facts[0]
    assert snap.receipts[0].status == "PARSED" and fact.key_size == size
    assert fact.runtime_use == fact.pqc_assessment == "UNKNOWN" and fact.policy_result == "NOT_EVALUATED"
    assert "BEGIN CERTIFICATE" not in snap.model_dump_json() and "synthetic.invalid" not in snap.model_dump_json()
    assert HostSnapshot.model_validate(snap.model_dump(mode="json")) == snap
    findings = snapshot_findings(snap, "a" * 36, "system-a")
    assert all(f["host_evidence"]["source_basis"] == "IMPORTED" for f in findings)


def test_approved_explicit_inputs_no_recursive_discovery_or_secret_text(tmp_path):
    (tmp_path / "tls.conf").write_text(
        "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers AES128-GCM-SHA256:AES256-GCM-SHA384:VENDOR_SECRET_VALUE;\npassword do-not-export-this;\n"
    )
    (tmp_path / "unapproved.pem").write_bytes(certificate())
    result = collect(manifest(tmp_path))
    assert len(result.receipts) == 1 and len(result.receipts[0].facts) == 1
    fact = result.receipts[0].facts[0]
    assert fact.protocols == ["TLSv1.2", "TLSv1.3"] and fact.unparsed_directives
    assert fact.local_basis == "DECLARED" and fact.algorithm == "UNKNOWN"
    assert fact.cipher_suites == ["AES128-GCM-SHA256", "AES256-GCM-SHA384"]
    assert not any(
        secret in result.model_dump_json() for secret in ("VENDOR_SECRET_VALUE", "do-not-export-this", "unapproved.pem")
    )


@pytest.mark.parametrize(
    "case,status,reason",
    [
        ("missing", "UNAVAILABLE", "NOT_FOUND"),
        ("key", "INVALID", "PRIVATE_MATERIAL_REFUSED"),
        ("bundle", "INVALID", "PRIVATE_MATERIAL_REFUSED"),
        ("unsupported", "UNSUPPORTED", "INVALID_FORMAT"),
        ("symlink", "UNSUPPORTED", "SYMLINK_OR_SPECIAL"),
        ("parent", "UNSUPPORTED", "SYMLINK_OR_SPECIAL"),
        ("fifo", "UNSUPPORTED", "SYMLINK_OR_SPECIAL"),
        ("hardlink", "UNSUPPORTED", "SYMLINK_OR_SPECIAL"),
        ("oversize", "BUDGET_EXCEEDED", "LIMIT"),
        ("denied", "DENIED", "ACCESS_DENIED"),
    ],
)
def test_negative_receipt_does_not_assert_an_insecure_or_secure_host(tmp_path, case, status, reason):
    p = tmp_path / "input"
    kind = "BINARY_METADATA"
    if case == "key":
        p.write_bytes(b"-----BEGIN PRIVATE KEY-----\nprivate-test-canary")
    if case == "bundle":
        p.write_bytes(certificate() + b"-----BEGIN PRIVATE KEY-----\nprivate-test-canary")
        kind = "PUBLIC_CERTIFICATE"
    if case == "unsupported":
        p.write_bytes(b"arbitrary input private-test-canary")
    if case == "symlink":
        p.symlink_to(tmp_path / "target")
        (tmp_path / "target").write_bytes(b"\x7fELF")
    if case == "parent":
        d = tmp_path / "real"
        d.mkdir()
        (d / "input").write_bytes(b"\x7fELF")
        (tmp_path / "alias").symlink_to(d)
        p = tmp_path / "alias" / "input"
    if case == "fifo":
        os.mkfifo(p)
    if case == "hardlink":
        (tmp_path / "real").write_bytes(b"\x7fELF")
        os.link(tmp_path / "real", p)
    if case == "oversize":
        p.write_bytes(b"x" * 100)
    m = manifest(
        tmp_path,
        [HostInput(input_id="input", kind=kind, path=str(p))],
        max_file_bytes=32 if case == "oversize" else 128,
    )
    if case == "bundle":
        m = m.model_copy(update={"max_file_bytes": 1048576})
    with (
        patch("inventory.host._read", side_effect=PermissionError())
        if case == "denied"
        else patch("inventory.host.elevated", return_value=False)
    ):
        snap = collect(m)
    receipt = snap.receipts[0]
    assert (receipt.status, receipt.reason) == (status, reason)
    assert receipt.facts == [] and receipt.content_sha256 is None and not snap.whole_host_coverage_verified
    assert "private-test-canary" not in snap.model_dump_json()


def test_failed_parse_consumes_shared_read_budget(tmp_path):
    paths = []
    for i in range(3):
        p = tmp_path / f"{i}.txt"
        p.write_bytes(b"x" * 16)
        paths.append(HostInput(input_id=f"f{i}", kind="BINARY_METADATA", path=str(p)))
    snap = collect(manifest(tmp_path, paths, max_total_bytes=32))
    assert [r.byte_count for r in snap.receipts] == [16, 16, 0]
    assert snap.receipts[-1].status == "BUDGET_EXCEEDED"


def test_package_or_binary_presence_never_means_algorithm_use(tmp_path):
    p = tmp_path / "status"
    p.write_text(
        "Package: openssl\nStatus: install ok installed\nVersion: 3.0.0~test\n\nPackage: removed\nStatus: deinstall ok config-files\nVersion: 1\n"
    )
    binary = tmp_path / "libssl.so"
    binary.write_bytes(b"\x7fELFexample-only-not-runtime-proof")
    snap = collect(
        manifest(
            tmp_path,
            [
                HostInput(input_id="packages", kind="DPKG_STATUS", path=str(p)),
                HostInput(input_id="library", kind="BINARY_METADATA", path=str(binary)),
            ],
        )
    )
    assert [r.status for r in snap.receipts] == ["PARSED", "PARSED"]
    facts = [f for r in snap.receipts for f in r.facts]
    assert facts[0].software_name == "openssl" and facts[0].software_version == "3.0.0~test"
    assert all(f.algorithm == f.runtime_use == "UNKNOWN" and f.key_size is None for f in facts)
    assert all(f["finding_type"] == "HOST_COLLECTION_RECEIPT" for f in snapshot_findings(snap, "a" * 36, "system-a"))


@pytest.mark.parametrize("case", ["elevated", "expired", "wrong_platform"])
def test_no_file_open_when_admission_refused(tmp_path, case):
    m = manifest(tmp_path)
    if case == "expired":
        m = m.model_copy(update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
    if case == "wrong_platform":
        m = m.model_copy(update={"platform": "windows"})
    with patch("inventory.host.elevated", return_value=case == "elevated"), patch("inventory.host._read") as read:
        result = collect(m)
    read.assert_not_called()
    assert result.receipts[0].facts == []
    assert not result.windows_execution_qualified and not result.production_execution_qualified


@pytest.mark.parametrize(
    "change",
    [
        "manifest_digest",
        "missing_receipt",
        "duplicate_receipt",
        "raw",
        "promote",
        "runtime",
        "positive_failure",
        "algorithm_presence",
        "policy",
        "size",
        "total",
    ],
)
def test_exact_contract_rejects_tampering_and_promotion(tmp_path, change):
    (tmp_path / "tls.conf").write_text("ssl_protocols TLSv1.2;")
    raw = collect(manifest(tmp_path)).model_dump(mode="json")
    if change == "manifest_digest":
        raw["manifest_sha256"] = "a" * 64
    if change == "missing_receipt":
        raw["receipts"] = []
    if change == "duplicate_receipt":
        raw["receipts"] *= 2
    if change == "raw":
        raw["receipts"][0]["raw_contents"] = "secret"
    if change == "promote":
        raw["host_identity_attested"] = True
    if change == "runtime":
        raw["receipts"][0]["facts"][0]["runtime_use"] = "OBSERVED"
    if change == "positive_failure":
        raw["receipts"][0]["status"] = "DENIED"
    if change == "algorithm_presence":
        raw["receipts"][0]["facts"][0]["algorithm"] = "RSA"
    if change == "policy":
        raw["receipts"][0]["facts"][0]["policy_result"] = "PASS"
    if change == "size":
        raw["receipts"][0]["facts"][0]["key_size"] = 2048
    if change == "total":
        raw["manifest"]["max_total_bytes"] = 1
        raw["manifest_sha256"] = digest(raw["manifest"])
    with pytest.raises(ValueError):
        HostSnapshot.model_validate(raw)


def test_file_mutation_during_read_is_not_a_positive_fact(tmp_path, monkeypatch):
    p = tmp_path / "binary"
    p.write_bytes(b"\x7fELFabc")
    original = os.read

    def read(fd, count):
        value = original(fd, count)
        if value:
            p.write_bytes(b"\x7fELFchanged")
        return value

    monkeypatch.setattr(os, "read", read)
    result = collect(manifest(tmp_path, [HostInput(input_id="race", kind="BINARY_METADATA", path=str(p))]))
    assert result.receipts[0].status == "INVALID" and result.receipts[0].reason == "INPUT_CHANGED"
    assert not result.receipts[0].facts


def test_unknown_public_key_implementation_is_unknown_not_algorithm_guess(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from cryptography.exceptions import UnsupportedAlgorithm

    def unsupported():
        raise UnsupportedAlgorithm("synthetic unsupported public-key implementation")

    monkeypatch.setattr(
        x509,
        "load_pem_x509_certificate",
        lambda _: SimpleNamespace(
            public_key=unsupported, signature_hash_algorithm=hashes.SHA256(), fingerprint=lambda _: b"a" * 32
        ),
    )
    p = tmp_path / "public.pem"
    p.write_bytes(certificate())
    snap = collect(manifest(tmp_path, [HostInput(input_id="unknown", kind="PUBLIC_CERTIFICATE", path=str(p))]))
    fact = snap.receipts[0].facts[0]
    assert fact.algorithm == fact.pqc_assessment == "UNKNOWN" and fact.key_size is None


def test_pqc_names_in_configuration_never_prove_pqc_deployment(tmp_path):
    (tmp_path / "tls.conf").write_text("ssl_ciphers ML-KEM-768:ML-DSA-65;\ninclude /unsupported/effective.conf;")
    fact = collect(manifest(tmp_path)).receipts[0].facts[0]
    assert fact.algorithm == fact.pqc_assessment == fact.runtime_use == "UNKNOWN"
    assert not fact.cipher_suites and fact.unparsed_directives


def test_cli_has_no_upload_and_refuses_output_overwrite(tmp_path):
    import subprocess
    import sys
    from pathlib import Path

    (tmp_path / "tls.conf").write_text("ssl_protocols TLSv1.2 TLSv1.3;")
    approved = tmp_path / "manifest.json"
    approved.write_text(manifest(tmp_path).model_dump_json())
    output = tmp_path / "snapshot.json"
    script = Path(__file__).resolve().parents[3] / "scripts" / "collect_host.py"
    first = subprocess.run(
        [sys.executable, str(script), "--manifest", str(approved), "--output", str(output)],
        capture_output=True,
        timeout=15,
    )
    assert first.returncode == 0, first.stderr
    assert HostSnapshot.model_validate_json(output.read_bytes()).receipts[0].status == "PARSED"
    original = output.read_bytes()
    second = subprocess.run(
        [sys.executable, str(script), "--manifest", str(approved), "--output", str(output)],
        capture_output=True,
        timeout=15,
    )
    assert second.returncode == 64 and output.read_bytes() == original
    assert output.stat().st_mode & 0o077 == 0


def test_unsupported_certificate_version_stays_a_receipt(tmp_path, monkeypatch):
    p = tmp_path / "public.pem"
    p.write_bytes(certificate())

    def unsupported(_):
        raise x509.InvalidVersion("synthetic unsupported version", 100)

    monkeypatch.setattr(x509, "load_pem_x509_certificate", unsupported)
    result = collect(manifest(tmp_path, [HostInput(input_id="unsupported", kind="PUBLIC_CERTIFICATE", path=str(p))]))
    assert result.receipts[0].status == "UNSUPPORTED" and not result.receipts[0].facts


def test_unavailable_privilege_api_does_not_assert_an_elevated_caller(tmp_path, monkeypatch):
    import ctypes

    monkeypatch.setattr(ctypes, "CDLL", lambda _: object())
    with patch("inventory.host._read") as read:
        result = collect(manifest(tmp_path))
    read.assert_not_called()
    assert result.receipts[0].reason == "LEAST_PRIVILEGE_UNPROVEN" and not result.receipts[0].facts


def test_ec_subject_key_does_not_establish_ecdsa_or_ecdh_use(tmp_path):
    subject = ec.generate_private_key(ec.SECP256R1())
    issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic.invalid")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(subject.public_key())
        .serial_number(2)
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(issuer, hashes.SHA256())
    )
    p = tmp_path / "ec-subject-rsa-signed.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    result = collect(manifest(tmp_path, [HostInput(input_id="ec-key", kind="PUBLIC_CERTIFICATE", path=str(p))]))
    fact = result.receipts[0].facts[0]
    assert fact.algorithm == "EC" and fact.key_size == 256 and fact.curve == "secp256r1"
    assert fact.certificate_signature_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256.dotted_string
    assert fact.runtime_use == "UNKNOWN" and fact.purpose == "PUBLIC_KEY_METADATA"
