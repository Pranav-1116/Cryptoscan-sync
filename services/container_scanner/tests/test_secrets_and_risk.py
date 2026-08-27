"""Secrets detection, risk verdicts, and scan telemetry for containers."""

from __future__ import annotations

from container_scanner.analyzers.secrets.secret_scanner import (
    scan_filesystem_for_secrets,
    scan_text_for_secrets,
    secret_findings,
)
from container_scanner.core.scanner import ContainerScanner
from container_scanner.core.telemetry import build_scan_telemetry
from container_scanner.reports.risk import algorithm_verdicts, build_risk_report

PEM_KEY_LINE = "-----BEGIN RSA PRIVATE KEY-----"
OPENSSH_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"


# --------------------------------------------------------------------------- #
# secret scanning (pure)
# --------------------------------------------------------------------------- #

def test_detects_pem_private_key():
    hits = scan_text_for_secrets(f"foo\n{PEM_KEY_LINE}\nMIIEow...\n", rel_path="keys/prod.pem")
    assert len(hits) == 1
    hit = hits[0]
    assert hit["kind"] == "pem-private-key" and hit["confidence"] == "HIGH"
    assert hit["line_number"] == 2 and hit["path"] == "keys/prod.pem"


def test_detects_openssh_and_putty_keys():
    hits = scan_text_for_secrets(f"{OPENSSH_KEY}\nb3BlbnNzaC1rZXktdjEAAAAA\n", rel_path="id_ed25519")
    assert hits[0]["kind"] == "pem-private-key"
    ppk = scan_text_for_secrets("PuTTY-User-KeyFile-2: ssh-rsa\n", rel_path="k.ppk")
    assert ppk[0]["kind"] == "putty-private-key"
    assert ppk[0]["confidence"] == "HIGH"


def test_detects_jwt_only_with_alg_header():
    hits = scan_text_for_secrets(f'token = "{JWT}"\n', rel_path="app/.env")
    assert len(hits) == 1 and hits[0]["kind"] == "jwt"
    assert hits[0]["confidence"] == "MEDIUM"
    # three base64url-looking segments that are NOT a JWT header -> no hit
    fake = "eyJxx not json.eyJzz.totally_fake_signature_value"
    assert scan_text_for_secrets(fake, rel_path="x") == []


def test_detects_aws_access_key_id():
    hits = scan_text_for_secrets("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", rel_path=".env")
    assert hits[0]["kind"] == "aws-access-key-id"
    assert "AKIAIOSFODNN7EXA" not in hits[0]["preview"]  # redacted
    assert hits[0]["preview"].startswith("AKIA") and "…" in hits[0]["preview"]


def test_clean_text_has_no_hits():
    text = "print('hello')\nENCRYPTION = AES\n"
    assert scan_text_for_secrets(text, rel_path="app.py") == []


# --------------------------------------------------------------------------- #
# secret scanning (filesystem filters)
# --------------------------------------------------------------------------- #

def test_filesystem_skips_binary_and_non_config_files(tmp_path):
    (tmp_path / "key.bin").write_bytes(b"\x00\x01" + PEM_KEY_LINE.encode() + b"\x00")
    (tmp_path / "photo.dat").write_text(PEM_KEY_LINE)
    assert scan_filesystem_for_secrets(tmp_path) == []


def test_filesystem_finds_env_secret(tmp_path):
    (tmp_path / ".env").write_text(f"PRIVATE=\n{PEM_KEY_LINE}\n")
    (tmp_path / "deploy.yaml").write_text(f"  key: |\n    {OPENSSH_KEY}\n")
    hits = scan_filesystem_for_secrets(tmp_path)
    kinds = sorted(hit["kind"] for hit in hits)
    assert kinds == ["pem-private-key", "pem-private-key"]
    assert {hit["path"] for hit in hits} == {".env", "deploy.yaml"}


def test_filesystem_skips_oversized_files(tmp_path):
    (tmp_path / "big.log").write_text(f"{PEM_KEY_LINE}\n" + "x" * (2 * 1024 * 1024))
    assert scan_filesystem_for_secrets(tmp_path) == []


def test_secret_findings_shape():
    raw = scan_text_for_secrets(PEM_KEY_LINE, rel_path="k.pem")
    findings = secret_findings(raw)
    finding = findings[0]
    assert finding["source"]["type"] == "CONTAINER_SECRET"
    assert finding["crypto"]["purpose"] == "KEY_MATERIAL"
    assert finding["metadata"]["is_hardcoded_key"] is True
    assert finding["metadata"]["confidence"] == "HIGH"
    assert finding["finding_id"]


# --------------------------------------------------------------------------- #
# risk report
# --------------------------------------------------------------------------- #

def test_algorithm_verdicts_ordered_by_severity():
    verdicts = algorithm_verdicts(["AES", "3DES", "RC4", "SHA-1"])
    assert verdicts["RC4"]["status"] == "DISALLOWED"
    assert verdicts["3DES"]["status"] == "DEPRECATED"
    assert list(verdicts)[0] == "RC4"  # most severe first


def test_risk_fail_on_disallowed_algorithm():
    report = build_risk_report(
        libraries=[{"name": "legacylib", "algorithms": ["AES", "RC4"]}],
    )
    assert report["posture"] == "FAIL"
    assert "DISALLOWED_ALGORITHM" in report["policy_issues"]
    assert report["disallowed_algorithms"] == ["RC4"]
    assert "RC4" in report["headline"]


def test_risk_fail_on_hardcoded_private_key():
    secrets = [{"kind": "pem-private-key", "confidence": "HIGH"}]
    report = build_risk_report(libraries=[{"name": "ok", "algorithms": ["AES"]}], secrets=secrets)
    assert report["posture"] == "FAIL"
    assert report["policy_issues"][0] == "HARDCODED_PRIVATE_KEY"
    assert "private key" in report["headline"]


def test_risk_warn_on_deprecated_library_and_cves():
    report = build_risk_report(
        libraries=[{"name": "pycrypto", "version": "2.6.1", "algorithms": ["AES"]}],
        vulnerabilities=[
            {"cve": "CVE-2013-1445", "package": "pycrypto", "severity": "MEDIUM"},
            {"cve": "CVE-2023-1", "package": "openssl", "severity": "HIGH"},
        ],
    )
    assert report["posture"] == "WARN"
    assert "DEPRECATED_CRYPTO_LIBRARY" in report["policy_issues"]
    assert "HIGH_CVE_PRESENT" in report["policy_issues"]
    assert report["deprecated_libraries"] == ["pycrypto"]
    assert report["cve_severity_counts"] == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "UNKNOWN": 0}
    assert report["vulnerable_packages"] == ["openssl", "pycrypto"]


def test_risk_critical_cve_beats_everything_but_keys():
    report = build_risk_report(
        libraries=[{"name": "lib", "algorithms": ["AES"]}],
        vulnerabilities=[{"cve": "CVE-2022-3602", "package": "openssl", "severity": "CRITICAL"}],
    )
    assert report["posture"] == "FAIL"
    assert report["policy_issues"][0] == "CRITICAL_CVE_PRESENT"


def test_risk_pass_on_clean_scan():
    report = build_risk_report(
        libraries=[{"name": "cryptography", "algorithms": ["AES", "ChaCha20"]}],
        binaries=[{"name": "libcrypto.so.3", "type": "shared-library", "algorithms": ["AES", "RSA"]}],
    )
    assert report["posture"] == "PASS"
    assert report["policy_issues"] == []
    assert report["headline"] is None
    assert report["counts"] == {"libraries": 1, "binaries": 1, "vulnerabilities": 0, "secrets": 0}


def test_risk_tokens_only_warn_not_fail():
    secrets = [{"kind": "jwt", "confidence": "MEDIUM"}]
    report = build_risk_report(libraries=[], secrets=secrets)
    assert report["posture"] == "WARN"
    assert "HARDCODED_TOKEN" in report["policy_issues"]


# --------------------------------------------------------------------------- #
# telemetry
# --------------------------------------------------------------------------- #

def test_telemetry_counts_and_hit_rate():
    telemetry = build_scan_telemetry(
        packages=[
            {"name": "a", "manager": "pip"},
            {"name": "b", "manager": "pip"},
            {"name": "c", "manager": "npm", "manifest": "package.json"},
        ],
        libraries=[{"name": "a"}],
        binaries=[
            {"type": "shared-library", "detection_method": "BINARY_FINGERPRINT"},
            {"type": "shared-library"},
            {"type": "jar"},
        ],
        vulnerabilities=[{"cve": "X"}],
        secrets=[{"kind": "jwt"}, {"kind": "jwt"}],
        files_scanned=42,
    )
    assert telemetry["packages_by_manager"] == {"npm": 1, "pip": 2}
    assert telemetry["manifests_parsed"] == 1
    assert telemetry["binaries_by_type"] == {"jar": 1, "shared-library": 2}
    assert telemetry["binaries_fingerprinted"] == 1
    assert telemetry["fingerprint_hit_rate"] == 0.333
    assert telemetry["secrets_by_kind"] == {"jwt": 2}
    assert telemetry["status"] == "OK"
    assert telemetry["files_scanned"] == 42


def test_telemetry_verdicts():
    assert build_scan_telemetry(packages=[], binaries=[], files_scanned=0)["status"] == "SKIPPED"
    assert build_scan_telemetry(packages=[], binaries=[], files_scanned=10)["status"] == "FAILED"
    # packages found but no crypto fingerprints matched
    assert build_scan_telemetry(packages=[{"name": "x", "manager": "pip"}], files_scanned=5)["status"] == "PARTIAL"


# --------------------------------------------------------------------------- #
# end-to-end through the scanner
# --------------------------------------------------------------------------- #

def test_scanner_end_to_end_risk_and_secrets(tmp_path):
    (tmp_path / "requirements.txt").write_text("pycrypto==2.6.1\n")
    (tmp_path / ".env").write_text(f"GATEWAY_KEY=\n{PEM_KEY_LINE}\n")
    (tmp_path / "package.json").write_text('{"dependencies": {}}\n')
    result = ContainerScanner().scan_filesystem(tmp_path)

    kinds = {secret["kind"] for secret in result["secrets"]}
    assert kinds == {"pem-private-key"}
    assert result["secrets"][0]["path"] == ".env"

    secret_sources = {
        finding["source"]["type"] for finding in result["findings"]
    }
    assert "CONTAINER_SECRET" in secret_sources
    hardcoded = [f for f in result["findings"] if f["metadata"]["is_hardcoded_key"]]
    assert hardcoded and hardcoded[0]["metadata"]["confidence"] == "HIGH"

    risk = result["risk_report"]
    assert risk["posture"] == "FAIL"
    assert "HARDCODED_PRIVATE_KEY" in risk["policy_issues"]
    assert risk["deprecated_libraries"] == ["pycrypto"]
    assert risk["vulnerable_packages"] == ["pycrypto"]

    telemetry = result["scan_telemetry"]
    assert telemetry["packages"] >= 1
    assert telemetry["packages_by_manager"].get("pip") == 1
    assert telemetry["files_scanned"] >= 3
    assert telemetry["secrets_by_kind"] == {"pem-private-key": 1}
