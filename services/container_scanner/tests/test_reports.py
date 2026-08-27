"""Container reports: CycloneDX SBOM, scan drift, Prometheus metrics."""

from __future__ import annotations

from container_scanner.reports.metrics import render_prometheus
from container_scanner.reports.sbom import build_sbom
from container_scanner.reports.scan_drift import diff_scans


def _scan(packages=None, vulns=None, secrets=None, binaries=None, libraries=None, scan_id="s", posture="PASS"):
    return {
        "scan_id": scan_id,
        "target": "registry.local/app:1.0",
        "target_kind": "registry",
        "packages": packages or [],
        "libraries": libraries or [],
        "binaries": binaries or [],
        "vulnerabilities": vulns or [],
        "secrets": secrets or [],
        "risk_report": {"posture": posture, "cve_severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}},
        "scan_telemetry": {"status": "OK"},
    }


# --------------------------------------------------------------------------- #
# SBOM
# --------------------------------------------------------------------------- #

def test_sbom_shape_and_purls():
    sbom = build_sbom(
        _scan(
            packages=[
                {"name": "cryptography", "version": "41.0.7", "manager": "pip"},
                {"name": "@scope/pkg", "version": "1.2.3", "manager": "npm"},
                {"name": "libssl3", "version": "3.0.7", "manager": "dpkg"},
                {"name": "openssl", "version": "3.0.7", "manager": "apk"},
            ],
            libraries=[{"name": "cryptography", "vendor": "pyca", "algorithms": ["AES", "RSA"], "deprecated": False}],
            binaries=[{"name": "libcrypto.so.3", "path": "usr/lib/libcrypto.so.3", "type": "shared-library", "sha256": "ab" * 32}],
        )
    )
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    assert sbom["serialNumber"].startswith("urn:uuid:")
    assert sbom["metadata"]["component"]["type"] == "container"  # target_kind=registry
    purls = {component["purl"] for component in sbom["components"] if "purl" in component}
    assert "pkg:pypi/cryptography@41.0.7" in purls
    assert "pkg:npm/%40scope/pkg@1.2.3" in purls  # npm scope must be %40-escaped
    assert "pkg:deb/debian/libssl3@3.0.7" in purls
    assert "pkg:apk/openssl@3.0.7" in purls
    # crypto library properties ride along
    crypto = next(c for c in sbom["components"] if c["name"] == "cryptography")
    props = {p["name"]: p["value"] for p in crypto["properties"]}
    assert props["cryptoscan:crypto-library"] == "true"
    assert props["cryptoscan:vendor"] == "pyca"
    # binary component carries its hash
    binary = next(c for c in sbom["components"] if c["name"] == "libcrypto.so.3")
    assert binary["hashes"] == [{"alg": "SHA-256", "content": "ab" * 32}]


def test_sbom_vulnerabilities_link_to_components():
    sbom = build_sbom(
        _scan(
            packages=[{"name": "openssl", "version": "3.0.6", "manager": "apk"}],
            vulns=[{"cve": "CVE-2022-3602", "package": "openssl", "severity": "HIGH", "summary": "buffer overflow"}],
        )
    )
    vuln = sbom["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2022-3602"
    assert vuln["ratings"][0]["severity"] == "high"
    assert vuln["affects"][0]["ref"] == "pkg:apk/openssl@3.0.6"
    assert vuln["description"].startswith("buffer overflow")


def test_sbom_omits_unknown_version_and_handles_empty():
    sbom = build_sbom(_scan(packages=[{"name": "noversion", "manager": "pip"}]))
    assert all("@" not in c["purl"].split("pkg:pypi/")[-1] for c in sbom["components"])
    empty = build_sbom(None)
    assert empty["components"] == [] and empty["vulnerabilities"] == []
    assert empty["metadata"]["component"]["type"] == "file"  # filesystem default


# --------------------------------------------------------------------------- #
# drift
# --------------------------------------------------------------------------- #

def test_drunchanged_on_identical_scans():
    scan = _scan(packages=[{"name": "openssl", "version": "3.0.7", "manager": "apk"}])
    assert diff_scans(scan, _scan(packages=[{"name": "openssl", "version": "3.0.7", "manager": "apk"}]))["verdict"] == "UNCHANGED"


def test_drift_new_cve_is_regression():
    report = diff_scans(
        _scan(packages=[{"name": "openssl", "version": "3.0.7", "manager": "apk"}]),
        _scan(
            packages=[{"name": "openssl", "version": "3.0.7", "manager": "apk"}],
            vulns=[{"cve": "CVE-2023-0286", "package": "openssl", "severity": "HIGH"}],
        ),
    )
    assert report["verdict"] == "REGRESSED"
    assert report["changes"][0]["type"] == "NEW_CVE"
    assert report["changes"][0]["severity"] == "HIGH"
    assert report["summary"]["new_cves"] == 1


def test_drift_resolved_cve_is_improvement():
    report = diff_scans(
        _scan(packages=[{"name": "openssl", "manager": "apk"}], vulns=[{"cve": "CVE-2022-3602", "package": "openssl", "severity": "HIGH"}]),
        _scan(packages=[{"name": "openssl", "manager": "apk"}]),
    )
    assert report["verdict"] == "IMPROVED"
    assert report["summary"]["resolved_cves"] == 1


def test_drift_package_and_binary_changes():
    report = diff_scans(
        _scan(
            packages=[
                {"name": "old", "version": "1.0", "manager": "pip"},
                {"name": "kept", "version": "2.0", "manager": "pip"},
            ],
            binaries=[{"path": "usr/lib/libgcrypt.so.20"}],
        ),
        _scan(
            packages=[
                {"name": "kept", "version": "2.1", "manager": "pip"},
                {"name": "new", "version": "1.0", "manager": "npm"},
            ],
            binaries=[{"path": "usr/lib/libcrypto.so.3"}],
        ),
    )
    types = [change["type"] for change in report["changes"]]
    assert "PACKAGE_ADDED" in types and "PACKAGE_REMOVED" in types
    assert "PACKAGE_VERSION_CHANGED" in types
    assert "CRYPTO_BINARY_ADDED" in types and "CRYPTO_BINARY_REMOVED" in types
    assert report["verdict"] == "UNCHANGED"  # info-level churn is not regression


def test_drift_new_secret_is_critical():
    report = diff_scans(
        _scan(),
        _scan(secrets=[{"kind": "pem-private-key", "path": ".env", "line_number": 3}]),
    )
    change = report["changes"][0]
    assert change["type"] == "NEW_HARDCODED_SECRET" and change["severity"] == "CRITICAL"
    assert report["verdict"] == "REGRESSED"


def test_drift_posture_transitions():
    degraded = diff_scans(_scan(posture="PASS"), _scan(posture="FAIL"))
    assert degraded["changes"][-1]["type"] == "POSTURE_DEGRADED"
    assert degraded["verdict"] == "REGRESSED"
    improved = diff_scans(_scan(posture="FAIL"), _scan(posture="PASS"))
    assert any(c["type"] == "POSTURE_IMPROVED" for c in improved["changes"])
    assert improved["verdict"] == "IMPROVED"


def test_drift_severity_ordering_and_headline():
    report = diff_scans(
        _scan(),
        _scan(
            vulns=[{"cve": "CVE-2023-1", "package": "x", "severity": "MEDIUM"}],
            secrets=[{"kind": "jwt", "path": ".env", "line_number": 1}],
        ),
    )
    severities = [change["severity"] for change in report["changes"]]
    assert severities == sorted(severities, key=lambda sev: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[sev])
    assert report["headline"] == report["changes"][0]["detail"]


# --------------------------------------------------------------------------- #
# metrics
# --------------------------------------------------------------------------- #

def _telemetry_scan():
    return {
        "scan_telemetry": {
            "status": "OK", "packages": 7, "libraries_fingerprinted": 3, "binaries": 2,
            "vulnerabilities": 4, "secrets": 1, "files_scanned": 120, "fingerprint_hit_rate": 0.5,
            "packages_by_manager": {"apk": 5, "pip": 2},
            "binaries_by_type": {"shared-library": 2},
            "secrets_by_kind": {"pem-private-key": 1},
        },
        "risk_report": {
            "posture": "WARN",
            "cve_severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 3, "LOW": 0, "UNKNOWN": 0},
        },
    }


def test_metrics_container_families():
    text = render_prometheus(_telemetry_scan())
    assert "cryptoscan_container_packages 7" in text
    assert "cryptoscan_container_files_scanned 120" in text
    assert "cryptoscan_container_fingerprint_hit_rate 0.5" in text
    assert 'cryptoscan_container_packages_by_manager{manager="apk"} 5' in text
    assert 'cryptoscan_container_secrets_by_kind{kind="pem-private-key"} 1' in text
    assert 'cryptoscan_container_cves{severity="HIGH"} 1' in text
    assert 'cryptoscan_container_scan_verdict{verdict="OK"} 1' in text
    assert 'cryptoscan_container_posture{posture="WARN"} 1' in text
    assert 'cryptoscan_container_posture{posture="PASS"} 0' in text


def test_metrics_drift_families():
    text = render_prometheus(
        {"verdict": "REGRESSED", "change_count": 3,
         "severity_counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFO": 0},
         "changes": [1, 2, 3]}
    )
    assert "cryptoscan_drift_change_total 3" in text
    assert 'cryptoscan_drift_changes{severity="CRITICAL"} 1' in text
    assert 'cryptoscan_drift_verdict{verdict="REGRESSED"} 1' in text


def test_metrics_unknown_payload_is_comment_only():
    assert render_prometheus({"x": 1}).strip().startswith("# cryptoscan:")
    assert render_prometheus(None).startswith("# cryptoscan:")
    assert render_prometheus(_telemetry_scan()).endswith("\n")
