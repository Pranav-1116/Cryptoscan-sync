"""Base-image fingerprinting: distro detection, EOL verdicts, manager cross-check, SPDX."""

from __future__ import annotations

from datetime import date

from container_scanner.core.scanner import ContainerScanner
from container_scanner.image.distro import (
    detect_distro,
    eol_status,
    fingerprint_base_image,
    package_manager_evidence,
    parse_os_release,
)
from container_scanner.reports.risk import build_risk_report
from container_scanner.reports.spdx import build_spdx

TODAY = date(2026, 8, 27)

OS_RELEASE_UBUNTU = """
# a comment
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="22.04"
"""


# --------------------------------------------------------------------------- #
# os-release parsing + detection
# --------------------------------------------------------------------------- #

def test_parse_os_release_quoting_and_comments():
    fields = parse_os_release(OS_RELEASE_UBUNTU)
    assert fields["ID"] == "ubuntu"
    assert fields["VERSION_ID"] == "22.04"
    assert fields["ID_LIKE"] == "debian"
    assert "# a comment" not in fields
    assert parse_os_release("") == {}


def test_detect_distro_from_os_release(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text(OS_RELEASE_UBUNTU)
    distro = detect_distro(tmp_path)
    assert distro["id"] == "ubuntu" and distro["family"] == "debian"
    assert distro["version_id"] == "22.04"
    assert distro["source"] == "etc/os-release"


def test_detect_distro_legacy_fallbacks(tmp_path):
    alpine = tmp_path / "alpine"
    (alpine / "etc").mkdir(parents=True)
    (alpine / "etc/alpine-release").write_text("3.16.4\n")
    found = detect_distro(alpine)
    assert found["id"] == "alpine" and found["version_id"] == "3.16.4"
    assert found["source"] == "etc/alpine-release"

    debian = tmp_path / "debian"
    (debian / "etc").mkdir(parents=True)
    (debian / "etc/debian_version").write_text("11.7\n")
    found = detect_distro(debian)
    assert found["id"] == "debian" and found["family"] == "debian"

    centos = tmp_path / "centos"
    (centos / "etc").mkdir(parents=True)
    (centos / "etc/centos-release").write_text("CentOS Linux release 7.9.2009 (Core)\n")
    found = detect_distro(centos)
    assert found["id"] == "centos" and found["family"] == "rhel"
    assert found["version_id"] == "7.9.2009"


def test_detect_distro_absent_returns_none(tmp_path):
    assert detect_distro(tmp_path) is None


# --------------------------------------------------------------------------- #
# EOL table
# --------------------------------------------------------------------------- #

def test_eol_status_matrix():
    assert eol_status("alpine", "3.18", today=TODAY)["status"] == "EOL"
    assert eol_status("alpine", "3.18", today=TODAY)["days_past_eol"] > 400
    assert eol_status("alpine", "3.20", today=TODAY)["status"] == "EOL"  # 2026-05-01
    assert eol_status("debian", "12", today=TODAY)["status"] == "SUPPORTED"
    assert eol_status("ubuntu", "22.04", today=TODAY)["status"] == "SUPPORTED"
    assert eol_status("ubuntu", "18.04", today=TODAY)["status"] == "EOL"
    # honest unknowns: no version, unknown distro, off-table version
    assert eol_status("alpine", "", today=TODAY)["status"] == "UNKNOWN"
    assert eol_status("fedora", "38", today=TODAY)["status"] == "UNKNOWN"
    assert eol_status("alpine", "9.9", today=TODAY)["status"] == "UNKNOWN"
    # debian major-version match: "11.7" hits the "11" row
    assert eol_status("debian", "11.7", today=TODAY)["status"] == "SUPPORTED"


# --------------------------------------------------------------------------- #
# fingerprint + cross-check
# --------------------------------------------------------------------------- #

def test_fingerprint_matches_expected_manager(tmp_path):
    (tmp_path / "etc").mkdir(parents=True)
    (tmp_path / "etc/os-release").write_text('ID=alpine\nVERSION_ID=3.19.1\nNAME="Alpine Linux"\n')
    (tmp_path / "lib/apk/db").mkdir(parents=True)
    (tmp_path / "lib/apk/db/installed").write_text("P:libcrypto3\n")
    fp = fingerprint_base_image(tmp_path, today=TODAY)
    assert fp["id"] == "alpine"
    assert fp["package_managers_present"] == ["apk"]
    assert fp["manager_mismatch"] is False
    assert fp["eol"]["status"] == "EOL"


def test_fingerprint_flags_manager_mismatch(tmp_path):
    # os-release says ubuntu, but only the apk database exists on disk
    (tmp_path / "etc").mkdir(parents=True)
    (tmp_path / "etc/os-release").write_text("ID=ubuntu\nVERSION_ID=22.04\n")
    (tmp_path / "lib/apk/db").mkdir(parents=True)
    (tmp_path / "lib/apk/db/installed").write_text("P:a\n")
    fp = fingerprint_base_image(tmp_path, today=TODAY)
    assert fp["manager_mismatch"] is True
    assert "dpkg" in fp["package_managers_expected"]


def test_package_manager_evidence_empty_root(tmp_path):
    evidence = package_manager_evidence(tmp_path)
    assert evidence == {"dpkg": False, "rpm": False, "apk": False}


# --------------------------------------------------------------------------- #
# risk integration
# --------------------------------------------------------------------------- #

def _distro(status="EOL", mismatch=False):
    return {
        "id": "alpine", "name": "Alpine Linux", "version_id": "3.18.5", "family": "alpine",
        "package_managers_present": ["apk"] if not mismatch else [],
        "package_managers_expected": ["apk"],
        "manager_mismatch": mismatch,
        "eol": {"status": status, "eol_date": "2025-05-09", "days_past_eol": 475},
    }


def test_risk_eol_base_image_warns_with_issue():
    report = build_risk_report(libraries=[{"name": "lib", "algorithms": ["AES"]}], distro=_distro())
    assert "EOL_BASE_IMAGE" in report["policy_issues"]
    assert report["posture"] == "WARN"
    assert "Alpine Linux 3.18.5 is EOL" in report["headline"]
    assert report["distro"]["id"] == "alpine"


def test_risk_supported_distro_adds_no_issue():
    report = build_risk_report(
        libraries=[{"name": "lib", "algorithms": ["AES"]}],
        distro=_distro(status="SUPPORTED"),
    )
    assert "EOL_BASE_IMAGE" not in report["policy_issues"]
    assert report["posture"] == "PASS"


def test_risk_manager_mismatch_reported():
    report = build_risk_report(distro=_distro(status="SUPPORTED", mismatch=True))
    assert report["policy_issues"] == ["DISTRO_MANAGER_MISMATCH"]
    assert report["posture"] == "WARN"


# --------------------------------------------------------------------------- #
# scanner end-to-end
# --------------------------------------------------------------------------- #

def test_scanner_detects_eol_base_image(tmp_path):
    (tmp_path / "etc").mkdir(parents=True)
    (tmp_path / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID=18.04\nNAME="Ubuntu"\n')
    (tmp_path / "requirements.txt").write_text("cryptography==41.0.7\n")
    result = ContainerScanner().scan_filesystem(tmp_path)
    assert result["distro"]["id"] == "ubuntu"
    assert result["distro"]["eol"]["status"] == "EOL"
    assert "EOL_BASE_IMAGE" in result["risk_report"]["policy_issues"]
    assert result["risk_report"]["posture"] == "WARN"


# --------------------------------------------------------------------------- #
# SPDX
# --------------------------------------------------------------------------- #

def _scan_result():
    return {
        "scan_id": "s1",
        "target": "registry.local/app:2.0",
        "target_kind": "registry",
        "scanner_version": "1.0.0",
        "packages": [
            {"name": "cryptography", "version": "41.0.7", "manager": "pip"},
            {"name": "noversion", "manager": "npm"},
        ],
    }


def test_spdx_document_shape():
    doc = build_spdx(_scan_result())
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert doc["documentNamespace"].startswith("https://cryptoscan.local/spdx/")
    assert doc["creationInfo"]["creators"] == ["Tool: CryptoScan-container-scanner-1.0.0"]
    names = [pkg["name"] for pkg in doc["packages"]]
    assert names[0] == "registry.local/app:2.0"  # described target leads
    assert "cryptography" in names and "noversion" in names


def test_spdx_purls_and_noassertion():
    doc = build_spdx(_scan_result())
    by_name = {pkg["name"]: pkg for pkg in doc["packages"]}
    crypto = by_name["cryptography"]
    assert crypto["versionInfo"] == "41.0.7"
    assert crypto["externalRefs"][0] == {
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": "pkg:pypi/cryptography@41.0.7",
    }
    assert by_name["noversion"]["versionInfo"] == "NOASSERTION"  # never invented
    assert all(pkg["licenseConcluded"] == "NOASSERTION" for pkg in doc["packages"])


def test_spdx_relationships():
    doc = build_spdx(_scan_result())
    relates = [rel for rel in doc["relationships"] if rel["relationshipType"] == "DESCRIBES"]
    assert relates and relates[0]["relatedSpdxElement"] == "SPDXRef-Container"
    contains = [rel for rel in doc["relationships"] if rel["relationshipType"] == "CONTAINS"]
    assert len(contains) == 2  # both real packages hang off the target


def test_spdx_empty_result_is_valid():
    doc = build_spdx(None)
    assert doc["packages"][0]["SPDXID"] == "SPDXRef-Rootfs"  # filesystem default
    assert len(doc["packages"]) == 1
