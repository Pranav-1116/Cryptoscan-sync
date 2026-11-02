"""Range-aware matching, the restore drill, and licence states.

Three claims from the review that used to be a list of intentions:

* an advisory that names a *range* must apply to the versions inside it, and a
  range nobody can read must be ``UNKNOWN`` rather than "clean";
* a restore must have been run, not merely configured — and the check must catch
  a corrupted copy;
* a licence state must never turn a declaration into an approval.
"""

from __future__ import annotations

from datetime import date

import pytest

from devsecops import artifact_store as store
from devsecops import sbom_evidence as se
from devsecops import sbom_license as lic
from devsecops import sbom_scan

AS_OF = date(2026, 11, 2)
FEED = {"name": "osv", "version": "2026-11-01", "updated_at": date(2026, 11, 1)}


def _assess(component: dict, advisories: list[dict]) -> dict:
    return se.assess_vulnerabilities(component, feed=FEED, advisories=advisories, as_of=AS_OF)


# ------------------------------------------------------- advisory ranges -- #


def test_an_exact_version_list_still_matches() -> None:
    result = _assess({"name": "openssl", "version": "3.0.11",
                      "purl": "pkg:generic/openssl@3.0.11"},
                     [{"id": "CVE-1", "package": "pkg:generic/openssl",
                       "affected_versions": ["3.0.11"]}])
    assert result["status"] == "MATCHED"
    assert result["match_method"] == "purl+version"


def test_a_comparator_range_matches_and_says_so() -> None:
    result = _assess({"name": "openssl", "version": "3.0.11",
                      "purl": "pkg:generic/openssl@3.0.11"},
                     [{"id": "CVE-2", "package": "pkg:generic/openssl",
                       "affected_versions": [">=3.0.0, <3.0.13"]}])
    assert result["status"] == "MATCHED"
    assert result["match_method"] == "purl+range"


def test_a_version_outside_the_range_is_a_real_non_match() -> None:
    result = _assess({"name": "openssl", "version": "3.0.13",
                      "purl": "pkg:generic/openssl@3.0.13"},
                     [{"id": "CVE-2", "package": "pkg:generic/openssl",
                       "affected_versions": [">=3.0.0, <3.0.13"]}])
    assert result["status"] == "ASSESSED_NO_MATCH"
    assert result["match_method"] == "purl+range"


def test_the_purl_decides_the_comparator() -> None:
    npm = _assess({"name": "jose", "version": "5.2.3", "purl": "pkg:npm/jose@5.2.3"},
                  [{"id": "CVE-3", "package": "pkg:npm/jose",
                    "affected_versions": ["^5.0.0"]}])
    pypi = _assess({"name": "cryptography", "version": "41.0.7",
                    "purl": "pkg:pypi/cryptography@41.0.7"},
                   [{"id": "CVE-4", "package": "pkg:pypi/cryptography",
                     "affected_versions": ["<42.0.0"]}])
    assert npm["ecosystem"] == "semver" and npm["status"] == "MATCHED"
    assert pypi["ecosystem"] == "pep440" and pypi["status"] == "MATCHED"


def test_a_semver_prerelease_is_outside_a_range_that_starts_at_the_release() -> None:
    result = _assess({"name": "widget", "version": "2.0.0-rc1",
                      "purl": "pkg:npm/widget@2.0.0-rc1"},
                     [{"id": "CVE-5", "package": "pkg:npm/widget",
                       "affected_versions": [">=2.0.0"]}])
    assert result["status"] == "ASSESSED_NO_MATCH"


def test_the_introduced_fixed_window_shape_is_understood() -> None:
    result = _assess({"name": "openssl", "version": "3.0.11",
                      "purl": "pkg:generic/openssl@3.0.11"},
                     [{"id": "CVE-6", "package": "pkg:generic/openssl",
                       "introduced": "3.0.0", "fixed": "3.0.13"}])
    assert result["status"] == "MATCHED"
    assert result["match_method"] == "purl+range"


def test_an_unreadable_advisory_range_is_unknown_not_clean() -> None:
    result = _assess({"name": "widget", "version": "1.2.3",
                      "purl": "pkg:npm/widget@1.2.3"},
                     [{"id": "CVE-7", "package": "pkg:npm/widget",
                       "affected_versions": [">=three"]}])
    assert result["status"] == "UNKNOWN"
    assert result["unevaluable_ranges"]
    assert "could not be interpreted" in result["reason"]


def test_a_match_inside_an_unreadable_set_still_matches() -> None:
    result = _assess({"name": "widget", "version": "1.2.3",
                      "purl": "pkg:npm/widget@1.2.3"},
                     [{"id": "CVE-8", "package": "pkg:npm/widget",
                       "affected_versions": [">=three", "<1.3.0"]}])
    assert result["status"] == "MATCHED"
    assert result["unevaluable_ranges"]


# ------------------------------------------------------------ restore -- #


@pytest.fixture()
def artifact(tmp_path, monkeypatch):
    from governance.backup_jobs import DiskBackupStorage

    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "primary"))
    monkeypatch.setenv("ENVIRONMENT", "test")
    bom = sbom_scan.render_sbom(
        {"target": "/srv/app", "packages": [{"name": "openssl", "version": "3.0.13"}],
         "libraries": [], "binaries": [], "vulnerabilities": [], "manifests": [],
         "lockfiles": [], "dependencies": []}, fmt="cyclonedx", created_by="tester")
    stored = store.store_binary_artifact(
        scan={"target": "/srv/app", "files_walked": 1},
        result={"target": "/srv/app", "packages": [{"name": "openssl", "version": "3.0.13"}],
                "manifests": [], "lockfiles": [], "dependencies": [], "libraries": [],
                "binaries": []},
        bom=bom, cbom={}, created_by="tester", secret=("demo-secret", "settings"))
    return {
        "key": stored["artifact_key"],
        "primary": store.artifact_storage(),
        "backup": DiskBackupStorage(tmp_path / "backup"),
        "root": tmp_path,
    }


def test_a_backup_is_read_back_and_compared(artifact) -> None:
    result = store.backup_artifact(artifact["primary"], artifact["backup"], artifact["key"])
    assert result["verdict"] == "BACKED_UP"
    assert result["byte_identical"] is True
    assert result["manifest"] is True


def test_a_restore_is_verified_not_assumed(artifact) -> None:
    store.backup_artifact(artifact["primary"], artifact["backup"], artifact["key"])
    drill = store.restore_drill(artifact["backup"], artifact["key"], secret="demo-secret")
    assert drill["verdict"] == "RESTORED"
    assert drill["byte_identical"] is True
    assert drill["digest_check"] == "MATCH"
    assert drill["signature_check"] == "VALID"
    assert drill["tamper_detected"] is True


def test_a_flipped_byte_in_the_backup_fails_the_drill(artifact) -> None:
    from governance.backup_jobs import DiskBackupStorage

    store.backup_artifact(artifact["primary"], artifact["backup"], artifact["key"])
    damaged = DiskBackupStorage(artifact["root"] / "damaged")
    blob = bytearray(artifact["backup"].get(artifact["key"]))
    blob[-1] ^= 0xFF
    damaged.put(artifact["key"], bytes(blob))
    damaged.put_manifest(artifact["key"],
                         store._manifest_for(artifact["backup"], artifact["key"]) or {})
    drill = store.restore_drill(damaged, artifact["key"], secret="demo-secret")
    assert drill["verdict"] == "FAILED"
    assert drill["digest_check"] == "MISMATCH"


def test_the_drill_is_reported_over_every_artifact(artifact) -> None:
    store.backup_artifact(artifact["primary"], artifact["backup"], artifact["key"])
    report = store.restore_drill_all(artifact["backup"], secret="demo-secret")
    assert report["verdict"] == "RESTORED"
    assert report["artifacts"] == 1


def test_an_empty_backup_proves_nothing(tmp_path) -> None:
    from governance.backup_jobs import DiskBackupStorage

    report = store.restore_drill_all(DiskBackupStorage(tmp_path / "empty"))
    assert report["verdict"] == "NO_ARTIFACTS"
    assert "proves nothing" in report["statement"]


# ------------------------------------------------------ licence states -- #

BOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
    {"name": "openssl", "version": "3.0.13",
     "licenses": [{"license": {"id": "Apache-2.0"}}]},
    {"name": "left-pad", "version": "1.0.0", "licenses": [{"license": {"id": "MIT"}}]},
    {"name": "gpl-helper", "version": "2.1.0",
     "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
    {"name": "mystery-lib", "version": "0.1"},
]}


def test_the_vocabulary_is_the_reviews_seven_states() -> None:
    assert lic.LICENSE_STATES == ("DECLARED", "DETECTED", "UNKNOWN", "CONFLICT",
                                 "POLICY_ACCEPTED", "POLICY_REJECTED", "REQUIRES_REVIEW")


def test_a_declared_licence_is_not_an_approval() -> None:
    states = lic.license_states(BOM, policy={"allowed": ["MIT"]})
    by_component = {row["component"]: row["state"] for row in states["components"]}
    assert by_component["openssl"] == "DECLARED"
    assert by_component["left-pad"] == "POLICY_ACCEPTED"
    assert by_component["mystery-lib"] == "UNKNOWN"


def test_a_forbidden_family_is_rejected_even_with_a_version_suffix() -> None:
    states = lic.license_states(BOM, policy={"forbidden": ["GPL-3.0"]})
    by_component = {row["component"]: row["state"] for row in states["components"]}
    assert by_component["gpl-helper"] == "POLICY_REJECTED"


def test_a_conflict_between_declaration_and_detection_is_its_own_state() -> None:
    states = lic.license_states(BOM, detected={"openssl": "GPL-3.0-only"})
    row = next(row for row in states["components"] if row["component"] == "openssl")
    assert row["state"] == "CONFLICT"


def test_a_detection_without_a_declaration_is_detected_not_approved() -> None:
    states = lic.license_states(
        {"bomFormat": "CycloneDX", "specVersion": "1.5",
         "components": [{"name": "silent", "version": "1.0"}]},
        detected={"silent": "MIT"})
    assert states["components"][0]["state"] == "DETECTED"
    assert states["approved"] == 0


def test_the_summary_counts_what_nobody_reviewed() -> None:
    states = lic.license_states(BOM, policy={"allowed": ["MIT"]})
    # openssl (Apache-2.0) and gpl-helper (GPL-3.0-only) are both declared and
    # neither has a decision, so neither may render as approved
    assert states["counts"]["DECLARED"] == 2
    assert "not legal advice" in states["statement"]
