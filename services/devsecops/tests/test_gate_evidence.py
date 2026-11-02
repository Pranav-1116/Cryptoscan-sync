"""The gate decided on the document's own CVE table; now it decides on evidence.

Two failures motivated these tests. A component nobody assessed produced the same
``PASS`` as a component assessed against a current feed, and a VEX statement was
accepted on its word rather than re-validated at the moment it suppresses a
finding.
"""

from __future__ import annotations

from datetime import date

import pytest

from devsecops import artifact_store, sbom_assurance as assurance

AS_OF = date(2026, 11, 2)
FEED = {"name": "osv", "version": "2026-11-01", "updated_at": "2026-11-01"}
STALE = {"name": "osv", "version": "2026-09-01", "updated_at": "2026-09-01"}
ADVISORY = [{"id": "CVE-2026-11111", "severity": "CRITICAL", "purl": "pkg:deb/openssl",
             "affected_versions": ["<3.0.13"]}]
DIGEST = "sha256:" + "a" * 64


def _bom(*, vulnerabilities=None, version="3.0.12"):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"name": "openssl", "version": version,
                            "purl": f"pkg:deb/openssl@{version}"}],
            "vulnerabilities": vulnerabilities or []}


def _vex(**overrides):
    row = {"cve": "CVE-2026-11111", "component": "openssl",
           "affected_versions": ["<3.0.13"], "status": "NOT_AFFECTED",
           "justification": "VULNERABLE_CODE_NOT_IN_EXECUTE_PATH",
           "reviewer": "alice.chen", "evidence_id": "EV-1",
           "assessed_at": "2026-10-20", "expires_at": "2026-12-20"}
    row.update(overrides)
    return row


# --------------------------------------------------------------------------- #
# the document is not the assessment
# --------------------------------------------------------------------------- #


def test_a_silent_document_is_reported_as_unassessed_not_clean():
    result = assurance.evaluate_gate(_bom(), as_of=AS_OF)
    evidence = result["vulnerability_evidence"]
    assert evidence["assessment"] == "NOT_SUPPLIED"
    assert evidence["unassessed"] == 1
    assert "not an all-clear" in evidence["statement"]
    # the old answer is unchanged — a document-only gate still passes
    assert result["verdict"] == "PASS"


def test_a_feed_turns_the_same_document_into_a_failure():
    result = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY, as_of=AS_OF)
    assert result["verdict"] == "FAIL"
    assert "GATE-VULN-CRITICAL" in {row["code"] for row in result["blockers"]}
    assert result["counts"]["document_cve_entries"] == 0
    assert result["counts"]["assessed_open"] == 1


def test_the_assessed_finding_carries_its_match_evidence():
    result = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY, as_of=AS_OF)
    open_row = result["vulnerability_evidence"]["open"][0]
    assert open_row["advisory"] == "CVE-2026-11111"
    assert open_row["severity"] == "CRITICAL"
    assert open_row["match_method"] == "purl+range"
    assert open_row["confidence"] == "HIGH"
    assert open_row["vex"] == "NONE"


def test_an_unaffected_version_does_not_match():
    result = assurance.evaluate_gate(_bom(version="3.0.13"), feed=FEED, advisories=ADVISORY,
                                     as_of=AS_OF)
    assert result["verdict"] == "PASS"
    assert result["vulnerability_evidence"]["states"]["ASSESSED_NO_MATCH"] == 1


def test_a_stale_feed_is_counted_as_unassessed():
    result = assurance.evaluate_gate(_bom(), feed=STALE, advisories=ADVISORY, as_of=AS_OF)
    evidence = result["vulnerability_evidence"]
    assert evidence["states"]["STALE_FEED"] == 1
    assert evidence["unassessed"] == 1
    assert "GATE-VULN-UNASSESSED" in {row["code"] for row in result["warnings"]}


def test_a_policy_can_make_unassessed_a_blocker():
    result = assurance.evaluate_gate(_bom(), policy={"require_vulnerability_assessment": True},
                                     feed=STALE, advisories=ADVISORY, as_of=AS_OF)
    assert result["verdict"] == "FAIL"
    assert "GATE-VULN-UNASSESSED" in {row["code"] for row in result["blockers"]}


def test_the_documents_own_claim_still_gates_without_a_feed():
    bom = _bom(vulnerabilities=[{"id": "CVE-2026-22222",
                                 "ratings": [{"severity": "critical"}]}])
    result = assurance.evaluate_gate(bom, as_of=AS_OF)
    assert result["verdict"] == "FAIL"
    assert "GATE-CVE-CRITICAL" in {row["code"] for row in result["blockers"]}


def test_the_evidence_block_is_always_present():
    assert "vulnerability_evidence" in assurance.evaluate_gate(_bom(), as_of=AS_OF)
    assert "vulnerability_evidence" in assurance.evaluate_gate(None, as_of=AS_OF)


# --------------------------------------------------------------------------- #
# VEX is re-validated when it is used
# --------------------------------------------------------------------------- #


def test_a_current_justified_statement_suppresses_the_finding():
    result = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY,
                                     vex=[_vex()], as_of=AS_OF)
    assert result["verdict"] == "PASS"
    suppressed = result["vulnerability_evidence"]["suppressed_by_vex"]
    assert len(suppressed) == 1
    assert suppressed[0]["reviewer"] == "alice.chen"
    assert suppressed[0]["justification"] == "VULNERABLE_CODE_NOT_IN_EXECUTE_PATH"


def test_a_lapsed_statement_suppresses_nothing():
    result = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY,
                                     vex=[_vex(assessed_at="2026-08-01",
                                               expires_at="2026-09-01")], as_of=AS_OF)
    assert result["verdict"] == "FAIL"
    assert "GATE-VEX-LAPSED" in {row["code"] for row in result["warnings"]}
    assert result["vulnerability_evidence"]["lapsed_or_invalid_vex"][0]["vex"] == "EXPIRED"


def test_free_text_is_not_a_justification():
    result = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY,
                                     vex=[_vex(justification="we looked at it")], as_of=AS_OF)
    probe = result["vulnerability_evidence"]["lapsed_or_invalid_vex"][0]
    assert probe["vex"] == "INVALID"
    assert any("justification" in problem for problem in probe["problems"])


def test_an_unreviewed_statement_is_invalid():
    result = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY,
                                     vex=[_vex(reviewer=None)], as_of=AS_OF)
    assert result["verdict"] == "FAIL"
    assert any("reviewer" in problem for problem in
               result["vulnerability_evidence"]["lapsed_or_invalid_vex"][0]["problems"])


def test_a_statement_without_an_evidence_id_is_invalid():
    result = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY,
                                     vex=[_vex(evidence_id="")], as_of=AS_OF)
    assert result["verdict"] == "FAIL"


def test_a_statement_about_another_component_does_not_apply():
    result = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY,
                                     vex=[_vex(component="libcurl")], as_of=AS_OF)
    assert result["verdict"] == "FAIL"
    assert result["vulnerability_evidence"]["suppressed_by_vex"] == []


def test_a_statement_that_expires_before_it_was_assessed_is_invalid():
    result = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY,
                                     vex=[_vex(assessed_at="2026-11-01",
                                               expires_at="2026-10-01")], as_of=AS_OF)
    assert result["verdict"] == "FAIL"


def test_an_under_investigation_statement_leaves_the_finding_open():
    result = assurance.evaluate_gate(_bom(), feed=FEED, advisories=ADVISORY,
                                     vex=[_vex(status="UNDER_INVESTIGATION")], as_of=AS_OF)
    assert result["verdict"] == "FAIL"
    assert result["vulnerability_evidence"]["suppressed_by_vex"] == []


# --------------------------------------------------------------------------- #
# the signature records what it proves
# --------------------------------------------------------------------------- #


@pytest.fixture()
def store_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "primary"))
    monkeypatch.setenv("SBOM_STORAGE_BACKUP_DIR", str(tmp_path / "backup"))
    monkeypatch.setenv("SBOM_RETENTION_DAYS", "365")
    monkeypatch.delenv("SBOM_STORAGE_REPLICA_DIRS", raising=False)
    monkeypatch.delenv("SBOM_STORAGE_SITES", raising=False)
    monkeypatch.delenv("SBOM_SIGNING_KEY_STATUS", raising=False)
    return tmp_path


def _store(tmp_path, *, secret=("secret-material", "hmac-2026-11"), build=None,
           target="/opt/app"):
    return artifact_store.store_binary_artifact(
        scan={"target": target}, result={"packages": []},
        bom={"bomFormat": "CycloneDX", "specVersion": "1.5",
             "components": [{"name": "openssl", "version": "3.0.13"}]},
        cbom={"components": []}, created_by="tester", secret=secret, build=build)


def test_the_manifest_records_the_signing_identity(store_env):
    manifest = _store(store_env)["manifest"]
    evidence = manifest["signature_evidence"]
    assert evidence["algorithm"] == "HMAC-SHA256"
    assert evidence["key_id"] == "hmac-2026-11"
    assert evidence["key_version"]
    assert evidence["key_status"] == "ACTIVE"
    assert evidence["trust_anchor"]
    assert evidence["signed_at"] and evidence["verified_at"]
    assert evidence["revoked"] is False
    assert evidence["manifest_digest"].startswith("sha256:")


def test_hmac_claims_authenticity_but_never_non_repudiation(store_env):
    evidence = _store(store_env)["manifest"]["signature_evidence"]
    assert evidence["claims"] == {"integrity": True, "authenticity": True,
                                 "non_repudiation": False}
    assert evidence["verdict"] == "AUTHENTIC"
    assert "non-repudiation no" in evidence["statement"]


def test_key_version_is_operational_configuration(store_env, monkeypatch):
    monkeypatch.setenv("SBOM_SIGNING_KEY_VERSION", "v3")
    assert _store(store_env)["manifest"]["signature_evidence"]["key_version"] == "v3"


def test_a_revoked_key_refuses_to_sign(store_env, monkeypatch):
    monkeypatch.setenv("SBOM_SIGNING_KEY_STATUS", "REVOKED")
    with pytest.raises(artifact_store.SigningRefused, match="REVOKED"):
        _store(store_env)


def test_an_expired_key_refuses_to_sign(store_env, monkeypatch):
    monkeypatch.setenv("SBOM_SIGNING_KEY_STATUS", "EXPIRED")
    with pytest.raises(artifact_store.SigningRefused):
        _store(store_env)


def test_an_unsigned_artifact_says_it_is_unsigned(store_env):
    evidence = _store(store_env, secret=(None, "unsigned"))["manifest"]["signature_evidence"]
    assert evidence["verdict"] == "UNSIGNED"
    assert evidence["claims"]["authenticity"] is False
    assert evidence["signed_at"] is None


def test_the_signature_covers_the_evidence_block(store_env):
    from devsecops.sbom_scan import verify_manifest

    manifest = _store(store_env)["manifest"]
    assert verify_manifest(manifest, "secret-material") is True
    manifest["signature_evidence"]["key_version"] = "v99"
    assert verify_manifest(manifest, "secret-material") is False


# --------------------------------------------------------------------------- #
# provenance: what produced this artifact
# --------------------------------------------------------------------------- #

BUILD = {"source_commit": "9f2c1ab4d7", "build_id": "BUILD-1", "builder": "github-actions",
         "pipeline": "release", "artifact_reference": "ghcr.io/bank/api",
         "artifact_digest": DIGEST, "started_at": "2026-11-02T09:00:00Z",
         "finished_at": "2026-11-02T09:14:00Z"}


def test_a_supplied_build_is_recorded_without_gaps(store_env):
    provenance = _store(store_env, build=BUILD)["manifest"]["provenance"]
    assert provenance["gaps"] == []
    assert provenance["build"]["source_commit"] == "9f2c1ab4d7"
    assert provenance["build"]["artifact"]["digest"] == DIGEST
    assert provenance["complete"] is False           # nothing observed it running
    assert provenance["deployed_environments"] == []


def test_a_discovery_scan_records_no_provenance_block(store_env):
    assert _store(store_env)["manifest"].get("provenance") is None


def test_a_bad_commit_and_missing_builder_are_named(store_env):
    gaps = _store(store_env, build={**BUILD, "source_commit": "main",
                                    "builder": ""})["manifest"]["provenance"]["gaps"]
    assert any("commit hash" in gap for gap in gaps)
    assert any("builder" in gap for gap in gaps)


def test_a_build_with_no_artifact_digest_is_a_gap(store_env):
    gaps = _store(store_env, build={k: v for k, v in BUILD.items()
                                    if k != "artifact_digest"})["manifest"]["provenance"]["gaps"]
    assert any("artifact digest" in gap for gap in gaps)


def test_a_malformed_digest_is_not_recorded_as_an_identity(store_env):
    provenance = _store(store_env, build={**BUILD, "artifact_digest": "not-a-digest"})[
        "manifest"]["provenance"]
    assert provenance["build"]["artifact"] is None
    assert any("artifact digest" in gap for gap in provenance["gaps"])
