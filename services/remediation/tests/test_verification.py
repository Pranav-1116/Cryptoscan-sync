"""Remediation verification — the five-verdict decision table (audit 62 / GAP-006).

Every verdict must be derivable from the recorded comparison alone; these
tests pin the decision table so the label can always be replayed.
"""

from __future__ import annotations

from remediation.verification import (
    FAILED,
    INCONCLUSIVE,
    PARTIAL,
    REGRESSION,
    VERIFIED,
    apply_result_to_status,
    verify_remediation,
)

ORIG = {
    "algorithm": "DES", "key_size": 56, "mode": None, "purpose": "ENCRYPTION",
    "file_path": "src/payments/CardCipher.java", "line_number": 42,
    "compliance_status": "FAIL", "is_hardcoded_key": False,
}
RULE = {"rule": "replace-des", "replace_with": "AES-256-GCM", "category": "SYMMETRIC", "priority": "P0"}


def _f(algorithm, status="PASS", file_path="src/payments/CardCipher.java", line=42, **extra):
    return {"algorithm": algorithm, "compliance_status": status, "file_path": file_path,
            "line_number": line, **extra}


def test_no_rescan_is_inconclusive():
    out = verify_remediation(ORIG, RULE, None)
    assert out["result"] == INCONCLUSIVE
    assert "no rescan evidence" in out["reason"]


def test_empty_rescan_is_inconclusive_not_verified():
    out = verify_remediation(ORIG, RULE, [])
    assert out["result"] == INCONCLUSIVE
    assert "produced no evidence" in out["reason"]


def test_replacement_present_and_compliant_is_verified():
    out = verify_remediation(ORIG, RULE, [_f("AES-256-GCM")])
    assert out["result"] == VERIFIED
    assert out["comparison"]["replacement_found"] is True
    assert out["comparison"]["same_algorithm_remaining"] == []


def test_original_algorithm_gone_file_fully_compliant_is_verified():
    # no template rule (manual review) — any compliant change counts
    out = verify_remediation(ORIG, None, [_f("ChaCha20-Poly1305")])
    assert out["result"] == VERIFIED


def test_file_missing_from_rescan_is_inconclusive():
    out = verify_remediation(ORIG, RULE, [_f("RSA-2048", file_path="other/File.java", line=1)])
    assert out["result"] == INCONCLUSIVE
    assert out["comparison"]["file_present_in_rescan"] is False


def test_replacement_present_but_still_failing_is_partial():
    out = verify_remediation(ORIG, RULE, [_f("AES-256-GCM", status="WARN")])
    assert out["result"] == PARTIAL


def test_original_still_present_failing_is_failed():
    out = verify_remediation(ORIG, RULE, [_f("DES", status="FAIL", key_size=56)])
    assert out["result"] == FAILED
    assert out["comparison"]["same_algorithm_remaining"][0]["key_size"] == 56


def test_original_present_but_improved_is_partial():
    out = verify_remediation(
        {**ORIG, "algorithm": "RSA", "key_size": 1024},
        {"rule": "plan-rsa-pqc", "replace_with": "ML-DSA-65"},
        [_f("RSA", status="FAIL", key_size=3072)],
    )
    assert out["result"] == PARTIAL


def test_fixed_but_new_violation_in_same_file_is_regression():
    out = verify_remediation(ORIG, RULE, [_f("AES-256-GCM"), _f("RC4", status="FAIL", line=99)])
    assert out["result"] == REGRESSION
    assert out["comparison"]["new_violations"] == [
        {"file_path": "src/payments/CardCipher.java", "line_number": 99, "algorithm": "RC4"}]


def test_new_violation_in_other_file_needs_original_scan_to_count():
    new_elsewhere = [_f("AES-256-GCM"), _f("RC4", status="FAIL", file_path="src/other.java", line=1)]
    # without the original scan's evidence the scope is the file only
    out = verify_remediation(ORIG, RULE, new_elsewhere)
    assert out["result"] == VERIFIED
    assert out["comparison"]["regression_scope"] == "file"
    # with it, the new site elsewhere is a regression
    out = verify_remediation(
        ORIG, RULE, new_elsewhere,
        original_scan_findings=[_f("DES", status="FAIL"), _f("RSA-4096", file_path="src/other.java", line=1)])
    assert out["result"] == REGRESSION
    assert out["comparison"]["regression_scope"] == "target"


def test_old_unrelated_violation_is_not_a_regression():
    rescan = [_f("AES-256-GCM"), _f("RC4", status="FAIL", line=7)]
    original_scan = [_f("DES", status="FAIL"), _f("RC4", status="FAIL", line=7)]
    out = verify_remediation(ORIG, RULE, rescan, original_scan_findings=original_scan)
    assert out["result"] == VERIFIED


def test_failed_plus_new_violations_stays_failed_with_note():
    rescan = [_f("DES", status="FAIL"), _f("RC4", status="FAIL", line=99)]
    out = verify_remediation(ORIG, RULE, rescan, original_scan_findings=[_f("DES", status="FAIL")])
    assert out["result"] == FAILED
    assert "new non-compliant site" in out["reason"]


def test_status_mapping_round_trip():
    assert apply_result_to_status(VERIFIED) == "VERIFIED"
    assert apply_result_to_status(REGRESSION) == "REGRESSION"
    # INCONCLUSIVE says nothing about the remediation itself
    assert apply_result_to_status(INCONCLUSIVE) == "COMPLETED"
    assert apply_result_to_status("WHATEVER") == "COMPLETED"


# ---------------------------------------------------------------------------
# Evidence identity must be stable across rescans (round 81).
#
# A fingerprint is (file_path, line_number, algorithm). Findings derived from a
# dependency manifest used to arrive carrying the worker's staging path —
# data/workspaces/job-<uuid>/repo/pom.xml — so the job id became part of the
# identity and the next rescan "introduced" them again. The consequence, caught
# by the operator-loop drill: an honestly fixed condition could never read as
# VERIFIED on any target that declares a crypto dependency; it degraded to
# REGRESSION. The paths are rebased at the source
# (worker/pipeline/stage_container_scan.py); these two tests pin why that
# matters here, from the verifier's side.
# ---------------------------------------------------------------------------


def _dep_finding(path: str, algorithm: str = "AES") -> dict:
    """A package-manager fingerprint: a library capability, no call site."""
    return _f(algorithm, status="FAIL", file_path=path, line=0,
              class_name="bouncycastle")


def test_stable_dependency_paths_do_not_mask_a_verified_fix():
    manifest = "pom.xml"
    rescan = [_f("AES-256-GCM"), _dep_finding(manifest)]
    original = [_f("DES", status="FAIL"), _dep_finding(manifest)]
    out = verify_remediation(ORIG, RULE, rescan, original_scan_findings=original)
    assert out["result"] == VERIFIED
    assert out["comparison"]["new_violations"] == []


def test_job_scoped_dependency_paths_degrade_verified_to_regression():
    """Same fix, same dependency, unstable evidence path — the defect pinned."""
    rescan = [_f("AES-256-GCM"), _dep_finding("data/workspaces/job-2/repo/pom.xml")]
    original = [_f("DES", status="FAIL"), _dep_finding("data/workspaces/job-1/repo/pom.xml")]
    out = verify_remediation(ORIG, RULE, rescan, original_scan_findings=original)
    assert out["result"] == REGRESSION
    assert [v["file_path"] for v in out["comparison"]["new_violations"]] == [
        "data/workspaces/job-2/repo/pom.xml"]
    assert "new non-compliant crypto" in out["reason"]


def test_unknown_policy_and_moved_site_do_not_verify():
    for findings in [[_f("AES-256-GCM", status="UNKNOWN")], [_f("DES", status=None)], [_f("AES-256-GCM", line=99)]]:
        assert verify_remediation(ORIG, RULE, findings)["result"] == INCONCLUSIVE
