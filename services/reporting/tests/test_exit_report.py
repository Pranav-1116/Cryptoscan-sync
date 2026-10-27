"""Exit-report generator — deterministic scoring, honest coverage, hash chain."""

from __future__ import annotations

from reporting.exit_report import (
    build_exit_report,
    render_markdown,
    verify_exit_report,
)

SCOPE = {"client": "First Abu Dhabi Bank", "window": "2026-09-14 .. 2026-09-25",
         "owner": "A. Crypto Owner", "generated_at": "2026-09-25T10:00:00+00:00"}

FULL_ESTATE = {
    "payment_keys": 12,
    "certificates": 140,
    "cloud_kms": {"assets": 18, "skipped": [
        "ref k9: unsupported KeySpec 'SM2_KEY AGREE' — not classified"]},
    "acm": {"certificates": 6, "skipped": [
        "ref pending.bank.example: no PEM issued yet (status PENDING_VALIDATION)"]},
    "code": {"assets": 310},
    "telecom": {"targets": 2, "rows": 2, "critical": 1},
    "roadmap_families": ["RSA-2048", "RSA-3072", "ECDSA-P256"],
}


def test_report_is_deterministic_and_self_verifying():
    one = build_exit_report(FULL_ESTATE, **SCOPE)
    two = build_exit_report(FULL_ESTATE, **SCOPE)
    assert one == two, "same estate+scope must produce byte-identical reports"
    assert verify_exit_report(one) is True

    tampered = dict(one)
    tampered["executive_summary"] = dict(tampered["executive_summary"],
                                         collected_total=999_999)
    assert verify_exit_report(tampered) is False  # any edit breaks the hash


def test_coverage_math_and_threshold():
    report = build_exit_report(FULL_ESTATE, **SCOPE)
    coverage = report["executive_summary"]["coverage_pct"]
    assert coverage["cloud_kms"] == round(100 * 18 / 19, 1)   # 18 collected, 1 skipped
    assert coverage["acm"] == round(100 * 6 / 7, 1)
    assert coverage["code"] == 100.0

    sc1 = next(sc for sc in report["success_criteria"] if sc["id"] == "SC-1")
    worst = min(v for v in coverage.values() if v is not None)
    assert sc1["met"] is (worst >= 90.0), "threshold must follow the computed worst estate"
    detail = sc1["detail"]
    assert f"{worst}%" in detail

    # drops below the threshold when skips dominate
    thin = build_exit_report(
        {**FULL_ESTATE, "cloud_kms": {"assets": 5, "skipped": [f"s{i}" for i in range(5)]}},
        **SCOPE)
    sc1_thin = next(sc for sc in thin["success_criteria"] if sc["id"] == "SC-1")
    assert sc1_thin["met"] is False
    # the skip reasons surface verbatim in limitations
    flat = "\n".join(thin["limitations"]["skipped_items"])
    assert "s0" in flat and len(thin["limitations"]["skipped_items"]) >= 5


def test_empty_estates_are_honest_not_faked():
    report = build_exit_report({}, **SCOPE)
    assert report["executive_summary"]["collected_total"] == 0
    coverage = report["executive_summary"]["coverage_pct"]
    assert all(v is None for v in coverage.values()), "no data → coverage NOT measurable, never 100%"
    sc1 = next(sc for sc in report["success_criteria"] if sc["id"] == "SC-1")
    assert sc1["met"] is None and "not measurable" in sc1["detail"]
    sc2 = next(sc for sc in report["success_criteria"] if sc["id"] == "SC-2")
    assert sc2["met"] is False and "no inventory collected" in sc2["detail"]
    # client never blank in the document
    assert report["client"] == "First Abu Dhabi Bank"
    blank = build_exit_report({}, client="", window="", **{"generated_at": SCOPE["generated_at"]})
    assert blank["client"] == "unnamed client"


def test_acceptance_is_a_human_fact():
    pending = build_exit_report(FULL_ESTATE, **SCOPE)
    sc4 = next(sc for sc in pending["success_criteria"] if sc["id"] == "SC-4")
    assert sc4["met"] is False and "never inferred" in sc4["detail"]
    accepted = build_exit_report(FULL_ESTATE, accepted_by="A. Al Mansouri", **SCOPE)
    sc4_done = next(sc for sc in accepted["success_criteria"] if sc["id"] == "SC-4")
    assert sc4_done["met"] is True and "A. Al Mansouri" in sc4_done["detail"]


def test_telecom_block_absent_when_out_of_scope():
    without = build_exit_report(
        {k: v for k, v in FULL_ESTATE.items() if k != "telecom"}, **SCOPE)
    assert "telecom" not in without
    with_telecom = build_exit_report(FULL_ESTATE, **SCOPE)
    assert with_telecom["telecom"]["critical_findings"] == 1


def test_markdown_render_contains_scores_and_hash():
    report = build_exit_report(FULL_ESTATE, **SCOPE)
    md = render_markdown(report)
    assert md.startswith("# PoC exit report — First Abu Dhabi Bank")
    assert report["report_hash"] in md
    assert "NOT MEASURABLE" not in md  # full estate: every row has a number
    assert "SC-4" in md and "pending — acceptance is a human sign-off" in md
    # verbatim limitation lines survive rendering
    assert "unsupported KeySpec 'SM2_KEY AGREE'" in md
    empty_md = render_markdown(build_exit_report({}, **SCOPE))
    assert "not measurable" in empty_md
    # deterministic rendering
    assert render_markdown(build_exit_report(FULL_ESTATE, **SCOPE)) == md
