"""Vendor-lifecycle contract tests (gap analysis Phase 5: vendor lifecycle
and supplier-risk workflows)."""

from __future__ import annotations

import pytest

from shared_models.vendor_lifecycle import (
    SUPPORTED, END_OF_SUPPORT, UNKNOWN,
    RELEASE, END_OF_SUPPORT_ANNOUNCED, OWNERSHIP_CHANGE,
    deployed_exposure, product_support, supplier_change, supplier_risk,
    vendor_log_digest,
)

AS_OF = "2026-11-07"


def _support(**over):
    base = dict(vendor="ACME HSM", product="ACME-Luna", version="7.13.0",
                status=SUPPORTED, evidence_ref="decl-2026-04",
                end_of_support_at="2027-06-30", as_of=AS_OF)
    base.update(over)
    return product_support(**base)


# ------------------------------------------------------- lifecycle claims
def test_a_support_claim_needs_evidence():
    with pytest.raises(ValueError):
        _support(evidence_ref="")


def test_a_claim_names_vendor_product_and_version():
    with pytest.raises(ValueError):
        _support(version="")


def test_a_past_end_of_support_date_is_never_supported():
    with pytest.raises(ValueError):
        _support(status=SUPPORTED, end_of_support_at="2026-01-31")
    honest = _support(status=END_OF_SUPPORT, end_of_support_at="2026-01-31")
    assert honest["status"] == END_OF_SUPPORT


def test_an_unknown_status_stays_unknown_with_its_evidence():
    row = _support(status=UNKNOWN, evidence_ref="vendor-portal-screenshot-12")
    assert row["status"] == UNKNOWN


# --------------------------------------------------------- supplier changes
def test_a_supplier_change_needs_evidence_date_and_detail():
    with pytest.raises(ValueError):
        supplier_change(vendor="ACME HSM", kind=RELEASE, announced_at="2026-10-01",
                        evidence_ref="", detail="new release")
    with pytest.raises(ValueError):
        supplier_change(vendor="ACME HSM", kind=RELEASE, announced_at="",
                        evidence_ref="adv-9", detail="new release")
    with pytest.raises(ValueError):
        supplier_change(vendor="ACME HSM", kind=RELEASE, announced_at="2026-10-01",
                        evidence_ref="adv-9", detail="")


# ------------------------------------------------------------ exposure
def test_unsupported_deployed_is_named_with_both_records():
    dep = {"asset": "hsm-01", "vendor": "ACME HSM", "product": "ACME-Luna",
           "version": "7.13.0"}
    record = _support(status=END_OF_SUPPORT, end_of_support_at="2026-01-31")
    report = deployed_exposure(deployments=[dep], support_records=[record],
                               as_of=AS_OF)
    assert report["is_clean_result"] is False
    finding = report["unsupported_deployed"][0]
    assert finding["deployment"] == dep
    assert finding["support_record"]["evidence_ref"] == "decl-2026-04"
    assert finding["exposure"] == "UNSUPPORTED_DEPLOYED"


def test_missing_lifecycle_data_is_never_a_clean_result():
    dep = {"asset": "hsm-02", "vendor": "ACME HSM", "product": "ACME-Luna",
           "version": "9.0.1"}
    report = deployed_exposure(deployments=[dep], support_records=[], as_of=AS_OF)
    assert report["unknown_support"][0]["exposure"] == UNKNOWN
    assert report["is_clean_result"] is False
    assert "not a clean result" in report["unknown_support"][0]["note"]


def test_current_supported_deployment_is_a_measured_clean():
    dep = {"asset": "hsm-01", "vendor": "ACME HSM", "product": "ACME-Luna",
           "version": "7.13.0"}
    report = deployed_exposure(deployments=[dep], support_records=[_support()],
                               as_of=AS_OF)
    assert report["supported"][0]["exposure"] == "SUPPORTED"
    assert report["is_clean_result"] is True


# --------------------------------------------------------- supplier risk
def test_supplier_risk_never_blends_into_one_number():
    dep = {"asset": "hsm-01", "vendor": "ACME HSM", "product": "ACME-Luna",
           "version": "7.13.0"}
    record = _support(status=END_OF_SUPPORT, end_of_support_at="2026-01-31")
    exposure = deployed_exposure(deployments=[dep], support_records=[record],
                                 as_of=AS_OF)
    change = supplier_change(vendor="ACME HSM", kind=END_OF_SUPPORT_ANNOUNCED,
                             announced_at="2026-09-01", evidence_ref="adv-eol",
                             detail="7.13 goes EOL 2027", products=["ACME-Luna"])
    risk = supplier_risk(vendor="ACME HSM", deployments_report=exposure,
                         changes=[change])
    assert risk["state"] == "ACTION_REQUIRED"
    assert risk["is_clean_result"] is False
    assert "score" not in risk, "drivers explain; nothing blends into a number"
    names = {d["driver"] for d in risk["drivers"]}
    assert "unsupported_product_deployed" in names
    assert "supplier_change:end_of_support_announced" in names
    for driver in risk["drivers"]:
        assert driver["records"], "every driver links its records"


def test_no_data_reads_as_unknown_risk_not_low_risk():
    exposure = deployed_exposure(deployments=[], support_records=[], as_of=AS_OF)
    risk = supplier_risk(vendor="ACME HSM", deployments_report=exposure)
    assert risk["state"] == UNKNOWN
    assert risk["is_clean_result"] is False
    assert "never a clean bill" in risk["note"]


def test_full_coverage_with_no_exposure_is_the_only_clean():
    dep = {"asset": "hsm-01", "vendor": "ACME HSM", "product": "ACME-Luna",
           "version": "7.13.0"}
    exposure = deployed_exposure(deployments=[dep], support_records=[_support()],
                                 as_of=AS_OF)
    risk = supplier_risk(vendor="ACME HSM", deployments_report=exposure)
    assert risk["state"] == "NO_FINDINGS"
    assert risk["is_clean_result"] is True


# ---------------------------------------------------------------- digest
def test_change_log_digest_is_order_insensitive():
    a = supplier_change(vendor="ACME HSM", kind=OWNERSHIP_CHANGE,
                        announced_at="2026-10-01", evidence_ref="adv-1",
                        detail="acquired")
    b = supplier_change(vendor="ACME HSM", kind=RELEASE,
                        announced_at="2026-10-02", evidence_ref="adv-2",
                        detail="7.14 released")
    assert vendor_log_digest([a, b]) == vendor_log_digest([b, a])
    assert vendor_log_digest([a, b]) != vendor_log_digest([a])


# ---- PQC supplier readiness ("questions to ask your vendors") ----

from shared_models.vendor_lifecycle import (
    ANSWERED, DECLINED, INDEPENDENT_TEST, READY, PARTIAL,
    VENDOR_CLAIM, least_ready_suppliers, supplier_readiness,
)


def _answer(dimension, **over):
    base = {"dimension": dimension, "status": ANSWERED,
            "evidence_ref": f"ev-{dimension}", "verification": VENDOR_CLAIM,
            "detail": "vendor questionnaire response"}
    base.update(over)
    return base


def _full_answers(**overrides):
    rows = [
        _answer("pqc_roadmap", verification=INDEPENDENT_TEST),
        _answer("implementation_capability"),
        _answer("testing_evidence", verification=INDEPENDENT_TEST),
        _answer("product_support_lifecycle"),
        _answer("upgrade_commitment"),
    ]
    return rows


def test_a_vendor_claim_of_testing_is_not_test_evidence():
    rows = _full_answers()
    rows[2] = _answer("testing_evidence", verification=VENDOR_CLAIM)
    out = supplier_readiness(vendor="ACME HSM", product="Luna", responses=rows,
                             as_of=AS_OF)
    assert out["state"] == PARTIAL
    assert out["is_clean_result"] is False
    testing = next(d for d in out["dimensions"] if d["dimension"] == "testing_evidence")
    assert testing["met"] is False
    assert "only an independent test" in testing["note"]


def test_ready_requires_every_dimension_with_evidence():
    out = supplier_readiness(vendor="ACME HSM", product="Luna",
                             responses=_full_answers(), as_of=AS_OF)
    assert out["state"] == READY
    assert out["is_clean_result"] is True
    assert out["dimensions_met"] == 5 == out["dimensions_total"]


def test_a_positive_answer_needs_evidence_and_verification_kind():
    rows = _full_answers()
    rows[0] = _answer("pqc_roadmap", evidence_ref="")
    with pytest.raises(ValueError):
        supplier_readiness(vendor="ACME HSM", product="Luna", responses=rows,
                           as_of=AS_OF)
    rows[0] = _answer("pqc_roadmap", verification="")
    with pytest.raises(ValueError):
        supplier_readiness(vendor="ACME HSM", product="Luna", responses=rows,
                           as_of=AS_OF)


def test_no_response_is_unknown_for_that_dimension_never_readiness():
    out = supplier_readiness(vendor="ACME HSM", product="Luna",
                             responses=_full_answers()[:3], as_of=AS_OF)
    unasked = [d for d in out["dimensions"] if d["status"] == "UNKNOWN"]
    assert {d["dimension"] for d in unasked} == {
        "product_support_lifecycle", "upgrade_commitment"}
    assert all(d["note"] == "no response is not readiness" for d in unasked)
    assert out["is_clean_result"] is False


def test_a_declined_dimension_reads_not_ready():
    rows = _full_answers()
    rows[4] = _answer("upgrade_commitment", status=DECLINED, evidence_ref=None,
                      verification=None)
    out = supplier_readiness(vendor="ACME HSM", product="Luna", responses=rows,
                             as_of=AS_OF)
    assert out["state"] == PARTIAL
    declined = next(d for d in out["dimensions"]
                    if d["dimension"] == "upgrade_commitment")
    assert declined["status"] == DECLINED and declined["met"] is False


def test_least_ready_suppliers_names_the_pacing_constraints():
    ready = supplier_readiness(vendor="Fast Co", product="FastHSM",
                               responses=_full_answers(), as_of=AS_OF)
    slow = supplier_readiness(vendor="ACME HSM", product="Luna",
                              responses=_full_answers()[:2], as_of=AS_OF)
    out = least_ready_suppliers([ready, slow])
    assert out["state"] == "CONSTRAINED"
    assert out["is_clean_result"] is False
    assert [s["vendor"] for s in out["suppliers"]] == ["ACME HSM"]
    assert "no average readiness number" in out["note"]
    all_ready = least_ready_suppliers([ready])
    assert all_ready["state"] == "NO_CONSTRAINT"
    assert all_ready["is_clean_result"] is True


def test_dimension_answered_twice_is_refused():
    rows = _full_answers() + [_answer("pqc_roadmap")]
    with pytest.raises(ValueError):
        supplier_readiness(vendor="ACME HSM", product="Luna", responses=rows,
                           as_of=AS_OF)
