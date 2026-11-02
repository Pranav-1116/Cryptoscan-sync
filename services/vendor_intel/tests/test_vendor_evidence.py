"""Vendor evidence: a declaration is not a deployment.

Each test here is one sentence the review would accept as an answer: a vendor
document for 8.2 does not describe an 8.4 appliance, an unversioned deployment
cannot be matched, a stale questionnaire cannot support "PQC ready", agreement is
not assumed when sources disagree, and a risk rating is a list of reasons rather
than a colour.
"""

from __future__ import annotations

from datetime import date

import pytest

from vendor_intel.vendor_evidence import (
    APPLICABILITY_STATES,
    DUE_DILIGENCE_SECTIONS,
    EVIDENCE_RANK,
    EVIDENCE_TYPES,
    LIFECYCLE_ORDER,
    VENDOR_EVENTS,
    Applicability,
    CapabilityClaim,
    Evidence,
    EvidenceType,
    Freshness,
    HardwareDependency,
    Lifecycle,
    LifecycleState,
    ProductIdentity,
    ReconciliationState,
    SoftwareDependency,
    VendorDeclaration,
    VerificationStatus,
    VersionRelation,
    assess_applicability,
    build_vbom_slice,
    claims_from_declaration,
    compare_versions,
    evaluate_due_diligence,
    events_for,
    freshness,
    reconcile,
    reconcile_capabilities,
    pqc_basis,
    software_impact,
    strongest,
    to_vbom_row,
    vendor_exposure,
    vendor_risk,
    version_tokens,
)

AS_OF = date(2026, 11, 2)


def declaration(version: str | None = "8.2.1", *, issued: str = "2026-06-01",
                capabilities: tuple[str, ...] = ("AES-256", "ML-DSA-65"),
                document: str = "doc:vendor-x-hsm-x500-crypto-8.2.1",
                **kwargs) -> VendorDeclaration:
    return VendorDeclaration(ProductIdentity("Vendor-X", "HSM-X500", version),
                             document, issued_at=date.fromisoformat(issued),
                             capabilities=capabilities, **kwargs)


# -- 6. the evidence vocabulary -------------------------------------------- #


def test_the_eight_evidence_types_are_the_review_vocabulary():
    assert EVIDENCE_TYPES == ("DECLARED", "IMPORTED", "CONFIGURED", "OBSERVED",
                              "RUNTIME_OBSERVED", "NETWORK_OBSERVED", "INFERRED", "UNKNOWN")
    # A vendor claim ranks below anything the bank's own estate produced.
    assert EVIDENCE_RANK["DECLARED"] < EVIDENCE_RANK["IMPORTED"]
    assert EVIDENCE_RANK["IMPORTED"] < EVIDENCE_RANK["OBSERVED"]
    assert EVIDENCE_RANK["OBSERVED"] < EVIDENCE_RANK["RUNTIME_OBSERVED"]
    assert EVIDENCE_RANK["UNKNOWN"] == 0


def test_an_evidence_row_without_a_reference_is_refused():
    with pytest.raises(ValueError):
        Evidence(EvidenceType.DECLARED, "   ")


def test_evidence_ids_are_stable_and_distinct():
    first = Evidence(EvidenceType.DECLARED, "doc:a#AES-256")
    again = Evidence(EvidenceType.DECLARED, "doc:a#AES-256")
    other = Evidence(EvidenceType.OBSERVED, "doc:a#AES-256")
    assert first.evidence_id == again.evidence_id
    assert first.evidence_id != other.evidence_id
    assert first.evidence_id.startswith("VE-")


def test_the_strongest_evidence_wins_and_a_tie_keeps_the_first():
    declared = Evidence(EvidenceType.DECLARED, "doc:a#AES", observed_at=date(2026, 1, 1))
    runtime = Evidence(EvidenceType.RUNTIME_OBSERVED, "session:7", observed_at=date(2026, 2, 1))
    assert strongest([declared, runtime]) is runtime
    first = Evidence(EvidenceType.OBSERVED, "asset:1")
    second = Evidence(EvidenceType.OBSERVED, "asset:2")
    assert strongest([first, second]) is first


# -- 7. product identity and version matching ------------------------------ #


def test_a_product_identity_needs_a_vendor_and_a_product():
    with pytest.raises(ValueError):
        ProductIdentity("", "HSM-X500", "1.0")
    with pytest.raises(ValueError):
        ProductIdentity("Vendor-X", "  ", "1.0")


def test_versions_compare_numerically_not_lexically():
    assert version_tokens("8.10.1") == (8, 10, 1)
    assert compare_versions("8.10", "8.9") is VersionRelation.MINOR_DIFF
    assert compare_versions("8.2.1", "8.2.2") is VersionRelation.PATCH_DIFF
    assert compare_versions("8.2", "8.2.0") is VersionRelation.REVISION_DIFF
    assert compare_versions("8.2.1", "9.0.0") is VersionRelation.MAJOR_DIFF
    assert compare_versions(None, "8.2") is VersionRelation.INCOMPARABLE


def test_an_exact_version_is_the_only_full_match():
    result = assess_applicability(declaration("8.2.1"),
                                  ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"), as_of=AS_OF)
    assert result.state is Applicability.MATCHED
    assert result.applicable and result.vendor_capabilities_usable


def test_a_patch_difference_is_a_partial_match_not_a_match():
    result = assess_applicability(declaration("8.2.1"),
                                  ProductIdentity("Vendor-X", "HSM-X500", "8.2.2"), as_of=AS_OF)
    assert result.state is Applicability.PARTIAL_MATCH
    assert result.applicable, "same generation: the bank still has to read the advisory"
    assert result.version_relation is VersionRelation.PATCH_DIFF


def test_a_minor_version_difference_refuses_the_declaration():
    """The review's example: declared 8.2, deployed 8.4."""
    result = assess_applicability(declaration("8.2.1"),
                                  ProductIdentity("Vendor-X", "HSM-X500", "8.4.0"), as_of=AS_OF)
    assert result.state is Applicability.VERSION_MISMATCH
    assert not result.applicable
    assert "does not travel" in result.reasons[-1]


def test_a_different_product_never_matches_even_at_the_same_version():
    result = assess_applicability(declaration("8.2.1"),
                                  ProductIdentity("Vendor-X", "HSM-X700", "8.2.1"), as_of=AS_OF)
    assert result.state is Applicability.PRODUCT_MISMATCH
    assert "deployed Vendor-X HSM-X700" in result.reasons[0]


def test_a_different_vendor_never_matches_even_at_the_same_product_name():
    result = assess_applicability(declaration("8.2.1"),
                                  ProductIdentity("Vendor-Y", "HSM-X500", "8.2.1"), as_of=AS_OF)
    assert result.state is Applicability.PRODUCT_MISMATCH


def test_an_unversioned_deployment_is_unverified_not_matched():
    result = assess_applicability(declaration("8.2.1"),
                                  ProductIdentity("Vendor-X", "HSM-X500", None), as_of=AS_OF)
    assert result.state is Applicability.DEPLOYMENT_UNVERIFIED
    assert "no observed version" in result.reasons[0]


def test_a_declaration_without_a_version_cannot_be_matched():
    result = assess_applicability(declaration(None),
                                  ProductIdentity("Vendor-X", "HSM-X500", "8.4.0"), as_of=AS_OF)
    assert result.state is Applicability.UNKNOWN


def test_a_superseded_document_is_refused_before_any_version_comparison():
    result = assess_applicability(
        declaration("8.2.1", superseded_by="doc:vendor-x-8.3-rev2"),
        ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"), as_of=AS_OF)
    assert result.state is Applicability.SUPERSEDED
    assert "superseded by doc:vendor-x-8.3-rev2" in result.reasons


def test_every_applicability_state_the_review_named_exists():
    assert set(APPLICABILITY_STATES) == {
        "MATCHED", "PARTIAL_MATCH", "VERSION_MISMATCH", "PRODUCT_MISMATCH",
        "DEPLOYMENT_UNVERIFIED", "EXPIRED", "SUPERSEDED", "UNKNOWN"}


# -- 14. freshness ---------------------------------------------------------- #


def test_freshness_is_a_state_and_a_sentence_not_a_boolean():
    stale = freshness("2024-08-11", as_of=AS_OF)
    assert stale["state"] == Freshness.EXPIRED.value
    assert stale["age_days"] == 813
    assert "2024-08-11" in stale["statement"]
    current = freshness("2026-09-01", as_of=AS_OF)
    assert current["state"] == Freshness.FRESH.value
    assert "62 days ago" in current["statement"]


def test_evidence_between_one_and_two_review_windows_is_stale():
    result = freshness("2025-06-01", as_of=AS_OF, max_age_days=365)
    assert result["state"] == Freshness.STALE.value


def test_an_undated_or_future_dated_evidence_row_is_unknown():
    assert freshness(None, as_of=AS_OF)["state"] == Freshness.UNKNOWN.value
    ahead = freshness("2027-01-01", as_of=AS_OF)
    assert ahead["state"] == Freshness.UNKNOWN.value
    assert "in the future" in ahead["statement"]


def test_an_expired_document_cannot_be_applicable_even_at_the_right_version():
    result = assess_applicability(declaration("8.2.1", issued="2024-01-01"),
                                  ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"), as_of=AS_OF)
    assert result.state is Applicability.EXPIRED
    assert "validity" in result.reasons[-1] or "expired" in result.reasons[-1]


# -- 13. capability claims -------------------------------------------------- #


def test_a_declaration_for_another_version_does_not_light_the_declared_flag():
    claims = claims_from_declaration(declaration("8.2.1"),
                                     ProductIdentity("Vendor-X", "HSM-X500", "8.4.0"),
                                     asset_id="HSM-001", as_of=AS_OF)
    claim = claims[0]
    assert claim.applicability.state is Applicability.VERSION_MISMATCH
    assert claim.vendor_declared is False
    assert claim.verification_status is VerificationStatus.INAPPLICABLE
    assert claim.confidence == "LOW"


def test_an_applicable_declaration_alone_is_only_declared():
    claim = claims_from_declaration(declaration("8.2.1"),
                                    ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"),
                                    asset_id="HSM-001", as_of=AS_OF)[0]
    assert claim.vendor_declared is True
    assert claim.bank_observed is False
    assert claim.verification_status is VerificationStatus.DECLARED_ONLY
    assert claim.to_dict()["verification"] == {
        "vendor_declared": True, "bank_observed": False, "runtime_observed": False,
        "production_usage": False, "version_matched": True, "evidence_fresh": True}


def test_a_declaration_plus_a_bank_observation_is_confirmed():
    claim = claims_from_declaration(
        declaration("8.2.1"), ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"),
        asset_id="HSM-001", as_of=AS_OF,
        extra_evidence=[Evidence(EvidenceType.OBSERVED, "observation:HBOM-4471",
                                 observed_at=date(2026, 9, 30))])[0]
    assert claim.bank_observed and claim.verification_status is VerificationStatus.CONFIRMED
    assert claim.confidence == "MEDIUM"


def test_runtime_evidence_corroborates_and_raises_confidence():
    claim = claims_from_declaration(
        declaration("8.2.1"), ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"),
        asset_id="HSM-001", as_of=AS_OF,
        extra_evidence=[
            Evidence(EvidenceType.OBSERVED, "observation:HBOM-4471",
                     observed_at=date(2026, 9, 30)),
            Evidence(EvidenceType.RUNTIME_OBSERVED, "session:pkcs11-8821",
                     observed_at=date(2026, 10, 2))])[0]
    assert claim.runtime_observed
    assert claim.verification_status is VerificationStatus.CORROBORATED
    assert claim.confidence == "HIGH"


def test_a_bank_observation_the_vendor_never_declared_is_still_recorded():
    claim = CapabilityClaim(asset_id="HSM-001", algorithm="AES-128",
                            evidence=(Evidence(EvidenceType.OBSERVED, "observation:HBOM-9"),
                                      Evidence(EvidenceType.CONFIGURED,
                                               "config:apps/payment/pkcs11.yml")),
                            observed_at=date(2026, 9, 30))
    assert claim.vendor_declared is False
    assert claim.verification_status is VerificationStatus.BANK_OBSERVED_ONLY
    assert claim.production_usage is True


def test_a_capability_with_no_evidence_at_all_is_unknown():
    claim = CapabilityClaim(asset_id="HSM-001", algorithm="RSA-2048")
    assert claim.verification_status is VerificationStatus.UNKNOWN
    assert claim.confidence == "UNKNOWN"
    assert claim.to_dict()["applicability"]["vendor_capabilities_usable"] is False


def test_the_claim_document_carries_every_field_the_review_named():
    claim = claims_from_declaration(declaration("8.2.1"),
                                    ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"),
                                    asset_id="HSM-001", as_of=AS_OF)[0]
    payload = claim.to_dict()
    for field_name in ("algorithm", "key_size", "curve", "mode", "purpose", "provider",
                       "product", "firmware_version", "discovery_method", "source_document",
                       "source_hash", "observed_at", "valid_from", "valid_until",
                       "applicability", "confidence", "verification_status", "evidence"):
        assert field_name in payload, field_name
    assert "key_material" not in payload


def test_a_pqc_tick_carries_its_basis():
    assert pqc_basis("ML-DSA-65")[0] is True
    assert pqc_basis("RSA-3072") == (False, "RSA is broken by Shor's algorithm")
    assert "Grover" in pqc_basis("AES-256")[1]


def test_a_claim_bridges_into_the_existing_vbom_row_shape():
    claim = claims_from_declaration(
        declaration("8.2.1", capabilities=("ML-DSA-65",)),
        ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"), asset_id="HSM-001", as_of=AS_OF,
        extra_evidence=[Evidence(EvidenceType.OBSERVED, "observation:HBOM-1",
                                 observed_at=date(2026, 10, 1))])[0]
    row = to_vbom_row(claim)
    assert row["algorithm"] == "ML-DSA-65"
    assert row["pqc_ready"] is True
    assert row["verification_status"] == VerificationStatus.CONFIRMED.value
    assert row["applicability"] == "MATCHED"
    assert row["evidence_type"] == "OBSERVED"
    assert len(row["evidence_ids"]) == 2


# -- 15. reconciliation ----------------------------------------------------- #


def test_two_sources_that_disagree_produce_a_conflict_not_a_winner():
    report = reconcile("openssl_version",
                       {"vendor": "3.0.13", "sbom": "3.0.11", "runtime": "3.0.11"},
                       sources={"vendor": EvidenceType.DECLARED, "sbom": EvidenceType.IMPORTED,
                                "runtime": EvidenceType.RUNTIME_OBSERVED})
    assert report["state"] == ReconciliationState.CONFLICT.value
    assert report["distinct_values"] == ["3.0.11", "3.0.13"]
    assert [row["value"] for row in report["rows"]] == ["3.0.13", "3.0.11", "3.0.11"]
    assert "CONFLICT" in report["statement"]


def test_two_strong_sources_that_disagree_conflict_even_with_a_weak_tiebreak():
    report = reconcile("cipher", {"cbom": "AES-256", "runtime": "AES-128-GCM"},
                       sources={"cbom": EvidenceType.OBSERVED,
                                "runtime": EvidenceType.RUNTIME_OBSERVED})
    assert report["state"] == ReconciliationState.CONFLICT.value


def test_a_vendor_claim_contradicted_by_one_bank_source_is_a_conflict():
    report = reconcile("openssl_version", {"vendor": "3.0.13", "sbom": "3.0.11"},
                       sources={"vendor": EvidenceType.DECLARED,
                                "sbom": EvidenceType.IMPORTED})
    assert report["state"] == ReconciliationState.CONFLICT.value
    # The strongest source is named for triage, and is not used to overwrite the other.
    assert report["strongest_evidence_type"] == EvidenceType.IMPORTED.value
    assert {row["value"] for row in report["rows"]} == {"3.0.13", "3.0.11"}


def test_a_less_specific_value_is_partial_rather_than_a_contradiction():
    report = reconcile("openssl_version", {"sbom": "3.0.11", "vendor": "3.0"},
                       sources={"sbom": EvidenceType.IMPORTED,
                                "vendor": EvidenceType.DECLARED})
    assert report["state"] == ReconciliationState.PARTIAL.value
    assert report["distinct_values"] == ["3.0", "3.0.11"]


def test_one_source_is_not_corroboration_and_none_is_unknown():
    single = reconcile("firmware", {"vendor": "8.2.1"},
                       sources={"vendor": EvidenceType.DECLARED})
    assert single["state"] == ReconciliationState.SINGLE_SOURCE.value
    assert "not corroboration" in single["statement"]
    empty = reconcile("firmware", {"vendor": None})
    assert empty["state"] == ReconciliationState.UNKNOWN.value


def test_agreement_is_reported_as_agreement():
    report = reconcile("openssl_version", {"sbom": "3.0.11", "runtime": "3.0.11"},
                       sources={"sbom": EvidenceType.IMPORTED,
                                "runtime": EvidenceType.RUNTIME_OBSERVED})
    assert report["state"] == ReconciliationState.AGREE.value
    assert report["row_count"] == 2


def test_capability_reconciliation_groups_by_asset_and_algorithm():
    declared = claims_from_declaration(declaration("8.2.1", capabilities=("AES-256",)),
                                       ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"),
                                       asset_id="HSM-001", as_of=AS_OF)
    observed = CapabilityClaim(asset_id="HSM-001", algorithm="AES-256", key_size=256,
                               discovery_method="pkcs11",
                               evidence=(Evidence(EvidenceType.OBSERVED, "observation:1"),),
                               observed_at=date(2026, 10, 1))
    reports = reconcile_capabilities([*declared, observed], as_of=AS_OF)
    assert len(reports) == 1
    assert reports[0]["asset_id"] == "HSM-001"
    assert reports[0]["verification_status"] == VerificationStatus.CONFIRMED.value
    assert len(reports[0]["evidence"]) == 2


# -- 9. due diligence ------------------------------------------------------- #


def test_due_diligence_names_the_sections_a_bank_procurement_needs():
    assert len(DUE_DILIGENCE_SECTIONS) == 22
    for section in ("end_of_life", "security_advisories", "pqc_roadmap", "fips_claims",
                    "common_criteria_claims", "sbom_availability", "cbom_availability",
                    "vulnerability_disclosure", "supply_chain_evidence", "reviewer"):
        assert section in DUE_DILIGENCE_SECTIONS


def test_an_empty_due_diligence_record_is_incomplete_with_reasons():
    report = evaluate_due_diligence({}, as_of=AS_OF)
    assert report["status"] == "INCOMPLETE"
    assert report["sections_present"] == 0
    assert len(report["missing"]) == 22
    assert any("review status" in blocker for blocker in report["blockers"])
    assert any("sbom_availability" in blocker for blocker in report["blockers"])


def test_a_complete_current_review_has_no_blockers():
    sections = {name: "present" for name in DUE_DILIGENCE_SECTIONS}
    sections.update({"last_review": "2026-09-01", "reviewer": "risk-eng",
                     "review_status": "APPROVED"})
    report = evaluate_due_diligence(sections, as_of=AS_OF)
    assert report["status"] == "COMPLETE"
    assert report["completeness"] == 100.0
    assert report["blockers"] == []


def test_an_old_review_blocks_approval_even_when_every_section_is_present():
    sections = {name: "present" for name in DUE_DILIGENCE_SECTIONS}
    sections.update({"last_review": "2024-08-11", "review_status": "APPROVED"})
    report = evaluate_due_diligence(sections, as_of=AS_OF)
    assert report["status"] == "INCOMPLETE"
    assert any("last review is expired" in blocker for blocker in report["blockers"])
    assert report["review_age"]["age_days"] == 813


def test_an_unknown_review_status_is_refused():
    with pytest.raises(ValueError):
        evaluate_due_diligence({"review_status": "PROBABLY_FINE"}, as_of=AS_OF)


# -- 10. lifecycle ---------------------------------------------------------- #


def test_every_lifecycle_state_the_review_named_exists():
    assert LIFECYCLE_ORDER == ("CURRENT", "SUPPORTED", "MAINTENANCE", "END_OF_SUPPORT",
                               "END_OF_LIFE", "RETIRED")


def test_dates_override_a_stale_declared_state():
    product = ProductIdentity("Vendor-X", "HSM-X500", "8.2.1")
    lifecycle = Lifecycle(product, LifecycleState.SUPPORTED,
                          support_ends_on=date(2026, 6, 30),
                          end_of_life_on=date(2027, 6, 30), source="vendor:lifecycle-2026")
    assert lifecycle.effective_state(as_of=AS_OF) is LifecycleState.END_OF_SUPPORT
    payload = lifecycle.to_dict(as_of=AS_OF)
    assert payload["declared_state"] == "SUPPORTED"
    assert payload["effective_state"] == "END_OF_SUPPORT"
    assert payload["drifted"] is True
    assert payload["unsupported"] is True


def test_a_product_past_its_end_of_life_is_end_of_life_not_end_of_support():
    lifecycle = Lifecycle(ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"),
                          LifecycleState.SUPPORTED,
                          support_ends_on=date(2026, 6, 30),
                          end_of_life_on=date(2026, 9, 30))
    assert lifecycle.effective_state(as_of=AS_OF) is LifecycleState.END_OF_LIFE


# -- 11 / 12. dependency chains --------------------------------------------- #


def test_vendor_exposure_counts_each_level_separately():
    assets = [
        HardwareDependency("HSM-001", ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"),
                           applications=("Payment API", "Card Gateway"),
                           services=("Payment Processing",),
                           business_systems=("Card Authorization",),
                           critical_systems=("Card Authorization",),
                           evidence=(Evidence(EvidenceType.CONFIGURED,
                                              "config:apps/payment/pkcs11.yml"),)),
        HardwareDependency("HSM-002", ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"),
                           applications=("Payment API",),
                           services=("Payment Processing", "Fraud Scoring"),
                           business_systems=("Card Authorization",)),
        HardwareDependency("HSM-900", ProductIdentity("Vendor-Y", "HSM-Y100", "2.0"),
                           applications=("Reporting",)),
    ]
    exposure = vendor_exposure(assets, vendor="Vendor-X")
    assert exposure["asset_count"] == 2
    assert exposure["applications"] == ["Card Gateway", "Payment API"]
    assert exposure["services"] == ["Fraud Scoring", "Payment Processing"]
    assert exposure["critical_systems"] == ["Card Authorization"]
    assert "2 asset(s)" in exposure["statement"]
    assert len(exposure["evidence"]) == 1


def test_vendor_exposure_narrows_to_a_product():
    assets = [HardwareDependency("HSM-001", ProductIdentity("Vendor-X", "HSM-X500", "8.2.1")),
              HardwareDependency("KMS-001", ProductIdentity("Vendor-X", "KMS-X1", "1.0"))]
    exposure = vendor_exposure(assets, vendor="Vendor-X", product="KMS-X1")
    assert exposure["assets"] == ["KMS-001"]


def test_no_recorded_deployment_is_not_the_same_as_no_dependency():
    exposure = vendor_exposure([], vendor="Vendor-X")
    assert exposure["asset_count"] == 0
    assert "not the same as none" in exposure["statement"]


def test_software_impact_counts_applications_containers_and_systems():
    dependencies = [
        SoftwareDependency("Vendor-X", "Crypto SDK", "openssl-wrapper", "4.2",
                           applications=("Payments API", "Card Gateway"),
                           containers=("payments-api:1.9", "gateway:3.2"),
                           systems=("Payment Processing",),
                           critical_services=("Card Authorization",)),
        SoftwareDependency("Vendor-X", "Crypto SDK", "openssl-wrapper", "4.1",
                           applications=("Reporting",)),
        SoftwareDependency("Vendor-X", "Crypto SDK", "other-helper", "4.2",
                           applications=("Unrelated",)),
    ]
    impact = software_impact("openssl-wrapper", dependencies, version="4.2")
    assert impact["applications"] == ["Card Gateway", "Payments API"]
    assert impact["containers"] == ["gateway:3.2", "payments-api:1.9"]
    assert impact["installed_versions"] == ["4.2"]
    assert "1 deployment(s) of openssl-wrapper 4.2" in impact["statement"]
    assert "2 application(s)" in impact["statement"]
    everything = software_impact("openssl-wrapper", dependencies)
    assert everything["installed_versions"] == ["4.1", "4.2"]


# -- 16. risk --------------------------------------------------------------- #


def test_a_risk_rating_is_a_list_of_reasons():
    lifecycle = Lifecycle(ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"),
                          LifecycleState.SUPPORTED, support_ends_on=date(2026, 6, 30))
    risk = vendor_risk(critical_systems=1, weak_algorithms=["RSA-1024", "DES"],
                       lifecycle=lifecycle, pqc_available=False, stale_evidence=True,
                       deployment_verified=False, sbom_available=False, open_advisories=2,
                       business_criticality="CRITICAL", crypto_dependency=True, as_of=AS_OF)
    assert risk["severity"] in {"CRITICAL", "HIGH"}
    assert risk["explainable"] is True
    names = {factor["factor"] for factor in risk["factors"]}
    assert {"critical_systems_affected", "weak_algorithms", "product_lifecycle",
            "pqc_capability", "evidence_freshness", "deployment_verification",
            "sbom_availability", "vulnerability_history"} <= names
    assert all(factor["reason"] for factor in risk["factors"])
    assert risk["factors"] == sorted(risk["factors"], key=lambda row: -row["points"])


def test_a_clean_vendor_scores_low_and_says_so():
    lifecycle = Lifecycle(ProductIdentity("Vendor-X", "HSM-X500", "9.0"),
                          LifecycleState.CURRENT)
    risk = vendor_risk(lifecycle=lifecycle, pqc_available=True, deployment_verified=True,
                       sbom_available=True, supply_chain_evidence=True,
                       business_criticality="LOW", crypto_dependency=False, as_of=AS_OF)
    assert risk["severity"] == "LOW"
    assert risk["score"] == 0
    assert risk["factors"] == []


def test_an_unstated_pqc_position_scores_below_a_refusal():
    absent = vendor_risk(pqc_available=None, as_of=AS_OF)
    refused = vendor_risk(pqc_available=False, as_of=AS_OF)
    assert refused["score"] > absent["score"]
    states = {factor["factor"]: factor["state"] for factor in absent["factors"]}
    assert states["pqc_capability"] == "UNKNOWN"


# -- drift vocabulary ------------------------------------------------------- #


def test_the_vendor_vocabulary_separates_declared_from_observed():
    for name in ("CAPABILITY_DECLARED", "CAPABILITY_OBSERVED", "USAGE_OBSERVED",
                 "VENDOR_EVIDENCE_STALE", "VENDOR_DOCUMENT_SUPERSEDED",
                 "VENDOR_DOCUMENT_EXPIRED", "VENDOR_PRODUCT_MISMATCH",
                 "VENDOR_DEPLOYMENT_UNVERIFIED", "VENDOR_VERSION_MISMATCH",
                 "EVIDENCE_CONFLICT"):
        assert name in VENDOR_EVENTS


def test_a_mismatched_declaration_emits_a_mismatch_not_a_capability():
    claims = claims_from_declaration(declaration("8.2.1", capabilities=("AES-256",)),
                                     ProductIdentity("Vendor-X", "HSM-X500", "8.4.0"),
                                     asset_id="HSM-001", as_of=AS_OF)
    events = events_for(claims, as_of=AS_OF)
    types = [event["event_type"] for event in events]
    assert "VENDOR_VERSION_MISMATCH" in types
    assert "CAPABILITY_DECLARED" not in types, "an inapplicable document declares nothing"


def test_a_declared_and_confirmed_capability_emits_three_distinct_events():
    claims = claims_from_declaration(
        declaration("8.2.1", capabilities=("AES-256",)),
        ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"), asset_id="HSM-001", as_of=AS_OF,
        extra_evidence=[Evidence(EvidenceType.OBSERVED, "observation:HBOM-1",
                                 observed_at=date(2026, 10, 1)),
                        Evidence(EvidenceType.CONFIGURED, "config:apps/payment/pkcs11.yml")])
    types = {event["event_type"] for event in events_for(claims, as_of=AS_OF)}
    assert {"CAPABILITY_DECLARED", "CAPABILITY_OBSERVED", "USAGE_OBSERVED"} <= types


def test_stale_evidence_emits_its_own_event():
    claim = claims_from_declaration(declaration("8.2.1", issued="2024-01-01"),
                                    ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"),
                                    asset_id="HSM-001", as_of=AS_OF)[0]
    events = events_for([claim], as_of=AS_OF)
    types = {event["event_type"] for event in events}
    assert "VENDOR_EVIDENCE_STALE" in types
    # An expired document is filed as expired, not as a version mismatch.
    assert "VENDOR_DOCUMENT_EXPIRED" in types and "VENDOR_VERSION_MISMATCH" not in types


# -- the VBOM slice --------------------------------------------------------- #


def test_the_vbom_slice_carries_evidence_and_never_a_bare_boolean():
    sections = {name: "present" for name in DUE_DILIGENCE_SECTIONS}
    sections.update({"last_review": "2026-09-01", "review_status": "APPROVED"})
    claims = claims_from_declaration(
        declaration("8.2.1", capabilities=("AES-256", "ML-DSA-65")),
        ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"), asset_id="HSM-001", as_of=AS_OF,
        extra_evidence=[Evidence(EvidenceType.OBSERVED, "observation:HBOM-1",
                                 observed_at=date(2026, 10, 1))])
    entry = build_vbom_slice(
        vendor="Vendor-X", declarations=[declaration("8.2.1")],
        deployments=[ProductIdentity("Vendor-X", "HSM-X500", "8.2.1")],
        assets=[HardwareDependency("HSM-001", ProductIdentity("Vendor-X", "HSM-X500", "8.2.1"),
                                   applications=("Payment API",))],
        claims=claims, due_diligence=evaluate_due_diligence(sections, as_of=AS_OF),
        as_of=AS_OF)
    assert entry["verification_counts"] == {"CONFIRMED": 2}
    assert entry["applicability"][0]["applicability"] == "MATCHED"
    assert entry["exposure"]["applications"] == ["Payment API"]
    assert "2 are confirmed" in entry["statement"]
    assert entry["reconciliation"][0]["state"] in {"AGREE", "SINGLE_SOURCE", "CONFLICT"}
    rendered = str(entry)
    assert "key_material" not in rendered and "PRIVATE KEY" not in rendered
