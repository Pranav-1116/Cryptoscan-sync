"""The second pass: the gaps guide 130 named, closed one at a time."""

from __future__ import annotations

from datetime import date

import pytest

from vendor_intel.runtime_usage import ingest_sessions, to_claims
from vendor_intel.vbom import VbomGenerator
from vendor_intel.vendor_evidence import (
    Applicability,
    CapabilityClaim,
    Evidence,
    EvidenceType,
    HardwareDependency,
    ProductIdentity,
    SubVendorEdge,
    VerificationStatus,
    VendorDeclaration,
    add_claims,
    assess_applicability,
    evidence_backed_pqc_coverage,
    partial_ledger,
    reconcile_algorithms,
    sub_vendor_chain,
    to_vbom_row,
    vendor_footprint,
)

AS_OF = date(2026, 11, 2)


def _declaration(*, version: str = "8.4.0", profile: str | None = "3.1") -> VendorDeclaration:
    return VendorDeclaration(
        ProductIdentity("Vendor-X", "HSM-X500", version, crypto_profile_version=profile),
        "doc:vendor-x/hsm-x500-crypto-profile-8.4",
        issued_at=date(2026, 6, 1), capabilities=("AES-256", "ML-DSA-65"))


def test_a_crypto_profile_that_differs_is_a_mismatch_even_when_the_firmware_agrees():
    verdict = assess_applicability(
        _declaration(profile="3.0"),
        ProductIdentity("Vendor-X", "HSM-X500", "8.4.0", crypto_profile_version="3.1"),
        as_of=AS_OF)
    assert verdict.state is Applicability.VERSION_MISMATCH
    assert verdict.axis == "crypto_profile"
    assert verdict.axes == {"product_version": "EXACT", "crypto_profile": "MISMATCH"}
    assert verdict.vendor_capabilities_usable is False


def test_an_unobserved_profile_leaves_the_match_partial_not_green():
    verdict = assess_applicability(
        _declaration(profile="3.1"),
        ProductIdentity("Vendor-X", "HSM-X500", "8.4.0"),
        as_of=AS_OF)
    assert verdict.state is Applicability.PARTIAL_MATCH
    assert verdict.axis == "crypto_profile"
    assert verdict.axes["crypto_profile"] == "UNVERIFIED"
    assert "unverified" in verdict.reasons[-1]


def test_both_axes_matching_is_what_earns_matched():
    verdict = assess_applicability(
        _declaration(profile="3.1"),
        ProductIdentity("Vendor-X", "HSM-X500", "8.4.0", crypto_profile_version="3.1.0"),
        as_of=AS_OF)
    assert verdict.state is Applicability.MATCHED
    assert verdict.axes == {"product_version": "EXACT", "crypto_profile": "MATCH"}


def test_a_firmware_mismatch_is_not_reported_as_a_profile_problem():
    verdict = assess_applicability(
        _declaration(version="8.2.1", profile="3.0"),
        ProductIdentity("Vendor-X", "HSM-X500", "8.4.0", crypto_profile_version="3.1"),
        as_of=AS_OF)
    assert verdict.state is Applicability.VERSION_MISMATCH
    assert verdict.axis == "product_version"


def test_a_declaration_without_a_profile_axis_still_matches_on_firmware():
    verdict = assess_applicability(
        _declaration(profile=None),
        ProductIdentity("Vendor-X", "HSM-X500", "8.4.0", crypto_profile_version="3.1"),
        as_of=AS_OF)
    assert verdict.state is Applicability.MATCHED
    assert verdict.axes["crypto_profile"] == "UNSTATED"


def test_two_spellings_of_one_algorithm_agree_and_the_normalisation_is_recorded():
    report = reconcile_algorithms(
        "aes", {"vendor": "AES256", "runtime": "AES-256"},
        sources={"vendor": EvidenceType.DECLARED, "runtime": EvidenceType.RUNTIME_OBSERVED})
    assert report["state"] == "AGREE"
    assert report["normalisation_applied"] is True
    assert report["canonical"] == ["AES-256"]
    assert "normalised, not rewritten" in report["statement"]
    assert [row["value"] for row in report["rows"]] == ["AES256", "AES-256"]


def test_a_size_difference_is_a_conflict_with_the_reason_attached():
    report = reconcile_algorithms("aes", {"cbom": "AES-256", "runtime": "AES-128-GCM"})
    assert report["state"] == "CONFLICT"
    assert report["relations"][0]["relation"] == "DIFFERENT_PARAMETER"
    assert "256 against 128" in report["statement"]


def test_a_source_that_names_no_mode_is_partial():
    report = reconcile_algorithms("aes", {"vendor": "AES-256", "runtime": "AES-256-GCM"})
    assert report["state"] == "PARTIAL"
    assert report["relations"][0]["relation"] == "LESS_SPECIFIC"


def test_a_single_row_is_not_corroboration():
    assert reconcile_algorithms("aes", {"vendor": "AES-256"})["state"] == "SINGLE_SOURCE"


def test_the_partial_ledger_lists_every_partial_and_rounds_none_of_them():
    partial = assess_applicability(
        _declaration(profile="3.1"), ProductIdentity("Vendor-X", "HSM-X500", "8.4.0"),
        as_of=AS_OF)
    matched = assess_applicability(
        _declaration(), ProductIdentity("Vendor-X", "HSM-X500", "8.4.0",
                                        crypto_profile_version="3.1"), as_of=AS_OF)
    ledger = partial_ledger([partial, matched, {"state": "PARTIAL", "subject": "openssl"}])
    assert ledger["total"] == 3
    assert ledger["partial_count"] == 2
    assert ledger["dropped"] == 0
    assert all(entry["renderable_as_pass"] is False for entry in ledger["entries"])
    assert ledger["counts"] == {"MATCHED": 1, "PARTIAL": 1, "PARTIAL_MATCH": 1}
    assert ledger["entries"][0]["reasons"]


def test_a_clean_run_says_that_nothing_is_partial():
    ledger = partial_ledger([{"state": "MATCHED"}, {"state": "AGREE"}])
    assert ledger["partial_count"] == 0
    assert "none of 2" in ledger["statement"]


def test_a_sub_vendor_chain_carries_its_depth_and_path():
    edge = SubVendorEdge(
        "Vendor-X", "Crypto SDK 4.2", "Vendor-Z", "OpenSSL Wrapper 1.0",
        evidence=Evidence(EvidenceType.IMPORTED, "sbom:vendor-x-sdk-4.2", date(2026, 5, 1)))
    chain = sub_vendor_chain("Vendor-X", [edge])
    assert chain["depth"] == 1
    assert chain["vendor_names"] == ["Vendor-Z"]
    assert chain["vendors"][0]["path"] == ["Vendor-X", "Vendor-Z"]
    assert chain["vendors"][0]["evidence_id"].startswith("VE-")


def test_a_cycle_is_refused_rather_than_followed():
    there = SubVendorEdge("Vendor-X", "SDK 4.2", "Vendor-Z", "Wrapper 1.0")
    back = SubVendorEdge("Vendor-Z", "Wrapper 1.0", "Vendor-X", "SDK 4.2")
    chain = sub_vendor_chain("Vendor-X", [there, back])
    assert chain["cycles"] == [{"path": ["Vendor-X", "Vendor-Z", "Vendor-X"],
                                "reason": "the chain returns to a vendor already in the path"}]
    assert chain["vendor_names"] == ["Vendor-Z"]


def test_a_vendor_cannot_be_its_own_sub_vendor():
    with pytest.raises(ValueError):
        SubVendorEdge("Vendor-X", "SDK 4.2", "vendor-x", "SDK 3.0")


def test_indirect_exposure_is_counted_separately_from_direct():
    asset = HardwareDependency(
        "HSM-001", ProductIdentity("Vendor-X", "HSM-X500", "8.4.0"),
        applications=("Payments API",), services=("Card Auth Service",),
        business_systems=("Payment System",), critical_systems=("Card Authorization",))
    inherited = HardwareDependency(
        "HSM-009", ProductIdentity("Vendor-Z", "HSA 9", "1.0"),
        applications=("Reporting",), business_systems=("Regulatory Reporting",))
    edge = SubVendorEdge("Vendor-X", "Crypto SDK 4.2", "Vendor-Z", "HSA 9")
    footprint = vendor_footprint("Vendor-X", edges=[edge], assets=[asset, inherited])
    assert footprint["direct"]["assets"] == ["HSM-001"]
    assert footprint["indirect"]["assets"] == ["HSM-009"]
    assert footprint["sub_vendors"] == ["Vendor-Z"]
    assert "1 appliance(s) bought directly" in footprint["statement"]


def test_the_vbom_row_can_be_fed_to_the_existing_generator():
    claim = CapabilityClaim(
        asset_id="HSM-001", algorithm="ML-DSA-65", provider="Vendor-X",
        product=ProductIdentity("Vendor-X", "HSM-X500", "8.4.0"),
        discovery_method="vendor-declaration", observed_at=date(2026, 6, 1),
        applicability=assess_applicability(
            _declaration(), ProductIdentity("Vendor-X", "HSM-X500", "8.4.0",
                                            crypto_profile_version="3.1"), as_of=AS_OF),
        evidence=(Evidence(EvidenceType.DECLARED, "doc:vendor-x#ML-DSA-65",
                           observed_at=date(2026, 6, 1)),))
    row = to_vbom_row(claim)
    generator = VbomGenerator()
    block = add_claims(generator, {"id": "vendor-x", "name": "Vendor-X"}, [claim])
    assert block["crypto"][0]["verification_status"] == VerificationStatus.DECLARED_ONLY.value
    assert block["crypto"][0]["applicability"] == "MATCHED"
    assert row["pqc_ready"] is True
    assert block["pqc_coverage"] == {"entries": 1, "pqc_ready": 1, "not_ready": 0}


def test_pqc_coverage_and_evidence_backed_coverage_are_two_different_numbers():
    declared = CapabilityClaim(
        asset_id="HSM-001", algorithm="ML-DSA-65",
        product=ProductIdentity("Vendor-X", "HSM-X500", "8.4.0"),
        observed_at=date(2026, 6, 1),
        applicability=assess_applicability(
            _declaration(), ProductIdentity("Vendor-X", "HSM-X500", "8.4.0",
                                            crypto_profile_version="3.1"), as_of=AS_OF),
        evidence=(Evidence(EvidenceType.DECLARED, "doc:vendor-x#ML-DSA-65",
                           observed_at=date(2026, 6, 1)),))
    summary = ingest_sessions(
        [{"session_id": f"S-{index}", "started_at": "2026-10-01",
          "peer": "10.0.0.5:443", "cipher_suite": "TLS_AES_256_GCM_SHA384",
          "group": "x25519mlkem768"} for index in range(12)],
        asset_id="HSM-001")
    observed = next(claim for claim in to_claims(summary) if claim.algorithm == "ML-KEM-768")
    generator = VbomGenerator()
    add_claims(generator, {"id": "vendor-x", "name": "Vendor-X"}, [declared, observed])
    coverage = evidence_backed_pqc_coverage(generator.vendors())
    assert coverage["pqc_ready"] == 2
    assert coverage["pqc_evidence_backed"] == 1
    assert coverage["pqc_declared_only"] == 1
    assert coverage["backed_algorithms"] == ["ML-KEM-768"]
    assert coverage["declared_only_algorithms"] == ["ML-DSA-65"]
    assert "rest on the vendor's declaration alone" in coverage["statement"]
