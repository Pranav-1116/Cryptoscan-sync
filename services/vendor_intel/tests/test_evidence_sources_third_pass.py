"""Attribution, sub-vendor discovery and the bank's own alias table."""

from __future__ import annotations

from datetime import date

import pytest

from vendor_intel.algorithm_names import (
    AliasConflict,
    AlgorithmTable,
    algorithm_identity,
    load_alias_table,
)
from vendor_intel.sbom_edges import (
    SbomShapeError,
    component_vendor,
    edges_for_footprint,
    vendor_edges_from_cyclonedx,
)
from vendor_intel.usage_attribution import (
    Endpoint,
    attribute_sessions,
    endpoints_from_inventory,
    split_peer,
    workload_summary,
)
from vendor_intel.vendor_evidence import (
    Evidence,
    EvidenceType,
    HardwareDependency,
    ProductIdentity,
    SubVendorEdge,
    vendor_footprint,
)

RECORDS = ([{"peer": "10.0.0.5:443"}] * 8 + [{"peer": "10.0.0.7:443"}] * 3
           + [{"peer": "10.9.9.9:443"}] * 2 + [{"peer": "10.0.0.8:443"}])

ENDPOINTS = [
    Endpoint("10.0.0.5", asset_id="HSM-001", applications=("Payments API",),
             evidence=Evidence(EvidenceType.OBSERVED, "cmdb:HSM-001")),
    Endpoint("10.0.0.7", asset_id="HSM-001", applications=("Payments API", "Reporting")),
    Endpoint("10.0.0.8", asset_id="WEB-01"),
]

BOM = {
    "bomFormat": "CycloneDX",
    "serialNumber": "urn:uuid:1234",
    "metadata": {"component": {"name": "Crypto SDK 4.2",
                               "supplier": {"name": "Vendor-X"}}},
    "components": [
        {"name": "openssl-wrapper", "version": "1.0.3", "bom-ref": "c1",
         "supplier": {"name": "Vendor-Z"}, "purl": "pkg:generic/wrapper@1.0.3"},
        {"name": "libfoo", "version": "2.0"},
        {"name": "vendor-x-core", "version": "4.2", "publisher": "Vendor-X"},
        {"name": "dup", "version": "1", "supplier": {"name": "Vendor-Z"}},
        {"name": "dup", "version": "1", "supplier": {"name": "vendor-z"}},
    ],
}


# --------------------------------------------------------------------------- #
# attribution
# --------------------------------------------------------------------------- #


def test_one_endpoint_one_application_is_the_only_attributed_answer():
    report = attribute_sessions(RECORDS, ENDPOINTS, default_asset_id="HSM-001")
    payments = next(row for row in report["rows"] if row["peer"] == "10.0.0.5:443")
    assert payments["state"] == "ATTRIBUTED"
    assert payments["applications"] == ["Payments API"]
    assert payments["endpoint_evidence"][0].startswith("VE-")


def test_a_shared_appliance_is_ambiguous_and_both_applications_are_named():
    report = attribute_sessions(RECORDS, ENDPOINTS)
    shared = next(row for row in report["rows"] if row["peer"] == "10.0.0.7:443")
    assert shared["state"] == "AMBIGUOUS"
    assert shared["applications"] == ["Payments API", "Reporting"]
    assert "cannot say which one" in shared["reason"]


def test_an_endpoint_with_no_application_is_partial_not_attributed():
    report = attribute_sessions(RECORDS, ENDPOINTS)
    known = next(row for row in report["rows"] if row["peer"] == "10.0.0.8:443")
    assert known["state"] == "PARTIAL"
    assert known["asset_ids"] == ["WEB-01"] and known["applications"] == []


def test_an_unknown_peer_is_not_assigned_to_the_nearest_appliance():
    report = attribute_sessions(RECORDS, ENDPOINTS, default_asset_id="HSM-001")
    unknown = next(row for row in report["rows"] if row["peer"] == "10.9.9.9:443")
    assert unknown["state"] == "UNATTRIBUTED"
    assert unknown["applications"] == []
    assert unknown["asset_ids"] == ["HSM-001"]  # the collector's asset, not the workload


def test_the_workload_table_keeps_the_unattributed_remainder():
    report = attribute_sessions(RECORDS, ENDPOINTS)
    summary = workload_summary(report)
    assert summary["applications"] == {"Payments API": 8}
    assert summary["unattributed_sessions"] == 6
    assert summary["coverage"] == 57.1
    assert "unknown workload" in summary["statement"]


def test_every_half_answer_reaches_the_ledger():
    report = attribute_sessions(RECORDS, ENDPOINTS)
    assert {entry["state"] for entry in report["ledger"]} == {"PARTIAL", "AMBIGUOUS",
                                                             "UNATTRIBUTED"}
    assert len(report["ledger"]) == 3


def test_a_port_narrows_a_shared_address_and_matching_is_by_host():
    endpoints = [Endpoint("10.0.0.5", port=443, applications=("Payments API",)),
                 Endpoint("10.0.0.5", port=8443, applications=("Admin API",))]
    report = attribute_sessions([{"peer": "10.0.0.5:8443"}], endpoints)
    assert report["rows"][0]["applications"] == ["Admin API"]


def test_the_register_export_is_read_and_an_addressless_row_is_refused():
    endpoints = endpoints_from_inventory([
        {"host": "10.0.0.5", "port": 443, "asset_id": "HSM-001",
         "applications": ["Payments API"]}])
    assert endpoints[0].port == 443
    with pytest.raises(ValueError):
        endpoints_from_inventory([{"asset_id": "HSM-001"}])


def test_a_peer_without_a_port_is_still_a_peer():
    assert split_peer("hsm-001.corp") == ("hsm-001.corp", None)
    assert split_peer("10.0.0.5:443") == ("10.0.0.5", 443)
    assert split_peer("") == ("", None)


# --------------------------------------------------------------------------- #
# sub-vendor discovery from an SBOM
# --------------------------------------------------------------------------- #


def test_a_supplier_becomes_an_edge_with_the_sbom_as_its_citation():
    report = vendor_edges_from_cyclonedx(BOM, parent_vendor="Vendor-X",
                                         observed_at=date(2026, 5, 1),
                                         evidence_factory=Evidence)
    wrapper = next(edge for edge in report["edges"] if edge["child_vendor"] == "Vendor-Z")
    assert wrapper["child_product"] == "openssl-wrapper 1.0.3"
    assert wrapper["reference"] == "sbom:urn:uuid:1234#c1"
    assert wrapper["evidence"].evidence_id.startswith("VE-")
    assert wrapper["evidence"].kind is EvidenceType.IMPORTED


def test_a_component_with_no_supplier_is_listed_and_never_inferred():
    report = vendor_edges_from_cyclonedx(BOM, parent_vendor="Vendor-X")
    assert report["unattributed"][0]["component"] == "libfoo"
    assert "not a vendor" in report["unattributed"][0]["reason"]
    assert all(edge["child_vendor"] != "libfoo" for edge in report["edges"])


def test_the_parents_own_component_and_a_duplicate_are_not_edges():
    report = vendor_edges_from_cyclonedx(BOM, parent_vendor="Vendor-X")
    assert report["self_edges"][0]["component"] == "vendor-x-core"
    assert report["duplicates"] == ["dup"]
    # Two components from the same vendor are two edges to one vendor; the same
    # component twice is one edge and a duplicate note.
    edges = [edge["child_product"] for edge in report["edges"]]
    assert edges == ["openssl-wrapper 1.0.3", "dup 1"]


def test_which_field_named_the_vendor_is_recorded():
    assert component_vendor({"supplier": {"name": "Vendor-Z"}}) == ("Vendor-Z", "supplier")
    assert component_vendor({"group": "acme"}) == ("acme", "group")
    assert component_vendor({"name": "openssl-wrapper"}) == (None, None)


def test_edges_reach_the_footprint_and_are_counted_apart_from_direct_buys():
    report = vendor_edges_from_cyclonedx(BOM, parent_vendor="Vendor-X",
                                         evidence_factory=Evidence)
    edges = edges_for_footprint(report, edge_factory=SubVendorEdge)
    asset = HardwareDependency("HSM-001", ProductIdentity("Vendor-X", "HSM-X500", "8.4.0"),
                               business_systems=("Payment System",),
                               critical_systems=("Card Authorization",))
    inherited = HardwareDependency("HSM-009", ProductIdentity("Vendor-Z", "HSA 9", "1.0"),
                                   business_systems=("Reporting",))
    footprint = vendor_footprint("Vendor-X", edges=edges, assets=[asset, inherited])
    assert footprint["direct"]["assets"] == ["HSM-001"]
    assert footprint["indirect"]["assets"] == ["HSM-009"]
    assert "bought directly" in footprint["statement"]


def test_a_document_that_is_not_a_bom_is_refused():
    with pytest.raises(SbomShapeError):
        vendor_edges_from_cyclonedx({"bomFormat": "SPDX", "components": []},
                                    parent_vendor="Vendor-X")
    with pytest.raises(SbomShapeError):
        vendor_edges_from_cyclonedx({"components": "nope"}, parent_vendor="Vendor-X")
    with pytest.raises(SbomShapeError):
        vendor_edges_from_cyclonedx(BOM, parent_vendor="  ")


def test_an_empty_bom_says_the_metadata_is_the_gap():
    report = vendor_edges_from_cyclonedx({"bomFormat": "CycloneDX", "components": []},
                                        parent_vendor="Vendor-X")
    assert report["edges"] == []
    assert "gap in the SBOM's supplier metadata" in report["statement"]


# --------------------------------------------------------------------------- #
# the bank's own alias table
# --------------------------------------------------------------------------- #


def test_a_bank_spelling_resolves_through_the_supplied_table():
    table = AlgorithmTable(extra={"AESGCM256": "AES-256-GCM", "RSA-3K": "RSA-3072"})
    assert table.identity("AESGCM256").canonical == "AES-256-GCM"
    assert table.same("RSA-3K", "RSA-3072") is True
    assert table.compare("AESGCM256", "AES-256")["relation"] == "LESS_SPECIFIC"


def test_an_override_cannot_redefine_a_builtin_spelling():
    with pytest.raises(AliasConflict) as raised:
        AlgorithmTable(extra={"AES256": "AES-128"})
    assert "already a builtin spelling" in str(raised.value)


def test_an_alias_cannot_point_at_a_name_nobody_knows():
    with pytest.raises(AliasConflict) as raised:
        AlgorithmTable(extra={"X99": "NOPE-1"})
    assert "does not know" in str(raised.value)


def test_the_review_stub_is_emitted_unfilled():
    table = AlgorithmTable()
    stub = table.stub(["AES-256", "Weird-99-xyz", "weird-99-xyz"])
    assert stub["aliases"] == {"Weird-99-xyz": "", "weird-99-xyz": ""}
    assert stub["unresolved"] == 2
    with pytest.raises(AliasConflict) as raised:
        load_alias_table(stub)
    assert "no target yet" in str(raised.value)


def test_a_filled_stub_loads_and_a_bare_mapping_loads_too():
    table = load_alias_table({"aliases": {"MYCIPHER-1": "AES-128"}})
    assert table.identity("MYCIPHER-1").canonical == "AES-128"
    bare = load_alias_table({"MYCIPHER-2": "AES-256"})
    assert bare.normalise(["MYCIPHER-2"]) == ["AES-256"]
    with pytest.raises(AliasConflict):
        load_alias_table({"aliases": "not a mapping"})


def test_the_table_does_not_change_the_default_answers():
    assert algorithm_identity("AES256").canonical == "AES-256"
    assert algorithm_identity("MYCIPHER-1").recognised is False
