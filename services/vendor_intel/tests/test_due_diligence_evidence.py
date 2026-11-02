"""A due-diligence section that cites nothing is a sentence, not a record."""

from __future__ import annotations

from datetime import date

from vendor_intel.vendor_evidence import (
    DUE_DILIGENCE_SECTIONS,
    audit_due_diligence_evidence,
    evaluate_due_diligence,
    partial_ledger,
)


def _sections(*, cited: bool = True) -> dict:
    sections = {name: f"{name} on file" for name in DUE_DILIGENCE_SECTIONS}
    sections["review_status"] = "APPROVED"
    sections["last_review"] = date(2026, 9, 1)
    if cited:
        for name in DUE_DILIGENCE_SECTIONS:
            sections[name] = {"value": f"{name} on file", "evidence": [f"VD-{name[:6]}"]}
    return sections


def test_a_filled_in_record_can_be_complete_and_entirely_uncited():
    sections = _sections(cited=False)
    completeness = evaluate_due_diligence(sections, as_of=date(2026, 11, 2))
    assert completeness["status"] == "COMPLETE"
    audit = audit_due_diligence_evidence(sections)
    assert audit["counts"]["UNCITED"] == len(DUE_DILIGENCE_SECTIONS)
    assert audit["supported"] == 0
    assert "filled in and uncited" in audit["statement"]


def test_cited_sections_are_supported_and_uncited_ones_are_partials():
    sections = _sections()
    sections["sbom_availability"] = "we can provide one"
    audit = audit_due_diligence_evidence(sections)
    assert audit["counts"]["SUPPORTED"] == len(DUE_DILIGENCE_SECTIONS) - 1
    assert audit["unsupported"] == 1
    assert audit["ledger"] == [{"state": "PARTIAL", "subject": "sbom_availability",
                                "reasons": audit["ledger"][0]["reasons"]}]


def test_a_citation_that_does_not_resolve_is_not_support():
    sections = _sections()
    sections["fips_claims"] = {"value": "FIPS 140-3", "evidence": ["VD-missing"]}
    index = {f"VD-{name[:6]}" for name in DUE_DILIGENCE_SECTIONS}
    audit = audit_due_diligence_evidence(sections, evidence_index=index)
    assert audit["counts"]["UNRESOLVED"] == 1
    assert audit["counts"]["SUPPORTED"] == len(DUE_DILIGENCE_SECTIONS) - 1
    row = next(item for item in audit["rows"] if item["section"] == "fips_claims")
    assert row["state"] == "UNRESOLVED"
    assert "do not resolve" in row["reason"]


def test_a_resolvable_citation_with_no_index_is_still_only_a_citation():
    sections = _sections()
    audit = audit_due_diligence_evidence(sections)
    assert audit["counts"]["SUPPORTED"] == len(DUE_DILIGENCE_SECTIONS)
    assert audit["rows"][0]["reason"] == "cites 1 record(s)"


def test_an_empty_section_is_missing_not_uncited():
    sections = _sections()
    sections["contract"] = ""
    audit = audit_due_diligence_evidence(sections)
    assert audit["counts"]["MISSING"] == 1
    row = next(item for item in audit["rows"] if item["section"] == "contract")
    assert row["state"] == "MISSING"


def test_the_audit_ledger_feeds_the_partial_ledger():
    sections = _sections(cited=False)
    audit = audit_due_diligence_evidence(sections)
    ledger = partial_ledger(audit["ledger"])
    assert ledger["partial_count"] == len(DUE_DILIGENCE_SECTIONS)
    assert ledger["dropped"] == 0


def test_a_string_citation_is_read_as_one_record():
    sections = _sections()
    sections["contract"] = {"value": "contract", "evidence": "VD-contract"}
    audit = audit_due_diligence_evidence(sections, evidence_index={"VD-contract"})
    row = next(item for item in audit["rows"] if item["section"] == "contract")
    assert row["state"] == "SUPPORTED" and row["citations"] == ["VD-contract"]
