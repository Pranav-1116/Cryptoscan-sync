"""Public-source baseline acceptance tests
(docs/bank-environment/emirates-nbd/GAP-ANALYSIS.md).

PROVENANCE: the dataset under docs/bank-environment/emirates-nbd/ is
the user-provided Emirates NBD public-source baseline prepared 7 Nov
2026 for ZELNX (desk research of public sources only). Every row was
transcribed from that document with its refs and confidence.

Discipline proven here:
- public disclosures NEVER confirm current state (was deployed, not is
  deployed);
- low-confidence rows are leads to verify, never facts;
- crypto siting is inference, never a claim;
- unverified claims are recorded, never asserted;
- gaps are never absence claims;
- external acts are never marked done from inside the repo;
- discovery matches are candidates, never confirmation.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from vendor_intel.public_source import (
    REQUEST_STATUSES, advance_request, load_baseline,
    load_baseline_file, match_observation)

REPO = Path(__file__).resolve().parents[3]
DATASET = (REPO / "docs" / "bank-environment" / "emirates-nbd" /
           "baseline-dataset-2026-11-07.json")


@pytest.fixture(scope="module")
def baseline():
    return load_baseline_file(DATASET)


@pytest.fixture()
def raw():
    return json.loads(DATASET.read_text())


class TestDatasetProvenance:
    def test_source_document_saved_verbatim(self):
        doc = (REPO / "docs" / "bank-environment" / "emirates-nbd" /
               "public-source-baseline-2026-11-07.md").read_text()
        assert "user-provided document, saved verbatim" in doc
        assert "It is NOT a CBOM" in doc
        assert "No scanning, probing or non-public data" in doc

    def test_dataset_loads_with_zero_errors(self, baseline):
        assert baseline.load_errors == []
        assert baseline.subject == "Emirates NBD"
        assert "NOT a CBOM" in baseline.status

    def test_every_disclosure_is_sourced_and_confidence_valid(
            self, baseline):
        assert len(baseline.disclosures) >= 20
        for d in baseline.disclosures:
            assert d.refs, f"{d.item_id} must carry source refs"
            for ref in d.refs:
                assert ref in baseline.references, \
                    f"ref [{ref}] must resolve in the reference list"
            assert d.confidence in ("high", "high_medium", "medium",
                                    "low_medium", "low")
            assert d.confidence_basis


class TestCurrencyDiscipline:
    def test_public_sources_never_confirm_current_state(self, baseline):
        """The decisive honesty field: a public disclosure is evidence
        of a PUBLICATION — never of the estate as it is now."""
        for d in baseline.disclosures:
            assert d.current_state_confirmed is False

    def test_dated_disclosures_read_as_was_deployed(self, baseline):
        ncr = [d for d in baseline.disclosures
               if d.item_id == "ncr-atm"][0]
        assert "was deployed" in ncr.currency_note
        assert "confirm current state" in ncr.currency_note

    def test_job_advert_rows_carry_the_team_caveat(self, baseline):
        cisco = [d for d in baseline.disclosures
                 if d.item_id == "cisco-sonic"][0]
        assert "specific team" in cisco.currency_note
        assert cisco.confidence == "low_medium"

    def test_low_confidence_rows_are_leads_never_facts(self, baseline):
        for d in baseline.disclosures:
            if d.confidence in ("low", "low_medium"):
                note = d.as_dict()["note"]
                assert "LEAD TO VERIFY, never a fact" in note
        agg = [d for d in baseline.disclosures
               if d.item_id == "aggregator-stack"][0]
        assert agg.confidence == "low"
        assert "Not confirmed by the bank" in agg.disclosed


class TestInferenceNeverClaims:
    def test_siting_is_always_inference_with_questions(self, baseline):
        assert len(baseline.crypto_siting) == 8
        for s in baseline.crypto_siting:
            assert s.evidence_class == "inferred"
            assert s.question_to_confirm
            assert "never a claim about the subject" in s.as_dict()[
                "note"]

    def test_baseline_asserts_no_claims(self, baseline):
        assert baseline.claims() == []

    def test_as_dict_note_labels_the_stage(self, baseline):
        note = baseline.as_dict()["note"]
        assert "NOT a CBOM" in note


class TestUnverifiedAndGaps:
    def test_qkd_claim_stays_unverified(self, baseline):
        qkd = [c for c in baseline.unverified_claims
               if c.claim_id == "qkd-pilot-toshiba"][0]
        assert qkd.status == "unverified"
        assert qkd.source_quality == "low"
        assert "not as fact" in qkd.treatment
        assert "never asserted" in qkd.as_dict()["note"]

    def test_gaps_are_never_absence_claims(self, baseline):
        assert len(baseline.gaps) == 5
        for g in baseline.gaps:
            assert "NEVER an absence claim" in g.note
        missing = [g for g in baseline.gaps
                   if g.gap_id == "gap-missing-vendor-classes"][0]
        assert "Do not assume any" in missing.statement


class TestDataRequestList:
    def test_all_eleven_categories_present(self, baseline):
        categories = {r.category for r in baseline.data_requests}
        assert categories == {
            "hsm_inventory", "pki", "certificate_inventory",
            "tls_ssh", "network_crypto", "payment_card_crypto",
            "core_db_encryption", "cloud_kms",
            "software_supply_chain", "vendor_pqc_roadmaps",
            "data_retention"}
        assert len(baseline.data_requests) == 11

    def test_advance_without_evidence_is_refused(self, baseline):
        result = advance_request(baseline, "req-hsm-inventory",
                                 "requested", evidence={})
        assert result["advanced"] is False
        assert "never marked done from inside the repo" in \
            result["reason"]
        row = [r for r in baseline.data_requests
               if r.request_id == "req-hsm-inventory"][0]
        assert row.status == "listed", "nothing changed on refusal"

    def test_partial_evidence_is_still_refused(self, baseline):
        result = advance_request(
            baseline, "req-hsm-inventory", "requested",
            evidence={"actor": "zelnx-consultant"})
        assert result["advanced"] is False

    def test_advance_with_imported_evidence_records_the_act(
            self, baseline):
        result = advance_request(
            baseline, "req-pki", "requested",
            evidence={"actor": "engagement-lead",
                      "date": "2026-11-20",
                      "artifact_ref": "signed-request-email-001"})
        assert result["advanced"] is True
        row = [r for r in baseline.data_requests
               if r.request_id == "req-pki"][0]
        assert row.status == "requested"
        assert row.status_evidence[0]["artifact_ref"] == \
            "signed-request-email-001"

    def test_unknown_request_changes_nothing(self, baseline):
        result = advance_request(baseline, "req-nope", "requested",
                                 evidence={"actor": "a", "date": "d",
                                           "artifact_ref": "x"})
        assert result["advanced"] is False
        assert "nothing was changed" in result["reason"]

    def test_invalid_status_refused(self, baseline):
        with pytest.raises(ValueError):
            advance_request(baseline, "req-pki", "done-forever",
                            evidence={})
        assert set(REQUEST_STATUSES) == {
            "listed", "requested", "partially_received", "received"}


class TestVendorRegister:
    def test_register_is_derived_one_line_per_third_party(
            self, baseline):
        rows = baseline.vendor_register()
        assert len(rows) == len(baseline.disclosures)
        for r in rows:
            assert r["refs"]
            assert "never a contract date" in r["note"]
        names = {r["name"] for r in rows}
        assert "Infosys Finacle (EdgeVerve)" in names
        assert "NCR (ATM estate)" in names


class TestDiscoveryMatching:
    def test_observed_banner_yields_candidate_never_confirmation(
            self, baseline):
        results = match_observation(baseline, [
            {"name": "Finacle core banking", "host": "10.0.0.5"}])
        candidates = results[0]["candidates"]
        assert candidates
        assert candidates[0]["item_id"] == "finacle-core"
        assert candidates[0]["status"] == "candidate_match"
        assert "never confirmation" in candidates[0]["note"]

    def test_no_candidate_is_not_product_absent(self, baseline):
        results = match_observation(baseline, [
            {"name": "unknown-widget-9000"}])
        assert results[0]["candidates"] == []
        assert "not 'product absent'" in results[0]["note"]

    def test_matching_is_token_based_not_co_location(self, baseline):
        """Two observations on the same host never merge into a
        relationship — the provides/uses discipline: matching
        produces candidates only, and never a 'uses' edge or any
        cross-observation claim."""
        results = match_observation(baseline, [
            {"name": "APTRA", "host": "atm-1"},
            {"name": "PowerMax", "host": "atm-1"}])
        assert len(results) == 2, "one result row per observation"
        assert all(r["candidates"] for r in results)
        # each result stays scoped to its own observation — no
        # relationship object exists anywhere in the output
        for r in results:
            assert set(r.keys()) == {"observation", "candidates",
                                     "note"}
            for c in r["candidates"]:
                assert c["status"] == "candidate_match"


class TestLoaderFailSafe:
    def test_unsourced_row_skipped_with_reason(self, raw):
        data = copy.deepcopy(raw)
        data["disclosures"].append({
            "item_id": "ghost", "name": "Ghost Product",
            "category": "x", "role": "x", "disclosed": "x",
            "refs": [], "confidence": "high",
            "confidence_basis": "bank_or_vendor_published"})
        b = load_baseline(data)
        assert not any(d.item_id == "ghost" for d in b.disclosures)
        assert any("no source reference" in e for e in b.load_errors)

    def test_duplicate_id_skipped_never_merged(self, raw):
        data = copy.deepcopy(raw)
        data["disclosures"].append(dict(data["disclosures"][0]))
        b = load_baseline(data)
        assert any("duplicate item_id" in e for e in b.load_errors)

    def test_unknown_confidence_skipped_never_guessed(self, raw):
        data = copy.deepcopy(raw)
        row = dict(data["disclosures"][0])
        row["item_id"] = "weird"
        row["confidence"] = "very-sure"
        data["disclosures"].append(row)
        b = load_baseline(data)
        assert not any(d.item_id == "weird" for d in b.disclosures)
        assert any("unknown confidence" in e for e in b.load_errors)

    def test_wrong_schema_refused(self, raw):
        data = copy.deepcopy(raw)
        data["schema"] = "something-else"
        with pytest.raises(ValueError):
            load_baseline(data)
