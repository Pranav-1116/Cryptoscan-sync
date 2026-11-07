"""Deterministic Threat Intelligence Engine — roadmap item 4 acceptance rows.

Every finding answers the six mandated questions; a finding without evidence is
refused; a detection never declares a compromise and never invents evidence.
"""

from __future__ import annotations

import json

import pytest

from shared_models.algorithm_registry import parse_algorithm
from shared_models.threat_intelligence import (
    CERTIFICATE_RISK,
    COLLECTION_BLIND_SPOT,
    CRYPTO_REGRESSION,
    HSM_DEPENDENCY,
    LIBRARY_RISK,
    PQC_REGRESSION,
    THREAT_CLASSES,
    TRUST_PATH_MUTATION,
    VENDOR_RISK,
    WEAK_ALGORITHM_EXPOSURE,
    detect_certificate_risk,
    detect_collection_blind_spot,
    detect_crypto_regression,
    detect_hsm_dependency,
    detect_library_risk,
    detect_pqc_regression,
    detect_trust_path_mutation,
    detect_vendor_risk,
    detect_weak_algorithm_exposure,
    finding,
    threat_report,
)


class TestMandatoryShape:

    def test_every_finding_answers_all_six_questions(self):
        row = finding(
            class_=CRYPTO_REGRESSION, asset="payments-api",
            what_changed="AES-256 → AES-128", why_it_matters="weaker traffic protection",
            evidence_ids=["E1"], not_proven="no attack is proven",
            investigate="check the change log")
        assert row["asset"] == "payments-api"
        for key in ("what_changed", "why_it_matters", "not_proven", "investigate"):
            assert row[key].strip(), key
        assert row["evidence_ids"] == ["E1"]

    def test_a_finding_without_evidence_is_refused(self):
        with pytest.raises(ValueError, match="without evidence"):
            finding(class_=CRYPTO_REGRESSION, asset="a", what_changed="x",
                    why_it_matters="y", evidence_ids=[],
                    not_proven="z", investigate="w")

    def test_not_proven_is_mandatory(self):
        with pytest.raises(ValueError, match="not_proven"):
            finding(class_=CRYPTO_REGRESSION, asset="a", what_changed="x",
                    why_it_matters="y", evidence_ids=["E1"],
                    not_proven="  ", investigate="w")

    def test_a_finding_never_declares_a_compromise(self):
        row = finding(class_=CRYPTO_REGRESSION, asset="a", what_changed="x",
                      why_it_matters="y", evidence_ids=["E1"],
                      not_proven="z", investigate="w")
        assert row["compromise_declared"] is False
        report = threat_report([row])
        assert report["compromise_declared"] is False
        assert "never declares a compromise" in report["note"]

    def test_an_unknown_class_is_refused(self):
        with pytest.raises(ValueError, match="unknown threat class"):
            finding(class_="MADE_UP", asset="a", what_changed="x",
                    why_it_matters="y", evidence_ids=["E1"],
                    not_proven="z", investigate="w")


class TestDetectors:

    def test_crypto_regression_fires_on_a_weakening_drop_only(self):
        drop = detect_crypto_regression(
            asset="a",
            observations=[{"algorithm": "AES-256", "observed_at": "2026-10-01"},
                          {"algorithm": "AES-128", "observed_at": "2026-11-01"}],
            evidence_ids=["E1"])
        assert len(drop) == 1
        assert drop[0]["class"] == CRYPTO_REGRESSION
        assert "does not prove an attack" in drop[0]["not_proven"]
        upgrade = detect_crypto_regression(
            asset="a",
            observations=[{"algorithm": "AES-128", "observed_at": "2026-10-01"},
                          {"algorithm": "AES-256", "observed_at": "2026-11-01"}],
            evidence_ids=["E1"])
        assert upgrade == []

    def test_weak_exposure_needs_live_use_not_capability(self):
        capable = detect_weak_algorithm_exposure(
            asset="a", algorithm="MD5", algorithm_info={"status": "DISALLOWED"},
            usage_state="SUPPORTED", evidence_ids=["E1"])
        assert capable == []          # capability is not exposure
        live = detect_weak_algorithm_exposure(
            asset="a", algorithm="MD5", algorithm_info={"status": "DISALLOWED"},
            usage_state="OBSERVED", evidence_ids=["E1"])
        assert len(live) == 1
        assert live[0]["class"] == WEAK_ALGORITHM_EXPOSURE

    def test_weak_exposure_reads_real_registry_facts(self):
        rows = detect_weak_algorithm_exposure(
            asset="a", algorithm="MD5", algorithm_info=parse_algorithm("MD5"),
            usage_state="NEGOTIATED", evidence_ids=["E1"])
        assert len(rows) == 1

    def test_certificate_risk_reads_the_record_not_the_wall_clock(self):
        soon = detect_certificate_risk(
            asset="a", certificate={"days_until_expiry": 5}, evidence_ids=["E1"])
        assert len(soon) == 1
        assert soon[0]["class"] == CERTIFICATE_RISK
        fine = detect_certificate_risk(
            asset="a", certificate={"days_until_expiry": 100}, evidence_ids=["E1"])
        assert fine == []

    def test_an_undated_certificate_is_unknown_not_safe(self):
        rows = detect_certificate_risk(
            asset="a", certificate={}, evidence_ids=["E1"])
        assert len(rows) == 1
        assert "unknown" in rows[0]["why_it_matters"]
        assert "does not prove" in rows[0]["not_proven"]

    def test_trust_path_mutation_preserves_both_sides(self):
        rows = detect_trust_path_mutation(
            asset="a",
            before={"issuer": "old-ca", "root": "old-root"},
            after={"issuer": "new-ca", "root": "old-root"},
            evidence_ids=["E1"])
        assert len(rows) == 1
        assert rows[0]["class"] == TRUST_PATH_MUTATION
        assert "old-ca" in rows[0]["what_changed"] and "new-ca" in rows[0]["what_changed"]
        unchanged = detect_trust_path_mutation(
            asset="a", before={"issuer": "ca"}, after={"issuer": "ca"},
            evidence_ids=["E1"])
        assert unchanged == []

    def test_hsm_dependency_distinguishes_proven_from_unassessed(self):
        proven = detect_hsm_dependency(
            asset="a", target_algorithm="ML-DSA-65",
            dependency={"name": "hsm-1", "capability_state": "LACKS",
                        "evidence_ids": ["E2"]},
            evidence_ids=["E1"])
        assert "proven missing" in proven[0]["what_changed"]
        unassessed = detect_hsm_dependency(
            asset="a", target_algorithm="ML-DSA-65",
            dependency={"name": "hsm-1", "capability_state": "NOT_ASSESSED",
                        "evidence_ids": []},
            evidence_ids=["E1"])
        assert "unassessed" in unassessed[0]["what_changed"]
        backed = detect_hsm_dependency(
            asset="a", target_algorithm="ML-DSA-65",
            dependency={"name": "hsm-1", "capability_state": "SUPPORTS",
                        "evidence_ids": ["E2"]},
            evidence_ids=["E1"])
        assert backed == []

    def test_library_matching_never_invents_an_advisory(self):
        with pytest.raises(ValueError, match="anonymous"):
            detect_library_risk(
                asset="a", library={"name": "openssl", "version": "1.1.1"},
                advisory={"affected_versions": "1.1.1"}, evidence_ids=["E1"])
        hit = detect_library_risk(
            asset="a", library={"name": "openssl", "version": "1.1.1"},
            advisory={"advisory_id": "ADV-2026-1", "affected_versions": "1.1.1"},
            evidence_ids=["E1"])
        assert len(hit) == 1
        assert hit[0]["class"] == LIBRARY_RISK
        assert "ADV-2026-1" in hit[0]["evidence_ids"]
        miss = detect_library_risk(
            asset="a", library={"name": "openssl", "version": "3.0.0"},
            advisory={"advisory_id": "ADV-2026-1", "affected_versions": "1.1.1"},
            evidence_ids=["E1"])
        assert miss == []

    def test_vendor_risk_fires_on_recorded_standing_only(self):
        rows = detect_vendor_risk(
            asset="a", vendor_facts={"vendor": "acme", "support_state": "EOL",
                                     "eol_announced": True, "pqc_roadmap_gap": True},
            evidence_ids=["E1"])
        assert rows[0]["class"] == VENDOR_RISK
        assert "no PQC roadmap" in rows[0]["what_changed"]
        healthy = detect_vendor_risk(
            asset="a", vendor_facts={"vendor": "acme", "support_state": "SUPPORTED"},
            evidence_ids=["E1"])
        assert healthy == []

    def test_coverage_gaps_become_blind_spot_findings(self):
        coverage = {"gaps": [
            {"kind": "UNKNOWN_ASSET", "count": 3,
             "detail": "assets whose presence or absence is unknown: a missing "
                       "asset must never silently become a clean security result"},
        ]}
        rows = detect_collection_blind_spot(coverage=coverage, evidence_ids=["E1"])
        assert len(rows) == 1
        assert rows[0]["class"] == COLLECTION_BLIND_SPOT
        assert "never a clean security result" in rows[0]["why_it_matters"]

    def test_pqc_regression_reads_the_preserved_contradiction(self):
        contradiction = [{
            "validated_claim": {"algorithm": "ML-DSA-65"},
            "conflicting_claim": {"algorithm": "RSA-2048"},
        }]
        rows = detect_pqc_regression(asset="a", contradictions=contradiction,
                                     evidence_ids=["E1"])
        assert rows[0]["class"] == PQC_REGRESSION
        assert "ML-DSA-65" in rows[0]["what_changed"]
        assert "RSA-2048" in rows[0]["what_changed"]


class TestReport:

    def test_the_report_counts_each_class_and_stays_deterministic(self):
        rows = detect_crypto_regression(
            asset="a",
            observations=[{"algorithm": "AES-256", "observed_at": "2026-10-01"},
                          {"algorithm": "AES-128", "observed_at": "2026-11-01"}],
            evidence_ids=["E1"])
        first = json.dumps(threat_report(rows), sort_keys=True)
        second = json.dumps(threat_report(rows), sort_keys=True)
        assert first == second
        report = threat_report(rows)
        assert report["counts"][CRYPTO_REGRESSION] == 1
        assert set(report["counts"]) == set(THREAT_CLASSES)
