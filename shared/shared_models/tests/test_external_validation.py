"""External validation register — the standing external-only rule, as tests.

"Bank triage loop; DR/PITR/soak drills; third-party pen test; real HSM run;
SOC2/ISO; release-manifest + branch-protection — external-only, never sandbox."
These tests pin that the register files evidence of external acts and never
turns absence into a pass.
"""

from __future__ import annotations

import json

import pytest

from shared_models.external_validation import (
    BANK_TRIAGE_LOOP,
    EXTERNAL_KINDS,
    FILED,
    NOT_FILED,
    file_validation,
    validation_status,
)


def filing(kind: str = "DR_DRILL", **over):
    base = dict(kind=kind, performed_by="bank DR team",
                evidence_ids=["DRILL-LOG-2026-11"],
                performed_at="2026-11-01T02:00:00+00:00",
                scope="region pair failover, 4h window",
                result="PASSED")
    base.update(over)
    return file_validation(**base)


class TestFiling:

    def test_every_roadsmap_external_kind_is_registered(self):
        assert set(EXTERNAL_KINDS) == {
            "DR_DRILL", "PITR_DRILL", "SOAK_DRILL", "THIRD_PARTY_PEN_TEST",
            "REAL_HSM_RUN", "BANK_TRIAGE_LOOP", "SOC2_ISO_AUDIT",
            "RELEASE_MANIFEST_CHECK", "BRANCH_PROTECTION_CHECK"}

    def test_a_filing_without_evidence_is_refused(self):
        with pytest.raises(ValueError, match="is a claim"):
            filing(evidence_ids=[])

    def test_a_filing_without_a_performing_party_is_refused(self):
        with pytest.raises(ValueError, match="self-attest"):
            filing(performed_by="")

    def test_the_platform_cannot_file_itself_as_performer(self):
        with pytest.raises(ValueError, match="did not perform this"):
            filing(performed_by="CryptoScan")

    def test_an_undated_or_unscoped_filing_is_refused(self):
        with pytest.raises(ValueError, match="undated drill"):
            filing(performed_at="")
        with pytest.raises(ValueError, match="without a scope"):
            filing(scope=" ")

    def test_a_filing_records_both_sides_of_the_boundary(self):
        row = filing()
        assert row["performed_by_platform"] is False
        assert row["filed_by_platform"] is True


class TestStatus:

    def test_a_missing_validation_is_not_filed_never_passed(self):
        report = validation_status([])
        entry = report["kinds"][BANK_TRIAGE_LOOP]
        assert entry["status"] == NOT_FILED
        assert "not filed is not passed" in entry["reason"]
        assert report["counts"][NOT_FILED] == len(EXTERNAL_KINDS)

    def test_a_filed_validation_shows_its_result_and_performer(self):
        report = validation_status([filing(result="FAILED")])
        entry = report["kinds"]["DR_DRILL"]
        assert entry["status"] == FILED
        assert entry["latest"]["result"] == "FAILED"
        assert "bank DR team" in entry["reason"]

    def test_history_is_kept_and_the_newest_filing_decides(self):
        rows = [
            filing(performed_at="2026-05-01T00:00:00+00:00", result="FAILED"),
            filing(performed_at="2026-11-01T00:00:00+00:00", result="PASSED"),
        ]
        entry = validation_status(rows)["kinds"]["DR_DRILL"]
        assert entry["latest"]["result"] == "PASSED"
        assert len(entry["history"]) == 2

    def test_the_report_is_reproducible_and_names_the_boundary(self):
        rows = [filing()]
        first = json.dumps(validation_status(rows), sort_keys=True)
        second = json.dumps(validation_status(rows), sort_keys=True)
        assert first == second
        assert "never marks them done" in validation_status(rows)["note"]
