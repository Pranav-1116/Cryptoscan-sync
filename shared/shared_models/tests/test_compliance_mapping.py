"""Compliance mapping (gap analysis §I), as tests.

"Compliance should be mapped to specific requirements, evidence and
assessment outcomes. A policy match is not automatically proof of compliance."
"""

from __future__ import annotations

import pytest

from shared_models.compliance_mapping import (
    COMPLIANT,
    NON_COMPLIANT,
    NOT_ASSESSED,
    POLICY_MATCH_ONLY,
    assessment,
    compliance_status,
    requirement,
)


REQ = requirement(requirement_id="PCI-6.4", framework="PCI-DSS", clause="6.4",
                  text="production changes are controlled")


class TestAssessment:

    def test_a_verdict_without_evidence_or_an_assessor_is_refused(self):
        with pytest.raises(ValueError, match="verdict about nothing"):
            assessment(requirement_id="PCI-6.4", policy_match=True,
                       evidence_ids=[], assessed_by="auditor",
                       outcome=COMPLIANT)
        with pytest.raises(ValueError, match="does not audit itself"):
            assessment(requirement_id="PCI-6.4", policy_match=True,
                       evidence_ids=["E-1"], assessed_by="",
                       outcome=COMPLIANT)

    def test_compliance_over_a_failed_match_contradicts_the_record(self):
        with pytest.raises(ValueError, match="contradicts the record"):
            assessment(requirement_id="PCI-6.4", policy_match=False,
                       evidence_ids=["E-1"], assessed_by="auditor",
                       outcome=COMPLIANT)


class TestStatus:

    def test_a_policy_match_alone_is_never_proof_of_compliance(self):
        # the only row is an unassessed match record
        rows = [{"requirement_id": "PCI-6.4", "policy_match": True}]
        report = compliance_status(requirements=[REQ], assessments=rows)
        entry = report["requirements"]["PCI-6.4"]
        assert entry["status"] == POLICY_MATCH_ONLY
        assert "not automatically proof" in entry["reason"]

    def test_an_assessed_verdict_wins_with_its_evidence_and_assessor(self):
        rows = [
            {"requirement_id": "PCI-6.4", "policy_match": True},
            assessment(requirement_id="PCI-6.4", policy_match=True,
                       evidence_ids=["CHANGE-LOG-1"], assessed_by="auditor",
                       outcome=COMPLIANT),
        ]
        entry = compliance_status(requirements=[REQ],
                                  assessments=rows)["requirements"]["PCI-6.4"]
        assert entry["status"] == COMPLIANT
        assert "auditor" in entry["reason"]

    def test_unaddressed_is_not_compliance(self):
        report = compliance_status(requirements=[REQ], assessments=[])
        entry = report["requirements"]["PCI-6.4"]
        assert entry["status"] == NOT_ASSESSED
        assert "not compliance" in entry["reason"]

    def test_a_non_compliant_assessment_stays_visible(self):
        rows = [assessment(requirement_id="PCI-6.4", policy_match=False,
                           evidence_ids=["E-1"], assessed_by="auditor",
                           outcome=NON_COMPLIANT)]
        entry = compliance_status(requirements=[REQ],
                                  assessments=rows)["requirements"]["PCI-6.4"]
        assert entry["status"] == NON_COMPLIANT
        assert entry["latest_assessment"]["evidence_ids"] == ["E-1"]
