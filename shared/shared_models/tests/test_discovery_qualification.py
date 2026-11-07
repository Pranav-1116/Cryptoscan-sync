"""Discovery qualification — roadmap item 5 acceptance rows.

Standing directive: "Don't claim support simply because an integration has a
fixture or a connector definition. Track its actual qualification status."
"""

from __future__ import annotations

import pytest

from shared_models.discovery_qualification import (
    DEFINED,
    FIXTURE_VERIFIED,
    LIVE_QUALIFIED,
    REVOKED,
    qualification,
    qualification_summary,
    support_claim,
)


class TestQualificationConstruction:

    def test_live_qualification_requires_run_evidence(self):
        with pytest.raises(ValueError, match="trench coat"):
            qualification(collector="hsm.thales", family="hsm.thales",
                          state=LIVE_QUALIFIED, evidence_ids=[],
                          observed_at="2026-11-01")

    def test_live_qualification_requires_a_clock(self):
        with pytest.raises(ValueError, match="observed_at"):
            qualification(collector="hsm.thales", family="hsm.thales",
                          state=LIVE_QUALIFIED, evidence_ids=["E1"])

    def test_a_fixture_record_needs_no_evidence_and_says_what_it_is(self):
        row = qualification(collector="hsm.thales", family="hsm.thales",
                            state=FIXTURE_VERIFIED,
                            reason="passes against the recorded fixture only")
        assert row["state"] == FIXTURE_VERIFIED
        assert row["evidence_ids"] == []


class TestSupportClaims:

    def _rows(self):
        return [
            qualification(collector="hsm.thales", family="hsm.thales",
                          state=DEFINED),
            qualification(collector="hsm.thales", family="hsm.thales",
                          state=FIXTURE_VERIFIED),
        ]

    def test_a_fixture_is_not_qualification(self):
        claim = support_claim(self._rows(), collector="hsm.thales",
                              family="hsm.thales")
        assert claim["claimable"] is False
        assert "is not qualification" in claim["reason"]
        assert "FIXTURE_VERIFIED" in claim["reason"]

    def test_a_connector_definition_alone_is_not_support(self):
        claim = support_claim(
            [qualification(collector="db.oracle", family="database.oracle",
                           state=DEFINED)],
            collector="db.oracle", family="database.oracle")
        assert claim["claimable"] is False

    def test_live_qualification_with_evidence_backs_the_claim(self):
        rows = self._rows() + [
            qualification(collector="hsm.thales", family="hsm.thales",
                          state=LIVE_QUALIFIED, evidence_ids=["E1"],
                          observed_at="2026-11-01")]
        claim = support_claim(rows, collector="hsm.thales", family="hsm.thales")
        assert claim["claimable"] is True
        assert "real target" in claim["reason"]

    def test_a_revocation_beats_an_older_qualification_and_both_are_kept(self):
        rows = [
            qualification(collector="hsm.thales", family="hsm.thales",
                          state=LIVE_QUALIFIED, evidence_ids=["E1"],
                          observed_at="2026-09-01"),
            qualification(collector="hsm.thales", family="hsm.thales",
                          state=REVOKED, evidence_ids=["E2"],
                          observed_at="2026-11-01",
                          reason="the live run regressed after a firmware change"),
        ]
        claim = support_claim(rows, collector="hsm.thales", family="hsm.thales")
        assert claim["claimable"] is False
        assert "revoked" in claim["reason"]
        assert len(claim["records"]) == 2          # history preserved

    def test_no_record_is_unknown_never_supported(self):
        claim = support_claim([], collector="ghost", family="hsm.thales")
        assert claim["claimable"] is False
        assert "unknown, which is not supported" in claim["reason"]


class TestSummary:

    def test_counts_are_per_family_and_zeroes_are_measured(self):
        rows = [
            qualification(collector="a", family="load_balancer.f5",
                          state=FIXTURE_VERIFIED),
            qualification(collector="b", family="firewall.paloalto",
                          state=LIVE_QUALIFIED, evidence_ids=["E1"],
                          observed_at="2026-11-01"),
        ]
        summary = qualification_summary(
            rows, families=["load_balancer.f5", "firewall.paloalto", "waf"])
        assert summary["families"]["load_balancer.f5"]["counts"][FIXTURE_VERIFIED] == 1
        assert summary["families"]["load_balancer.f5"]["claimable_collectors"] == []
        assert summary["families"]["firewall.paloalto"]["claimable_collectors"] == ["b"]
        # a family with no records at all reports honest zeroes
        assert summary["families"]["waf"]["counts"][LIVE_QUALIFIED] == 0
        assert summary["totals"][LIVE_QUALIFIED] == 1
        assert "not qualification" in summary["note"]
