"""Finding lifecycle (gap analysis §G) — the consistent structure and the
change ladder, as tests.

"Every finding should contain a consistent structure" (the eighteen fields);
"The engine must distinguish: a configuration change, a suspicious change, a
correlated pattern, a confirmed security incident"; "A pattern should never
automatically become a confirmed compromise."
"""

from __future__ import annotations

import pytest

from shared_models.finding_lifecycle import (
    CONFIRMED_INCIDENT,
    CORRELATED_PATTERN,
    assign,
    confirm_incident,
    finding_digest,
    finding_record,
)


def record(**over):
    base = dict(
        finding_id="F-1", pattern_id="CERT_RISK", tenant_id="bank-a",
        affected_asset_ids=["cert-1", "lb-1"], affected_system_ids=["payments"],
        severity="HIGH", confidence="MEDIUM",
        first_seen="2026-11-01T00:00:00+00:00",
        last_seen="2026-11-07T00:00:00+00:00",
        evidence_ids=["EV-1"], observed_change="the cert drops to RSA-1024",
        expected_state="RSA-2048 or better per policy P-7",
        reason="the downgrade weakens transport security",
        not_proven="this does not prove the key was compromised",
        recommended_investigation="who changed the cipher policy and when",
    )
    base.update(over)
    return finding_record(**base)


class TestStructure:

    def test_every_named_field_is_present(self):
        row = record()
        for field in ("finding_id", "tenant_id", "pattern_id",
                      "affected_asset_ids", "affected_system_ids", "severity",
                      "confidence", "first_seen", "last_seen", "evidence_ids",
                      "observed_change", "expected_state", "reason",
                      "not_proven", "recommended_investigation", "status",
                      "owner"):
            assert field in row, field

    def test_a_finding_without_evidence_is_a_rumour(self):
        with pytest.raises(ValueError, match="rumour"):
            record(evidence_ids=[])

    def test_a_finding_without_uncertainty_or_explanation_is_refused(self):
        with pytest.raises(ValueError, match="overclaims certainty"):
            record(not_proven="")
        with pytest.raises(ValueError, match="mandatory"):
            record(expected_state="")

    def test_the_digest_is_reproducible(self):
        row = record()
        assert finding_digest(row) == finding_digest(row)


class TestChangeLadder:

    def test_the_engine_never_claims_a_confirmed_incident(self):
        with pytest.raises(ValueError, match="never automatically"):
            record(change_class=CONFIRMED_INCIDENT)

    def test_correlated_pattern_is_engine_reachable(self):
        assert record(change_class=CORRELATED_PATTERN)["change_class"] == \
            CORRELATED_PATTERN

    def test_confirmation_is_human_with_incident_evidence(self):
        row = record(change_class=CORRELATED_PATTERN)
        with pytest.raises(ValueError, match="incident reference"):
            confirm_incident(row, incident_ref="", actor="soc-lead",
                             at="2026-11-08T00:00:00+00:00",
                             evidence_ids=["INC-1"])
        with pytest.raises(ValueError, match="named human"):
            confirm_incident(row, incident_ref="INC-42", actor="",
                             at="2026-11-08T00:00:00+00:00",
                             evidence_ids=["INC-1"])
        with pytest.raises(ValueError, match="rumour about a rumour"):
            confirm_incident(row, incident_ref="INC-42", actor="soc-lead",
                             at="2026-11-08T00:00:00+00:00", evidence_ids=[])

        confirmed = confirm_incident(
            row, incident_ref="INC-42", actor="soc-lead",
            at="2026-11-08T00:00:00+00:00", evidence_ids=["INC-LOG-1"])
        assert confirmed["change_class"] == CONFIRMED_INCIDENT
        assert confirmed["confirmation"]["actor"] == "soc-lead"
        # the input record is untouched: the pattern stays a pattern
        assert row["change_class"] == CORRELATED_PATTERN
        assert row["confirmation"] is None


class TestAssignment:

    def test_assignment_records_owner_and_actor(self):
        row = assign(record(), owner="boris", actor="ana")
        assert row["owner"] == "boris"
        assert row["status"] == "ASSIGNED"
        assert row["assignments"] == [{"owner": "boris", "actor": "ana"}]

    def test_an_ownerless_or_anonymous_assignment_is_refused(self):
        with pytest.raises(ValueError, match="nobody owns"):
            assign(record(), owner="", actor="ana")
        with pytest.raises(ValueError, match="decisions have actors"):
            assign(record(), owner="boris", actor="")
