"""Governance workflows — roadmap item 9 acceptance rows.

Role checks, mandatory expiries, evidence-backed decisions, and an immutable
hash-chained audit that detects edits, deletions and reordering.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from shared_models.governance import (
    AUDITOR,
    EXECUTIVE,
    IN_PROGRESS,
    OPEN,
    SECURITY_ARCHITECT,
    active_authorization,
    create_ticket,
    transition,
    verify_audit,
)

NOW = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)


def at(days: float) -> str:
    return (NOW + timedelta(days=days)).isoformat()


def open_ticket():
    return create_ticket(ticket_id="GOV-1", subject="payments-api RSA exposure",
                         opened_by="alice", role="SECURITY_ARCHITECT", now=NOW)


def in_progress(ticket=None):
    ticket = ticket or open_ticket()
    ticket = transition(ticket, "ASSIGN", actor="alice",
                        role=SECURITY_ARCHITECT, now=NOW,
                        assignee="bob")
    return transition(ticket, "START", actor="bob",
                      role="CRYPTO_ENGINEER", now=NOW)


class TestRoleMatrix:

    def test_an_infra_engineer_cannot_accept_risk_or_grant_exceptions(self):
        ticket = in_progress()
        for action in ("ACCEPT_RISK", "GRANT_EXCEPTION"):
            with pytest.raises(ValueError, match="may not"):
                transition(ticket, action, actor="bob", role="INFRA_ENGINEER",
                           now=NOW, evidence_ids=["E1"], expires_at=at(30))

    def test_an_executive_can_accept_risk(self):
        ticket = in_progress()
        out = transition(ticket, "ACCEPT_RISK", actor="carol", role=EXECUTIVE,
                         now=NOW, evidence_ids=["E1"], expires_at=at(90),
                         note="accepted until the migration wave lands")
        assert out["state"] == "RISK_ACCEPTED"

    def test_only_an_auditor_signs_off(self):
        ticket = transition(in_progress(), "RESOLVE", actor="bob",
                            role="CRYPTO_ENGINEER", now=NOW,
                            evidence_ids=["E1"])
        with pytest.raises(ValueError, match="may not"):
            transition(ticket, "SIGN_OFF", actor="alice",
                       role=SECURITY_ARCHITECT, now=NOW)
        out = transition(ticket, "SIGN_OFF", actor="dana", role=AUDITOR, now=NOW)
        assert out["state"] == "AUDITOR_SIGNED_OFF"

    def test_an_unknown_role_cannot_even_open_a_ticket(self):
        with pytest.raises(ValueError, match="unknown role"):
            create_ticket(ticket_id="GOV-2", subject="x", opened_by="eve",
                          role="WIZARD", now=NOW)

    def test_an_invalid_state_transition_is_refused(self):
        ticket = open_ticket()
        with pytest.raises(ValueError, match="not valid from state OPEN"):
            transition(ticket, "SIGN_OFF", actor="dana", role=AUDITOR, now=NOW)


class TestAuthorisations:

    def test_risk_acceptance_requires_an_expiry(self):
        ticket = in_progress()
        with pytest.raises(ValueError, match="permanent hole"):
            transition(ticket, "ACCEPT_RISK", actor="carol", role=EXECUTIVE,
                       now=NOW, evidence_ids=["E1"], expires_at=None)

    def test_an_exception_requires_an_expiry_too(self):
        ticket = in_progress()
        with pytest.raises(ValueError, match="permanent hole"):
            transition(ticket, "GRANT_EXCEPTION", actor="alice",
                       role=SECURITY_ARCHITECT, now=NOW, evidence_ids=["E1"])

    def test_decisions_require_evidence(self):
        ticket = in_progress()
        with pytest.raises(ValueError, match="requires evidence"):
            transition(ticket, "ACCEPT_RISK", actor="carol", role=EXECUTIVE,
                       now=NOW, evidence_ids=[], expires_at=at(30))
        with pytest.raises(ValueError, match="requires evidence"):
            transition(ticket, "RESOLVE", actor="bob", role="CRYPTO_ENGINEER",
                       now=NOW, evidence_ids=[])

    def test_an_expired_authorisation_cannot_be_cited(self):
        ticket = transition(in_progress(), "GRANT_EXCEPTION", actor="alice",
                            role=SECURITY_ARCHITECT, now=NOW,
                            evidence_ids=["E1"], expires_at=at(30))
        live = active_authorization(ticket, now=at(10))
        assert live["usable"] is True
        dead = active_authorization(ticket, now=at(45))
        assert dead["usable"] is False
        assert "cannot be cited" in dead["reason"]
        assert "not consent" in dead["reason"]

    def test_absence_of_authorisation_is_never_consent(self):
        ticket = in_progress()
        result = active_authorization(ticket, now=NOW)
        assert result["usable"] is False
        assert "not consent" in result["reason"]


class TestImmutableAudit:

    def test_every_transition_lands_in_the_chained_audit(self):
        ticket = in_progress()
        ticket = transition(ticket, "RESOLVE", actor="bob",
                            role="CRYPTO_ENGINEER", now=NOW,
                            evidence_ids=["E1", "E2"], note="fixed and re-collected")
        report = verify_audit(ticket)
        assert report["verified"] is True
        assert report["entries"] == 4          # open, assign, start, resolve
        seqs = [e["seq"] for e in ticket["audit"]]
        assert seqs == [0, 1, 2, 3]
        assert ticket["evidence_ids"] == ["E1", "E2"]

    def test_an_edited_entry_breaks_verification(self):
        ticket = in_progress()
        ticket["audit"][1]["note"] = "something kinder"
        report = verify_audit(ticket)
        assert report["verified"] is False
        assert "edited after it was written" in report["problem"]

    def test_a_deleted_entry_breaks_verification(self):
        ticket = in_progress()
        del ticket["audit"][1]
        report = verify_audit(ticket)
        assert report["verified"] is False

    def test_the_input_ticket_is_never_mutated(self):
        ticket = in_progress()
        before_state = ticket["state"]
        out = transition(ticket, "ACCEPT_RISK", actor="carol", role=EXECUTIVE,
                         now=NOW, evidence_ids=["E1"], expires_at=at(30))
        assert ticket["state"] == before_state
        assert len(ticket["audit"]) == 3
        assert out["state"] == "RISK_ACCEPTED"
        assert len(out["audit"]) == 4
