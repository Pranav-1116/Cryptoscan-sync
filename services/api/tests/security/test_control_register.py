"""The control register must stay internally honest.

fix.md item 5 asks the product to distinguish an implemented repository
control from an operational record, a customer attestation and an external
certification. config/control-register.yaml records that per control and
scripts/control_register.py enforces it; this keeps the enforcement itself
under test, because a gate nobody runs is a document.

The tests that matter here are the negative ones. Checking the shipped
register passes only proves today's file is clean -- it says nothing about
whether the rule would catch tomorrow's edit. So each rule is also exercised
against a register crafted to violate it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
GATE = ROOT / "scripts" / "control_register.py"

pytest.importorskip("yaml")


def _gate():
    spec = importlib.util.spec_from_file_location("control_register", GATE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate():
    return _gate()


def test_the_shipped_register_is_internally_honest(gate):
    findings = gate.validate(gate._load())
    assert findings == [], (
        "the control register claims more than it evidences:\n  "
        + "\n  ".join(f"{f['control']}: {f['rule']}: {f['detail']}" for f in findings)
    )


def test_every_required_procurement_topic_is_present(gate):
    topics = {c.get("topic") for c in gate._load().get("controls", [])}
    missing = sorted(gate.REQUIRED_TOPICS - topics)
    assert not missing, f"register is silent on: {missing}"


def test_tiers_are_ordered_weakest_first(gate):
    """Other code may compare tiers by index, so the order is load-bearing."""
    assert gate.TIERS.index("repository_control") < gate.TIERS.index("operational_record")
    assert gate.TIERS.index("operational_record") < gate.TIERS.index("customer_attestation")
    assert gate.TIERS.index("customer_attestation") < gate.TIERS.index("external_certification")


# --------------------------------------------------------------------------- #
# the rules must actually reject things
# --------------------------------------------------------------------------- #

def _register(**overrides):
    control = {
        "id": "T-01", "topic": "Secure SDLC", "claimed": "repository_control",
        "evidence": ["VERSION"], "gap": "none",
    }
    control.update(overrides)
    # Satisfy the required-topic rule so only the rule under test can fire.
    extras = [{"id": f"X-{i}", "topic": t, "claimed": "none", "evidence": [],
               "gap": "not started"}
              for i, t in enumerate(sorted(_gate().REQUIRED_TOPICS - {control["topic"]}))]
    return {"controls": [control] + extras}


def _rules(gate, register) -> set[str]:
    return {f["rule"] for f in gate.validate(register)}


def test_a_certification_cannot_be_claimed_from_repository_paths(gate):
    """The headline rule: encryption code is not a FIPS validation."""
    rules = _rules(gate, _register(claimed="external_certification", evidence=["VERSION"]))
    assert "self_issued_claim" in rules


def test_a_customer_attestation_cannot_be_self_issued(gate):
    rules = _rules(gate, _register(claimed="customer_attestation", evidence=["VERSION"]))
    assert "self_issued_claim" in rules


def test_an_operational_record_needs_an_artifact(gate):
    rules = _rules(gate, _register(claimed="operational_record", evidence=[]))
    assert "unevidenced_claim" in rules


def test_citing_a_path_that_does_not_exist_is_rejected(gate):
    """A register pointing at a deleted file reads as substantiated and is not."""
    rules = _rules(gate, _register(evidence=["docs/this-was-deleted.md"]))
    assert "evidence_missing" in rules


def test_a_control_short_of_the_top_tier_must_state_its_gap(gate):
    rules = _rules(gate, _register(gap=""))
    assert "missing_gap" in rules


def test_an_unknown_tier_is_rejected(gate):
    rules = _rules(gate, _register(claimed="compliant"))
    assert "unknown_tier" in rules


def test_omitting_a_required_topic_is_reported(gate):
    register = {"controls": [{"id": "T-01", "topic": "Secure SDLC",
                              "claimed": "none", "evidence": [], "gap": "x"}]}
    findings = gate.validate(register)
    assert "topic_absent" in {f["rule"] for f in findings}


def test_no_control_currently_claims_an_external_certification(gate):
    """Guards the specific overstatement fix.md calls out.

    If this ever fails, a real certificate must exist and the row must cite
    the auditor's report -- not a source path.
    """
    claimed = [c["id"] for c in gate._load().get("controls", [])
               if c.get("claimed") == "external_certification"]
    assert not claimed, (
        f"{claimed} claim external certification; attach the issuing body's "
        "report, because this cannot be established from the repository"
    )
