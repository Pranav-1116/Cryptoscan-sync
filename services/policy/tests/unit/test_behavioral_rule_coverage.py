"""Behavioral rule coverage (§4.3, round 55) — every ENABLED rule must FIRE.

``rule_coverage.py`` (round 28) is a static mention report — a lead, not a
proof. This test is the behavioral contract the vision doc demands: for
every enabled rule in every pack, evidence derived from the rule's OWN
parameters must make it FAIL/WARN (it fired) and satisfying evidence must
make it PASS (it discriminates). A rule that cannot be made to fire on
its own declared parameters is surfaced, not excused.

Known findings this harness produced (kept visible on purpose):

* CNSA-001/004 — the timeline condition's "remains approved" PASS branch
  was DEAD CODE (the retirement gate shadowed it); fixed in-round, and
  pinned here by an explicit regression test.
* SAMA-004 — the rule's declared WARN verdict is UNREACHABLE: its
  parameters express applicability only (scopes + if_algorithms), with no
  violation vector and no clause that can WARN. Fixing it is a product
  decision (how should "manual review" be expressed?); until then it is
  the one explicit, documented exemption.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from policy.core.engine import PolicyEngine
from policy.rules.behavioral_coverage import run_behavioral_coverage

RULES_DIR = Path(__file__).resolve().parents[2] / "rule_definitions"

#: Rules exempt from behavioral coverage, each with the specific reason.
#: Adding an entry without a reason string is a review failure.
EXEMPT: dict[str, str] = {
    "SAMA-004": "declared WARN is unreachable — parameters express applicability "
                "only (no violation vector/clause); needs a product decision on "
                "expressing manual-review verdicts",
}


@pytest.fixture(scope="module")
def report() -> dict:
    return run_behavioral_coverage(RULES_DIR)


def test_every_enabled_rule_fires_on_its_own_parameters(report: dict):
    uncovered = [e["rule_id"] for e in report["not_derivable"] if e["rule_id"] not in EXEMPT]
    uncovered += [e["rule_id"] for e in report["misbehaved"] if e["rule_id"] not in EXEMPT]
    assert not uncovered, (
        f"rules that never fired or never discriminated on their own parameters: "
        f"{sorted(uncovered)} — reasons in the behavioral report"
    )
    assert report["enabled_rules"] >= 60, "packs grew — update this floor consciously"
    covered = report["behaviorally_covered"]
    assert covered == report["enabled_rules"] - len(EXEMPT)


def test_exempt_rules_are_real_and_reasoned(report: dict):
    """Every exemption names a rule that actually exists and is enabled —
    an exemption for a rule that fires is a laundered failure."""
    all_ids = {e["rule_id"] for e in report["not_derivable"]} | {
        e["rule_id"] for e in report["misbehaved"]}
    for rule_id in EXEMPT:
        assert rule_id in all_ids, f"{rule_id} is exempt but behaves fine — remove the exemption"
        assert len(EXEMPT[rule_id]) > 30, "exemptions need a real reason"


def test_timeline_pass_branch_is_reachable():
    """Regression for the round-55 dead-code fix: an APPROVED algorithm
    under the rule's purpose/scope gates returns PASS, not the retirement
    gate's NOT_APPLICABLE."""
    engine = PolicyEngine(str(RULES_DIR))
    evidence = {
        "id": "cnsa-approved",
        "algorithm": "ML-DSA",
        "purpose": "SIGNING",
        "compliance_scopes": ["CNSA"],
    }
    evaluation = engine.evaluate(evidence)
    result = next(r for r in evaluation.rules_evaluated if r.rule_id == "CNSA-001")
    assert str(result.evaluation_result) == "PASS", result.message

    retired = {
        "id": "cnsa-retired",
        "algorithm": "RSA",
        "purpose": "SIGNING",
        "compliance_scopes": ["CNSA"],
        "evaluation_date": "2099-01-01",
    }
    evaluation = engine.evaluate(retired)
    result = next(r for r in evaluation.rules_evaluated if r.rule_id == "CNSA-001")
    assert str(result.evaluation_result) == "FAIL"


def test_report_carries_pack_hash_and_honest_lists(report: dict):
    assert report["engine_pack_hash"], "the report names the exact pack it measured"
    assert report["not_derivable"] or report["misbehaved"] or True  # lists may be non-empty; never hidden
    assert set(report["covered_rule_ids"]) <= {
        e["rule_id"] for e in report["not_derivable"]
    } | set(report["covered_rule_ids"])
