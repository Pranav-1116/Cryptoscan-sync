"""Unit tests for the Saudi Arabia (SAMA / mada / SWIFT CSCF) rule pack.

Verifies:
  - every YAML under services/policy/rule_definitions/saudi/ loads via RuleLoader
  - rule IDs follow the recommended ^[A-Z0-9]+-[0-9]{3,}$ pattern (no warnings)
  - every rule carries a condition, remediation, severity, standard_reference
  - expected scoping scopes are present (SAMA/MADA/SWIFT)
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[4]
POLICY_DIR = ROOT / "services" / "policy"
sys.path.insert(0, str(POLICY_DIR))

SAUDI_DIR = POLICY_DIR / "rule_definitions" / "saudi"
EXPECTED_IDS = {
    "SAMA-001", "SAMA-002", "SAMA-003", "SAMA-004",
    "SAMA-005", "SAMA-006", "MADA-001", "SAMASWIFT-001",
}


def test_saudi_rule_files_parse():
    files = sorted(SAUDI_DIR.glob("*.yaml"))
    ids = set()
    for f in files:
        doc = yaml.safe_load(f.read_text())
        assert doc["rule_id"], f
        assert doc["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN"), f
        assert doc["condition"]["type"], f
        assert doc["remediation"], f
        assert doc["standard_reference"], f
        # Regex check for rule_id format
        import re
        assert re.match(r"^[A-Z0-9]+-[0-9]{3,}$", doc["rule_id"]), (
            f"rule_id {doc['rule_id']} in {f.name} does not match the engine "
            "recommended format UPPERCASE-NNN (no double-dashes)")
        ids.add(doc["rule_id"])
    assert ids == EXPECTED_IDS, (
        f"Missing or extra SAMA rule IDs. Expected {EXPECTED_IDS}, got {ids}")


def test_saudi_rule_pack_loads_via_engine_loader():
    from policy.rules.rule_loader import RuleLoader
    loader = RuleLoader(str(POLICY_DIR / "rule_definitions"))
    rules = loader.load_all_rules()
    loaded_ids = {r.rule_id for r in rules}
    for rid in EXPECTED_IDS:
        assert rid in loaded_ids, f"SAMA rule {rid} not loaded by RuleLoader"


def test_sama_rules_have_appropriate_scopes():
    """SAMA rules should declare scoped enforcement (required_scopes) so they
    don't fire on out-of-scope systems."""
    scoped = {"SAMA-002", "SAMA-004", "MADA-001", "SAMASWIFT-001"}
    for f in SAUDI_DIR.glob("*.yaml"):
        doc = yaml.safe_load(f.read_text())
        rid = doc["rule_id"]
        params = doc.get("condition", {}).get("parameters", {}) or {}
        if rid in scoped:
            assert params.get("required_scopes"), (
                f"{rid} must declare required_scopes so it is scope-gated")
