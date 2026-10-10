"""Per-rule test coverage reporting (audit 65 P0#4, round 28).

The rule *packs* are exercised by the policy suite, but nothing answered
"which rules have no test referencing them?" This module answers it with
honest static analysis: it maps every rule in the loaded packs to the
test files that mention its rule_id.

What "covered" means here — and what it does not:

* covered  = at least one file under the tests directory references the
  rule id (assertion, fixture, or listing). A strong signal the rule is
  exercised.
* uncovered = no test file mentions the id. The rule may still be
  exercised indirectly (e.g. an engine test that evaluates the whole
  pack), so uncovered is a *lead for review*, not a proof of absence.

Deterministic file scanning + YAML parsing; no execution, no coverage
tooling required.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

#: rule ids look like PACK-NNN / PACK-N-NNN (BASELINE-001, FIPS140-002,
#: CNSA-001 ...). Matching the id as a word boundary avoids prefix
#: collisions (BASELINE-001 vs BASELINE-0010).
_RULE_ID = re.compile(r"\b[A-Z][A-Z0-9]*-[0-9]{1,4}\b")


def load_pack_index(rules_dir: Path) -> dict[str, str]:
    """rule_id -> pack name (the YAML file's parent directory)."""
    index: dict[str, str] = {}
    for yaml_file in sorted(Path(rules_dir).glob("**/*.yaml")):
        if yaml_file.name.startswith("_") or yaml_file.parent.name.startswith("_"):
            continue
        try:
            with open(yaml_file, "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(data, dict) and data.get("rule_id"):
            index[str(data["rule_id"])] = yaml_file.parent.name
    return index


def scan_test_references(tests_dir: Path) -> dict[str, set[str]]:
    """rule_id -> set of test file (relative) paths mentioning it."""
    references: dict[str, set[str]] = {}
    root = Path(tests_dir)
    if not root.exists():
        return references
    for py_file in sorted(root.glob("**/*.py")):
        try:
            text = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _RULE_ID.findall(text):
            references.setdefault(match, set()).add(
                str(py_file.relative_to(root)).replace("\\", "/"))
    return references


def rule_test_coverage(rules_dir: Path, tests_dir: Path) -> dict[str, Any]:
    """Coverage matrix for every rule in the packs."""
    pack_index = load_pack_index(rules_dir)
    references = scan_test_references(tests_dir)

    rows: list[dict[str, Any]] = []
    for rule_id in sorted(pack_index):
        refs = sorted(references.get(rule_id, ()))
        rows.append({
            "rule_id": rule_id,
            "pack": pack_index[rule_id],
            "referenced_by": refs,
            "covered": bool(refs),
        })

    covered = sum(1 for row in rows if row["covered"])
    by_pack: dict[str, dict[str, int]] = {}
    for row in rows:
        stats = by_pack.setdefault(row["pack"], {"rules": 0, "covered": 0})
        stats["rules"] += 1
        stats["covered"] += 1 if row["covered"] else 0

    return {
        "rules": rows,
        "rule_count": len(rows),
        "covered_count": covered,
        "uncovered_count": len(rows) - covered,
        "coverage_ratio": round(covered / len(rows), 4) if rows else 0.0,
        "by_pack": {
            pack: {**stats, "coverage_ratio": round(stats["covered"] / stats["rules"], 4)}
            for pack, stats in sorted(by_pack.items())
        },
        "method": {
            "covered": "at least one test file under the tests directory "
                       "references the rule id",
            "caveat": "uncovered means no direct reference — indirect "
                      "whole-pack exercise is invisible to this scan, so "
                      "uncovered is a review lead, not a proof of absence",
            "tests_dir": str(tests_dir),
        },
    }
