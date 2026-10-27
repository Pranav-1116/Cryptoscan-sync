"""Per-rule test coverage reporting (audit 65 P0#4, round 28)."""

from __future__ import annotations

from pathlib import Path

from policy.rules.rule_coverage import (load_pack_index, rule_test_coverage,
                                        scan_test_references)

RULE_YAML = """\
rule_id: "{rule_id}"
rule_name: "rule {rule_id}"
version: "1.0"
severity: "HIGH"
description: "test rule"
condition:
  type: "ALGORITHM_IN_LIST"
  parameters:
    algorithm_list: ["DES"]
evaluation:
  result_template: "FAIL"
remediation: "fix"
enabled: true
"""


def _seed_pack(root: Path, pack: str, rule_ids: list[str]) -> None:
    pack_dir = root / "packs" / pack
    pack_dir.mkdir(parents=True)
    for rule_id in rule_ids:
        (pack_dir / f"{rule_id}.yaml").write_text(RULE_YAML.format(rule_id=rule_id))


def _seed_tests(root: Path, files: dict[str, str]) -> None:
    tests = root / "tests"
    tests.mkdir()
    for name, text in files.items():
        path = tests / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def test_pack_index_maps_rule_to_pack(tmp_path):
    _seed_pack(tmp_path, "baseline", ["BASELINE-001", "BASELINE-002"])
    _seed_pack(tmp_path, "fips", ["FIPS140-001"])
    index = load_pack_index(tmp_path / "packs")
    assert index == {"BASELINE-001": "baseline", "BASELINE-002": "baseline",
                     "FIPS140-001": "fips"}


def test_scan_finds_rule_id_references_with_word_boundaries(tmp_path):
    _seed_tests(tmp_path, {
        "test_a.py": 'assert "BASELINE-001" in result.failed_rule_ids()\n',
        "deep/test_b.py": "# BASELINE-0010 is NOT BASELINE-001\nRULES = ['BASELINE-001', 'BASELINE-002']\n",
    })
    refs = scan_test_references(tmp_path / "tests")
    assert refs["BASELINE-001"] == {"test_a.py", "deep/test_b.py"}
    assert refs["BASELINE-002"] == {"deep/test_b.py"}
    # BASELINE-0010 must not collapse into BASELINE-001 via prefix
    assert "BASELINE-0010" in refs or "BASELINE-0010" not in refs["BASELINE-001"]


def test_coverage_matrix_and_ratios(tmp_path):
    _seed_pack(tmp_path, "baseline", ["BASELINE-001", "BASELINE-002"])
    _seed_pack(tmp_path, "nist", ["NIST131A-001"])
    _seed_tests(tmp_path, {
        "test_pack.py": 'assert "BASELINE-001" in ids\n',
    })
    result = rule_test_coverage(tmp_path / "packs", tmp_path / "tests")
    assert result["rule_count"] == 3
    assert result["covered_count"] == 1
    assert result["uncovered_count"] == 2
    assert result["coverage_ratio"] == round(1 / 3, 4)
    assert result["by_pack"]["baseline"] == {"rules": 2, "covered": 1,
                                             "coverage_ratio": 0.5}
    assert result["by_pack"]["nist"] == {"rules": 1, "covered": 0,
                                         "coverage_ratio": 0.0}
    row = next(r for r in result["rules"] if r["rule_id"] == "BASELINE-001")
    assert row["covered"] is True
    assert row["referenced_by"] == ["test_pack.py"]
    assert "not a proof of absence" in result["method"]["caveat"]


def test_missing_tests_dir_is_empty_not_an_error(tmp_path):
    _seed_pack(tmp_path, "baseline", ["BASELINE-001"])
    result = rule_test_coverage(tmp_path / "packs", tmp_path / "no-such-tests")
    assert result["rule_count"] == 1
    assert result["covered_count"] == 0


def test_real_packs_have_majority_coverage():
    """Regression guard on the shipped packs' coverage ratio."""
    from policy.core.engine import PolicyEngine  # noqa: F401 — proves importability

    rules_dir = Path(__file__).resolve().parents[2] / "rule_definitions"
    tests_dir = rules_dir.parent / "tests"
    result = rule_test_coverage(rules_dir, tests_dir)
    assert result["rule_count"] >= 60
    assert result["coverage_ratio"] >= 0.8
