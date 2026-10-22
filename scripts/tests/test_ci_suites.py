"""Selection contracts for the disjoint backend and scanner CI matrices."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ci_suites", ROOT / "scripts/ci_suites.py")
assert spec and spec.loader
ci_suites = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci_suites)


def test_real_checkout_is_partitioned_without_omitting_any_suite():
    all_suites = set(ci_suites.discover_suites(ROOT))
    scanners = set(ci_suites.discover_suites(ROOT, scanners_only=True))
    other = set(ci_suites.discover_suites(ROOT, non_scanners_only=True))
    assert scanners and other
    assert not scanners & other
    assert scanners | other == all_suites
    assert {suite.split("/")[1] for suite in scanners} == ci_suites.SCANNERS
    assert "services/universal_vendor/sdk_template/tests" in scanners
    assert all(suite.startswith(("services/", "shared/")) for suite in other)


def test_cli_emits_disjoint_nonempty_matrices_for_real_checkout():
    def suites(*args: str) -> set[str]:
        result = subprocess.run(
            [sys.executable, "-I", str(ROOT / "scripts/ci_suites.py"), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return {entry["suite"] for entry in json.loads(result.stdout)["include"]}

    assert suites("--scanners-only") | suites("--non-scanners") == suites()
    assert not suites("--scanners-only") & suites("--non-scanners")


def test_synthetic_new_suites_route_to_one_matrix(tmp_path):
    for family in ci_suites.SCANNERS:
        (tmp_path / f"services/{family}/tests").mkdir(parents=True)
    for suite in ("services/universal_vendor/sdk_template/tests", "services/other/tests", "shared/common/tests"):
        (tmp_path / suite).mkdir(parents=True)
    assert set(ci_suites.discover_suites(tmp_path, scanners_only=True)) == {
        *(f"services/{family}/tests" for family in ci_suites.SCANNERS),
        "services/universal_vendor/sdk_template/tests",
    }
    assert ci_suites.discover_suites(tmp_path, non_scanners_only=True) == [
        "services/other/tests",
        "shared/common/tests",
    ]


def test_missing_scanner_family_fails_closed(tmp_path):
    (tmp_path / "services/scanner/tests").mkdir(parents=True)
    (tmp_path / "shared").mkdir()
    with pytest.raises(ValueError, match="missing scanner suite families"):
        ci_suites.discover_suites(tmp_path, scanners_only=True)


def test_empty_selection_and_conflicting_filters_fail_closed(tmp_path):
    (tmp_path / "services/other/tests").mkdir(parents=True)
    (tmp_path / "shared").mkdir()
    with pytest.raises(ValueError, match="no backend test suites"):
        ci_suites.discover_suites(tmp_path, scanners_only=True)
    with pytest.raises(ValueError, match="mutually exclusive"):
        ci_suites.discover_suites(tmp_path, scanners_only=True, non_scanners_only=True)
    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "scripts/ci_suites.py"), "--root", str(tmp_path), "--scanners-only"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "no backend test suites discovered" in result.stderr
