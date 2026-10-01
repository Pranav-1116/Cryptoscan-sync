"""The unified readiness report must include the operational policy boundary."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "bank_readiness.py"
POLICY = ROOT / "config" / "operational-policy.yaml"


def _gate():
    spec = importlib.util.spec_from_file_location("bank_readiness", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_readiness_has_structural_operational_policy_category():
    gate = _gate()
    row = gate.operational_policy_check(POLICY)
    assert row["category"] == "operational_policy"
    assert row["status"] == "PASS"
    assert row["policy_status"] == "draft"
    assert "strict" in row["approval_required"]
    assert "operational_policy" in gate.REQUIRED_CATEGORIES
    assert "readiness_closure" in gate.REQUIRED_CATEGORIES


def test_missing_operational_policy_is_blocking(tmp_path):
    gate = _gate()
    row = gate.operational_policy_check(tmp_path / "missing.yaml")
    assert row["status"] == "FAIL"


def test_readiness_report_explicitly_skips_external_closure_without_manifest():
    gate = _gate()
    row = gate.readiness_closure_check()
    assert row["category"] == "readiness_closure"
    assert row["status"] == "SKIP"
    assert "not inferred" in row["detail"]
