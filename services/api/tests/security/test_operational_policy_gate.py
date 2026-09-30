"""Operational policy shape and approval boundaries are explicit."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "operational_policy_gate.py"


def _gate():
    pytest.importorskip("yaml")
    spec = importlib.util.spec_from_file_location("operational_policy_gate", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shipped_policy_is_structurally_complete_but_not_approved():
    gate = _gate()
    policy = gate._load()
    assert gate.validate(policy) == []
    findings = gate.validate(policy, strict=True)
    assert "strict mode requires status=approved" in findings
    assert "strict mode requires reviewed_by" in findings
    assert "strict mode requires approved_at in YYYY-MM-DD format" in findings


def test_strict_policy_requires_real_approval_metadata():
    gate = _gate()
    policy = gate._load()
    policy.update({"status": "approved", "reviewed_by": "security-owner", "approved_at": "2026-09-29"})
    assert gate.validate(policy, strict=True) == []


def test_invalid_patch_deadline_is_rejected():
    gate = _gate()
    policy = gate._load()
    policy["patch_remediation"]["critical"]["remediate_within_days"] = 0
    findings = gate.validate(policy)
    assert "patch_remediation.critical.remediate_within_days must be a positive integer" in findings
