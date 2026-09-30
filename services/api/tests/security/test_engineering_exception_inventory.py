"""The exception inventory must distinguish reviewed boundaries from gaps."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
GATE = ROOT / "scripts" / "engineering_gate.py"


def _gate():
    spec = importlib.util.spec_from_file_location("engineering_gate", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shipped_exception_inventory_has_no_unreviewed_handlers():
    gate = _gate()
    checks: list[dict] = []

    gate.exception_inventory(checks)

    row = checks[0]
    assert row["check"] == "exception inventory"
    assert row["status"] == "PASS", row
    assert row["production_unresolved"] == 0
    assert row["unresolved"] == 0
    assert row["allowlisted"] >= 1
