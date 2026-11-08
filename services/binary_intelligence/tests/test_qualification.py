"""Binary-engine production qualification (docs/binary-intelligence/
01_PRODUCT_SPEC.md §13/§14) — the battery proves the claims:

- malformed input never crashes a parser — refused with its reason;
- backpressure refuses and counts, never silently drops;
- the engine contains NO execution primitives — static analysis
  never executes the artifact (§14), proven mechanically;
- timing measurements exist per stage (§13) — measurements, never
  production claims.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[2].parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))

from binary_engine_qualification import (  # noqa: E402
    _mutate, _no_execution_primitives, run_battery,
)
from binary_intelligence.pipeline import run_scan  # noqa: E402


def test_static_analysis_never_executes_the_artifact():
    safety = _no_execution_primitives(
        Path(__file__).resolve().parents[1] / "binary_intelligence")
    assert safety["offenders"] == [], \
        "an execution primitive in the engine is a §14 violation: " \
        f"{safety['offenders']}"
    assert safety["checked_files"] >= 15


def test_malformed_corpus_never_crashes_a_parser():
    from tests.fixtures import elf_crypto_sample, pe_crypto_sample
    for sample in (elf_crypto_sample(), pe_crypto_sample()):
        for mutant in _mutate(sample):
            try:
                result = run_scan(
                    tenant_id="qual", data=mutant,
                    original_filename="mutant.bin",
                    source_type="qualification",
                    uploaded_by="qualification-battery")
                assert result.status == "completed"
            except ValueError as exc:
                assert str(exc), \
                    "a refusal carries its reason — never a bare crash"


def test_qualification_battery_reports_honest_measurements():
    report = run_battery()
    assert report["valid_scan_failures"] == []
    assert report["malformed_failures"] == []
    assert "refused with its reason" in report["fail_safe_verdict"]
    assert report["queue"]["refused_and_counted"] > 0, \
        "backpressure is exercised and counted"
    assert report["queue"]["processed"] == report["queue"]["accepted"]
    assert report["static_safety"]["offenders"] == []
    assert report["timing_seconds"]["median"] > 0, \
        "timings are measurements on this machine — never claims (§13)"
    assert "never production claims" in report["measured_on"]
