"""The region/PITR drills are code drills — their reports must say so.

Roadmap phase 1.3, claim 2: ``docs/region-failover.md`` used to end with a bare
``**Verdict: PASS**`` a reader could take as a two-site failover — or even a
SOC 2 CC9.3/9.4 — qualification. The drill is two temporary directories in one
process. The report now carries that scope beside the verdict; these tests run
the real drills and hold the report to it.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

BARE_VERDICT = re.compile(r"^\*\*Verdict: \w+\*\*$", re.MULTILINE)


def _load():
    spec = importlib.util.spec_from_file_location(
        "region_drills", ROOT / "scripts" / "region_drills.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def drills():
    return _load()


def test_the_region_failover_drill_still_passes_against_real_bus_code(drills, tmp_path):
    results = drills.region_failover_drill(tmp_path / "regions")
    assert results, "the drill reported no checks at all — a refusal is not a pass"
    failed = [r for r in results if not r["ok"]]
    assert failed == []


def test_the_pitr_drill_still_passes_against_real_bus_code(drills, tmp_path):
    results = drills.pitr_drill(tmp_path / "pitr")
    assert results, "the drill reported no checks at all — a refusal is not a pass"
    failed = [r for r in results if not r["ok"]]
    assert failed == []


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def test_a_report_carries_its_scope_beside_the_verdict(drills):
    report = drills.build_report(
        "Region failover", [{"check": "x", "ok": True, "detail": ""}],
        ok=True, ran_at="2026-01-01T00:00:00+00:00")
    flat = _flat(report)
    assert "**Scope — what this drill is, and is not.**" in report
    assert "temporary directories inside one process on one machine" in flat
    assert "it is **not** a two-site failover" in flat
    assert re.search(r"not.{0,60}SOC 2 CC9\.3/9\.4 evidence", flat)
    assert BARE_VERDICT.search(report) is None
    assert "**Verdict: PASS — same-process code drill" in report


def test_the_pitr_report_names_what_it_is_not(drills):
    report = drills.build_report(
        "Point-in-time platform recovery", [{"check": "x", "ok": True, "detail": ""}],
        ok=True, ran_at="2026-01-01T00:00:00+00:00")
    flat = _flat(report)
    assert "**Scope — what this drill is, and is not.**" in report
    assert "is **not** PostgreSQL WAL PITR" in flat
    assert "scripts/restore_drill.py" in report
    assert BARE_VERDICT.search(report) is None


def test_a_failing_verdict_never_stands_alone_either(drills):
    report = drills.build_report(
        "Region failover", [{"check": "x", "ok": False, "detail": "broke"}],
        ok=False, ran_at="2026-01-01T00:00:00+00:00")
    assert BARE_VERDICT.search(report) is None
    assert "FAIL — a check above did not hold" in report


def test_the_checked_in_reports_match_the_generator(drills):
    """The committed reports are this generator's output — never hand-edited."""
    for name, path in (("Region failover", ROOT / "docs" / "region-failover.md"),
                       ("Point-in-time platform recovery", ROOT / "docs" / "pitr-drill.md")):
        text = path.read_text(encoding="utf-8")
        assert "**Scope — what this drill is, and is not.**" in text, path.name
        assert BARE_VERDICT.search(text) is None, path.name
        # everything except the check-table rows must be reproducible from the
        # builder (the rows themselves come from the live drill run)
        rebuilt = drills.build_report(
            name, [], ok=verdict_is_pass(text), ran_at=_stamp(text))
        assert _strip_rows(rebuilt) == _strip_rows(text), path.name


def verdict_is_pass(text: str) -> bool:
    return "PASS — same-process code drill" in text


def _stamp(text: str) -> str:
    match = re.search(r"^Ran (\S+) — executable proof", text, re.MULTILINE)
    assert match, "the report carries no run timestamp"
    return match.group(1)


def _strip_rows(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.startswith("| "))
