"""Accuracy gate: the source scanner must stay >= 95% on the ground-truth corpus.

Runs the same benchmark as ``scripts/accuracy_benchmark.py`` (hermetic: temp
dir, no network, no DB) and fails with the *named* misses so a regression is
a file, not a percentage.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
BENCH = ROOT / "scripts" / "accuracy_benchmark.py"

MIN_F1 = 0.95
MIN_PRECISION = 0.95
MIN_RECALL = 0.95
MIN_FILE_EXACT = 0.90


@pytest.fixture(scope="module")
def report() -> dict:
    spec = importlib.util.spec_from_file_location("accuracy_benchmark", BENCH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["accuracy_benchmark"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod.run()


def _fmt_misses(rep: dict) -> str:
    return "\n".join(
        f"  {r['language']}/{r['file']}: FN={r['fn']} FP={r['fp']}{' CRASH ' + r['crash'] if r['crash'] else ''}"
        for r in rep["misses"]
    ) or "  (none)"


def test_no_parser_crashes(report):
    crashes = [r for r in report["cases"] if r["crash"]]
    assert not crashes, "parser crashed on:\n" + "\n".join(f"  {r['language']}/{r['file']}: {r['crash']}" for r in crashes)


def test_overall_accuracy_gate(report):
    o = report["overall"]
    assert o["f1"] >= MIN_F1, f"F1 {o['f1']:.3f} < {MIN_F1}\n{_fmt_misses(report)}"
    assert o["precision"] >= MIN_PRECISION, f"precision {o['precision']:.3f} < {MIN_PRECISION}\n{_fmt_misses(report)}"
    assert o["recall"] >= MIN_RECALL, f"recall {o['recall']:.3f} < {MIN_RECALL}\n{_fmt_misses(report)}"
    assert o["file_exact_rate"] >= MIN_FILE_EXACT, f"file-exact {o['file_exact_rate']:.3f} < {MIN_FILE_EXACT}\n{_fmt_misses(report)}"


def test_negative_corpus_is_silent(report):
    """Hostile negatives (md5sum paths, 'description', CRC32, git SHAs...) must produce nothing."""
    noisy = [r for r in report["cases"] if r["category"] == "negative" and r["predicted"]]
    assert len(noisy) <= max(1, len([r for r in report["cases"] if r["category"] == "negative"]) // 20), (
        "false positives on negative files:\n" + "\n".join(f"  {r['language']}/{r['file']}: {r['predicted']}" for r in noisy)
    )


def test_every_language_meets_bar(report):
    weak = {k: m for k, m in report["by_language"].items() if m["files"] >= 5 and m["f1"] < 0.90}
    assert not weak, f"languages below 0.90 F1: {weak}\n{_fmt_misses(report)}"
