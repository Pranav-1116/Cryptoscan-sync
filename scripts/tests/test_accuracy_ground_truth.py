"""The accuracy programme, run as a gate rather than read as a report.

A dashboard nobody has to clear is a document. These tests run the harness inside the ordinary
suite, so a change that trades precision for a richer-looking BOM fails the build in the same run
that made it.

The second half is the shortcut. The same corpus is scored through ``collector → CBOM``, and if
that pipeline ever passes, the corpus has stopped containing the cases that distinguish honest
scanning from confident guessing and the measurement has quietly become decorative.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _harness():
    spec = importlib.util.spec_from_file_location(
        "accuracy_ground_truth", ROOT / "scripts" / "accuracy_ground_truth.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = _harness()


@pytest.fixture(scope="module")
def report():
    return harness.measure()


# --------------------------------------------------------------------------- #
# the platform's rule meets its targets
# --------------------------------------------------------------------------- #

def test_the_fact_rule_meets_every_published_target(report):
    assert report["rigorous"]["ok"] is True, report["rigorous"]["failures"]


def test_every_target_in_the_review_is_actually_measured(report):
    unmeasured = [name for name, value in report["rigorous"]["measured"].items() if value is None]
    assert unmeasured == [], f"not measured: {unmeasured}"


def test_unknown_is_reported_beside_the_metric_never_inside_it(report):
    for dimension, summary in report["rigorous"]["dimensions"].items():
        assert "unresolved_rate" in summary
        # the rule travels with the number, so a quoted precision carries its own caveat
        assert "not a false positive" in summary["rules"]["unknown"]


def test_the_honest_gaps_are_visible_rather_than_rounded_away(report):
    """Perfect precision with a hidden unanswered column is the failure mode being avoided."""
    algorithm = report["rigorous"]["dimensions"]["algorithm"]
    assert algorithm["answered"] is not None and algorithm["answered"] < 1.0, \
        "the corpus stopped containing cases the rule cannot prove"
    assert algorithm["counts"]["unresolved"] > 0
    assert report["rigorous"]["dimensions"]["asset"]["counts"]["not_observable"] > 0


def test_the_corpus_contains_the_cases_where_accuracy_is_won(report):
    cases = set(report["corpus"]["hard_cases"])
    for required in ("installed-but-unused", "configured-but-unused", "supported-not-negotiated",
                     "runtime-only", "network-only", "static-only", "vendor-only", "stale-sbom",
                     "container-library-mismatch", "custom-crypto", "duplicate-app-name",
                     "tls-re-encryption", "expired-certificate", "unreachable-hsm",
                     "collection-failure", "permission-denied", "partial-collection",
                     "unmapped-owner", "inferred-only", "parser-disagreement"):
        assert required in cases


def test_the_report_says_what_it_did_not_measure(report):
    assert report["scope"].startswith("the fact-derivation rules")
    assert "not exercised here" in report["scope"]


# --------------------------------------------------------------------------- #
# the shortcut fails, loudly
# --------------------------------------------------------------------------- #

def test_collector_to_cbom_is_measurably_worse(report):
    naive, rigorous = report["naive"], report["rigorous"]
    assert naive["ok"] is False
    assert (naive["measured"]["algorithm_precision"]
            < rigorous["measured"]["algorithm_precision"])
    assert (naive["measured"]["false_positive_rate"]
            > rigorous["measured"]["false_positive_rate"])


def test_the_shortcut_fails_on_exactly_the_gates_it_should(report):
    failed = {failure["metric"] for failure in report["naive"]["failures"]}
    assert {"algorithm_precision", "false_positive_rate", "evidence_attribution_accuracy"} <= failed


def test_the_shortcut_never_cites_real_evidence(report):
    assert report["naive"]["measured"]["evidence_attribution_accuracy"] == 0.0


# --------------------------------------------------------------------------- #
# the command line is the gate
# --------------------------------------------------------------------------- #

def test_the_gate_passes_on_the_platform_rule(tmp_path, capsys):
    out = tmp_path / "report.json"
    assert harness.main(["--json", str(out), "--gate"]) == 0
    payload = json.loads(out.read_text())
    assert payload["selected"] == "rigorous"
    assert payload["corpus"]["truth_items"] > 0
    capsys.readouterr()


def test_the_gate_fails_when_the_shortcut_is_scored(tmp_path, capsys):
    out = tmp_path / "naive.json"
    assert harness.main(["--naive", "--json", str(out), "--gate"]) == 1
    capsys.readouterr()


def test_a_regressed_baseline_blocks_the_release(tmp_path, capsys):
    """The realistic regression: someone replaces the fact rule with the shortcut."""
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(harness.measure()))
    assert harness.main(["--naive", "--baseline", str(baseline), "--gate"]) == 1
    assert "regressed beyond tolerance" in capsys.readouterr().out


def test_an_unchanged_baseline_does_not_block(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(harness.measure()))
    assert harness.main(["--baseline", str(baseline), "--gate"]) == 0
    assert "no metric regressed" in capsys.readouterr().out


def test_the_dashboard_and_json_are_written_together(tmp_path, capsys):
    out_json, out_md = tmp_path / "report.json", tmp_path / "dashboard.md"
    assert harness.main(["--json", str(out_json), "--md", str(out_md)]) == 0
    text = out_md.read_text()
    assert "Accuracy against a planted ground truth" in text
    assert "What the shortcut costs" in text
    assert "Counting rules" in text
    assert "Hard cases in the corpus" in text
    assert harness.SCOPE.split(".")[0] in text
    capsys.readouterr()


def test_the_committed_documents_are_the_ones_this_harness_writes(tmp_path, capsys):
    """The guide's numbers are generated, so a committed dashboard that drifts is a bug."""
    committed_md = ROOT / "docs" / "bank-environment" / "185-accuracy-dashboard.md"
    committed_json = ROOT / "docs" / "bank-environment" / "185-accuracy-ground-truth.json"
    out_md, out_json = tmp_path / "dashboard.md", tmp_path / "report.json"
    assert harness.main(["--md", str(out_md), "--json", str(out_json)]) == 0
    capsys.readouterr()
    if not committed_md.is_file():
        pytest.skip("the generated dashboard has not been committed yet")
    assert out_md.read_text() == committed_md.read_text(), (
        "185-accuracy-dashboard.md is stale — regenerate it with "
        "`.venv/bin/python scripts/accuracy_ground_truth.py --json "
        "docs/bank-environment/185-accuracy-ground-truth.json --md "
        "docs/bank-environment/185-accuracy-dashboard.md`")

    payload = json.loads(out_json.read_text())
    stored = json.loads(committed_json.read_text())
    # generated_at moves on every run; the numbers must not
    payload.pop("rigorous", None), stored.pop("rigorous", None)
    assert stored["naive"]["measured"] == payload["naive"]["measured"]
