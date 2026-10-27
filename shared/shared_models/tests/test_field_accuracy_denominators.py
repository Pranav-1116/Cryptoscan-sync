"""M4: undefined denominators and unreviewed work must not mean 100%."""
import pytest
from shared_models.field_accuracy import aggregate, score_workbook


@pytest.mark.parametrize("workbook,precision,recall,f1", [
    ({}, None, None, None),
    ({"findings": [{"file": "x.py", "algorithm": "RSA", "verdict": ""}]}, None, None, None),
    ({"findings": [{"file": "x.py", "algorithm": "RSA", "verdict": "FP"}]}, 0.0, None, 0.0),
    ({"candidate_misses": [{"file": "x.py", "expected": ["RSA"], "verdict": "FN"}]}, None, 0.0, 0.0),
])
def test_undefined_metrics_remain_null_in_scoring_and_pooling(workbook, precision, recall, f1):
    result = score_workbook(workbook)
    assert (result.precision, result.recall, result.f1) == (precision, recall, f1)
    pooled = aggregate([result])
    assert (pooled.precision, pooled.recall, pooled.f1) == (precision, recall, f1)
    assert pooled.status == ("MEASURED" if result.tp + result.fp + result.fn else "NO_REVIEWED_UNITS")
    for language in result.by_language:
        assert language.precision == precision
        assert language.recall == recall


def test_precision_is_not_a_false_positive_rate_without_true_negatives():
    result = aggregate([score_workbook({"findings": [
        {"file": "x.py", "algorithm": "RSA", "verdict": "TP"},
        {"file": "x.py", "algorithm": "AES", "verdict": "FP"},
    ]})])
    assert result.precision == 0.5
    assert result.false_positive_rate is None  # no true-negative denominator
    assert result.false_negative_rate == 0.0
    assert result.metric_scope == "REVIEWED_FILE_ALGORITHM_UNITS_NOT_ESTATE_COMPLETENESS"


@pytest.mark.parametrize("wb", [
    {"findings": [{"file": "x", "algorithm": "AES", "verdict": "MAYBE"}]},
    {"candidate_misses": [{"file": "x", "verdict": "TP"}]},
    {"candidate_misses": [{"file": "x", "verdict": "FN", "expected": "RSA"}]},
    {"findings": "bad"}, {"findings": [None]},
])
def test_invalid_workbooks_fail_with_validation_error_not_silent_review(wb):
    with pytest.raises(ValueError):
        score_workbook(wb)


@pytest.mark.parametrize("kind", ["empty", "fp", "fn"])
def test_existing_triage_cli_handles_undefined_metrics(tmp_path, kind):
    import json
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[3]
    wb = {"repo": "synthetic", "findings": [], "candidate_misses": []}
    if kind == "fp":
        wb["findings"] = [{"file": "x.py", "algorithm": "RSA", "verdict": "FP"}]
    if kind == "fn":
        wb["candidate_misses"] = [{"file": "x.py", "expected": ["RSA"], "verdict": "FN"}]
    source = tmp_path / "workbook.json"
    source.write_text(json.dumps(wb))
    output = tmp_path / "score.json"
    run = subprocess.run([sys.executable, str(root / "scripts/bank_triage.py"), "score", str(source),
                          "--json-out", str(output)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert "NOT_MEASURED" in run.stdout
    assert "1.000" not in run.stdout
    result = json.loads(output.read_text())
    assert result["precision"] is None or result["recall"] is None
