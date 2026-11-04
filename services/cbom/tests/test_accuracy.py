"""Measuring with UNKNOWN kept out of the wrong column — and out of the escape hatch.

Two ways to get this wrong, and the tests are split along them:

* counting ``UNKNOWN`` as a wrong answer punishes honesty, so the product learns to guess;
* not counting it at all lets a scanner reach 100% precision by answering three questions.

Everything below is about the difference between those.
"""

from __future__ import annotations

import pytest

from cbom import accuracy
from cbom.accuracy import Prediction, Truth


def p(subject="a", attribute="algorithm", value="AES-256-GCM", state=accuracy.FOUND,
      dimension="algorithm", evidence_ids=("EVID-v1-x",)):
    return Prediction(dimension=dimension, subject=subject, attribute=attribute, value=value,
                      state=state, evidence_ids=evidence_ids)


def t(subject="a", attribute="algorithm", value="AES-256-GCM", observable=True,
      dimension="algorithm"):
    return Truth(dimension=dimension, subject=subject, attribute=attribute, value=value,
                 observable=observable)


# --------------------------------------------------------------------------- #
# UNKNOWN is never a wrong answer
# --------------------------------------------------------------------------- #

def test_an_unknown_prediction_is_excluded_from_precision_and_recall():
    counts = accuracy.score([p(state=accuracy.UNKNOWN, value=None)], [t()])["algorithm"]
    assert (counts.tp, counts.fp, counts.fn) == (0, 0, 0)
    assert counts.unresolved == 1
    summary = accuracy.metrics(counts)
    assert summary["precision"] is None          # 0/0 is not a perfect score
    assert summary["recall"] is None
    assert summary["unresolved_rate"] == 1.0


def test_answering_unknown_does_not_lower_precision_of_the_answers_that_were_given():
    predictions = [p(subject="a"), p(subject="b", state=accuracy.UNKNOWN, value=None)]
    truths = [t(subject="a"), t(subject="b")]
    summary = accuracy.metrics(accuracy.score(predictions, truths)["algorithm"])
    assert summary["precision"] == 1.0
    assert summary["answered"] == pytest.approx(0.5)   # ...but it shows up here


def test_a_failed_collection_is_not_a_wrong_answer_either():
    counts = accuracy.score([p(state=accuracy.COLLECTION_FAILED, value=None)],
                            [t()])["algorithm"]
    assert counts.fn == 0 and counts.fp == 0
    assert counts.unresolved == 1


# --------------------------------------------------------------------------- #
# ...but silence still costs something
# --------------------------------------------------------------------------- #

def test_a_dimension_answered_mostly_by_unknown_fails_the_gate():
    predictions = [p(subject=str(index), state=accuracy.UNKNOWN, value=None) for index in range(10)]
    truths = [t(subject=str(index)) for index in range(10)]
    result = accuracy.evaluate(predictions, truths, min_answered=0.8, max_unresolved=1.0,
                               targets={"algorithm_recall": 0.0})
    assert result["ok"] is False
    assert any("answered" in failure["metric"] for failure in result["failures"])


def test_too_much_unknown_invalidates_the_precision_number():
    predictions = [p(subject="wrong", value="DES"),
                   *[p(subject=str(index), state=accuracy.UNKNOWN, value=None)
                     for index in range(9)]]
    truths = [t(subject="wrong"), *[t(subject=str(index)) for index in range(9)]]
    result = accuracy.evaluate(predictions, truths, max_unresolved=0.25, min_answered=0.0,
                               targets={"false_positive_rate": 1.0})
    assert any("unresolved_rate" in failure["metric"] for failure in result["failures"])


# --------------------------------------------------------------------------- #
# the unobservable is a correct refusal, not a miss
# --------------------------------------------------------------------------- #

def test_answering_unknown_for_an_unobservable_item_is_correct():
    counts = accuracy.score([p(state=accuracy.UNKNOWN, value=None)],
                            [t(value="AES-256-GCM", observable=False)])["algorithm"]
    assert counts.tn == 1 and counts.fp == 0 and counts.fn == 0
    assert counts.not_observable == 1


def test_declining_an_unobservable_item_in_words_is_also_correct():
    counts = accuracy.score([p(state=accuracy.NOT_OBSERVABLE, value=None)],
                            [t(observable=False)])["algorithm"]
    assert counts.tn == 1


def test_asserting_a_value_for_an_unobservable_item_is_a_false_positive():
    counts = accuracy.score([p(value="AES-256-GCM")], [t(observable=False)])["algorithm"]
    assert counts.fp == 1 and counts.tp == 0


# --------------------------------------------------------------------------- #
# the ordinary confusions
# --------------------------------------------------------------------------- #

def test_a_confidently_wrong_value_is_one_false_positive_and_one_false_negative():
    counts = accuracy.score([p(value="AES-128-GCM")], [t()])["algorithm"]
    assert (counts.fp, counts.fn) == (1, 1)
    summary = accuracy.metrics(counts)
    assert summary["precision"] == 0.0 and summary["recall"] == 0.0


def test_declining_an_item_the_truth_does_not_hold_is_correct():
    for state in (accuracy.UNKNOWN, accuracy.NOT_FOUND_WITHIN_SCOPE):
        counts = accuracy.score([p(state=state, value=None)], [t(value=None)])["algorithm"]
        assert counts.tn == 1, state
    assert accuracy.score([p(value="DES")], [t(value=None)])["algorithm"].fp == 1


def test_claiming_absence_where_the_truth_holds_a_value_is_a_miss():
    counts = accuracy.score([p(state=accuracy.NOT_FOUND_WITHIN_SCOPE, value=None)],
                            [t()])["algorithm"]
    assert counts.fn == 1


def test_an_unpredicted_observable_item_is_a_miss_not_a_pass():
    counts = accuracy.score([], [t()])["algorithm"]
    assert counts.fn == 1 and counts.unpredicted == 1


def test_a_conflict_where_the_key_has_one_answer_is_a_miss():
    counts = accuracy.score([p(state=accuracy.CONFLICT, value=None)], [t()])["algorithm"]
    assert counts.fn == 1 and counts.tp == 0


def test_a_conflict_where_the_key_holds_a_conflict_is_correct():
    counts = accuracy.score([p(state=accuracy.CONFLICT, value=None)],
                            [t(value=accuracy.TRUTH_CONFLICT)])["algorithm"]
    assert counts.tp == 1


def test_picking_a_side_of_a_known_conflict_is_wrong():
    counts = accuracy.score([p(value="AES-256-GCM")],
                            [t(value=accuracy.TRUTH_CONFLICT)])["algorithm"]
    assert (counts.fp, counts.fn) == (1, 1)


def test_values_are_compared_without_case_or_padding():
    assert accuracy.score([p(value=" aes-256-gcm ")], [t()])["algorithm"].tp == 1


# --------------------------------------------------------------------------- #
# evidence attribution
# --------------------------------------------------------------------------- #

def test_attribution_accepts_any_real_evidence_for_this_item():
    truth = t(dimension="evidence_attribution", attribute="evidence",
              value=("EVID-v1-a", "EVID-v1-b"))
    counts = accuracy.score([p(dimension="evidence_attribution", attribute="evidence",
                               value="EVID-v1-a,EVID-v1-b")], [truth])["evidence_attribution"]
    assert counts.tp == 1


def test_attribution_rejects_a_fabricated_evidence_id():
    truth = t(dimension="evidence_attribution", attribute="evidence", value=("EVID-v1-a",))
    counts = accuracy.score([p(dimension="evidence_attribution", attribute="evidence",
                               value="EVID-v1-fabricated")], [truth])["evidence_attribution"]
    assert (counts.fp, counts.fn) == (1, 1)


# --------------------------------------------------------------------------- #
# the gate
# --------------------------------------------------------------------------- #

def _perfect(dimension: str = "algorithm", count: int = 10):
    return ([p(subject=str(index), dimension=dimension) for index in range(count)],
            [t(subject=str(index), dimension=dimension) for index in range(count)])


def test_a_dimension_with_no_truth_items_fails_as_not_measured():
    predictions, truths = _perfect()
    result = accuracy.evaluate(predictions, truths)
    assert result["ok"] is False
    assert any(failure["observed"] is None for failure in result["failures"])


def test_ceiling_targets_are_read_in_the_other_direction():
    predictions = [p(subject="a", value="AES-128-GCM")]
    truths = [t(subject="a", value="AES-256-GCM")]
    result = accuracy.evaluate(predictions, truths,
                               targets={"false_positive_rate": 0.5},
                               min_answered=0.0, max_unresolved=1.0)
    assert [failure["metric"] for failure in result["failures"]] == ["false_positive_rate"]


def test_every_measured_metric_carries_the_counts_and_the_rules():
    result = accuracy.evaluate(*_perfect())
    for summary in result["dimensions"].values():
        assert "counts" in summary and "rules" in summary
        assert summary["rules"]["unknown"]


def test_the_gate_reports_the_numbers_it_used():
    result = accuracy.evaluate(*_perfect())
    assert result["schema"] == accuracy.SCHEMA
    assert result["thresholds"] == {"min_answered": accuracy.MIN_ANSWERED,
                                    "max_unresolved": accuracy.MAX_UNRESOLVED}
    assert result["totals"]["tp"] == 10


# --------------------------------------------------------------------------- #
# regression
# --------------------------------------------------------------------------- #

def test_a_metric_that_dropped_beyond_tolerance_blocks_the_release():
    baseline = {"measured": {"algorithm_precision": 0.971, "false_positive_rate": 0.026},
                "generated_at": "2026-11-01T00:00:00Z"}
    current = {"measured": {"algorithm_precision": 0.948, "false_positive_rate": 0.026}}
    verdict = accuracy.compare(baseline, current, tolerance=0.005)
    assert verdict["ok"] is False
    assert verdict["regressions"][0]["metric"] == "algorithm_precision"
    assert verdict["regressions"][0]["delta"] == pytest.approx(-0.023)


def test_a_ceiling_that_went_up_also_regresses():
    baseline = {"measured": {"false_positive_rate": 0.02}}
    current = {"measured": {"false_positive_rate": 0.09}}
    assert accuracy.compare(baseline, current)["ok"] is False


def test_noise_inside_the_tolerance_is_not_a_regression():
    baseline = {"measured": {"algorithm_precision": 0.960}}
    current = {"measured": {"algorithm_precision": 0.958}}
    assert accuracy.compare(baseline, current, tolerance=0.005)["ok"] is True


def test_a_metric_that_stopped_being_measured_is_a_regression():
    verdict = accuracy.compare({"measured": {"key_size_accuracy": 0.99}}, {"measured": {}})
    assert verdict["ok"] is False
    assert "not measured" in verdict["regressions"][0]["why"]


# --------------------------------------------------------------------------- #
# the dashboard
# --------------------------------------------------------------------------- #

def test_the_dashboard_says_which_metrics_failed_and_why():
    predictions, truths = _perfect()
    rendered = accuracy.dashboard(accuracy.evaluate(predictions, truths))
    assert "| Metric | Target | Measured | Verdict |" in rendered
    assert "NOT MEASURED" in rendered
    assert "UNKNOWN is not counted as wrong" in rendered
    assert "**FAIL**" in rendered


def test_a_passing_dashboard_says_so_once():
    result = {"schema": accuracy.SCHEMA, "generated_at": "2026-11-04T00:00:00Z",
              "ok": True, "failures": [], "targets": {"algorithm_precision": 0.95},
              "measured": {"algorithm_precision": 1.0},
              "thresholds": {"min_answered": 0.8, "max_unresolved": 0.25},
              "dimensions": {"algorithm": {"precision": 1.0, "recall": 1.0, "accuracy": 1.0,
                                           "answered": 1.0, "unresolved_rate": 0.0,
                                           "counts": {"tp": 1, "fp": 0, "tn": 0, "fn": 0}}}}
    rendered = accuracy.dashboard(result)
    assert rendered.count("**PASS**") == 1


# --------------------------------------------------------------------------- #
# the contract of the types themselves
# --------------------------------------------------------------------------- #

def test_an_unknown_dimension_is_refused_at_the_boundary():
    with pytest.raises(ValueError, match="unknown dimension"):
        Truth(dimension="vibes", subject="a", attribute="b", value=1)
