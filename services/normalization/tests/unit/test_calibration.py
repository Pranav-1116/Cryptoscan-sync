"""Detector calibration scorecards (audit 49 P0#4, round 28).

Pure counting over views + conflicts: retraction rates, decisive
authority losses, tier thresholds, thin-data honesty, and the
annotate-never-override contract.
"""

from __future__ import annotations

from normalization.calibration import (
    MIN_OBSERVATIONS,
    UNATTRIBUTED,
    detector_key,
    detector_scorecards,
)


def _view(detector: str, *, deleted: bool = False, **extra) -> dict:
    return {
        "algorithm": "RSA",
        "key_size": 2048,
        "file_path": "a.java",
        "line_number": 1,
        "compliance_status": "PASS",
        "scanner_ids": [detector],
        "deleted": deleted,
        **extra,
    }


def _card(result: dict, detector: str) -> dict:
    return next(c for c in result["detectors"] if c["detector"] == detector)


def test_detector_key_resolution_order():
    assert detector_key(_view("java-scanner")) == "java-scanner"
    assert detector_key({"scanner_ids": []}) == UNATTRIBUTED
    # provenance fallback
    assert detector_key({"provenance": {"scanner_ids": ["ot-probe"]}}) == "ot-probe"
    assert detector_key({"provenance": {"scanner_id": "network-scanner"}}) == "network-scanner"
    # finding source fallback
    assert detector_key({"finding_data": {"source": {"scanner_id": "binary-scanner"}}}) == \
        "binary-scanner"
    # nothing -> honestly unattributed
    assert detector_key({}) == UNATTRIBUTED


def test_retraction_rate_drives_the_tier():
    # 25 observations, 1 retracted (4%) -> CALIBRATED
    views = [_view("good")] * 24 + [_view("good", deleted=True)]
    result = detector_scorecards(views, [])
    card = _card(result, "good")
    assert card["observations"] == 25
    assert card["retracted"] == 1
    assert card["retraction_rate"] == 0.04
    assert card["calibration_tier"] == "CALIBRATED"
    assert card["reliability_multiplier"] == 1.0

    # 5 of 25 retracted (20%) -> DEGRADED
    views = [_view("bad")] * 20 + [_view("bad", deleted=True)] * 5
    card = _card(detector_scorecards(views, []), "bad")
    assert card["calibration_tier"] == "DEGRADED"
    assert card["reliability_multiplier"] == 0.7


def test_thin_data_is_insufficient_not_scored():
    views = [_view("sparse", deleted=True)] * 5  # 100% retraction, but n=5
    card = _card(detector_scorecards(views, []), "sparse")
    assert card["calibration_tier"] == "INSUFFICIENT_DATA"
    assert card["reliability_multiplier"] is None
    assert MIN_OBSERVATIONS == 20


def test_decisive_authority_losses_count_against_the_loser():
    views = ([_view("runtime-probe")] * 20 + [_view("regex-scanner")] * 20)
    conflicts = [{
        "conflict_type": "PARAMETER_MISMATCH",
        "observers": ["runtime-probe", "regex-scanner"],
        "authority": {
            "decisive": True,
            "preferred": [{"observer": "runtime-probe", "tier": 1, "label": "RUNTIME"}],
        },
    }]
    result = detector_scorecards(views, conflicts)
    winner = _card(result, "runtime-probe")
    loser = _card(result, "regex-scanner")
    assert winner["authority_losses"] == 0
    assert loser["authority_losses"] == 1
    # the loss share is against the detector's 20 observations, not its
    # single conflict — one disagreement is not a pattern
    assert loser["authority_loss_rate"] == 0.05
    assert loser["calibration_tier"] == "CALIBRATED"
    assert winner["calibration_tier"] == "CALIBRATED"


def test_repeated_authority_losses_degrade_the_tier():
    # 20 observations, 6 of them on the losing side of decisive
    # conflicts -> 30% loss share -> DEGRADED
    views = [_view("regex-scanner")] * 20 + [_view("runtime-probe")] * 20
    conflicts = [{
        "conflict_type": "PARAMETER_MISMATCH",
        "observers": ["runtime-probe", "regex-scanner"],
        "authority": {
            "decisive": True,
            "preferred": [{"observer": "runtime-probe", "tier": 1, "label": "RUNTIME"}],
        },
    } for _ in range(6)]
    result = detector_scorecards(views, conflicts)
    loser = _card(result, "regex-scanner")
    assert loser["authority_losses"] == 6
    assert loser["authority_loss_rate"] == 0.3
    assert loser["calibration_tier"] == "DEGRADED"
    assert loser["reliability_multiplier"] == 0.7


def test_tied_conflicts_are_not_detector_failures():
    # a tie at the highest tier is a human/policy decision: involved,
    # yes; lost, no
    views = [_view("probe-a")] * 20 + [_view("probe-b")] * 20
    conflicts = [{
        "conflict_type": "ALGORITHM_MISMATCH",
        "observers": ["probe-a", "probe-b"],
        "authority": {"decisive": False, "preferred": []},
    }]
    result = detector_scorecards(views, conflicts)
    for name in ("probe-a", "probe-b"):
        card = _card(result, name)
        assert card["conflicts_involved"] == 1
        assert card["authority_losses"] == 0
        assert card["calibration_tier"] == "CALIBRATED"

def test_unattributed_evidence_is_surfaced_not_hidden():
    views = [{"algorithm": "RSA", "file_path": "x", "line_number": 1}] * 3
    result = detector_scorecards(views, [])
    card = _card(result, UNATTRIBUTED)
    assert card["observations"] == 3
    assert card["calibration_tier"] == "INSUFFICIENT_DATA"


def test_method_block_documents_the_proxies_and_contract():
    result = detector_scorecards([_view("d")] * 20, [])
    method = result["method"]
    assert "operator judgment" in method["retraction"]
    assert "not proven error" in method["authority_loss"]
    assert "never" in method["contract"]
    assert method["thresholds"]["min_observations"] == 20
    assert result["tier_counts"] == {"CALIBRATED": 1}


def test_empty_inputs():
    result = detector_scorecards([], [])
    assert result["detectors"] == []
    assert result["detector_count"] == 0
    assert result["tier_counts"] == {}
