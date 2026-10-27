"""Condition-level verification of resolved drift events (§4.7, round 40).

RESOLVED is administrative; these verdicts come from a later scan's
evidence. A vanished path is UNCOVERED — never a pass. No signature
means NOT_CHECKABLE — never a guess.
"""

from __future__ import annotations

from drift.core.verification import (
    CONDITION_PRESENT,
    NOT_CHECKABLE,
    UNCOVERED,
    VERIFIED,
    evaluate_condition_verification,
)


def _event(drift_id="d1", algorithm="RSA", file_path="src/k.py", key_size=1024):
    current = {"algorithm": algorithm, "file_path": file_path, "key_size": key_size}
    if algorithm is None and file_path is None:
        current = None
    return {"drift_id": drift_id, "drift_details": {"current_finding": current}}


def _row(algorithm, file_path, key_size=None):
    return {"algorithm": algorithm, "file_path": file_path, "key_size": key_size}


def test_condition_present_when_rescan_still_matches():
    verdicts = evaluate_condition_verification(
        [_event()],
        [_row("RSA", "src/k.py", 1024), _row("AES", "src/other.py", 256)],
    )
    assert verdicts == [{
        "drift_id": "d1", "verification_status": CONDITION_PRESENT,
        "reason": "condition signature still present in the rescan's evidence",
    }]


def test_verified_when_file_observed_and_condition_gone():
    verdicts = evaluate_condition_verification(
        [_event(key_size=1024)],
        [_row("RSA", "src/k.py", 4096), _row("RSA", "src/k.py", 2048)],
    )
    assert verdicts[0]["verification_status"] == VERIFIED
    assert "file observed (2 evidence records)" in verdicts[0]["reason"]


def test_vanished_path_is_uncovered_never_a_pass():
    verdicts = evaluate_condition_verification(
        [_event()], [_row("RSA", "src/different.py", 2048)],
    )
    assert verdicts[0]["verification_status"] == UNCOVERED
    assert "not proof of remediation" in verdicts[0]["reason"]


def test_no_signature_is_not_checkable():
    verdicts = evaluate_condition_verification(
        [_event(algorithm=None, file_path=None)], [_row("RSA", "src/k.py")],
    )
    assert verdicts[0]["verification_status"] == NOT_CHECKABLE


def test_key_size_distinguishes_changed_conditions():
    # a CHANGED drift (RSA-1024 -> RSA-4096): the condition is the 4096 state
    verdicts = evaluate_condition_verification(
        [_event(key_size=4096)], [_row("RSA", "src/k.py", 1024)],
    )
    assert verdicts[0]["verification_status"] == VERIFIED

    # the same file still carrying the drifted-to size is present
    verdicts = evaluate_condition_verification(
        [_event(key_size=4096)], [_row("RSA", "src/k.py", 4096)],
    )
    assert verdicts[0]["verification_status"] == CONDITION_PRESENT


def test_missing_key_size_matches_algorithm_and_path_only():
    verdicts = evaluate_condition_verification(
        [_event(key_size=None)], [_row("RSA", "src/k.py", 1024)],
    )
    assert verdicts[0]["verification_status"] == CONDITION_PRESENT
