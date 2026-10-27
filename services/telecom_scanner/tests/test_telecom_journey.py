"""PQC adoption journey — coalescing, transitions, honest adoption math.

The journey turns per-pass drift detection into the trend answer: eras of
readiness per NF (consecutive same-verdict passes coalesce into one era),
flip transitions, and adoption over tracked NFs only. This pins the pure
engine the API and the monitor mirror share.
"""

from __future__ import annotations

from telecom_scanner.journey import pqc_adoption, update_journey


def _row(nf, ready, **extra):
    return {"nf_id": nf, "pqc_ready": ready, **extra}


def test_first_pass_opens_era_and_same_verdict_coalesces():
    j = update_journey(None, "2026-09-13T06:00:00+00:00", [_row("gw-za-01", False)])
    assert j["eras"]["gw-za-01"] == [
        {"from": "2026-09-13T06:00:00+00:00", "until": "2026-09-13T06:00:00+00:00",
         "pqc_ready": False, "passes": 1}]

    # two more passes with the SAME verdict: one era, passes grow, window moves
    j = update_journey(j, "2026-09-13T07:00:00+00:00", [_row("gw-za-01", False)])
    j = update_journey(j, "2026-09-13T08:00:00+00:00", [_row("gw-za-01", False)])
    assert len(j["eras"]["gw-za-01"]) == 1
    assert j["eras"]["gw-za-01"][0]["passes"] == 3
    assert j["eras"]["gw-za-01"][0]["until"] == "2026-09-13T08:00:00+00:00"

    adoption = pqc_adoption(j)
    assert adoption["nf_tracked"] == 1
    assert adoption["pqc_ready_now"] == 0
    assert adoption["adoption_pct"] == 0.0
    assert adoption["transitions"] == 0


def test_flip_opens_new_era_and_counts_transition():
    j = update_journey(None, "2026-09-13T06:00:00+00:00", [_row("sepp-01", False)])
    j = update_journey(j, "2026-09-13T07:00:00+00:00", [_row("sepp-01", True)])
    j = update_journey(j, "2026-09-13T08:00:00+00:00", [_row("sepp-01", True)])
    eras = j["eras"]["sepp-01"]
    assert [(e["pqc_ready"], e["passes"]) for e in eras] == [(False, 1), (True, 2)]

    adoption = pqc_adoption(j)
    assert adoption["pqc_ready_now"] == 1
    assert adoption["adoption_pct"] == 100.0
    assert adoption["transitions"] == 1
    per_nf = adoption["per_nf"]["sepp-01"]
    assert per_nf["since"] == "2026-09-13T07:00:00+00:00"  # ready SINCE the flip
    assert per_nf["flips"] == 1


def test_adoption_is_over_tracked_nfs_and_honest_when_empty():
    j = update_journey(None, "2026-09-13T06:00:00+00:00",
                       [_row("a", True), _row("b", False), _row("c", True)])
    adoption = pqc_adoption(j)
    assert adoption["nf_tracked"] == 3
    assert adoption["pqc_ready_now"] == 2
    assert adoption["adoption_pct"] == 66.7

    # nothing probed yet: None, never a fabricated percent
    empty = pqc_adoption(None)
    assert empty["nf_tracked"] == 0 and empty["adoption_pct"] is None


def test_rows_without_pqc_ready_fall_back_to_pqc_kex():
    # the mirror contract: pqc_ready may be absent -> derive from pqc_kex
    j = update_journey(None, "2026-09-13T06:00:00+00:00",
                       [{"nf_id": "x", "pqc_kex": ["x25519mlkem768"]}])
    assert j["eras"]["x"][0]["pqc_ready"] is True
    j = update_journey(j, "2026-09-13T07:00:00+00:00", [{"nf_id": "x", "pqc_kex": []}])
    assert len(j["eras"]["x"]) == 2 and j["eras"]["x"][1]["pqc_ready"] is False
