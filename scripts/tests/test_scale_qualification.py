"""The bank-scale drill must measure, grade, and be able to fail.

The point of `scripts/scale_qualification.py` is that a verdict cannot be written
without executing the path. These tests run the small profile once, then check
that each row is graded against its stated criterion, that the numbers behind the
headline exist, and that lowering a threshold actually turns a PASS into a FAIL —
otherwise the verdicts are decoration.
"""

from __future__ import annotations

import json

import pytest

from scripts import scale_qualification as scale


@pytest.fixture(scope="module")
def report():
    return scale.measure("ci")


def _row(report, row_id):
    for row in report["rows"]:
        if row["id"] == row_id:
            return row
    raise AssertionError(f"row {row_id} missing from the report")


# ------------------------------------------------------------------- the cap --- #
def test_a_bank_scale_request_is_refused_at_the_model():
    """The 20,000-asset cap is the first thing a deployment meets; pin the boundary."""
    from pydantic import ValidationError

    from api.routers.estate_graph import EstateDiscoverRequest

    limit = 20_000
    assets, evidence = scale.estate_payload(limit)
    EstateDiscoverRequest(estate="bank", assets=assets, evidence=evidence)  # accepted

    assets, evidence = scale.estate_payload(limit + 1)
    with pytest.raises(ValidationError) as excinfo:
        EstateDiscoverRequest(estate="bank", assets=assets, evidence=evidence)
    assert "20000" in str(excinfo.value)


def test_the_ceiling_row_reports_the_cap_it_hit(report):
    row = _row(report, "ingest_ceiling")
    assert row["measured"]["accepted"] is False
    assert any("20000" in error for error in row["measured"]["validation_errors"])
    assert row["criterion"].startswith("assets list length")
    assert row["verdict"] in {scale.PASS, scale.FAIL}


# --------------------------------------------------------------- the measures --- #
def test_throughput_row_carries_every_measured_point(report):
    row = _row(report, "ingest_throughput")
    points = row["measured"]["points"]
    assert [point["assets"] for point in points] == list(scale.PROFILES["ci"]["ladder"])
    for point in points:
        assert point["seconds"] > 0
        assert point["assets_per_second"] > 0
        assert point["database_mb"] > 0
    assert row["measured"]["projected_100k_seconds"] > 0
    assert "projection" in row["note"]


def test_read_paths_measure_every_read_at_the_seeded_size(report):
    row = _row(report, "read_paths")
    reads = row["measured"]["reads"]
    assert set(reads) == {
        "catalog_page", "asset_detail", "history", "why", "evidence_for",
        "catalog_summary", "observation_summary",
    }
    for name, values in reads.items():
        assert values["p95_ms"] >= values["p50_ms"] or values["p95_ms"] == 0, name
        assert values["max_ms"] >= values["p50_ms"], name
    assert row["measured"]["seed"]["assets"] == scale.PROFILES["ci"]["storage_assets"]
    assert row["measured"]["seed"]["facts"] > 0
    worst = max(reads.values(), key=lambda value: value["p95_ms"])
    expected = scale.PASS if worst["p95_ms"] <= scale.THRESHOLDS["read_p95_ms"] else scale.FAIL
    assert row["verdict"] == expected


def test_the_composite_index_is_measured_both_ways(report):
    """The row must show the index's effect, not claim it.

    The drill reports which way the gap fell instead of asserting it: on a small
    database SQLite finds a usable plan without the composite index, and only at
    scale does the tenant index become the access path. A hard assertion here
    would encode one machine's planner.
    """
    effect = _row(report, "read_paths")["measured"]["index_effect"]
    assert effect["with_index"]["history_ms_p50"] > 0
    assert effect["without_index"]["history_ms_p50"] > 0
    gap = effect["without_index"]["history_ms_p50"] - effect["with_index"]["history_ms_p50"]
    expected = "with_index" if gap > 0 else "without_index" if gap < 0 else "same"
    assert effect["faster"] == expected


def test_continuous_ingest_proves_one_row_per_changed_fact(report):
    row = _row(report, "continuous_ingest")
    measured = row["measured"]
    assert measured["rows_added_per_round"] == [measured["batch_assets"]] * (
        len(measured["rounds"]) - 1)
    assert measured["current_rows_flat"] is True
    assert row["verdict"] in {scale.PASS, scale.FAIL}


def test_sharding_reports_the_true_row_counts(report):
    """Two declared slices accumulate; the undeclared control still retires."""
    row = _row(report, "sharding")
    measured = row["measured"]
    after = measured["after_two_slices"]
    control = measured["control_undeclared_slice"]
    assert after["stale_rows"] == 0, after
    assert after["active_rows"] >= 2 * measured["slice_assets"], after
    assert control["stale_rows"] > 0, "the flag must be load-bearing, not decoration"
    assert row["verdict"] == scale.PASS
    assert "STALE" in row["criterion"]


def test_bom_projection_at_bank_scale_is_unproven_not_passed(report):
    row = _row(report, "bom_projection_at_scale")
    assert row["verdict"] == scale.UNPROVEN
    assert "request cap" in row["note"] or "ceiling" in row["note"]


def test_the_report_states_its_own_limits(report):
    assert report["limits"]
    assert any("SQLite" in limit for limit in report["limits"])
    assert any("concurrent" in limit for limit in report["limits"])
    assert report["counts"][scale.PASS] + report["counts"][scale.FAIL] + \
        report["counts"][scale.UNPROVEN] == len(report["rows"])


def test_the_drill_names_a_defect_it_found(report):
    """The change-feed contradiction is part of the measurement, not a surprise later."""
    defects = report.get("defects") or []
    assert any(defect["id"] == "change-verdict-contradicts-its-own-claims" for defect in defects)
    assert all(defect["detail"] and defect["affects"] for defect in defects)


# --------------------------------------------------------------- falsification --- #
def test_lowering_the_read_budget_turns_the_row_red(monkeypatch):
    """A verdict that cannot move with its threshold is not a measurement."""
    monkeypatch.setitem(scale.THRESHOLDS, "read_p95_ms", 0.001)
    row, _ = scale.read_paths(200, 3, 2)
    assert row.verdict == scale.FAIL
    assert "p95" in row.criterion


def test_raising_the_growth_budget_does_not_rescue_a_bad_measurement(monkeypatch):
    """The continuous row also checks row growth, so a loose time budget is not enough."""
    monkeypatch.setitem(scale.THRESHOLDS, "continuous_growth_factor", 1_000.0)
    monkeypatch.setattr(scale, "PROFILES", {**scale.PROFILES, "tiny": {
        **scale.PROFILES["ci"], "continuous_batches": 2, "continuous_batch_assets": 100}})
    row = scale.continuous_ingest(2, 100).as_dict()
    measured = row["measured"]
    assert measured["rows_added_per_round"] == [100]
    assert measured["current_rows_flat"] is True
    assert row["verdict"] == scale.PASS


def test_markdown_artifact_states_the_limits():
    path = scale.REPO_ROOT / "docs" / "bank-environment" / "114-scale-qualification.md"
    if not path.exists():  # pragma: no cover - regenerated by the script
        pytest.skip("artifact not generated in this checkout")
    text = path.read_text(encoding="utf-8")
    assert "What this does not prove" in text
    assert "SQLite" in text
    assert "memory guard" in text


def test_json_artifact_matches_the_drill():
    path = scale.REPO_ROOT / "docs" / "bank-environment" / "114-scale-qualification.json"
    if not path.exists():  # pragma: no cover
        pytest.skip("artifact not generated in this checkout")
    artifact = json.loads(path.read_text(encoding="utf-8"))
    assert artifact["schema"] == scale.SCHEMA
    assert {row["id"] for row in artifact["rows"]} == {
        "ingest_ceiling", "ingest_throughput", "read_paths", "continuous_ingest",
        "sharding", "bom_projection_at_scale",
    }
