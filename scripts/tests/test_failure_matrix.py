"""G — the nine failure modes are proven by drills, and the report cannot lie.

The harness is the thing under test here: a failure matrix's only value is that
its verdicts mean something, so these tests check that the verdict is tied to a
real execution (a raising drill is UNPROVEN, a failing check is BROKEN), that
the nine modes cannot be quietly dropped, and that the endpoint refuses a report
that claims a proof it has no evidence for.
"""

from __future__ import annotations

import json

import pytest

from api.routers import failure_matrix as endpoint
from scripts import failure_matrix as harness


# ------------------------------------------------------------------ harness --- #
def test_the_matrix_is_exactly_the_nine_modes():
    assert [entry["mode"] for entry in harness.MODES] == list(endpoint.REQUIRED_MODES)
    assert len(harness.MODES) == 9
    assert set(harness.DRILLS) == set(endpoint.REQUIRED_MODES)


def test_every_mode_has_a_drill_rather_than_a_hand_written_verdict():
    for entry in harness.MODES:
        assert entry["mode"] in harness.DRILLS, f"{entry['mode']} has no drill"


@pytest.mark.parametrize("mode", ["api", "collector", "agent", "network", "certificate_expiry"])
def test_individual_drills_are_proven_and_record_evidence(mode):
    """A representative subset; the full nine run in the harness and in CI docs."""
    report = harness.measure([mode])
    assert report["modes"] == 1
    row = report["rows"][0]
    assert row["verdict"] == "PROVEN", f"{mode}: {row['reason']}"
    assert row["observations"], f"{mode} proved something without observing anything"
    assert row["behavior"]
    assert row["limit"], f"{mode} claims proof without stating what it did not establish"


def test_a_drill_that_cannot_run_is_unproven_not_passing(monkeypatch):
    def unavailable(_run):
        raise harness.Unavailable("no PostgreSQL on this host")

    monkeypatch.setitem(harness.DRILLS, "database", unavailable)
    report = harness.measure(["database"])
    row = report["rows"][0]
    assert row["verdict"] == "UNPROVEN"
    assert "no PostgreSQL" in row["reason"]
    assert report["proven"] == 0
    assert report["complete"] is False


def test_a_crashing_drill_is_unproven_not_broken(monkeypatch):
    """A drill bug is not a system defect; the two must not be confused."""

    def explodes(_run):
        raise KeyError("unexpected payload shape")

    monkeypatch.setitem(harness.DRILLS, "worker", explodes)
    report = harness.measure(["worker"])
    row = report["rows"][0]
    assert row["verdict"] == "UNPROVEN"
    assert "could not execute" in row["reason"]


def test_a_failing_check_is_broken_and_keeps_what_was_observed(monkeypatch):
    def fails(run):
        run.see(readiness_status=200)
        run.check(False, "readiness answered 200 during a database stall")

    monkeypatch.setitem(harness.DRILLS, "api", fails)
    report = harness.measure(["api"])
    row = report["rows"][0]
    assert row["verdict"] == "BROKEN"
    assert "readiness answered 200" in row["reason"]
    assert row["observations"]["readiness_status"] == 200


def test_measure_reports_the_documented_row_shape():
    report = harness.measure(["collector"])
    assert report["schema"] == harness.SCHEMA
    assert report["expected_modes"] == 9
    assert set(report["rows"][0]) == {
        "mode", "what_breaks", "expected", "verdict", "behavior", "observations", "reason", "limit",
    }
    rendered = harness.render_md(report)
    assert "| Mode | What breaks | Observed behaviour | Verdict |" in rendered
    assert "What this does not prove" in rendered


def test_render_md_marks_unproven_and_broken_rows_visibly():
    report = {
        "schema": harness.SCHEMA,
        "version": harness.VERSION,
        "generated_at": "2026-10-31T00:00:00+00:00",
        "modes": 2,
        "expected_modes": 9,
        "proven": 0,
        "broken": 1,
        "unproven": 1,
        "complete": False,
        "rows": [
            {"mode": "api", "what_breaks": "x", "expected": "", "verdict": "BROKEN",
             "behavior": "", "observations": {}, "reason": "answered 200", "limit": None},
            {"mode": "database", "what_breaks": "y", "expected": "", "verdict": "UNPROVEN",
             "behavior": "", "observations": {}, "reason": "no PostgreSQL", "limit": None},
        ],
    }
    rendered = harness.render_md(report)
    assert "**BROKEN**" in rendered and "**UNPROVEN**" in rendered
    assert "answered 200" in rendered and "no PostgreSQL" in rendered
    assert "do not read these as passes" in rendered


def test_cli_exit_code_reflects_the_proven_count(tmp_path, capsys):
    json_path = tmp_path / "matrix.json"
    md_path = tmp_path / "matrix.md"
    code = harness.main(["--only", "collector",
                         "--json", str(json_path), "--md", str(md_path), "--min-proven", "1"])
    assert code == 0
    written = json.loads(json_path.read_text())
    assert written["proven"] == 1
    assert "PROVEN" in md_path.read_text()
    assert harness.main(["--only", "collector", "--min-proven", "9"]) == 1


# ----------------------------------------------------------------- endpoint --- #
def _artifact(**overrides):
    rows = [
        {"mode": mode, "what_breaks": "x", "expected": "y", "verdict": "PROVEN",
         "behavior": "observed", "observations": {"k": 1}, "reason": None, "limit": "not a chaos run"}
        for mode in endpoint.REQUIRED_MODES
    ]
    document = {"schema": endpoint.SCHEMA, "generated_at": "2026-10-31T00:00:00+00:00",
                "proven": 9, "rows": rows}
    document.update(overrides)
    return document


def _write(tmp_path, document):
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(document))
    return path


def test_endpoint_serves_the_committed_artifact():
    matrix = endpoint.load()
    assert matrix.complete is True
    assert matrix.proven == 9 and matrix.broken == 0 and matrix.unproven == 0
    assert [row.mode for row in matrix.rows] == list(endpoint.REQUIRED_MODES)
    for row in matrix.rows:
        assert row.observations and row.behavior and row.limit


def test_endpoint_serves_a_complete_matrix(tmp_path):
    matrix = endpoint.load(_write(tmp_path, _artifact()))
    assert matrix.complete is True and matrix.proven == 9
    assert matrix.model_dump(by_alias=True)["schema"] == endpoint.SCHEMA


def test_endpoint_refuses_a_missing_artifact(tmp_path):
    with pytest.raises(FileNotFoundError, match="no failure matrix"):
        endpoint.load(tmp_path / "absent.json")


def test_endpoint_refuses_another_schema(tmp_path):
    with pytest.raises(ValueError, match="declares"):
        endpoint.load(_write(tmp_path, _artifact(schema="cryptoscan.failure-matrix/0")))


def test_endpoint_refuses_a_dropped_mode(tmp_path):
    document = _artifact()
    document["rows"] = [row for row in document["rows"] if row["mode"] != "queue"]
    document["proven"] = 8
    with pytest.raises(ValueError, match="missing.*queue"):
        endpoint.load(_write(tmp_path, document))


def test_endpoint_refuses_a_duplicated_mode(tmp_path):
    document = _artifact()
    document["rows"].append(dict(document["rows"][0]))
    with pytest.raises(ValueError, match="more than once"):
        endpoint.load(_write(tmp_path, document))


def test_endpoint_refuses_a_proven_row_with_no_executed_evidence(tmp_path):
    document = _artifact()
    document["rows"][4]["observations"] = {}
    with pytest.raises(ValueError, match="PROVEN with no observations"):
        endpoint.load(_write(tmp_path, document))


def test_endpoint_refuses_proven_with_no_observed_behaviour(tmp_path):
    document = _artifact()
    document["rows"][0]["behavior"] = ""
    with pytest.raises(ValueError, match="PROVEN with no observations"):
        endpoint.load(_write(tmp_path, document))


def test_endpoint_refuses_unproven_without_a_reason(tmp_path):
    document = _artifact()
    document["rows"][2].update({"verdict": "UNPROVEN", "observations": {}, "behavior": "",
                                "reason": None})
    document["proven"] = 8
    with pytest.raises(ValueError, match="UNPROVEN with no reason"):
        endpoint.load(_write(tmp_path, document))


def test_endpoint_refuses_a_count_that_does_not_match_the_rows(tmp_path):
    document = _artifact(proven=9)
    document["rows"][0]["verdict"] = "BROKEN"
    with pytest.raises(ValueError, match="but 8 rows are PROVEN"):
        endpoint.load(_write(tmp_path, document))


def test_endpoint_serves_a_broken_row_rather_than_hiding_it(tmp_path):
    """A failing mode must stay visible; a report of only greens is the failure."""
    document = _artifact()
    document["rows"][0].update({"verdict": "BROKEN", "behavior": "",
                                "observations": {"readiness_status": 200},
                                "reason": "readiness answered 200 during a database stall"})
    document["proven"] = 8
    matrix = endpoint.load(_write(tmp_path, document))
    assert matrix.broken == 1 and matrix.complete is False
    assert matrix.rows[0].reason


def test_route_returns_a_matrix_and_refuses_unusable_artifacts(tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_FAILURE_MATRIX", str(_write(tmp_path, _artifact())))
    served = endpoint.failure_matrix(user="auditor")
    assert served.proven == 9 and served.rows[0].mode == "api"

    monkeypatch.setenv("CRYPTOSCAN_FAILURE_MATRIX", str(tmp_path / "absent.json"))
    with pytest.raises(Exception) as missing:
        endpoint.failure_matrix(user="auditor")
    assert getattr(missing.value, "status_code", None) == 404
    assert missing.value.detail["error"] == "failure_matrix_missing"

    document = _artifact()
    document["rows"][0]["observations"] = {}
    monkeypatch.setenv("CRYPTOSCAN_FAILURE_MATRIX", str(_write(tmp_path, document)))
    with pytest.raises(Exception) as unusable:
        endpoint.failure_matrix(user="auditor")
    assert getattr(unusable.value, "status_code", None) == 409
    assert unusable.value.detail["error"] == "failure_matrix_unusable"
