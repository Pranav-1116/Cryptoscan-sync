"""The job/worker contract matrix: nine properties, each tied to a real run.

As with the failure matrix, the value here is that a verdict cannot be produced
without executing something. These tests check that binding, that the nine
properties are the nine the code claims, and that the honest limits are carried
in the artifact rather than in someone's memory.
"""

from __future__ import annotations

import json

import pytest

from scripts import job_contract_matrix as contract


EXPECTED = {
    "job_queue": "job queue",
    "worker": "worker",
    "retry": "retry",
    "timeout": "timeout",
    "cancellation": "cancellation",
    "idempotency": "idempotency",
    "dead_letter": "dead-letter",
    "recovery": "recovery",
    "concurrency": "controlled concurrency",
}


def test_the_nine_properties_are_the_nine_the_brief_names():
    items = [entry["item"] for entry in contract.PROPERTIES]
    assert items == list(EXPECTED)
    assert len(items) == 9
    assert set(contract.DRILLS) == set(items)


def test_the_committed_artifact_is_complete_and_carries_its_limits():
    report = json.loads((contract.Path(__file__).resolve().parents[2] / "docs" /
                         "bank-environment" / "111-job-contract.json").read_text())
    assert report["schema"] == contract.SCHEMA
    assert report["properties"] == 9 and report["expected_properties"] == 9
    assert report["complete"] is True
    assert report["proven"] == 9 and report["broken"] == 0 and report["unproven"] == 0
    for row in report["rows"]:
        assert row["verdict"] == "PROVEN"
        assert row["observations"], f"{row['item']} claims proof with no observations"
        assert row["behavior"], f"{row['item']} claims proof with no observed behaviour"
        assert row["limit"], f"{row['item']} claims proof without stating what it did not establish"


@pytest.mark.parametrize("item", ["job_queue", "idempotency", "dead_letter", "concurrency"])
def test_representative_drills_prove_their_property(item):
    report = contract.measure([item])
    row = report["rows"][0]
    assert row["verdict"] == "PROVEN", f"{item}: {row['reason']}"
    assert row["observations"]


def test_a_drill_that_cannot_run_is_unproven_not_passing(monkeypatch):
    def unavailable(_run):
        raise contract.Unavailable("no Redis client here")

    monkeypatch.setitem(contract.DRILLS, "job_queue", unavailable)
    report = contract.measure(["job_queue"])
    assert report["rows"][0]["verdict"] == "UNPROVEN"
    assert "no Redis" in report["rows"][0]["reason"]
    assert report["complete"] is False


def test_a_crashing_drill_is_unproven_not_broken(monkeypatch):
    def explodes(_run):
        raise KeyError("unexpected queue payload")

    monkeypatch.setitem(contract.DRILLS, "worker", explodes)
    report = contract.measure(["worker"])
    row = report["rows"][0]
    assert row["verdict"] == "UNPROVEN"
    assert "could not execute" in row["reason"]


def test_a_failing_check_is_broken_and_keeps_what_was_observed(monkeypatch):
    def fails(run):
        run.see(second_pop="q1")
        run.check(False, "the same job was delivered twice")

    monkeypatch.setitem(contract.DRILLS, "job_queue", fails)
    report = contract.measure(["job_queue"])
    row = report["rows"][0]
    assert row["verdict"] == "BROKEN"
    assert "delivered twice" in row["reason"]
    assert row["observations"]["second_pop"] == "q1"


def test_the_retry_row_says_what_it_does_not_cover():
    """A handler failure is not retried; the report must say so, not imply it."""
    report = contract.measure(["retry", "worker"])
    by_item = {row["item"]: row for row in report["rows"]}
    assert "not retry-after-failure" in by_item["retry"]["limit"]
    assert "ack-and-move-on" in by_item["worker"]["limit"]


def test_render_md_marks_every_verdict_visibly():
    report = contract.measure(["job_queue"])
    report["rows"][0]["verdict"] = "BROKEN"
    report["rows"][0]["reason"] = "the same job was delivered twice"
    rendered = contract.render_md(report)
    assert "**BROKEN**" in rendered
    assert "the same job was delivered twice" in rendered
    assert "What this does not prove" in rendered


def test_cli_exit_code_reflects_the_proven_count(tmp_path):
    json_path = tmp_path / "contract.json"
    md_path = tmp_path / "contract.md"
    assert contract.main(["--only", "job_queue", "--json", str(json_path), "--md", str(md_path),
                          "--min-proven", "1"]) == 0
    written = json.loads(json_path.read_text())
    assert written["proven"] == 1 and written["expected_properties"] == 9
    assert "PROVEN" in md_path.read_text()
    assert contract.main(["--only", "job_queue", "--min-proven", "9"]) == 1
