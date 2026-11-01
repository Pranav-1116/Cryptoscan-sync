"""Guide 117's artifact, pinned — including the three controls it added.

The claim is a number (ten surfaces, every one answering) and a shape (three of
those answers are executions, not reads). Both live in
``docs/bank-environment/117-observability-coverage.json``, so they are checked
here without re-running the drill: a row that regresses to PARTIAL, an evidence
kind that softens from EXECUTED to READ, or an artifact that stops naming the
worker probe and the pager path fails the build.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "docs" / "bank-environment" / "117-observability-coverage.json"
MARKDOWN = ROOT / "docs" / "bank-environment" / "117-observability-coverage.md"

#: Every surface the report grades, in order. A surface that disappears is a
#: regression even though the counts would still look healthy.
SURFACES = (
    "collector_metrics", "queue_metrics", "database_metrics", "evidence_metrics",
    "agent_metrics", "coverage_metrics", "health_surfaces", "traces", "logs",
    "alert_rules",
)

#: Surfaces that must be *driven*, not read: a citation cannot show that a probe
#: answers, an exporter exports or a pager is told anything.
MUST_BE_EXECUTED = ("health_surfaces", "traces", "alert_rules")


@pytest.fixture(scope="module")
def report() -> dict:
    if not ARTIFACT.exists():  # pragma: no cover - the artifact ships with the repo
        pytest.skip("the guide 117 artifact has not been generated")
    return json.loads(ARTIFACT.read_text(encoding="utf-8"))


def rows(report: dict) -> dict[str, dict]:
    return {row["id"]: row for row in report["rows"]}


def test_every_surface_is_graded_and_none_fails(report):
    assert tuple(row["id"] for row in report["rows"]) == SURFACES
    assert report["counts"]["FAIL"] == 0
    assert report["counts"]["PASS"] == len(SURFACES)
    assert report["metrics"]["status_code"] == 200
    assert report["metrics"]["series"] > 0


def test_the_three_new_controls_are_executed_with_their_evidence(report):
    graded = rows(report)
    for surface in MUST_BE_EXECUTED:
        assert graded[surface]["evidence_kind"] == "EXECUTED", surface
        assert graded[surface]["verdict"] == "PASS", surface

    probes = graded["health_surfaces"]["found"]
    assert probes["worker_probe_q"]["status_code"] == 503
    assert probes["worker_probe_draining"]["status_code"] == 200
    assert probes["liveness"]["status_code"] == 200
    assert probes["distinguishes"] is True

    exported = graded["traces"]["found"]["otlp_export"]
    assert exported["notifications"] >= 1
    assert exported["trace_id_matches"] is True
    assert exported["span_id_matches"] is True
    assert exported["timings_present"] is True
    assert exported["unconfigured_store_spawns_exporter"] is False

    pager = graded["alert_rules"]["found"]["pager_path"]
    assert pager["post_status"] == 200
    assert pager["accepted"] == 1
    assert pager["counted_in_metrics"] is True
    assert pager["unrouted_sub_routes"] == []
    assert pager["alertmanager_config"].endswith("alertmanager.yml")


def test_the_alert_receiver_is_a_real_receiver_and_a_real_rule(report):
    graded = rows(report)
    pager = graded["alert_rules"]["found"]["pager_path"]
    # the notification is built from a rule in alerts.yml, not a made-up name
    names = {rule["name"] for rule in report["rules"] if rule["name"]}
    assert pager["paging_rule_used"]["alertname"] in names
    assert pager["paging_rule_used"]["severity"] == "critical"
    # and the metric it produced is in the family list the endpoint emits
    assert "cryptoscan_alertmanager_notifications_total" in report["metrics"]["names"]
    # a malformed notification is refused rather than silently counted
    assert pager["malformed_notification_status"] == 422


def test_the_markdown_headline_matches_the_json(report):
    text = MARKDOWN.read_text(encoding="utf-8")
    counts = report["counts"]
    assert (f"{counts['PASS']} pass · {counts['PARTIAL']} partial · "
            f"{counts['FAIL']} fail") in text
    for surface in SURFACES:
        assert f"### `{surface}`" in text, surface
    # the stale sentence the previous pass shipped must not come back
    assert "There is no tracing" not in text
