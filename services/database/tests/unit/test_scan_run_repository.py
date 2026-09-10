"""Network scan run persistence: create, list, latest-two for drift."""

from __future__ import annotations

import time

from db.models.network_scan_run import NetworkScanRun  # noqa: F401 — register table
from db.repositories.scan_run_repository import ScanRunRepository


def _result(scan_id, probed=2, ok=2, verdict="OK", findings=None):
    return {
        "scan_id": scan_id,
        "target_kind": "hosts",
        "findings": findings or [],
        "certificates": [],
        "probe_telemetry": {"status": verdict, "probed": probed, "ok": ok, "statuses": {"OK": ok}},
    }


def test_create_run_extracts_telemetry(db_session):
    repo = ScanRunRepository(db_session)
    row = repo.create_run(_result("run-1", probed=5, ok=3, verdict="PARTIAL"))
    assert row.scan_id == "run-1"
    assert row.target_kind == "hosts"
    assert row.verdict == "PARTIAL"
    assert row.probed == 5 and row.ok == 3
    assert row.result["probe_telemetry"]["probed"] == 5
    assert row.id and row.created_at is not None


def test_get_and_list_runs_newest_first(db_session):
    repo = ScanRunRepository(db_session)
    first = repo.create_run(_result("older"))
    time.sleep(0.01)
    _second = repo.create_run(_result("newer"))
    assert repo.get_run(first.id).scan_id == "older"
    listed = repo.list_runs(limit=10)
    assert [row.scan_id for row in listed] == ["newer", "older"]
    assert repo.count_runs() == 2


def test_list_runs_filters_target_kind(db_session):
    repo = ScanRunRepository(db_session)
    repo.create_run(_result("a"), target_kind="hosts")
    repo.create_run(_result("b"), target_kind="ssh-hosts")
    assert [row.scan_id for row in repo.list_runs(target_kind="ssh-hosts")] == ["b"]
    assert repo.count_runs(target_kind="hosts") == 1


def test_latest_two_feed_drift(db_session):
    repo = ScanRunRepository(db_session)
    repo.create_run(_result("oldest"))
    time.sleep(0.01)
    repo.create_run(_result("middle"))
    time.sleep(0.01)
    repo.create_run(_result("newest"))
    latest = repo.latest_runs(count=2)
    assert [row.scan_id for row in latest] == ["newest", "middle"]


def test_latest_runs_when_fewer_than_count(db_session):
    repo = ScanRunRepository(db_session)
    assert repo.latest_runs() == []
    repo.create_run(_result("only"))
    assert [row.scan_id for row in repo.latest_runs()] == ["only"]


def test_create_run_tolerates_minimal_result(db_session):
    repo = ScanRunRepository(db_session)
    row = repo.create_run({})
    assert row.verdict is None and row.probed is None
    assert row.target_kind == "hosts"
