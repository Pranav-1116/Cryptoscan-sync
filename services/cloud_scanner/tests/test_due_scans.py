"""Continuous-monitoring planner: due re-scans (never / stale / fresh)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cloud_scanner.estate import plan_due_scans


def _now():
    return datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)


def _system(sid, target, last_scanned=None, **extra):
    return {"id": sid, "name": sid, "scan_target": target, "scan_branch": "main",
            "last_scanned_at": last_scanned, **extra}


def test_never_scanned_first_then_stalest():
    now = _now()
    systems = [
        _system("fresh", "https://git/bank/fresh.git", now - timedelta(days=1)),
        _system("stale-3d", "https://git/bank/s3.git", now - timedelta(days=3)),
        _system("stale-10d", "https://git/bank/s10.git", now - timedelta(days=10)),
        _system("never", "https://git/bank/new.git", None),
    ]
    plan = plan_due_scans(systems, interval_days=2, now=now)
    assert [row["system_id"] for row in plan["jobs"]] == ["never", "stale-10d", "stale-3d"]
    assert plan["jobs"][0]["reason"] == "never_scanned"
    assert "10d ago" in plan["jobs"][1]["reason"]
    assert plan["fresh"] == 1 and plan["due"] == 3 and plan["eligible"] == 4


def test_limit_caps_and_counts_stay_honest():
    now = _now()
    systems = [_system(f"s{i}", f"https://git/bank/r{i}.git", now - timedelta(days=30)) for i in range(5)]
    plan = plan_due_scans(systems, interval_days=7, limit=2, now=now)
    assert len(plan["jobs"]) == 2
    assert plan["due"] == 5  # full due count preserved
    assert plan["fresh"] == 0


def test_cloud_targets_grouped_per_system_and_flags():
    now = _now()
    systems = [
        _system("c1", "cloud://aws/111", now - timedelta(days=30)),
        _system("c2", "cloud://aws/222", None),
        _system("g1", "https://git/bank/x.git", now - timedelta(days=30)),
    ]
    plan = plan_due_scans(systems, interval_days=7, now=now)
    assert {row["job_type"] for row in plan["jobs"]} == {"CLOUD", "SYSTEM"}
    git_only = plan_due_scans(systems, interval_days=7, now=now, include_cloud=False)
    assert all(row["job_type"] == "SYSTEM" for row in git_only["jobs"])
    cloud_only = plan_due_scans(systems, interval_days=7, now=now, include_git=False)
    assert all(row["job_type"] == "CLOUD" for row in cloud_only["jobs"])


def test_naive_timestamps_assumed_utc_and_boundary():
    now = _now()
    # naive datetime written by SQLite drivers — must not crash or misrank
    naive = (now - timedelta(days=10)).replace(tzinfo=None)
    plan = plan_due_scans([_system("n", "https://git/bank/n.git", naive)], interval_days=7, now=now)
    assert plan["due"] == 1
    # exactly at the interval boundary is fresh (age < interval required to be due? no: stale means older than floor)
    edge = plan_due_scans([_system("e", "https://git/bank/e.git", now - timedelta(days=7))], interval_days=7, now=now)
    assert edge["fresh"] == 1 and edge["due"] == 0  # 7d old with 7d interval = still fresh


def test_systems_without_targets_ignored():
    plan = plan_due_scans([_system("none", "", None)], interval_days=7, now=_now())
    assert plan["eligible"] == 0 and plan["jobs"] == []
