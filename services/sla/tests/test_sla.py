"""Deterministic remediation-SLA tracker tests (no AI/ML)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sla.tracker import (
    DEFAULT_SLA_DAYS,
    SlaState,
    due_date,
    evaluate_findings,
    evaluate_item,
    sla_window_days,
)

NOW = datetime(2026, 9, 3, tzinfo=timezone.utc)


def _finding(sev, days_ago_detected, resolved_days_ago=None, crit=None, fid="f"):
    f = {
        "id": fid,
        "severity": sev,
        "detected_at": (NOW - timedelta(days=days_ago_detected)).isoformat(),
    }
    if crit:
        f["asset_criticality"] = crit
    if resolved_days_ago is not None:
        f["resolved_at"] = (NOW - timedelta(days=resolved_days_ago)).isoformat()
    return f


def test_default_sla_table_by_severity():
    assert sla_window_days("CRITICAL") == 7
    assert sla_window_days("HIGH") == 30
    assert sla_window_days("MEDIUM") == 90


def test_critical_asset_halves_window():
    assert sla_window_days("HIGH", "SAFETY") == 15
    assert sla_window_days("CRITICAL", "PAYMENT") == 3  # 7//2 floor 3


def test_due_date_arithmetic():
    det = NOW
    assert due_date(det, "HIGH") == det + timedelta(days=30)


def test_on_track_when_recent():
    st = evaluate_item(_finding("HIGH", 2), now=NOW)
    assert st.state == SlaState.ON_TRACK
    assert st.days_remaining > 0


def test_breached_when_past_deadline():
    st = evaluate_item(_finding("HIGH", 45), now=NOW)  # 45 > 30 day window
    assert st.state == SlaState.BREACHED
    assert st.days_overdue == 15.0


def test_at_risk_within_warning_window():
    # HIGH window 30 days, warn at 20% = 6 days remaining -> detected 25 days ago
    st = evaluate_item(_finding("HIGH", 25), now=NOW)
    assert st.state == SlaState.AT_RISK


def test_resolved_item_state():
    st = evaluate_item(_finding("HIGH", 5, resolved_days_ago=20), now=NOW)
    assert st.state == SlaState.RESOLVED
    assert st.days_overdue == 0


def test_resolved_late_counted():
    # detected 45 days ago (already 15 overdue) but resolved just now -> late fix
    st = evaluate_item(_finding("HIGH", 45, resolved_days_ago=0), now=NOW)
    assert st.state == SlaState.RESOLVED
    assert st.days_overdue >= 14


def test_report_counts_and_ordering():
    findings = [
        _finding("HIGH", 2, fid="recent"),
        _finding("HIGH", 45, fid="old"),       # breached
        _finding("CRITICAL", 200, fid="ancient", crit="SAFETY"),  # 3-day window, very breached
    ]
    report = evaluate_findings(findings, now=NOW)
    assert report.breached == 2
    assert report.on_track == 1
    assert report.open_total == 3
    # most severe breach first (CRITICAL on safety asset)
    assert report.items[0].finding_id == "ancient"
    assert report.as_dict()["breach_rate"] == round(2 / 3, 4)


def test_unknown_severity_falls_back():
    st = evaluate_item(_finding("WEIRD", 5), now=NOW)
    assert st.window_days == DEFAULT_SLA_DAYS["UNKNOWN"]


def test_deterministic():
    fs = [_finding("HIGH", 10), _finding("LOW", 2)]
    a = evaluate_findings(fs, now=NOW).as_dict()
    b = evaluate_findings([dict(x) for x in fs], now=NOW).as_dict()
    assert a["items"] == b["items"]
