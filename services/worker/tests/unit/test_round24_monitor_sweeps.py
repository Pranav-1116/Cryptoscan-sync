"""Round 24 (audits 69 + 31 §5.2): monitor-time reintroduction detection
and drift-SLA escalation sweeps."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from db.connection.session import Base
from db.models.drift_event import DriftEvent
from db.models.evidence_record import EvidenceRecord
from db.models.retired_asset import RetiredAsset
from db.models.scan import Scan
from worker.monitor.reintroduction_sweep import run_reintroduction_sweep
from worker.monitor.sla_sweep import run_sla_sweep

NOW = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)


def _session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _retirement(session, *, algorithm="DES", scope="FILE", file_path=None,
                retired_at=NOW - timedelta(days=10), active=True):
    row = RetiredAsset(
        algorithm=algorithm, scope=scope, file_path=file_path,
        reason="test", retired_by="aud", retired_at=retired_at, active=active,
    )
    session.add(row)
    return row


def _scan_with_evidence(session, scan_id, target, when, rows):
    session.add(
        Scan(id=scan_id, scan_start=when, target_location=target,
             target_type="GIT_REPOSITORY", status="COMPLETED")
    )
    for i, (algorithm, path) in enumerate(rows):
        session.add(
            EvidenceRecord(
                id=f"{scan_id}-ev-{i}", scan_id=scan_id,
                content_hash=f"h{scan_id}{i}" * 8, chain_hash="c" * 64,
                chain_position=i, algorithm=algorithm, confidence="HIGH",
                file_path=path, line_number=i + 1, compliance_status="FAIL",
                finding_data={},
            )
        )
    session.commit()


# --------------------------------------------------------------------- #
# Reintroduction sweep (audit 69 monitor-time)
# --------------------------------------------------------------------- #

def test_monitor_sweep_detects_reintroduction_in_newest_scan():
    session = _session()
    _retirement(session, algorithm="DES", file_path="src/legacy.py")
    # newest scan for the target shows DES back at the retired location
    _scan_with_evidence(session, "scan-new", "repo-A", NOW - timedelta(hours=1),
                        [("DES", "src/legacy.py"), ("AES", "src/ok.py")])
    # an older scan predating the retirement also had it — not a breach
    _scan_with_evidence(session, "scan-old", "repo-A", NOW - timedelta(days=20),
                        [("DES", "src/legacy.py")])
    session.commit()

    result = run_reintroduction_sweep(session, now=NOW)
    assert result["retirements"] == 1
    assert result["scans_checked"] == 1  # newest per target only
    assert len(result["reintroductions"]) == 1
    detection = result["reintroductions"][0]
    assert detection["algorithm"] == "DES"
    assert detection["scan_id"] == "scan-new"
    assert detection["detected_by"] == "monitor"
    assert detection["severity"] in {"CRITICAL", "HIGH", "MEDIUM"}
    assert result["severity_counts"][detection["severity"]] == 1


def test_monitor_sweep_respects_algorithm_scope_and_alerts():
    session = _session()
    alerts: list[tuple] = []
    # ALGORITHM scope: must not reappear anywhere
    _retirement(session, algorithm="RC4", scope="ALGORITHM")
    _scan_with_evidence(session, "scan-1", "repo-B", NOW - timedelta(hours=2),
                        [("RC4", "src/anywhere/else.go")])
    session.commit()

    result = run_reintroduction_sweep(
        session, now=NOW, on_alert=lambda name, issue, payload: alerts.append((name, issue))
    )
    assert len(result["reintroductions"]) == 1
    assert result["reintroductions"][0]["algorithm"] == "RC4"
    # CRITICAL/HIGH detections escalate through the alert router
    if result["reintroductions"][0]["severity"] in {"CRITICAL", "HIGH"}:
        assert len(alerts) == 1
        assert "RC4" in alerts[0][1]


def test_monitor_sweep_no_active_retirements_is_a_noop():
    session = _session()
    _retirement(session, algorithm="DES", active=False)  # lifted
    _scan_with_evidence(session, "scan-1", "repo-C", NOW - timedelta(hours=1),
                        [("DES", "src/x.py")])
    session.commit()
    result = run_reintroduction_sweep(session, now=NOW)
    assert result["retirements"] == 0
    assert result["reintroductions"] == []


def test_monitor_sweep_evidence_predating_retirement_is_not_a_breach():
    session = _session()
    # retirement registered 1 hour ago; the newest scan started 2 hours ago
    # (its evidence predates the promise)
    _retirement(session, algorithm="MD5", file_path="src/old.py",
                retired_at=NOW - timedelta(hours=1))
    _scan_with_evidence(session, "scan-1", "repo-D", NOW - timedelta(hours=2),
                        [("MD5", "src/old.py")])
    session.commit()
    result = run_reintroduction_sweep(session, now=NOW)
    assert result["reintroductions"] == []


# --------------------------------------------------------------------- #
# SLA escalation sweep (audit 31 §5.2)
# --------------------------------------------------------------------- #

def _open_drift(session, severity, detected):
    session.add(
        DriftEvent(current_scan_id="scan-x", detected_at=detected,
                   drift_type="ALGORITHM_ADDED", severity=severity,
                   resolution_status="OPEN")
    )


def test_sla_sweep_alerts_on_window_crossing_once():
    session = _session()
    alerts: list[tuple] = []
    # CRITICAL unacked for 2h: crossed the 1h window 1h ago (within recent 24h)
    _open_drift(session, "CRITICAL", NOW - timedelta(hours=2))
    session.commit()

    result = run_sla_sweep(session, now=NOW, on_alert=lambda n, i, p: alerts.append((n, i)))
    assert result["escalated_severities"] == ["CRITICAL"]
    assert len(alerts) == 1
    assert "unacknowledged past the 1h window" in alerts[0][1]
    # the summary is included for the tick outcome
    assert result["summary"]["per_severity"]["CRITICAL"]["open"] == 1


def test_sla_sweep_old_breach_does_not_realert():
    session = _session()
    alerts: list[tuple] = []
    # CRITICAL unacked for 100h: crossed the 1h window 99h ago — outside the
    # 24h recent window, so no re-alert (the persistent signal is the open
    # event + GET /drift/sla, not repeated pages)
    _open_drift(session, "CRITICAL", NOW - timedelta(hours=100))
    session.commit()
    result = run_sla_sweep(session, now=NOW, on_alert=lambda n, i, p: alerts.append((n, i)))
    assert result["escalated_severities"] == []
    assert alerts == []


def test_sla_sweep_acked_events_do_not_breach_ack_window():
    session = _session()
    alerts: list[tuple] = []
    row = DriftEvent(current_scan_id="scan-x", detected_at=NOW - timedelta(hours=3),
                     drift_type="ALGORITHM_ADDED", severity="HIGH",
                     resolution_status="ACKNOWLEDGED")
    row.acknowledged_at = NOW - timedelta(hours=2.5)
    row.acknowledged_by = "aud"
    session.add(row)
    session.commit()
    result = run_sla_sweep(session, now=NOW, on_alert=lambda n, i, p: alerts.append((n, i)))
    # acked at 0.5h — within HIGH's 4h window; resolve window (7d) not crossed
    assert result["escalated_severities"] == []
    assert alerts == []


def test_sla_sweep_resolve_window_crossing_for_medium():
    session = _session()
    alerts: list[tuple] = []
    # MEDIUM unresolved for 31 days: crossed the 30d window yesterday
    _open_drift(session, "MEDIUM", NOW - timedelta(days=31))
    session.commit()
    result = run_sla_sweep(session, now=NOW, on_alert=lambda n, i, p: alerts.append((n, i)))
    assert "MEDIUM" in result["escalated_severities"]
    assert any("unresolved past the 720h window" in i for _n, i in alerts)
