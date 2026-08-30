"""Monitor runners for the new realtime target types: OT + VENDOR.

Also covers the report sweep (due compliance schedules actually executing in
the daemon) and the drift → SSE publish.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from db.connection.session import Base
from db.repositories.monitor_repository import MonitorRepository
from worker.monitor.engine import MonitorEngine
from worker.monitor.report_sweep import run_due_report_schedules
from worker.monitor.runners import ot_runner, vendor_runner


def _session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


# -------------------------------------------------------------- OT runner


def test_ot_runner_scans_capture_dir(tmp_path):
    (tmp_path / "plc.log").write_text(
        "ts=2026-08-30T10:00:00 proto=MODBUS ip=10.0.0.7 mac=00:1B:1B:11:22:33 "
        "port=502 product=S7-1500 firmware=2.8\n"
    )
    result = ot_runner({"path": str(tmp_path)}, None)
    assert result["summary"]["devices"] >= 1
    assert result["summary"]["unencrypted"] >= 1
    assert any("OT_UNENCRYPTED" in issue for issue in result["issues"])
    assert result["degraded"] is True
    # issue carries protocol + device ref, not a dumped dict
    assert any("Modbus TCP" in issue and "{" not in issue for issue in result["issues"])


def test_ot_runner_blocked_without_path():
    result = ot_runner({"path": ""}, None)
    assert result.get("blocked_reason") and "path" in result["blocked_reason"]


def test_ot_runner_persists_devices(tmp_path):
    session = _session()
    (tmp_path / "plc.log").write_text("proto=MODBUS ip=10.9.9.9 port=502\n")
    ot_runner({"path": str(tmp_path)}, session)
    session.commit()
    from sqlalchemy import func, select

    from db.models.ot_device import OtDevice

    n = int(session.execute(select(func.count()).select_from(OtDevice)).scalar_one())
    assert n >= 1


# ---------------------------------------------------------- VENDOR runner


def test_vendor_runner_flags_weak_crypto():
    result = vendor_runner({"name": "Acme HSM", "algorithms": ["DES", "RSA-1024"], "sensitive": ["PCI"]}, None)
    assert result["summary"]["score"] >= 50
    assert any(issue.startswith("VENDOR_ISSUE") for issue in result["issues"])
    assert any(issue.startswith("VENDOR_RISK") for issue in result["issues"])
    assert result["degraded"] is True


def test_vendor_runner_strong_crypto_is_not_an_issue():
    result = vendor_runner({"name": "Acme HSM", "algorithms": ["AES-256-GCM", "RSA-4096"]}, None)
    assert result["summary"]["score"] < 50
    assert result["issues"] == []
    assert result["degraded"] is False


def test_vendor_runner_blocked_without_name():
    result = vendor_runner({}, None)
    assert result.get("blocked_reason") and "vendor name" in result["blocked_reason"]


# ----------------------------------------------------------- report sweep


def _report_schedule(session, *, name="weekly-pci", target="repo://x"):
    from db.models.report_snapshot import ReportSchedule

    now = datetime.now(timezone.utc)
    row = ReportSchedule(
        name=name,
        template_id="pci-dss",
        scan_target=target,
        recipients=["soc@bank.example"],
        requirements=["PCI-DSS"],
        frequency="weekly",
        next_run_at=now - timedelta(seconds=1),  # due now
        active=True,
        created_at=now,
        updated_at=now,
    )
    session.add(row)
    session.commit()
    return row


def test_report_sweep_runs_due_schedules(tmp_path, monkeypatch):
    session = _session()
    _report_schedule(session)
    events: list[tuple[str, str, dict]] = []

    # no completed scan exists -> honest SKIPPED_NO_SCAN outcome + event
    outcomes = run_due_report_schedules(session, on_event=lambda t, d, p: events.append((t, d, p)))
    assert len(outcomes) == 1
    assert outcomes[0]["status"] == "SKIPPED_NO_SCAN"
    assert events and events[0][0] == "REPORT_SKIPPED"


def test_report_sweep_empty_is_noop(tmp_path):
    session = _session()
    assert run_due_report_schedules(session) == []


def test_engine_tick_runs_due_reports_and_records_event():
    session = _session()
    _report_schedule(session)
    engine = MonitorEngine(session, runners={}, clock=lambda: datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc))
    outcome = engine.tick()
    assert outcome["report_ran"] == 1
    types = {e.event_type for e in MonitorRepository(session).list_events()}
    assert "REPORT_SKIPPED" in types


# -------------------------------------------------------- drift -> SSE bus


def test_stage_drift_publishes_events(monkeypatch):
    published: list[tuple[str, dict]] = []

    class FakeBus:
        def publish(self, event_type, payload, source=None):
            published.append((event_type, payload))

    monkeypatch.setattr("api.events.bus.get_event_bus", lambda: FakeBus())
    from worker.pipeline.stage_drift import _publish_drift_events

    class Ctx:
        scan_id = "scan-1"
        job_id = "job-1"
        target_repo = "repo://x"

    _publish_drift_events(
        [{"drift_type": "NEW_WEAK_ALGORITHM", "severity": "HIGH", "reason": "DES added", "algorithm": "DES"}],
        Ctx(),
    )
    assert len(published) == 1
    assert published[0][0] == "drift.event"
    assert published[0][1]["severity"] == "HIGH" and published[0][1]["algorithm"] == "DES"


def test_stage_drift_no_events_no_publish(monkeypatch):
    called = {"n": 0}

    def boom(*_a, **_k):
        called["n"] += 1

    monkeypatch.setattr("api.events.bus.get_event_bus", boom)
    from worker.pipeline.stage_drift import _publish_drift_events

    class Ctx:
        scan_id = None
        job_id = None
        target_repo = None

    _publish_drift_events([], Ctx())
    assert called["n"] == 0
