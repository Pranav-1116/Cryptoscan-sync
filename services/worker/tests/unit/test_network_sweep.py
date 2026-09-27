"""The worker owns scheduled TLS target execution and NBOM persistence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from db.connection.session import Base
from db.models.network_scan_run import NetworkScanRun
from db.repositories.network_scan_target_repository import NetworkScanTargetRepository
from db.repositories.scan_run_repository import ScanRunRepository
from worker.monitor.engine import MonitorEngine
from worker.monitor.network_sweep import run_due_network_targets


T0 = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)


def _session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


class FakeScanner:
    calls: list[list[str]] = []

    def scan_hosts(self, endpoints):
        self.calls.append(list(endpoints))
        return {
            "scan_id": "scheduled-scan-1",
            "findings": [{"endpoint": endpoints[0], "status": "OK"}],
            "certificates": [],
            "probe_telemetry": {
                "status": "OK", "probed": len(endpoints), "ok": len(endpoints),
            },
        }


def test_due_network_targets_are_scanned_persisted_and_rescheduled():
    session = _session()
    row = NetworkScanTargetRepository(session).upsert(
        "bank.example:443",
        scan_frequency="hourly",
        enabled=True,
        next_scan_time=T0 - timedelta(seconds=1),
    )
    future = NetworkScanTargetRepository(session).upsert(
        "later.example:443",
        scan_frequency="daily",
        enabled=True,
        next_scan_time=T0 + timedelta(hours=1),
    )
    session.commit()
    FakeScanner.calls = []

    summary = run_due_network_targets(
        session, now=T0, scanner_factory=FakeScanner,
    )

    assert summary["status"] == "OK"
    assert summary["due"] == 1 and summary["scanned"] == 1
    assert FakeScanner.calls == [["bank.example:443"]]
    run = session.execute(select(NetworkScanRun)).scalar_one()
    assert run.target_kind == "scheduled"
    assert run.result["scan_id"] == "scheduled-scan-1"
    assert row.last_scan_time == T0
    assert row.next_scan_time == T0 + timedelta(hours=1)
    assert future.last_scan_time is None


def test_disabled_and_not_due_network_targets_are_not_run():
    session = _session()
    repo = NetworkScanTargetRepository(session)
    disabled = repo.upsert(
        "off.example:443", enabled=False, next_scan_time=T0 - timedelta(days=1)
    )
    future = repo.upsert(
        "future.example:443", enabled=True, next_scan_time=T0 + timedelta(minutes=5)
    )
    session.commit()
    FakeScanner.calls = []

    summary = run_due_network_targets(session, now=T0, scanner_factory=FakeScanner)

    assert summary == {"due": 0, "scanned": 0, "run_id": None, "status": "IDLE"}
    assert FakeScanner.calls == []
    assert disabled.last_scan_time is None and future.last_scan_time is None
    assert ScanRunRepository(session).count_runs() == 0


def test_scanner_failure_leaves_schedule_due_and_creates_no_false_run():
    session = _session()
    row = NetworkScanTargetRepository(session).upsert(
        "unreachable.example:443", scan_frequency="daily", enabled=True,
        next_scan_time=T0 - timedelta(seconds=1),
    )
    session.commit()

    class BrokenScanner:
        def scan_hosts(self, _endpoints):
            raise TimeoutError("probe timed out")

    try:
        run_due_network_targets(session, now=T0, scanner_factory=BrokenScanner)
    except TimeoutError:
        pass
    else:
        raise AssertionError("scanner failures must be visible to the monitor tick")

    assert row.last_scan_time is None
    assert row.next_scan_time <= T0
    assert ScanRunRepository(session).count_runs() == 0


def test_monitor_tick_invokes_scheduled_network_sweep(monkeypatch):
    session = _session()
    calls = []

    def fake_sweep(db, *, now):
        assert db is session
        calls.append(now)
        return {"due": 1, "scanned": 1, "run_id": "run-1", "status": "OK"}

    monkeypatch.setattr("worker.monitor.network_sweep.run_due_network_targets", fake_sweep)
    engine = MonitorEngine(
        session,
        runners={},
        clock=lambda: T0,
        watch_enabled=False,
        run_reports=False,
        run_backups=False,
    )

    outcome = engine.tick()

    assert calls == [T0]
    assert outcome["network"]["run_id"] == "run-1"
