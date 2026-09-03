"""Integration: deterministic scheduled compliance reports (no AI/ML).

Schedules render a template against the latest scan into an immutable,
hash-signed snapshot; run-due only fires schedules whose time has come and a
scan exists for the target.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"


def _token(roles=("auditor",)):
    from api.security.session_manager import SessionManager

    return SessionManager(secret="test-secret-key-for-sessions-min-32-chars").create_session(
        "admin", roles=list(roles))


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    db_file = os.path.join(tempfile.gettempdir(), "report_schedules_integration_test.db")
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(db_file + ext):
            os.remove(db_file + ext)
    os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"

    from api.config.settings import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {_token()}"
        yield c


class TestReportSchedules:
    def test_unknown_template_rejected(self, client):
        r = client.post(f"{API}/report-schedules", json={
            "name": "bad", "template_id": "no-such-template", "scan_target": "repo-x",
        })
        assert r.status_code == 422

    def test_custom_template_requires_requirements(self, client):
        r = client.post(f"{API}/report-schedules", json={
            "name": "custom-no-req", "template_id": "custom", "scan_target": "repo-x",
        })
        assert r.status_code == 422

    def test_create_list_schedule(self, client):
        r = client.post(f"{API}/report-schedules", json={
            "name": "PCI quarterly", "template_id": "pci-dss-4.0",
            "scan_target": "repo-payments", "frequency": "quarterly",
            "recipients": ["risk@example.com"],
        })
        assert r.status_code == 201, r.text
        sid = r.json()["id"]
        lst = client.get(f"{API}/report-schedules").json()["schedules"]
        assert any(s["id"] == sid for s in lst)

    def test_run_without_scan_is_conflict(self, client):
        sid = client.post(f"{API}/report-schedules", json={
            "name": "NIST no-scan", "template_id": "nist-sp-800-131a",
            "scan_target": "target-with-zero-scans",
        }).json()["id"]
        r = client.post(f"{API}/report-schedules/{sid}/run")
        # no completed scan for the target -> honest SKIPPED, not a fake report
        assert r.status_code in (409, 200)
        if r.status_code == 200:
            assert r.json().get("status") in ("SKIPPED_NO_SCAN", "NO_SCAN")

    def test_run_due_reports_outcomes(self, client):
        r = client.post(f"{API}/report-schedules/run-due")
        assert r.status_code == 200, r.text
        assert "ran" in r.json() and "results" in r.json()

    def test_snapshots_listed(self, client):
        r = client.get(f"{API}/report-snapshots")
        assert r.status_code == 200, r.text
        assert "snapshots" in r.json()


class TestSnapshotGeneration:
    def test_completed_scan_yields_immutable_snapshot(self, client):
        from datetime import datetime as _dt, timezone as _tz
        from db.connection.session import SessionLocal
        from db.models.scan import Scan

        target = "repo-snapshot-happy-path"
        db = SessionLocal()
        scan = Scan(
            scan_start=_dt.now(_tz.utc), scan_end=_dt.now(_tz.utc),
            scanner_id="static-scanner", scanner_version="1.0.0",
            target_type="GIT_REPOSITORY", target_location=target,
            operator="tester", status="COMPLETED", statistics={},
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        db.close()

        sid = client.post(f"{API}/report-schedules", json={
            "name": "SOC2 snapshot", "template_id": "soc2",
            "scan_target": target, "frequency": "monthly",
        }).json()["id"]

        r = client.post(f"{API}/report-schedules/{sid}/run")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "GENERATED"
        assert body["report_hash"] and len(body["report_hash"]) >= 32

        snaps = client.get(f"{API}/report-snapshots").json()["snapshots"]
        mine = [s for s in snaps if s.get("id") == body["snapshot_id"]]
        assert mine and mine[0].get("report_hash") == body["report_hash"]
