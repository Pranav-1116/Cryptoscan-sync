"""Integration: OT/ICS maintenance-window safety guard (deterministic, no AI).

Verifies passive-first authorization and the fail-closed maintenance-window
gate over the real API + sqlite database.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"


def _token():
    from api.security.session_manager import SessionManager

    return SessionManager(secret="test-secret-key-for-sessions-min-32-chars").create_session(
        "admin", roles=["superadmin"])


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    db_file = os.path.join(tempfile.gettempdir(), "ot_safety_integration_test.db")
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


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _provision_device(criticality="HIGH", device_type="plc", location="zone-a"):
    """Insert a real OT device row; return its id (fail-closed tests use real rows)."""
    from db.connection.session import SessionLocal
    from db.models.ot_device import OtDevice as OtDeviceModel

    db = SessionLocal()
    dev = OtDeviceModel(ip_address=f"10.0.0.{len(criticality)}", device_type=device_type,
                        criticality=criticality, location=location, vendor="TestCo")
    db.add(dev)
    db.commit()
    db.refresh(dev)
    dev_id = str(dev.id)
    db.close()
    return dev_id


class TestOtSafety:
    def test_operation_classes_listed(self, client):
        r = client.get(f"{API}/ot/safety/operations")
        assert r.status_code == 200
        body = r.json()
        assert "passive_capture" in body["passive_operations"]
        assert "active_probe" in body["active_operations"]

    def test_passive_allowed_anytime(self, client):
        r = client.post(f"{API}/ot/safety/authorize",
                        json={"operation": "passive_capture"})
        assert r.status_code == 200, r.text
        assert r.json()["allowed"] is True and r.json()["passive"] is True

    def test_active_denied_without_window(self, client):
        dev_id = _provision_device()
        r = client.post(f"{API}/ot/safety/authorize",
                        json={"operation": "active_probe", "device_id": dev_id})
        assert r.status_code == 403
        assert r.json()["detail"]["reason"] == "OUTSIDE_WINDOW"

    def test_window_in_effect_allows_active(self, client):
        dev_id = _provision_device(location="zone-b")
        now = datetime.now(timezone.utc)
        r = client.post(f"{API}/ot/maintenance-windows", json={
            "window_ref": "MW-ALLOW",
            "title": "scheduled probe",
            "starts_at": _iso(now - timedelta(hours=1)),
            "ends_at": _iso(now + timedelta(hours=2)),
            "zones": ["zone-b"],
            "allowed_action_class": "interact",
            "change_ticket": "CHG-3030",
        })
        assert r.status_code == 201, r.text
        r = client.post(f"{API}/ot/safety/authorize",
                        json={"operation": "active_probe", "device_id": dev_id})
        assert r.status_code == 200, r.text
        assert r.json()["allowed"] is True and r.json()["window_id"] == "MW-ALLOW"

    def test_safety_controller_never_probed(self, client):
        sis_id = _provision_device(criticality="SAFETY", device_type="sis")
        now = datetime.now(timezone.utc)
        # even an approved change-class window covering it must not allow a probe
        client.post(f"{API}/ot/maintenance-windows", json={
            "window_ref": "MW-SIS",
            "starts_at": _iso(now - timedelta(hours=1)),
            "ends_at": _iso(now + timedelta(hours=2)),
            "device_ids": [sis_id],
            "allowed_action_class": "change",
            "change_ticket": "CHG-4040",
        })
        r = client.post(f"{API}/ot/safety/authorize",
                        json={"operation": "active_probe", "device_id": sis_id})
        assert r.status_code == 403
        assert r.json()["detail"]["reason"] == "SAFETY_CONTROLLER_PROTECTED"

    def test_change_class_exceeds_interact_window(self, client):
        dev_id = _provision_device(location="zone-c")
        now = datetime.now(timezone.utc)
        client.post(f"{API}/ot/maintenance-windows", json={
            "window_ref": "MW-INTERACT",
            "starts_at": _iso(now - timedelta(hours=1)),
            "ends_at": _iso(now + timedelta(hours=2)),
            "zones": ["zone-c"],
            "allowed_action_class": "interact",
            "change_ticket": "CHG-5050",
        })
        r = client.post(f"{API}/ot/safety/authorize",
                        json={"operation": "firmware_push", "device_id": dev_id})
        assert r.status_code == 403
        assert r.json()["detail"]["reason"] == "ACTION_EXCEEDS_WINDOW_CLASS"

    def test_window_validation_requires_scope(self, client):
        now = datetime.now(timezone.utc)
        r = client.post(f"{API}/ot/maintenance-windows", json={
            "window_ref": "MW-BAD",
            "starts_at": _iso(now - timedelta(hours=1)),
            "ends_at": _iso(now + timedelta(hours=1)),
            "change_ticket": "CHG-1",
        })
        assert r.status_code == 422

    def test_window_bad_time_range(self, client):
        now = datetime.now(timezone.utc)
        r = client.post(f"{API}/ot/maintenance-windows", json={
            "window_ref": "MW-BAD2",
            "starts_at": _iso(now + timedelta(hours=2)),
            "ends_at": _iso(now),
            "zones": ["z1"],
            "change_ticket": "CHG-2",
        })
        assert r.status_code == 422

    def test_duplicate_window_ref_conflict(self, client):
        now = datetime.now(timezone.utc)
        r = client.post(f"{API}/ot/maintenance-windows", json={
            "window_ref": "MW-ALLOW",
            "starts_at": _iso(now),
            "ends_at": _iso(now + timedelta(hours=1)),
            "zones": ["z1"],
            "change_ticket": "CHG-3",
        })
        assert r.status_code == 409

    def test_list_windows_shows_in_effect(self, client):
        r = client.get(f"{API}/ot/maintenance-windows")
        assert r.status_code == 200
        windows = r.json()["windows"]
        assert any(w["window_ref"] == "MW-ALLOW" and w["in_effect"] for w in windows)

    def test_cancelled_window_no_longer_authorizes(self, client):
        r = client.post(f"{API}/ot/maintenance-windows/MW-INTERACT/cancel")
        assert r.status_code == 200
        r = client.get(f"{API}/ot/maintenance-windows")
        # cancelled windows excluded from active list
        assert all(w["window_ref"] != "MW-INTERACT" for w in r.json()["windows"])

    def test_unknown_operation_denied(self, client):
        r = client.post(f"{API}/ot/safety/authorize",
                        json={"operation": "reboot_floor"})
        assert r.status_code == 403
        assert r.json()["detail"]["reason"] == "UNKNOWN_OPERATION"
