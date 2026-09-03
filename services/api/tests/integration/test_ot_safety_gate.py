"""Integration: deterministic OT/ICS safety gate (no AI/ML).

Verifies the fail-closed maintenance-window guard:
- passive/observe operations always allowed (never require a window);
- active/intrusive operations denied without an approved window;
- active ops allowed only within an approved window covering the device;
- safety-integrity devices (SIS/ESD) NEVER actively probed, even with a window.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"
NOW = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)


def _token(roles=("superadmin",)):
    from api.security.session_manager import SessionManager

    return SessionManager(secret="test-secret-key-for-sessions-min-32-chars").create_session(
        "admin", roles=list(roles))


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


def _seed_device(device_type: str, criticality: str = "HIGH"):
    from db.connection.session import SessionLocal
    from db.models.ot_device import OtDevice as OtDeviceModel

    db = SessionLocal()
    d = OtDeviceModel(device_type=device_type, criticality=criticality,
                      location="zone-1", vendor="acme")
    db.add(d)
    db.commit()
    db.refresh(d)
    did = d.id
    db.close()
    return did


class TestPassiveFirst:
    def test_passive_capture_always_allowed_without_window(self, client):
        did = _seed_device("plc", "HIGH")
        r = client.post(f"{API}/ot/safety/authorize",
                        json={"operation": "passive_capture", "device_id": did})
        assert r.status_code == 200, r.text
        assert r.json()["allowed"] is True
        assert r.json()["passive"] is True

    def test_inventory_and_pcap_read_allowed(self, client):
        did = _seed_device("rtu", "MEDIUM")
        for op in ("inventory", "pcap_read", "filesystem_read"):
            r = client.post(f"{API}/ot/safety/authorize",
                            json={"operation": op, "device_id": did})
            assert r.status_code == 200, (op, r.text)
            assert r.json()["allowed"] is True


class TestActiveRequiresWindow:
    def test_active_probe_denied_without_window(self, client):
        did = _seed_device("plc", "HIGH")
        r = client.post(f"{API}/ot/safety/authorize",
                        json={"operation": "active_probe", "device_id": did})
        # fail-closed: denied 403 when no approved window covers the device
        assert r.status_code == 403
        detail = r.json()["detail"]
        assert detail["allowed"] is False

    def test_firmware_push_denied_without_window(self, client):
        did = _seed_device("dcs", "HIGH")
        r = client.post(f"{API}/ot/safety/authorize",
                        json={"operation": "firmware_push", "device_id": did})
        assert r.status_code == 403


class TestSafetyIntegrityNeverProbed:
    def test_sis_denied_even_with_window(self, client):
        # A SIS safety controller: active ops are prohibited regardless of window
        did = _seed_device("sis", "SAFETY")
        # open a broad window covering the device
        win = client.post(f"{API}/ot/maintenance-windows", json={
            "window_ref": f"win-sis-{did[:6]}",
            "title": "broad window",
            "starts_at": (NOW - timedelta(hours=1)).isoformat(),
            "ends_at": (NOW + timedelta(hours=4)).isoformat(),
            "device_ids": [did], "change_ticket": "CHG-1001",
        })
        assert win.status_code in (201, 200), win.text
        r = client.post(f"{API}/ot/safety/authorize",
                        json={"operation": "active_probe", "device_id": did})
        assert r.status_code == 403, r.text
        reason = r.json()["detail"].get("reason", "")
        assert "safety" in reason.lower() or "SIS" in reason or "prohibited" in reason.lower()


class TestActiveAllowedInWindow:
    def test_active_probe_allowed_inside_approved_window(self, client):
        did = _seed_device("plc", "HIGH")
        win = client.post(f"{API}/ot/maintenance-windows", json={
            "window_ref": f"win-plc-{did[:6]}",
            "title": "scheduled maintenance",
            "starts_at": (NOW - timedelta(hours=1)).isoformat(),
            "ends_at": (NOW + timedelta(hours=4)).isoformat(),
            "device_ids": [did], "change_ticket": "CHG-1002",
        })
        assert win.status_code in (201, 200), win.text
        r = client.post(f"{API}/ot/safety/authorize",
                        json={"operation": "active_probe", "device_id": did})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["allowed"] is True
        assert body["matched_window"] is True

    def test_active_probe_denied_outside_window_bounds(self, client):
        did = _seed_device("plc", "HIGH")
        # window in the future (not yet active)
        client.post(f"{API}/ot/maintenance-windows", json={
            "window_ref": f"win-future-{did[:6]}",
            "title": "future window",
            "starts_at": (NOW + timedelta(hours=5)).isoformat(),
            "ends_at": (NOW + timedelta(hours=9)).isoformat(),
            "device_ids": [did], "change_ticket": "CHG-1003",
        })
        r = client.post(f"{API}/ot/safety/authorize",
                        json={"operation": "active_probe", "device_id": did})
        assert r.status_code == 403


class TestOperationCatalog:
    def test_operations_listed(self, client):
        r = client.get(f"{API}/ot/safety/operations")
        assert r.status_code == 200, r.text
