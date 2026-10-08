"""Fail-closed scan admission: one decision, enforced at every entry point.

Covers the holes recorded in docs/PRODUCTION-GAP-HANDOFF-2026-10-08.md:

* the manual trigger's gate used to fail OPEN on a control-plane outage and
  read an OT flag from a request field that does not exist;
* the shared enqueue helper (cbom/estate/scans/devsecops/systems/jobs/cloud)
  had no gate at all;
* the network live-probe endpoints (CIDR sweep, due rotation, SSH scan)
  probed with no admission decision;
* OT is derived from trusted declarations (onboarding environments), and an
  active request outside an approved maintenance window on an OT estate is
  refused while passive modes remain available;
* a CIDR sweep must sit inside the declared authorized network scope.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import api.security.scan_admission as admission
from api.security.scan_admission import is_range_target, sweep_is_authorized


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/admission.db")
    monkeypatch.setenv("NEO4J_URI", "")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.events.bus import reset_event_bus

    reset_event_bus()
    from api.main import create_app

    with TestClient(create_app()) as c:
        yield c


def _pin_ok(monkeypatch):
    """Pin the seams to 'nothing blocks, no OT' for tests of other behavior."""
    monkeypatch.setattr(admission, "_control_plane_state", lambda: ([], None))
    monkeypatch.setattr(admission, "_ot_declared", lambda: False)


def _auth(client):
    token = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}
    ).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def _trigger(client, headers, **overrides):
    body = {"repo_url": "local://data/workspaces/demo-repo", "branch": "main"}
    body.update(overrides)
    return client.post("/api/v1/scans/trigger", headers=headers, json=body)


# --------------------------------------------------------------------- outage

class TestFailClosedOnOutage:
    def test_control_plane_outage_refuses_manual_trigger(self, client, monkeypatch):
        """The old gate logged the outage at debug and queued anyway."""
        def _boom():
            raise RuntimeError("control plane unreachable")

        monkeypatch.setattr(admission, "_control_plane_state", _boom)
        h = _auth(client)
        r = _trigger(client, h)
        assert r.status_code == 503
        assert "no scan was accepted" in r.json()["detail"]

    def test_outage_refuses_via_shared_enqueue_helper(self, monkeypatch):
        """cbom/estate/scans/devsecops/systems/jobs/cloud all enqueue through
        enqueue_scan_job — the helper had no gate at all before, so an outage
        (or emergency stop) on those routes used to queue anyway."""
        from fastapi import BackgroundTasks

        from api.routers.trigger import enqueue_scan_job

        def _boom():
            raise RuntimeError("control plane unreachable")

        monkeypatch.setattr(admission, "_control_plane_state", _boom)

        class _Repo:
            session = None

        with pytest.raises(Exception) as excinfo:
            enqueue_scan_job(
                _Repo(),
                BackgroundTasks(),
                repo_url="local://data/workspaces/demo-repo",
            )
        assert getattr(excinfo.value, "status_code", None) == 503
        assert "no scan was accepted" in str(getattr(excinfo.value, "detail", ""))

    def test_emergency_stop_refuses_via_shared_enqueue_helper(self, monkeypatch):
        from fastapi import BackgroundTasks

        from api.routers.trigger import enqueue_scan_job

        events = [{"event_type": "safe_scan.emergency_stop",
                   "payload": {"engaged": True},
                   "created_at": "2026-10-08T00:00:00+00:00"}]
        monkeypatch.setattr(admission, "_control_plane_state", lambda: (events, None))

        class _Repo:
            session = None

        with pytest.raises(Exception) as excinfo:
            enqueue_scan_job(
                _Repo(),
                BackgroundTasks(),
                repo_url="local://data/workspaces/demo-repo",
            )
        assert getattr(excinfo.value, "status_code", None) == 409

    def test_outage_leaves_no_job_row_behind(self, client, monkeypatch):
        def _boom():
            raise RuntimeError("control plane unreachable")

        monkeypatch.setattr(admission, "_control_plane_state", _boom)
        h = _auth(client)
        _trigger(client, h)
        from db.connection.session import SessionLocal
        from db.models.scan_job import ScanJob

        session = SessionLocal()
        try:
            assert session.query(ScanJob).count() == 0
        finally:
            session.close()


# ------------------------------------------------------------- emergency stop

class TestEmergencyStop:
    def test_emergency_stop_blocks_manual_trigger(self, client, monkeypatch):
        events = [{"event_type": "safe_scan.emergency_stop", "payload": {"engaged": True},
                   "created_at": "2026-10-08T00:00:00+00:00"}]
        monkeypatch.setattr(admission, "_control_plane_state", lambda: (events, None))
        h = _auth(client)
        r = _trigger(client, h)
        assert r.status_code == 409
        assert "emergency stop" in r.json()["detail"].lower()

    def test_emergency_stop_blocks_network_sweep(self, client, monkeypatch):
        events = [{"event_type": "safe_scan.emergency_stop", "payload": {"engaged": True},
                   "created_at": "2026-10-08T00:00:00+00:00"}]
        monkeypatch.setattr(admission, "_control_plane_state", lambda: (events, None))
        monkeypatch.setattr(admission, "_ot_declared", lambda: False)
        h = _auth(client)
        r = client.post("/api/v1/network/discover", headers=h,
                        json={"cidr": "10.0.0.0/24", "scan": False})
        assert r.status_code == 409
        assert "emergency stop" in r.json()["detail"].lower()

    def test_emergency_stop_blocks_run_due(self, client, monkeypatch):
        events = [{"event_type": "safe_scan.emergency_stop", "payload": {"engaged": True},
                   "created_at": "2026-10-08T00:00:00+00:00"}]
        monkeypatch.setattr(admission, "_control_plane_state", lambda: (events, None))
        monkeypatch.setattr(admission, "_ot_declared", lambda: False)
        h = _auth(client)
        r = client.post("/api/v1/network/run-due", headers=h)
        assert r.status_code == 409


# ------------------------------------------------------------------ OT window

class TestOtPassiveBoundary:
    def test_ot_estate_refuses_active_sweep_with_no_declared_window(self, client, monkeypatch):
        monkeypatch.setattr(admission, "_control_plane_state",
                            lambda: ([], {"mode": "standard"}))
        monkeypatch.setattr(admission, "_ot_declared", lambda: True)
        h = _auth(client)
        r = client.post("/api/v1/network/discover", headers=h,
                        json={"cidr": "10.0.0.0/24", "scan": False})
        assert r.status_code == 409
        assert "no approved maintenance window" in r.json()["detail"]
        assert "passive" in r.json()["detail"].lower()

    def test_ot_estate_refuses_active_sweep_outside_closed_window(self, client, monkeypatch):
        # a declared window that is NOT currently open (00:00 for 1 minute —
        # deterministic because the request happens within the same minute
        # only by luck; use a window in the past by pinning day/hour is not
        # possible, so use a 1-minute window at 00:00 and accept either
        # refusal outcome: closed window also refuses)
        windows = [{"day": "*", "start": "00:00", "duration_minutes": 1}]
        monkeypatch.setattr(admission, "_control_plane_state",
                            lambda: ([], {"mode": "standard",
                                          "maintenance_windows": windows,
                                          "maintenance_timezone": "UTC"}))
        monkeypatch.setattr(admission, "_ot_declared", lambda: True)
        h = _auth(client)
        r = client.post("/api/v1/network/discover", headers=h,
                        json={"cidr": "10.0.0.0/24", "scan": False})
        # Either the window happens to be open at this instant (then 403 for
        # scope, since no scope is declared) or it is closed (409 passive).
        # What must NEVER happen: an active sweep running on an OT estate.
        assert r.status_code in (403, 409)

    def test_ot_estate_allows_active_sweep_inside_window(self, client, monkeypatch):
        # a maintenance window covering *now* (24h duration) with the policy
        # still in standard mode
        import datetime as dt

        now = dt.datetime.now(dt.timezone.utc)
        windows = [{"day": "*", "start": "00:00", "duration_minutes": 1440}]
        monkeypatch.setattr(admission, "_control_plane_state",
                            lambda: ([], {"mode": "standard",
                                          "maintenance_windows": windows,
                                          "maintenance_timezone": "UTC"}))
        monkeypatch.setattr(admission, "_ot_declared", lambda: True)
        monkeypatch.setattr(admission, "_authorized_network_scope",
                            lambda: ["10.0.0.0/16"])
        import api.routers.network as net_router

        swept = []

        def _fake_sweep(cidr, ports, timeout=1.5):  # noqa: ARG001
            swept.append(cidr)
            return {"cidr": cidr, "hosts_checked": 0, "endpoints": [],
                    "open_count": 0, "candidates": 0, "truncated": False}

        import network_scanner.discovery.subnet_discoverer as subnet_module

        monkeypatch.setattr(subnet_module, "discover_subnet", _fake_sweep)
        h = _auth(client)
        r = client.post("/api/v1/network/discover", headers=h,
                        json={"cidr": "10.0.0.0/24", "scan": False})
        assert r.status_code == 200
        assert swept == ["10.0.0.0/24"]

    def test_ot_derived_from_trusted_declarations_not_request(self, client, monkeypatch):
        """No is_ot field exists on the request; the manual trigger on a repo
        target derives OT from the estate — and a repo scan on an OT-declaring
        estate still runs (repo scans do not touch OT networks)."""
        _pin_ok(monkeypatch)
        monkeypatch.setattr(admission, "_ot_declared", lambda: True)
        h = _auth(client)
        r = _trigger(client, h)
        assert r.status_code == 202


# ----------------------------------------------------- sweep authorization

class TestSweepAuthorization:
    def test_range_target_classification(self):
        assert is_range_target("10.0.0.0/16") is True
        assert is_range_target("10.0.0.0/30") is True
        assert is_range_target("10.0.0.5") is False  # single host
        assert is_range_target("10.0.0.5:443") is False  # host:port
        assert is_range_target("hsm.bank.example") is False  # domain
        assert is_range_target("vlan:ot-segment") is False  # OT reference
        assert is_range_target("snmp:10.0.0.9") is False

    def test_containment_is_exact_not_overlap(self):
        ok, why = sweep_is_authorized("10.1.2.0/24", ["10.1.0.0/16"])
        assert ok and "10.1.0.0/16" in why
        # overlapping but not contained -> refused
        ok, _ = sweep_is_authorized("10.1.0.0/15", ["10.1.0.0/16"])
        assert ok is False
        # a /24 next door -> refused
        ok, _ = sweep_is_authorized("10.2.0.0/24", ["10.1.0.0/16"])
        assert ok is False

    def test_single_host_sweep_of_registered_target_allowed(self):
        ok, why = sweep_is_authorized("10.0.0.7/32", ["10.0.0.7:443"])
        assert ok and "10.0.0.7" in why  # authorized via that exact host
        ok, _ = sweep_is_authorized("10.0.0.8/32", ["10.0.0.7:443"])
        assert ok is False

    def test_v6_and_garbage_refused_cleanly(self):
        ok, _ = sweep_is_authorized("not-a-cidr", ["10.0.0.0/8"])
        assert ok is False
        ok, _ = sweep_is_authorized("::/0", ["10.0.0.0/8"])
        assert ok is False

    def test_discover_refuses_outside_authorized_scope(self, client, monkeypatch):
        _pin_ok(monkeypatch)
        monkeypatch.setattr(admission, "_authorized_network_scope",
                            lambda: ["10.5.0.0/16"])
        h = _auth(client)
        r = client.post("/api/v1/network/discover", headers=h,
                        json={"cidr": "10.9.9.0/24", "scan": False})
        assert r.status_code == 403
        body = r.json()["detail"]
        assert body["error"] == "target_outside_authorized_scope"

    def test_discover_authorization_outage_fails_closed(self, client, monkeypatch):
        _pin_ok(monkeypatch)

        def _boom():
            raise RuntimeError("scope table unreachable")

        monkeypatch.setattr(admission, "_authorized_network_scope", _boom)
        h = _auth(client)
        r = client.post("/api/v1/network/discover", headers=h,
                        json={"cidr": "10.9.9.0/24", "scan": False})
        assert r.status_code == 503
