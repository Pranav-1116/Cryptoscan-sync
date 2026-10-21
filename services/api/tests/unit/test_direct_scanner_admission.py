"""Direct scanner routes share the central admission (product vision §4.1, P0).

The synchronous cloud/OT/container/network scan endpoints used to run
outside the common queued-job admission: a request-selected filesystem
target, no emergency-stop check, no queue depth, no safe-scan policy, and
(for live TLS and live cloud) no active-probing authorization. These tests
pin the unified contract: a refused target launches NO scan, and the
scanner class is never constructed on refusal.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings

EMERGENCY_EVENTS = [{
    "event_type": "safe_scan.emergency_stop",
    "payload": {"engaged": True},
    "created_at": "2026-10-13T00:00:00+00:00",
}]


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/direct.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.events.bus import reset_event_bus

    reset_event_bus()
    from api.main import create_app

    with TestClient(create_app()) as c:
        yield c


def _pin_ok(monkeypatch):
    """Admission seams pinned to 'nothing blocks, empty queue'."""
    from api.security import scan_admission as admission

    monkeypatch.setattr(admission, "_control_plane_state", lambda: ([], None))
    monkeypatch.setattr(admission, "_ot_declared", lambda: False)
    monkeypatch.setattr(admission, "_active_job_count", lambda: 0)


def _pin_emergency(monkeypatch):
    from api.security import scan_admission as admission

    monkeypatch.setattr(admission, "_control_plane_state",
                        lambda: (EMERGENCY_EVENTS, None))
    monkeypatch.setattr(admission, "_active_job_count", lambda: 0)


def _pin_outage(monkeypatch):
    from api.security import scan_admission as admission

    def _boom():
        raise RuntimeError("control plane unreachable")

    monkeypatch.setattr(admission, "_control_plane_state", _boom)
    monkeypatch.setattr(admission, "_active_job_count", lambda: 0)


def _auth(client):
    token = client.post("/api/v1/auth/login",
                        json={"username": "admin", "password": "cryptoscan"}
                        ).json()["token"]
    return {"Authorization": f"Bearer {token}"}


class _NeverScanner:
    """Sentinel: construction proves a scan path was reached."""

    instances = 0

    def __init__(self, *args, **kwargs):
        _NeverScanner.instances += 1
        raise AssertionError("scanner constructed — a refused scan ran anyway")

    @classmethod
    def reset(cls):
        cls.instances = 0


def _stub_scanner(monkeypatch, module, class_name, report):
    """Replace the router module's scanner class with a recording stub."""

    calls = []
    inits = []

    class _Stub:
        def __init__(self, *args, **kwargs):
            inits.append(kwargs)

        def scan_filesystem(self, target, **kwargs):
            calls.append(("fs", str(target)))
            return dict(report)

        def scan_hosts(self, hosts, **kwargs):
            calls.append(("hosts", list(hosts)))
            return dict(report)

        def scan(self, **kwargs):
            calls.append(("scan", kwargs))
            return dict(report)

    import importlib

    module = importlib.import_module(module)
    # monkeypatch-backed so the real class is restored at teardown: a raw
    # setattr leaks the stub into every later test in the same xdist worker
    # (seen as test_ot_scan_passive KeyError 'packets_sent').
    monkeypatch.setattr(module, class_name, _Stub)
    return calls, inits


REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parents[4]


# ── cloud ─────────────────────────────────────────────────────────────


def test_cloud_scan_refused_on_emergency_stop_launches_no_scan(client, monkeypatch):
    _pin_emergency(monkeypatch)
    monkeypatch.setattr("api.routers.cloud_scans.CloudScanner", _NeverScanner)
    _NeverScanner.reset()
    r = client.post("/api/v1/cloud-scans", headers=_auth(client),
                    json={"path": str(REPO_ROOT), "live": False})
    assert r.status_code == 409
    assert "emergency stop" in r.json()["detail"].lower()
    assert _NeverScanner.instances == 0


def test_cloud_scan_refused_on_admission_outage_launches_no_scan(client, monkeypatch):
    _pin_outage(monkeypatch)
    monkeypatch.setattr("api.routers.cloud_scans.CloudScanner", _NeverScanner)
    _NeverScanner.reset()
    r = client.post("/api/v1/cloud-scans", headers=_auth(client),
                    json={"path": str(REPO_ROOT)})
    assert r.status_code == 503
    assert "no scan was accepted" in r.json()["detail"]
    assert _NeverScanner.instances == 0


def test_cloud_scan_path_outside_source_roots_is_refused(client, monkeypatch):
    _pin_ok(monkeypatch)
    monkeypatch.setattr("api.routers.cloud_scans.CloudScanner", _NeverScanner)
    _NeverScanner.reset()
    r = client.post("/api/v1/cloud-scans", headers=_auth(client),
                    json={"path": "/etc"})
    assert r.status_code == 422
    assert "outside the allowed source roots" in r.json()["detail"]
    assert _NeverScanner.instances == 0


def test_cloud_scan_admitted_runs_and_reports_decision(client, monkeypatch):
    _pin_ok(monkeypatch)
    calls, inits = _stub_scanner(monkeypatch, "api.routers.cloud_scans", "CloudScanner",
                                 {"resources": 0, "findings": []})
    r = client.post("/api/v1/cloud-scans", headers=_auth(client),
                    json={"path": str(REPO_ROOT), "live": False})
    assert r.status_code == 200, r.text
    assert calls == [("fs", str(REPO_ROOT))]
    # the RUN was passive (live=False reaches the scanner constructor);
    # the decision's active_probing reports what the POLICY would allow
    assert inits and inits[0].get("live") is False
    body = r.json()
    assert body["admission"]["mode"] == "standard"


def test_cloud_live_scan_requires_active_probing_authorization(client, monkeypatch):
    """A live cloud read is an active collector: passive-only policy refuses it."""
    _pin_ok(monkeypatch)
    from api.security import scan_admission as admission

    monkeypatch.setattr(
        admission, "_control_plane_state",
        lambda: ([], {"mode": "passive"}))
    monkeypatch.setattr("api.routers.cloud_scans.CloudScanner", _NeverScanner)
    _NeverScanner.reset()
    r = client.post("/api/v1/cloud-scans", headers=_auth(client),
                    json={"path": str(REPO_ROOT), "live": True})
    assert r.status_code == 409
    assert "active probing is not authorized" in r.json()["detail"]
    assert _NeverScanner.instances == 0


# ── OT ────────────────────────────────────────────────────────────────


def test_ot_scan_refused_on_emergency_stop_launches_no_scan(client, monkeypatch):
    _pin_emergency(monkeypatch)
    monkeypatch.setattr("api.routers.ot.OtPassiveScanner", _NeverScanner)
    _NeverScanner.reset()
    r = client.post("/api/v1/ot/scan", headers=_auth(client),
                    json={"path": str(REPO_ROOT)})
    assert r.status_code == 409
    assert _NeverScanner.instances == 0


def test_ot_scan_path_outside_source_roots_is_refused(client, monkeypatch):
    _pin_ok(monkeypatch)
    monkeypatch.setattr("api.routers.ot.OtPassiveScanner", _NeverScanner)
    _NeverScanner.reset()
    r = client.post("/api/v1/ot/scan", headers=_auth(client),
                    json={"path": "/root"})
    assert r.status_code == 422
    assert "outside the allowed source roots" in r.json()["detail"]
    assert _NeverScanner.instances == 0


def test_ot_passive_scan_admitted_without_maintenance_window(client, monkeypatch):
    """Passive OT observation stays available with no declared window."""
    _pin_ok(monkeypatch)
    calls, _inits = _stub_scanner(monkeypatch, "api.routers.ot", "OtPassiveScanner",
                                  {"devices": [], "findings": []})
    r = client.post("/api/v1/ot/scan", headers=_auth(client),
                    json={"path": str(REPO_ROOT)})
    assert r.status_code == 200, r.text
    assert calls == [("fs", str(REPO_ROOT))]
    # the collector itself is passive by construction; admission knows the
    # target is OT (empty windows count as unrestricted for the ALLOWANCE,
    # but this endpoint never requests active probing)
    body = r.json()
    assert body["admission"]["is_ot"] is True


# ── container ─────────────────────────────────────────────────────────


def test_container_scan_refused_on_emergency_stop_launches_no_scan(client, monkeypatch):
    _pin_emergency(monkeypatch)
    monkeypatch.setattr("api.routers.container_scans.ContainerScanner", _NeverScanner)
    _NeverScanner.reset()
    r = client.post("/api/v1/container-scans", headers=_auth(client),
                    json={"path": str(REPO_ROOT)})
    assert r.status_code == 409
    assert _NeverScanner.instances == 0


def test_container_archive_outside_source_roots_is_refused(client, monkeypatch):
    _pin_ok(monkeypatch)
    monkeypatch.setattr("api.routers.container_scans.ContainerScanner", _NeverScanner)
    _NeverScanner.reset()
    r = client.post("/api/v1/container-scans", headers=_auth(client),
                    json={"archive": "/var/lib/docker/image.tar"})
    assert r.status_code == 422
    assert "outside the allowed source roots" in r.json()["detail"]
    assert _NeverScanner.instances == 0


def test_container_scan_admitted_runs_and_reports_decision(client, monkeypatch):
    _pin_ok(monkeypatch)
    calls, _inits = _stub_scanner(monkeypatch, "api.routers.container_scans", "ContainerScanner",
                                  {"layers": [], "findings": []})
    # patch _persist too: no container_scan table in this fixture's sqlite
    from api.routers import container_scans as cs

    monkeypatch.setattr(cs, "_persist", lambda db, result: type(
        "Row", (), {"id": "cs-test"})())
    r = client.post("/api/v1/container-scans", headers=_auth(client),
                    json={"path": str(REPO_ROOT)})
    assert r.status_code == 200, r.text
    assert calls and calls[0][0] == "fs"
    assert r.json()["admission"]["mode"] == "standard"


# ── network ───────────────────────────────────────────────────────────


def test_network_scan_refused_on_emergency_stop_launches_no_scan(client, monkeypatch):
    _pin_emergency(monkeypatch)
    monkeypatch.setattr("api.routers.network_scans.NetworkTlsScanner", _NeverScanner)
    _NeverScanner.reset()
    r = client.post("/api/v1/network-scans", headers=_auth(client),
                    json={"hosts": ["example.com"]})
    assert r.status_code == 409
    assert _NeverScanner.instances == 0


def test_network_scan_refused_when_policy_is_passive_only(client, monkeypatch):
    _pin_ok(monkeypatch)
    from api.security import scan_admission as admission

    monkeypatch.setattr(
        admission, "_control_plane_state",
        lambda: ([], {"mode": "passive"}))
    monkeypatch.setattr("api.routers.network_scans.NetworkTlsScanner", _NeverScanner)
    _NeverScanner.reset()
    r = client.post("/api/v1/network-scans", headers=_auth(client),
                    json={"hosts": ["example.com"]})
    assert r.status_code == 409
    assert "active probing is not authorized" in r.json()["detail"]
    assert _NeverScanner.instances == 0


def test_network_scan_admitted_runs(client, monkeypatch):
    _pin_ok(monkeypatch)
    calls, _inits = _stub_scanner(monkeypatch, "api.routers.network_scans", "NetworkTlsScanner",
                                  {"certificates": [], "usages": [], "hosts": []})
    r = client.post("/api/v1/network-scans", headers=_auth(client),
                    json={"hosts": ["example.com"]})
    assert r.status_code == 200, r.text
    assert calls == [("hosts", ["example.com:443"])]
