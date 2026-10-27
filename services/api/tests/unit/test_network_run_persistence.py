"""Stored scan runs: persist on scan, list/fetch, metrics, drift/latest."""

from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient

from api.dependencies import get_current_user, get_db_session
from api.main import create_app


class Row:
    def __init__(self, **kwargs):
        self.id = kwargs.get("id") or f"run-{kwargs.get('scan_id')}"
        self.scan_id = kwargs.get("scan_id")
        self.target_kind = kwargs.get("target_kind", "hosts")
        self.verdict = kwargs.get("verdict")
        self.probed = kwargs.get("probed")
        self.ok = kwargs.get("ok")
        self.result = kwargs.get("result")
        self.created_at = kwargs.get("created_at")

    def to_dict(self, exclude=None):
        data = {
            "id": self.id, "scan_id": self.scan_id, "target_kind": self.target_kind,
            "verdict": self.verdict, "probed": self.probed, "ok": self.ok,
            "result": self.result, "created_at": self.created_at,
        }
        for key in exclude or set():
            data.pop(key, None)
        return data


class FakeRunRepo:
    store: list[Row] = []

    def __init__(self, _db):
        pass

    def create_run(self, result, *, target_kind="hosts"):
        telemetry = (result or {}).get("probe_telemetry") or {}
        row = Row(
            scan_id=result.get("scan_id"),
            target_kind=target_kind,
            verdict=telemetry.get("status"),
            probed=telemetry.get("probed"),
            ok=telemetry.get("ok"),
            result=result,
            created_at=time.time(),
        )
        FakeRunRepo.store.append(row)
        return row

    def get_run(self, run_id):
        return next((row for row in FakeRunRepo.store if row.id == run_id), None)

    def list_runs(self, *, limit=20, target_kind=None):
        rows = [r for r in FakeRunRepo.store if target_kind is None or r.target_kind == target_kind]
        return sorted(rows, key=lambda r: r.created_at, reverse=True)[:limit]

    def latest_runs(self, *, count=2, target_kind=None):
        return self.list_runs(limit=count, target_kind=target_kind)

    def count_runs(self, *, target_kind=None):
        return len(self.list_runs(limit=10**6, target_kind=target_kind))


def _scan_payload(endpoint_issues=None, version="TLSv1.3"):
    return {
        "scan_id": f"s{len(FakeRunRepo.store)}",
        "findings": [
            {"endpoint": "a:443", "status": "OK", "policy_issues": endpoint_issues or [],
             "crypto": {"tls_version": version, "cipher_suite": "x"}}
        ],
        "certificates": [],
        "probe_telemetry": {"status": "OK", "probed": 1, "ok": 1, "statuses": {"OK": 1}},
    }


@pytest.fixture()
def app_with_fake_runs(monkeypatch):
    import api.routers.network as net_router

    FakeRunRepo.store = []
    monkeypatch.setattr(net_router, "ScanRunRepository", FakeRunRepo)
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"

    def _session():
        yield object()

    app.dependency_overrides[get_db_session] = _session
    return app


@pytest.mark.asyncio
async def test_scan_persists_run(app_with_fake_runs, monkeypatch):
    import network_scanner.core.scanner as scanner_mod

    monkeypatch.setattr(
        scanner_mod.NetworkTlsScanner, "scan_hosts", lambda self, hosts, **kw: _scan_payload()
    )
    transport = ASGITransport(app=app_with_fake_runs)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/network/scan", json={"hosts": ["a:443"]})
    assert response.status_code == 200
    payload = response.json()
    assert payload["run_id"]  # stored run id returned
    assert len(FakeRunRepo.store) == 1
    assert FakeRunRepo.store[0].result["scan_id"] == payload["scan_id"]


@pytest.mark.asyncio
async def test_scan_persist_run_false_skips_storage(app_with_fake_runs, monkeypatch):
    import network_scanner.core.scanner as scanner_mod

    monkeypatch.setattr(
        scanner_mod.NetworkTlsScanner, "scan_hosts", lambda self, hosts, **kw: _scan_payload()
    )
    transport = ASGITransport(app=app_with_fake_runs)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/network/scan", json={"hosts": ["a:443"], "persist_run": False}
        )
    assert response.status_code == 200
    assert "run_id" not in response.json()
    assert FakeRunRepo.store == []


@pytest.mark.asyncio
async def test_storage_failure_does_not_sink_scan(app_with_fake_runs, monkeypatch):
    import api.routers.network as net_router

    class BrokenRepo(FakeRunRepo):
        def create_run(self, result, *, target_kind="hosts"):
            raise RuntimeError("disk full")

    monkeypatch.setattr(net_router, "ScanRunRepository", BrokenRepo)
    import network_scanner.core.scanner as scanner_mod

    monkeypatch.setattr(
        scanner_mod.NetworkTlsScanner, "scan_hosts", lambda self, hosts, **kw: _scan_payload()
    )
    transport = ASGITransport(app=app_with_fake_runs)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/network/scan", json={"hosts": ["a:443"]})
    assert response.status_code == 200
    payload = response.json()
    assert "run_id" not in payload
    assert "storage_error" in payload and "disk full" in payload["storage_error"]


@pytest.mark.asyncio
async def test_list_and_fetch_runs(app_with_fake_runs):
    repo = FakeRunRepo(None)
    repo.create_run(_scan_payload())
    time.sleep(0.01)
    second = repo.create_run(_scan_payload())
    transport = ASGITransport(app=app_with_fake_runs)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        listed = await client.get("/api/v1/network/runs?limit=10")
        fetched = await client.get(f"/api/v1/network/runs/{second.id}")
        missing = await client.get("/api/v1/network/runs/nope")
    assert listed.status_code == 200
    runs = listed.json()["runs"]
    assert len(runs) == 2
    assert all("result" not in row for row in runs)  # metadata only
    assert runs[0]["id"] == second.id  # newest first
    assert fetched.status_code == 200 and fetched.json()["result"]["findings"]
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_run_metrics_endpoint(app_with_fake_runs):
    repo = FakeRunRepo(None)
    row = repo.create_run(_scan_payload(endpoint_issues=["CBC_ACCEPTED"]))
    transport = ASGITransport(app=app_with_fake_runs)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/api/v1/network/runs/{row.id}/metrics")
    assert response.status_code == 200
    assert "version=0.0.4" in response.headers["content-type"]
    assert "cryptoscan_network_scan_probed 1" in response.text


@pytest.mark.asyncio
async def test_drift_latest_between_stored_runs(app_with_fake_runs):
    repo = FakeRunRepo(None)
    repo.create_run(_scan_payload(version="TLSv1.3"))  # yesterday: healthy
    time.sleep(0.01)
    repo.create_run(_scan_payload(version="TLSv1.2", endpoint_issues=["CBC_ACCEPTED"]))
    transport = ASGITransport(app=app_with_fake_runs)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/network/drift/latest")
    assert response.status_code == 200
    report = response.json()
    assert report["verdict"] == "REGRESSED"
    types = [change["type"] for change in report["changes"]]
    assert "TLS_VERSION_DOWNGRADED" in types
    assert report["current_run_id"] and report["previous_run_id"]


@pytest.mark.asyncio
async def test_drift_latest_with_one_run_is_honest(app_with_fake_runs):
    FakeRunRepo(None).create_run(_scan_payload())
    transport = ASGITransport(app=app_with_fake_runs)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/network/drift/latest")
    assert response.status_code == 200
    payload = response.json()
    assert payload["verdict"] == "UNCHANGED"
    assert payload["change_count"] == 0
    assert "needs two" in payload["detail"]
