"""POST /container/scan returns the enriched payload (secrets, risk, telemetry)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from api.dependencies import get_current_user, get_db_session
from api.main import create_app


class FakeScanRepo:
    rows = []

    def __init__(self, _db):
        pass


class FakeVulnRepo:
    def __init__(self, _db):
        pass

    def replace_for_scan(self, _scan_id, _vulns):
        return None


@pytest.fixture()
def app(monkeypatch, tmp_path):
    import db.models.container_scan as container_scan_model  # noqa: F401 — table registered

    (tmp_path / "requirements.txt").write_text("pycrypto==2.6.1\n")
    (tmp_path / ".env").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n")
    scan_root = tmp_path / "rootfs"
    scan_root.mkdir()
    (scan_root / "requirements.txt").write_text("pycrypto==2.6.1\n")
    (scan_root / ".env").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n")

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"

    def _session():
        yield _FakeSession()

    application.dependency_overrides[get_db_session] = _session
    return application, str(scan_root)


class _FakeSession:
    def add(self, _row):
        pass

    def flush(self):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass


@pytest.mark.asyncio
async def test_container_scan_returns_risk_and_telemetry(app):
    application, root = app
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/container/scan", json={"path": root, "live_cve": False})
    assert response.status_code == 200
    payload = response.json()
    assert payload["risk_report"]["posture"] == "FAIL"
    assert "HARDCODED_PRIVATE_KEY" in payload["risk_report"]["policy_issues"]
    assert payload["secrets"] and payload["secrets"][0]["kind"] == "pem-private-key"
    assert payload["scan_telemetry"]["status"] in {"OK", "PARTIAL"}
    assert payload["scan_telemetry"]["secrets_by_kind"] == {"pem-private-key": 1}
    hardcoded = [f for f in payload["findings"] if f["metadata"]["is_hardcoded_key"]]
    assert hardcoded


@pytest.mark.asyncio
async def test_container_scan_missing_path_is_404(app):
    application, _root = app
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/container/scan", json={"path": "/nonexistent-rootfs", "live_cve": False}
        )
    assert response.status_code == 404
