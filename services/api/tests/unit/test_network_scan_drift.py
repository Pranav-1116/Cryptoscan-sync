"""POST /network/scan/drift diffs two scan results."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from api.dependencies import get_current_user
from api.main import create_app


def _scan(findings, certs=None, scan_id="s"):
    return {"scan_id": scan_id, "findings": findings, "certificates": certs or []}


@pytest.mark.asyncio
async def test_scan_drift_endpoint_flags_downgrade():
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    transport = ASGITransport(app=app)
    previous = _scan(
        [{"endpoint": "a:443", "status": "OK", "policy_issues": [],
          "crypto": {"tls_version": "TLSv1.3", "cipher_suite": "x"}}],
        scan_id="prev",
    )
    current = _scan(
        [{"endpoint": "a:443", "status": "OK", "policy_issues": ["CBC_ACCEPTED"],
          "crypto": {"tls_version": "TLSv1.2", "cipher_suite": "AES128-SHA"}}],
        [{"fingerprint_sha256": "fp1", "days_until_expiry": -1, "subject": "CN=a"}],
        scan_id="cur",
    )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/network/scan/drift",
            json={"previous": previous, "current": current, "expiry_warn_days": 7},
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["verdict"] == "REGRESSED"
    types = [change["type"] for change in payload["changes"]]
    assert "TLS_VERSION_DOWNGRADED" in types
    assert "POLICY_ISSUE_APPEARED" in types
    assert payload["severity_counts"]["HIGH"] >= 1
    assert payload["previous_scan_id"] == "prev" and payload["current_scan_id"] == "cur"


@pytest.mark.asyncio
async def test_scan_drift_identical_is_unchanged():
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    transport = ASGITransport(app=app)
    scan = _scan([{"endpoint": "a:443", "status": "OK", "policy_issues": [],
                   "crypto": {"tls_version": "TLSv1.3", "cipher_suite": "x"}}])
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/network/scan/drift", json={"previous": scan, "current": scan}
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["verdict"] == "UNCHANGED"
    assert payload["change_count"] == 0
