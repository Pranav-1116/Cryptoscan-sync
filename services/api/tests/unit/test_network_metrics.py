"""POST /network/metrics renders Prometheus text."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from api.dependencies import get_current_user
from api.main import create_app


@pytest.mark.asyncio
async def test_metrics_endpoint_renders_prometheus_text():
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    transport = ASGITransport(app=app)
    report = {
        "probe_telemetry": {
            "status": "PARTIAL", "probed": 3, "ok": 2,
            "statuses": {"OK": 2, "TIMEOUT": 1}, "weak_tls_versions": 1,
        },
        "certificates": [{"fingerprint_sha256": "fp1", "days_until_expiry": 5, "subject": "CN=a"}],
    }
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/network/metrics", json={"report": report})
    assert response.status_code == 200
    assert "version=0.0.4" in response.headers["content-type"]
    body = response.text
    assert "# TYPE cryptoscan_network_probe_status gauge" in body
    assert 'cryptoscan_network_probe_status{status="TIMEOUT"} 1' in body
    assert 'cryptoscan_network_cert_expiry_status{status="EXPIRING_7D"} 1' in body
    assert body.endswith("\n")


@pytest.mark.asyncio
async def test_metrics_endpoint_unknown_payload_still_valid():
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/network/metrics", json={"report": {"x": 1}})
    assert response.status_code == 200
    assert response.text.startswith("# cryptoscan:")
