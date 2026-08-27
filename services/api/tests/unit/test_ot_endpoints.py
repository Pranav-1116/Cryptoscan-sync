"""POST /ot/metrics renders Prometheus text for OT scan results."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from api.dependencies import get_current_user
from api.main import create_app


@pytest.mark.asyncio
async def test_ot_metrics_endpoint_renders_prometheus_text():
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    transport = ASGITransport(app=app)
    report = {
        "device_count": 2,
        "unencrypted": 1,
        "findings": [
            {
                "protocol": "Modbus TCP", "security_level": "NONE", "has_crypto": False,
                "compliance_issue": "OT_UNENCRYPTED_MODBUS",
                "device": {"ip_address": "10.0.0.2", "criticality": "SAFETY_CRITICAL"},
            },
            {
                "protocol": "OPC-UA", "security_level": "ENCRYPT", "has_crypto": True,
                "compliance_issue": None,
                "device": {"ip_address": "10.0.0.1", "criticality": "SAFETY_CRITICAL"},
            },
        ],
        "risk_report": {
            "posture": "FAIL", "device_count": 2, "unencrypted_observations": 1,
            "weak_crypto_observations": 0, "devices_with_cves": [],
            "protocol_counts": {"Modbus TCP": 1, "OPC-UA": 1},
            "security_level_counts": {"ENCRYPT": 1, "NONE": 1},
            "issue_counts": {"OT_UNENCRYPTED_MODBUS": 1},
        },
        "ot_telemetry": {"status": "OK", "records_analyzed": 2, "packets_sent": 0},
    }
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/ot/metrics", json={"report": report})
    assert response.status_code == 200
    assert "version=0.0.4" in response.headers["content-type"]
    body = response.text
    assert "# TYPE cryptoscan_ot_devices gauge" in body
    assert "cryptoscan_ot_devices 2" in body
    assert 'cryptoscan_ot_findings_by_protocol{protocol="Modbus TCP"} 1' in body
    assert 'cryptoscan_ot_posture{posture="FAIL"} 1' in body
    assert 'cryptoscan_ot_scan_verdict{verdict="OK"} 1' in body
    # the passive guarantee is always on the record
    assert "cryptoscan_ot_packets_sent 0" in body
    assert body.endswith("\n")


@pytest.mark.asyncio
async def test_ot_metrics_endpoint_unknown_payload_still_valid():
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/ot/metrics", json={"report": {"x": 1}})
    assert response.status_code == 200
    assert response.text.startswith("# cryptoscan:")
