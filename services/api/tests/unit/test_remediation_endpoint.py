"""/scans/{id}/remediation now returns prioritized suggestions + backlog."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from api.dependencies import get_current_user, get_evidence_repository, get_scan_repository
from api.main import create_app


def _evidence_row(eid, algorithm, status="FAIL", **extra):
    return SimpleNamespace(
        id=eid,
        scan_id="scan-1",
        algorithm=algorithm,
        key_size=extra.get("key_size"),
        mode=extra.get("mode"),
        purpose=extra.get("purpose", "ENCRYPTION"),
        file_path=extra.get("file_path", "src/App.java"),
        line_number=extra.get("line_number", 1),
        compliance_status=status,
        is_hardcoded_key=False,
        finding_data={},
    )


@pytest.fixture()
def app_remediation():
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"
    application.dependency_overrides[get_scan_repository] = lambda: SimpleNamespace(
        get_by_id=lambda scan_id: SimpleNamespace(id=scan_id) if scan_id == "scan-1" else None
    )
    application.dependency_overrides[get_evidence_repository] = lambda: SimpleNamespace(
        get_all_for_scan=lambda scan_id: [
            _evidence_row("e1", "DES", file_path="src/A.java", line_number=10),
            _evidence_row("e2", "RSA-2048", file_path="src/B.java", line_number=20),
            _evidence_row("e3", "RSA-4096", file_path="src/C.java", line_number=30),
        ]
        if scan_id == "scan-1"
        else []
    )
    return application


@pytest.mark.asyncio
async def test_remediation_endpoint_returns_prioritized_backlog(app_remediation):
    transport = ASGITransport(app=app_remediation)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/scans/scan-1/remediation")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 3
    # P0 first: DES before both RSA sites
    assert body["suggestions"][0]["rule"] == "replace-des"
    assert body["suggestions"][0]["priority"] == "P0"
    # family-prefix matching through the API path
    assert {row["algorithm"] for row in body["suggestions"]} == {"DES", "RSA-2048", "RSA-4096"}
    # backlog groups the two RSA sites into one workstream
    backlog = body["backlog"]
    assert backlog["total_rules"] == 2
    assert backlog["total_sites"] == 3
    rsa_item = next(item for item in backlog["items"] if item["rule"] == "plan-rsa-pqc")
    assert rsa_item["site_count"] == 2
    assert rsa_item["wave"] == 3
    assert backlog["waves"]["1"]["site_count"] == 1
    assert "policy engine" in body["disclaimer"]


@pytest.mark.asyncio
async def test_remediation_endpoint_404_for_unknown_scan(app_remediation):
    transport = ASGITransport(app=app_remediation)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/scans/nope/remediation")
    assert response.status_code == 404
