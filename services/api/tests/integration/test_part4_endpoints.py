from __future__ import annotations

from pathlib import Path

import pytest
from httpx import AsyncClient


class TestPart4Endpoints:
    @pytest.mark.asyncio
    async def test_ot_scan_passive(self, authenticated_client: AsyncClient, tmp_path: Path):
        (tmp_path / "modbus.log").write_text(
            "ts=2024-01-15T10:00:00 src=10.0.2.28 dst=10.0.2.1 port=502 proto=modbus tls=false\n"
        )
        response = await authenticated_client.post("/api/v1/ot/scan", json={"path": str(tmp_path)})
        assert response.status_code == 200
        body = response.json()
        assert body["packets_sent"] == 0
        assert body["findings"]
        assert body["findings"][0]["compliance_issue"] == "OT_UNENCRYPTED_MODBUS"

    @pytest.mark.asyncio
    async def test_cloud_scan_arm(self, authenticated_client: AsyncClient, tmp_path: Path):
        (tmp_path / "azuredeploy.json").write_text(
            '{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",'
            '"resources":[{"type":"Microsoft.Storage/storageAccounts","name":"logs",'
            '"properties":{"supportsHttpsTrafficOnly":false}}]}'
        )
        response = await authenticated_client.post("/api/v1/cloud/scan", json={"path": str(tmp_path), "live": False})
        assert response.status_code == 200
        assert response.json()["issues"] >= 1
