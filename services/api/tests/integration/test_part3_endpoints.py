from __future__ import annotations

from pathlib import Path

import pytest
from httpx import AsyncClient


class TestPart3Endpoints:
    @pytest.mark.asyncio
    async def test_cloud_scan_iac(self, authenticated_client: AsyncClient, tmp_path: Path):
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" { bucket = "x" }\n')
        response = await authenticated_client.post(
            "/api/v1/cloud/scan", json={"path": str(tmp_path), "live": False}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["resources"] >= 1
        assert body["issues"] >= 1

    @pytest.mark.asyncio
    async def test_network_scan_path_offline(self, authenticated_client: AsyncClient, tmp_path: Path):
        (tmp_path / "ingress.yaml").write_text(
            "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: web\n"
            "spec:\n  tls:\n    - hosts: [\"web.example.com\"]\n  rules:\n    - host: web.example.com\n"
        )
        response = await authenticated_client.post(
            "/api/v1/network/scan-path", json={"path": str(tmp_path), "live": False}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["live"] is False
        assert body["targets"]
