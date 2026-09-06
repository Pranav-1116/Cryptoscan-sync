"""Integration tests for scan list/detail endpoints."""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient


def _scan(**overrides):
    data = dict(
        id="scan-1",
        status="COMPLETED",
        target_location="local://demo/vulnerable-app",
        target_type="LOCAL_DIRECTORY",
        target_branch="main",
        target_commit="abc123",
        scanner_id="static-java-scanner-v0.1",
        scanner_version="0.1.0",
        operator="admin",
        scan_start=datetime.utcnow(),
        scan_end=datetime.utcnow(),
        duration_seconds=1.2,
        statistics={"total_findings": 13},
        manifest_hash="aa" * 32,
        error_message=None,
    )
    data.update(overrides)
    return SimpleNamespace(**data)


class TestScanEndpoints:
    @pytest.mark.asyncio
    async def test_list_scans(self, authenticated_client: AsyncClient, mock_scan_repo: MagicMock):
        mock_scan_repo.list_scans = MagicMock(return_value=([_scan()], 1))
        response = await authenticated_client.get("/api/v1/scans")
        assert response.status_code == 200
        body = response.json()
        assert body["total_count"] == 1
        assert body["scans"][0]["scan_id"] == "scan-1"

    @pytest.mark.asyncio
    async def test_get_scan_404(self, authenticated_client: AsyncClient, mock_scan_repo: MagicMock):
        mock_scan_repo.get_by_id = MagicMock(return_value=None)
        response = await authenticated_client.get("/api/v1/scans/missing")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_scan_success(self, authenticated_client: AsyncClient, mock_scan_repo: MagicMock):
        mock_scan_repo.get_by_id = MagicMock(return_value=_scan())
        response = await authenticated_client.get("/api/v1/scans/scan-1")
        assert response.status_code == 200
        assert response.json()["status"] == "COMPLETED"

    @pytest.mark.asyncio
    async def test_list_scans_unauthenticated(self, client: AsyncClient):
        response = await client.get("/api/v1/scans")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_retry_scan(
        self,
        authenticated_client: AsyncClient,
        mock_scan_repo: MagicMock,
        mock_job_repo: MagicMock,
    ):
        mock_scan_repo.get_by_id = MagicMock(return_value=_scan())
        mock_job_repo.create = MagicMock(
            return_value=SimpleNamespace(job_id="retry-1", status="QUEUED", created_at=datetime.utcnow())
        )
        response = await authenticated_client.post("/api/v1/scans/scan-1/retry")
        assert response.status_code == 200
        assert response.json()["job_id"] == "retry-1"

    @pytest.mark.asyncio
    async def test_retry_scan_denied_low_privilege(
        self,
        lowpriv_client: AsyncClient,
        mock_scan_repo: MagicMock,
        mock_job_repo: MagicMock,
    ):
        """BFLA: a read-only authenticated user must not re-trigger a scan."""
        mock_scan_repo.get_by_id = MagicMock(return_value=_scan())
        response = await lowpriv_client.post("/api/v1/scans/scan-1/retry")
        assert response.status_code == 403
        # no job may be enqueued on a denied retry
        mock_job_repo.create.assert_not_called()
