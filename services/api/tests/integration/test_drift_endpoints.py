"""Integration tests for drift endpoints."""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient


def _event(**overrides):
    data = dict(
        id="drift-1",
        current_scan_id="scan-2",
        baseline_id="base-1",
        drift_type="NEW",
        severity="HIGH",
        detected_at=datetime.utcnow(),
        resolution_status="OPEN",
        drift_details={"algorithm": "DES"},
        resolved_by=None,
        resolution_notes=None,
    )
    data.update(overrides)
    return SimpleNamespace(**data)


class TestDriftEndpoints:
    @pytest.mark.asyncio
    async def test_list_drift(self, authenticated_client: AsyncClient, mock_drift_repo: MagicMock):
        mock_drift_repo.list_events = MagicMock(return_value=([_event()], 1))
        response = await authenticated_client.get("/api/v1/drift")
        assert response.status_code == 200
        body = response.json()
        assert body["total_count"] == 1
        assert body["events"][0]["drift_id"] == "drift-1"

    @pytest.mark.asyncio
    async def test_acknowledge_404(self, authenticated_client: AsyncClient, mock_drift_repo: MagicMock):
        mock_drift_repo.acknowledge = MagicMock(return_value=None)
        response = await authenticated_client.post("/api/v1/drift/missing/acknowledge", json={})
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_acknowledge_success(self, authenticated_client: AsyncClient, mock_drift_repo: MagicMock):
        mock_drift_repo.acknowledge = MagicMock(
            return_value=_event(resolution_status="ACKNOWLEDGED", resolved_by="testuser")
        )
        response = await authenticated_client.post(
            "/api/v1/drift/drift-1/acknowledge", json={"notes": "ok"}
        )
        assert response.status_code == 200
        assert response.json()["resolution_status"] == "ACKNOWLEDGED"

    @pytest.mark.asyncio
    async def test_resolve_and_false_positive(self, authenticated_client: AsyncClient, mock_drift_repo: MagicMock):
        mock_drift_repo.resolve = MagicMock(
            return_value=_event(resolution_status="RESOLVED", resolved_by="testuser")
        )
        mock_drift_repo.mark_false_positive = MagicMock(
            return_value=_event(resolution_status="FALSE_POSITIVE", resolved_by="testuser")
        )
        resolved = await authenticated_client.post("/api/v1/drift/drift-1/resolve", json={"notes": "fixed"})
        assert resolved.status_code == 200
        assert resolved.json()["resolution_status"] == "RESOLVED"
        fp = await authenticated_client.post("/api/v1/drift/drift-1/false-positive", json={"notes": "noise"})
        assert fp.status_code == 200
        assert fp.json()["resolution_status"] == "FALSE_POSITIVE"

    @pytest.mark.asyncio
    async def test_digest(self, authenticated_client: AsyncClient, mock_drift_repo: MagicMock):
        mock_drift_repo.list_since = MagicMock(return_value=[_event()])
        response = await authenticated_client.get("/api/v1/drift/digest")
        assert response.status_code == 200
        assert response.json()["total"] == 1
