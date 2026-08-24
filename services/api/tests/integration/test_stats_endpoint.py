"""Integration tests for stats summary."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient


class _Scalar:
    def __init__(self, value):
        self._value = value

    def scalar_one(self):
        return self._value


class TestStatsEndpoint:
    @pytest.mark.asyncio
    async def test_summary_unauthenticated(self, client: AsyncClient):
        response = await client.get("/api/v1/stats/summary")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_summary_ok(self, authenticated_client: AsyncClient, app, mock_db_session: MagicMock):
        mock_db_session.execute = MagicMock(return_value=_Scalar(0))

        class _Drift:
            def open_counts_by_severity(self):
                return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}

        class _Evidence:
            def algorithm_breakdown(self):
                return []

        import api.routers.stats as stats_mod

        original_drift = stats_mod.DriftRepository
        original_ev = stats_mod.EvidenceRepository
        stats_mod.DriftRepository = lambda db: _Drift()
        stats_mod.EvidenceRepository = lambda db: _Evidence()
        try:
            response = await authenticated_client.get("/api/v1/stats/summary")
        finally:
            stats_mod.DriftRepository = original_drift
            stats_mod.EvidenceRepository = original_ev
        assert response.status_code == 200
        body = response.json()
        assert "total_scans" in body
        assert "total_findings" in body
