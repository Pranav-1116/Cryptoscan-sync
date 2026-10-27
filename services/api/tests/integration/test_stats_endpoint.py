"""Integration tests for stats summary."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient


class _Scalar:
    """The two shapes the stats endpoint reads from a result.

    ``scalar_one`` is used for the scan count; the evidence counts come back as
    one row of three aggregates, so ``one`` has to answer too.
    """

    def __init__(self, value, row=(0, 0, 0)):
        self._value = value
        self._row = row

    def scalar_one(self):
        return self._value

    def one(self):
        return self._row


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
