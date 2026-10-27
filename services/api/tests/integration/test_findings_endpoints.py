"""Integration tests for findings endpoints."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient


def _finding(**overrides):
    data = dict(
        id="ev-1",
        scan_id="scan-1",
        algorithm="DES",
        key_size=56,
        mode="ECB",
        padding=None,
        purpose="ENCRYPTION",
        confidence="HIGH",
        is_hardcoded_key=False,
        file_path="Pay.java",
        line_number=12,
        class_name="Pay",
        method_name="encrypt",
        compliance_status="FAIL",
        content_hash="ab" * 32,
        chain_hash="cd" * 32,
        normalized_crypto={"standard_name": "DES"},
        policy_evaluation={"overall_status": "FAIL"},
        finding_data={"source": {"code_snippet": "Cipher.getInstance(\"DES\")"}},
    )
    data.update(overrides)
    return SimpleNamespace(**data)


class TestFindingEndpoints:
    @pytest.mark.asyncio
    async def test_list_findings_for_scan(
        self, authenticated_client: AsyncClient, mock_evidence_repo: MagicMock
    ):
        mock_evidence_repo.list_for_scan = MagicMock(return_value=([_finding()], 1))
        response = await authenticated_client.get("/api/v1/scans/scan-1/findings")
        assert response.status_code == 200
        body = response.json()
        assert body["total_count"] == 1
        assert body["findings"][0]["algorithm"] == "DES"

    @pytest.mark.asyncio
    async def test_get_finding_404(self, authenticated_client: AsyncClient, mock_evidence_repo: MagicMock):
        mock_evidence_repo.get_by_id = MagicMock(return_value=None)
        response = await authenticated_client.get("/api/v1/findings/missing")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_finding_projects_legacy_source_without_raw_text(
        self, authenticated_client: AsyncClient, mock_evidence_repo: MagicMock
    ):
        mock_evidence_repo.get_by_id = MagicMock(return_value=_finding())
        response = await authenticated_client.get("/api/v1/findings/ev-1")
        assert response.status_code == 200
        assert response.json()["finding_data"]["source"] == {}
        assert response.json()["redacted_projection"] is True
        assert response.json()["content_hash"] == "ab" * 32
