"""Intelligence endpoints: pack, gate, agility, work-orders, audit zip."""

from __future__ import annotations

import hashlib
import io
import zipfile
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient

from evidence.hashing.chain_hasher import ChainHasher


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
        statistics={"total_findings": 2},
        manifest_hash="aa" * 32,
        error_message=None,
    )
    data.update(overrides)
    return SimpleNamespace(**data)


def _row(scan_id: str, index: int, algorithm: str, purpose: str, status: str, raw: str):
    content = hashlib.sha256(raw.encode()).hexdigest()
    return SimpleNamespace(
        id=f"finding-{index}",
        scan_id=scan_id,
        algorithm=algorithm,
        key_size=None,
        mode="ECB" if algorithm == "DES" else "GCM",
        padding=None,
        purpose=purpose,
        confidence="HIGH",
        is_hardcoded_key=False,
        file_path=f"{algorithm.lower()}.java",
        line_number=index + 1,
        class_name=None,
        method_name=None,
        compliance_status=status,
        content_hash=content,
        chain_hash="",
        chain_position=index,
        normalized_crypto={},
        policy_evaluation={
            "rules_evaluated": [
                {
                    "rule_id": "BASELINE-001",
                    "evaluation_result": status,
                    "message": "unit",
                    "severity": "HIGH",
                }
            ]
        },
        finding_data={"crypto": {"raw_transformation": raw}, "metadata": {"confidence_reason": "literal-api"}},
    )


def _seed_rows(mock_evidence_repo: MagicMock, scan_id: str = "scan-1"):
    rows = [
        _row(scan_id, 0, "DES", "ENCRYPTION", "FAIL", "DES/ECB/PKCS5Padding"),
        _row(scan_id, 1, "AES", "ENCRYPTION", "PASS", "AES/GCM/NoPadding"),
    ]
    hashes = [row.content_hash for row in rows]
    chain = ChainHasher.compute_chain(hashes, scan_id)
    for row, digest in zip(rows, chain):
        row.chain_hash = digest
    mock_evidence_repo.get_all_for_scan = MagicMock(return_value=rows)
    return rows


class TestIntelligenceEndpoints:
    @pytest.mark.asyncio
    async def test_evidence_pack_and_verify(
        self,
        authenticated_client: AsyncClient,
        mock_scan_repo: MagicMock,
        mock_evidence_repo: MagicMock,
    ):
        mock_scan_repo.get_by_id = MagicMock(return_value=_scan())
        _seed_rows(mock_evidence_repo)
        response = await authenticated_client.get("/api/v1/scans/scan-1/evidence-pack")
        assert response.status_code == 200
        pack = response.json()
        assert pack["pack_format"] == "cryptoscan-evidence-pack"
        assert pack["integrity"]["signed"] is True
        verify = await authenticated_client.post("/api/v1/evidence-pack/verify", json={"pack": pack})
        assert verify.status_code == 200
        assert verify.json()["result"] == "PASS"

    @pytest.mark.asyncio
    async def test_gate_and_work_orders(
        self,
        authenticated_client: AsyncClient,
        mock_scan_repo: MagicMock,
        mock_evidence_repo: MagicMock,
        mock_drift_repo: MagicMock,
    ):
        mock_scan_repo.get_by_id = MagicMock(return_value=_scan())
        _seed_rows(mock_evidence_repo)
        mock_drift_repo.list_events = MagicMock(return_value=([], 0))
        gate = await authenticated_client.get("/api/v1/scans/scan-1/gate")
        assert gate.status_code == 200
        body = gate.json()
        assert body["decision"] == "FAIL"
        assert body["sarif"]["version"] == "2.1.0"
        orders = await authenticated_client.get("/api/v1/scans/scan-1/work-orders")
        assert orders.status_code == 200
        assert orders.json()["total_orders"] >= 1
        agility = await authenticated_client.get("/api/v1/scans/scan-1/agility")
        assert agility.status_code == 200
        assert "score" in agility.json()
        ci = await authenticated_client.post("/api/v1/ci/gate", json={"scan_id": "scan-1"})
        assert ci.status_code == 200
        assert ci.json()["decision"] == "FAIL"

    @pytest.mark.asyncio
    async def test_audit_pack_zip(
        self,
        authenticated_client: AsyncClient,
        mock_scan_repo: MagicMock,
        mock_evidence_repo: MagicMock,
        mock_drift_repo: MagicMock,
    ):
        mock_scan_repo.get_by_id = MagicMock(return_value=_scan())
        _seed_rows(mock_evidence_repo)
        mock_drift_repo.list_events = MagicMock(return_value=([], 0))
        response = await authenticated_client.get("/api/v1/scans/scan-1/audit-pack")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/zip")
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            names = set(archive.namelist())
        assert "evidence-pack.json" in names
        assert "verify_pack.py" in names
        assert "work-orders.json" in names
        assert "cbom.json" in names

    @pytest.mark.asyncio
    async def test_missing_scan(
        self,
        authenticated_client: AsyncClient,
        mock_scan_repo: MagicMock,
    ):
        mock_scan_repo.get_by_id = MagicMock(return_value=None)
        response = await authenticated_client.get("/api/v1/scans/missing/evidence-pack")
        assert response.status_code == 404
