"""Committed scanner evidence reaches the Twin without a legacy asset write."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib

import pytest

from api import estate_discovery
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.tenancy import tenant_scope

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)
BASE = "/api/v1/estate/evidence"


def _retain(db, *, owner=None, status="COMPLETED", deleted=False):
    scan = Scan(tenant_id=owner, scan_start=datetime.now(timezone.utc),
                status=status, target_location="TEST_ONLY:source-tree")
    db.add(scan)
    db.flush()
    row = EvidenceRecord(
        tenant_id=owner, scan_id=scan.id, content_hash="a" * 64, chain_hash="b" * 64,
        chain_position=0, algorithm="AES-128-GCM", key_size=128, purpose="ENCRYPTION",
        confidence="HIGH", file_path="TEST_ONLY:source.py", line_number=3,
        finding_data={"source": {"type": "SOURCE_CODE"}},
        deleted_at=datetime.now(timezone.utc) if deleted else None,
    )
    db.add(row)
    db.commit()
    return row


def test_completed_unindexed_scan_flows_to_six_boms_twin_and_quarantined_simulation(api):
    http, db = api
    row = _retain(db)
    report_response = http.post(f"{BASE}/scan", json={"planes": ["STATIC"], "persist": True})
    assert report_response.status_code == 200, report_response.text
    report = report_response.json()
    assert report["verdict"] == "COMPLETE"  # only the requested STATIC plane ran
    assert "NETWORK" in report["skipped_planes"]
    assert {bom["projection_id"] for bom in report["boms"].values()} == {report["projection_id"]}
    assert len(report["boms"]) == 6
    static = next(item for item in report["collectors"] if item["plane"] == "STATIC")
    assert static["collected"] == static["expected"] == 1
    assert "unindexed static evidence" in static["reason"]

    twin = http.get(f"{BASE}/twin")
    assert twin.status_code == 200, twin.text
    graph = http.get(f"{BASE}/twin/graph").json()
    assert row.id in str(graph)
    simulation = http.post(f"{BASE}/twin/simulate", json={
        "kind": "REPLACE_ALGORITHM", "from": "AES-128-GCM", "to": "AES-256-GCM"})
    assert simulation.status_code == 200, simulation.text
    assert simulation.json()["status"] == "SIMULATED"
    assert simulation.json()["live_state_modified"] is False
    assert http.get(f"{BASE}/twin").json()["projection_id"] == twin.json()["projection_id"]


def test_real_scanner_finding_reaches_twin_and_simulation(api, tmp_path):
    from scanner.config.scanner_config import ScannerConfig
    from scanner.core.scanner import CryptoScanner

    source = tmp_path / "TestOnly.java"
    source.write_text('import javax.crypto.Cipher; class TestOnly { void run() throws Exception { '
                      'Cipher.getInstance("AES/GCM/NoPadding"); } }')
    result = CryptoScanner(config=ScannerConfig(max_workers=1, timeout_per_file=10,
                                                scan_test_files=True)).scan(tmp_path)
    assert result.scan_completed
    finding = next(row for row in result.findings if row.crypto.algorithm == "AES")
    http, db = api
    scan = Scan(scan_start=datetime.now(timezone.utc), status="COMPLETED",
                target_location=str(tmp_path))
    db.add(scan)
    db.flush()
    db.add(EvidenceRecord(
        scan_id=scan.id, content_hash=hashlib.sha256(source.read_bytes()).hexdigest(),
        chain_hash="c" * 64, chain_position=0, algorithm=finding.crypto.algorithm,
        mode=finding.crypto.mode, confidence="HIGH",
        file_path=str(finding.source.file_path), line_number=finding.source.line_number,
        finding_data=finding.model_dump(mode="json"),
    ))
    db.commit()

    report = http.post(f"{BASE}/scan", json={"planes": ["STATIC"], "persist": True})
    assert report.status_code == 200, report.text
    assert report.json()["summary"]["evidence"] >= 1
    simulation = http.post(f"{BASE}/twin/simulate", json={
        "kind": "REPLACE_ALGORITHM", "from": "AES", "to": "AES-256-GCM"})
    assert simulation.status_code == 200, simulation.text
    assert simulation.json()["status"] == "SIMULATED"
    assert simulation.json()["live_state_modified"] is False


def test_failed_and_tombstoned_scans_never_become_twin_facts(api):
    _http, db = api
    _retain(db, status="FAILED")
    _retain(db, status="COMPLETED", deleted=True)
    plane = estate_discovery.collect_static(db)
    assert plane["collected"] == 0
    assert not plane["evidence"]


def test_indexed_evidence_is_not_counted_again_as_an_unindexed_scan_row(api):
    from db.models.crypto_asset import CryptoAsset
    from db.models.crypto_asset_evidence import CryptoAssetEvidence

    _http, db = api
    row = _retain(db)
    asset = CryptoAsset(algorithm=row.algorithm, purpose=row.purpose, key_size=row.key_size,
                        file_path=row.file_path, line_number=row.line_number)
    db.add(asset)
    db.flush()
    db.add(CryptoAssetEvidence(asset_id=asset.id, evidence_id=row.id))
    db.commit()
    plane = estate_discovery.collect_static(db)
    assert plane["expected"] == plane["collected"] == 1
    assert len(plane["evidence"]) == 1


def test_bounded_scan_history_is_partial_even_if_the_read_page_is_empty(api):
    _http, db = api
    _retain(db)
    for index in range(21):
        db.add(Scan(scan_start=datetime.now(timezone.utc), status="COMPLETED",
                    target_location=f"TEST_ONLY:other-source-{index}"))
    db.commit()
    report = estate_discovery.run(db, planes=["STATIC"], persist=False)
    static = next(item for item in report["collectors"] if item["plane"] == "STATIC")
    assert static["status"] == "PARTIAL"
    assert "only the newest 20" in static["reason"]
    assert "may under-report" in static["impact"]


def test_retained_static_facts_remain_in_their_own_tenant(api):
    _http, db = api
    first = _retain(db, owner="bank-a")
    _retain(db, owner="bank-b")
    with tenant_scope("bank-a"):
        plane = estate_discovery.collect_static(db)
    assert plane["collected"] == 1
    assert plane["evidence"][0]["evidence_id"] == first.id
    assert plane["evidence"][0]["facts"]["usage_state_hint"] == "STATIC_PRESENCE_ONLY"
