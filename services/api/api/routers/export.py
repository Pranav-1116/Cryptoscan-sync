"""CBOM export and integrity verification."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from api.dependencies import get_current_user, get_evidence_repository, get_scan_repository
from db.repositories.evidence_repository import EvidenceRepository
from db.repositories.scan_repository import ScanRepository
from evidence.hashing.chain_hasher import ChainHasher
from evidence.hashing.content_hasher import ContentHasher

router = APIRouter(tags=["export"])


@router.get("/scans/{scan_id}/export")
def export_scan(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    scan = scans.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    rows = evidence.get_all_for_scan(scan_id)
    payload = {
        "scan": {
            "scan_id": scan.id,
            "status": scan.status,
            "target_location": scan.target_location,
            "target_branch": scan.target_branch,
            "target_commit": scan.target_commit,
            "statistics": scan.statistics,
            "manifest_hash": scan.manifest_hash,
        },
        "findings": [row.to_dict() for row in rows],
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "exported_by": user,
    }
    return JSONResponse(payload)


@router.get("/scans/{scan_id}/cbom")
def export_cbom(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    scan = scans.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    rows = evidence.get_all_for_scan(scan_id)
    components = []
    for row in rows:
        normalized = row.normalized_crypto or {}
        components.append(
            {
                "type": normalized.get("cbom_component_type") or "cryptographic-asset",
                "name": normalized.get("standard_name") or row.algorithm,
                "bom-ref": row.id,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": normalized.get("algorithm_family") or "unknown",
                        "algorithm": row.algorithm,
                        "mode": row.mode,
                        "padding": row.padding,
                        "parameterSetIdentifier": str(row.key_size) if row.key_size else None,
                    },
                    "nistDesignation": normalized.get("nist_designation"),
                    "quantumVulnerable": normalized.get("quantum_vulnerable"),
                },
                "evidence": {
                    "file": row.file_path,
                    "line": row.line_number,
                    "content_hash": row.content_hash,
                    "chain_hash": row.chain_hash,
                    "compliance_status": row.compliance_status,
                },
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": scan.target_location,
                "version": scan.target_commit or scan.target_branch or "unknown",
            },
            "tools": [{"name": "CryptoScan", "version": scan.scanner_version}],
        },
        "components": components,
    }


@router.get("/scans/{scan_id}/verify")
def verify_scan(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    scan = scans.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    rows = evidence.get_all_for_scan(scan_id)
    content_hashes = [r.content_hash for r in rows]
    chain_hashes = [r.chain_hash for r in rows]
    chain_ok = ChainHasher.verify_chain(content_hashes, chain_hashes, scan_id) if rows else True
    hash_ok = all(len(h or "") == 64 for h in content_hashes + chain_hashes)
    return {
        "scan_id": scan_id,
        "records": len(rows),
        "chain_intact": chain_ok,
        "hash_format_valid": hash_ok,
        "manifest_hash": scan.manifest_hash,
        "result": "PASS" if chain_ok and hash_ok else "FAIL",
        "verified_by": user,
        "content_hasher": ContentHasher.ALGORITHM,
    }
