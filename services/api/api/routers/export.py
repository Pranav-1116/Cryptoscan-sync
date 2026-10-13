"""CBOM export and integrity verification."""

from __future__ import annotations

from datetime import datetime, timezone

import csv
import io

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, Response

from api.dependencies import (
    get_current_user,
    get_db_session,
    get_evidence_repository,
    get_scan_repository,
)
from api.routers.evidence_disposition import export_refused_reason
from api.security.evidence_projection import project_finding, public_evidence_row
from sqlalchemy.orm import Session

from db.repositories.evidence_repository import EvidenceRepository
from db.repositories.scan_repository import ScanRepository
from evidence.hashing.content_hasher import ContentHasher
from evidence.verification.stored_scan import verify_stored_scan

router = APIRouter(tags=["export"])


@router.get("/scans/{scan_id}/export")
def export_scan(
    scan_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    scan = scans.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    # §4.2 (round 40): an operator disposition can quarantine a scan's
    # exports until a re-issued chain exists. Refuse, citing the decision.
    refused = export_refused_reason(db, scan_id)
    if refused:
        raise HTTPException(status_code=409, detail=refused)
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
        "findings": [public_evidence_row(row) for row in rows],
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "exported_by": user,
    }
    return JSONResponse(payload)


@router.get("/scans/{scan_id}/export.csv")
def export_scan_csv(
    scan_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    scan = scans.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    refused = export_refused_reason(db, scan_id)
    if refused:
        raise HTTPException(status_code=409, detail=refused)
    rows = evidence.get_all_for_scan(scan_id)
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "evidence_id",
            "scan_id",
            "algorithm",
            "mode",
            "key_size",
            "purpose",
            "file_path",
            "line_number",
            "confidence",
            "compliance_status",
            "is_hardcoded_key",
            "content_hash",
        ],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "evidence_id": row.id,
                "scan_id": row.scan_id,
                "algorithm": row.algorithm,
                "mode": row.mode or "",
                "key_size": row.key_size or "",
                "purpose": row.purpose or "",
                "file_path": row.file_path,
                "line_number": row.line_number,
                "confidence": row.confidence,
                "compliance_status": row.compliance_status or "",
                "is_hardcoded_key": row.is_hardcoded_key,
                "content_hash": row.content_hash,
            }
        )
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.csv"'},
    )


@router.get("/scans/{scan_id}/verification-script")
def export_verification_script(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    scan = scans.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    from evidence.scripts.verification_script_generator import generate_verification_script

    script = generate_verification_script(scan_id=scan_id, records=evidence.get_all_for_scan(scan_id))
    return Response(
        content=script,
        media_type="text/x-python",
        headers={"Content-Disposition": f'attachment; filename="verify-{scan_id}.py"'},
    )


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
    # key-inventory records: export metadata as CycloneDX properties (labels, store, state, dates — never values)
    for row, comp in zip(rows, components):
        inv = project_finding(row.finding_data)[0].get("inventory")
        if inv:
            comp["properties"] = [{"name": f"cryptoscan:key:{k}", "value": str(v)} for k, v in sorted(inv.items()) if v not in (None, "", [])][:24]
            comp["cryptoProperties"]["assetType"] = "related-crypto-material" if inv.get("key_label") and not inv.get("subject") else ("certificate" if inv.get("subject") else "algorithm")
    root_ref = f"root:{scan.id}"
    extra_components, dependencies = _cascade_dependencies(root_ref, (scan.statistics or {}).get("cascade") or {}, rows)
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": scan.target_location,
                "version": scan.target_commit or scan.target_branch or "unknown",
                "bom-ref": root_ref,
            },
            "tools": [{"name": "CryptoScan", "version": scan.scanner_version}],
        },
        "components": components + extra_components,
    }
    if dependencies:
        bom["dependencies"] = dependencies
    return bom


def _cascade_dependencies(root_ref: str, cascade: dict, rows) -> tuple[list[dict], list[dict]]:
    """Real CycloneDX `dependencies[]` from the scan's dependency & cascade analysis.

    file components for crypto-provider files (file → the crypto assets found in it, file → provider files it
    imports crypto from) and application components for business systems declared in cryptoscan-systems.yml
    (system → its provider files, system → systems whose crypto it imports). Root depends on systems (or on
    provider files when no system map exists). Every ref points at a component in this BOM.
    """
    providers = cascade.get("providers") or []
    systems = cascade.get("systems") or []
    if not providers:
        return [], []
    from fnmatch import fnmatch

    def _in(path: str, globs: list[str]) -> bool:
        path = path.split("!", 1)[0]
        return any(path == g.rstrip("/") or path.startswith(g.rstrip("/").removesuffix("/**").removesuffix("/*") + "/") or fnmatch(path, g) for g in globs)

    assets_by_file: dict[str, list[str]] = {}
    for row in rows:
        assets_by_file.setdefault(str(row.file_path).split("!", 1)[0], []).append(row.id)
    file_refs = {p["file"]: f"file:{p['file']}" for p in providers}
    components: list[dict] = []
    deps: list[dict] = []
    for p in providers:
        components.append({"type": "file", "name": p["file"], "bom-ref": file_refs[p["file"]],
                           "properties": [{"name": "cryptoscan:cascade:wave", "value": str(p.get("wave"))},
                                          {"name": "cryptoscan:cascade:direct_dependents", "value": str(p.get("direct_dependents", 0))},
                                          {"name": "cryptoscan:cascade:transitive_dependents", "value": str(p.get("transitive_dependents", 0))},
                                          {"name": "cryptoscan:cascade:algorithms", "value": ",".join(p.get("algorithms") or [])}]})
        depends = list(assets_by_file.get(p["file"], [])) + [file_refs[q] for q in (p.get("depends_on_providers") or []) if q in file_refs]
        if depends:
            deps.append({"ref": file_refs[p["file"]], "dependsOn": depends})
    sys_refs = {s["system"]: f"system:{s['system']}" for s in systems}
    for s in systems:
        components.append({"type": "application", "name": s["system"], "bom-ref": sys_refs[s["system"]],
                           "properties": [{"name": "cryptoscan:system:criticality", "value": str(s.get("criticality") or "")},
                                          {"name": "cryptoscan:system:earliest_wave", "value": str(s.get("earliest_wave") or "")}]})
        depends = [file_refs[p["file"]] for p in providers if _in(p["file"], s.get("paths") or [])]
        depends += [sys_refs[d] for d in (s.get("depends_on_systems") or []) if d in sys_refs]
        if depends:
            deps.append({"ref": sys_refs[s["system"]], "dependsOn": depends})
    top = list(sys_refs.values()) or list(file_refs.values())
    deps.insert(0, {"ref": root_ref, "dependsOn": top})
    return components, deps


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
    verdict = verify_stored_scan(scan, evidence.get_all_for_scan(scan_id))
    return {**verdict, "verified_by": user, "content_hasher": ContentHasher.ALGORITHM}


@router.get("/export/findings.csv")
def export_findings_csv(
    algorithm: str | None = None,
    compliance_status: str | None = None,
    scan_id: str | None = None,
    limit: int = 10000,
    user: str = Depends(get_current_user),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    """Estate-wide findings export (W59-60): Excel-compatible CSV over all scans.

    Honest scope: CSV (not .xlsx) — it opens directly in Excel/LibreOffice and
    stays diffable in git. Rows are capped (default 10k, max 50k) so a single
    request cannot exhaust memory; the response reports truncation.
    """
    limit = max(1, min(limit, 50_000))
    page_size = 1000
    rows: list = []
    page = 1
    total = 0
    while len(rows) < limit:
        chunk, total = evidence.list_all(
            algorithm=algorithm,
            compliance_status=compliance_status,
            scan_id=scan_id,
            page=page,
            page_size=page_size,
        )
        if not chunk:
            break
        rows.extend(chunk)
        if page * page_size >= total:
            break
        page += 1
    rows = rows[:limit]
    truncated = total > len(rows)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "evidence_id", "scan_id", "algorithm", "purpose", "mode", "key_size",
            "file_path", "line_number", "compliance_status", "is_hardcoded_key",
            "confidence", "created_at",
        ]
    )
    for r in rows:
        writer.writerow(
            [
                r.id, r.scan_id, r.algorithm, r.purpose or "", r.mode or "",
                r.key_size if r.key_size is not None else "",
                r.file_path or "", r.line_number or 0,
                r.compliance_status or "", bool(r.is_hardcoded_key),
                r.confidence or "",
                r.created_at.isoformat() if r.created_at else "",
            ]
        )
    from urllib.parse import quote

    filename = quote("cryptoscan-findings.csv")
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Total-Matching": str(total),
            "X-Exported-Rows": str(len(rows)),
            "X-Truncated": "true" if truncated else "false",
        },
    )
