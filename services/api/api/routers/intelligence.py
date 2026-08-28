"""Evidence packs, CI gate, agility, work-orders, materials, CRA/NIST zip."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from api.config.settings import get_settings
from api.dependencies import (
    get_current_user,
    get_db_session,
    get_drift_repository,
    get_evidence_repository,
    get_scan_repository,
    require_auditor,
)
from api.intelligence.payloads import (
    drift_to_dict,
    evidence_to_dict,
    is_material,
    scan_to_dict,
)
from sqlalchemy.orm import Session

from db.repositories.drift_repository import DriftRepository
from db.repositories.evidence_repository import EvidenceRepository
from db.repositories.scan_repository import ScanRepository
from drift.core.gate import evaluate_gate, gate_to_sarif
from evidence.intelligence.agility import compute_agility
from evidence.intelligence.work_orders import build_work_orders
from evidence.pack.audit_zip import build_audit_zip
from evidence.pack.evidence_pack import build_evidence_pack, verify_evidence_pack
from policy.core.engine import PolicyEngine
from quantum.risk import analyze_quantum_risk
from remediation.engine import suggest_remediations
from reporting.compliance_report import render_html, render_json
from scanner.detectors.materials.pem_scanner import join_materials_to_source

router = APIRouter(tags=["intelligence"])


class VerifyPackRequest(BaseModel):
    pack: dict = Field(..., description="The evidence pack JSON")
    secret: str | None = Field(
        default=None,
        description="Optional HMAC secret. Defaults to this instance SECRET_KEY when the pack is signed.",
    )


class CiGateRequest(BaseModel):
    scan_id: str
    require_baseline: bool = False


def _policy_engine() -> PolicyEngine:
    rules_dir = Path(__file__).resolve().parents[3] / "policy" / "rule_definitions"
    return PolicyEngine(str(rules_dir))


def _require_scan(scan_id: str, scans: ScanRepository):
    scan = scans.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _findings(scan_id: str, evidence: EvidenceRepository) -> list[dict]:
    return [evidence_to_dict(row) for row in evidence.get_all_for_scan(scan_id)]


def _drift_events(scan_id: str, drift: DriftRepository) -> list[dict]:
    events, _ = drift.list_events(scan_id=scan_id, page=1, page_size=500)
    return [drift_to_dict(event) for event in events]


def _build_pack(scan, findings: list[dict]) -> dict:
    settings = get_settings()
    engine = _policy_engine()
    return build_evidence_pack(
        scan=scan_to_dict(scan),
        records=findings,
        policy=engine.pack_descriptor(),
        secret=settings.SECRET_KEY,
    )


@router.get("/scans/{scan_id}/evidence-pack")
def get_evidence_pack(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    scan = _require_scan(scan_id, scans)
    pack = _build_pack(scan, _findings(scan_id, evidence))
    return JSONResponse(
        pack,
        headers={"Content-Disposition": f'attachment; filename="evidence-pack-{scan_id}.json"'},
    )


@router.post("/evidence-pack/verify")
def verify_pack(body: VerifyPackRequest, user: str = Depends(get_current_user)):
    settings = get_settings()
    secret = body.secret if body.secret is not None else settings.SECRET_KEY
    return verify_evidence_pack(body.pack, secret=secret)


@router.get("/scans/{scan_id}/agility")
def get_agility(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    _require_scan(scan_id, scans)
    return compute_agility(_findings(scan_id, evidence))


@router.get("/scans/{scan_id}/work-orders")
def get_work_orders(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    _require_scan(scan_id, scans)
    return build_work_orders(_findings(scan_id, evidence))


def _gate_for(scan_id: str, scans, evidence, drift, require_baseline: bool = False) -> dict:
    scan = _require_scan(scan_id, scans)
    findings = _findings(scan_id, evidence)
    events = _drift_events(scan_id, drift)
    stored = (scan.statistics or {}).get("gate") if isinstance(scan.statistics, dict) else None
    gate = evaluate_gate(findings, events, require_baseline=require_baseline)
    if stored and not events and isinstance(stored, dict) and stored.get("decision"):
        # Prefer freshly computed; stored is a hint only.
        gate.setdefault("stored", stored)
    gate["scan_id"] = scan_id
    gate["sarif"] = gate_to_sarif(gate, scan_id=scan_id)
    return gate


@router.get("/scans/{scan_id}/gate")
def get_gate(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
    drift: DriftRepository = Depends(get_drift_repository),
):
    return _gate_for(scan_id, scans, evidence, drift)


@router.get("/scans/{scan_id}/gate.sarif")
def get_gate_sarif(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
    drift: DriftRepository = Depends(get_drift_repository),
):
    gate = _gate_for(scan_id, scans, evidence, drift)
    return JSONResponse(
        gate["sarif"],
        headers={"Content-Disposition": f'attachment; filename="cryptoscan-gate-{scan_id}.sarif.json"'},
    )


@router.post("/ci/gate")
def ci_gate(
    body: CiGateRequest,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
    drift: DriftRepository = Depends(get_drift_repository),
):
    return _gate_for(body.scan_id, scans, evidence, drift, require_baseline=body.require_baseline)


@router.get("/scans/{scan_id}/materials")
def get_materials(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    _require_scan(scan_id, scans)
    findings = _findings(scan_id, evidence)
    materials = [row for row in findings if is_material(row)]
    source = [row for row in findings if not is_material(row)]
    joined = join_materials_to_source(materials, source)
    return {"count": len(joined), "materials": joined}


@router.get("/scans/{scan_id}/audit-pack")
def get_audit_pack(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
    drift: DriftRepository = Depends(get_drift_repository),
):
    scan = _require_scan(scan_id, scans)
    findings = _findings(scan_id, evidence)
    pack = _build_pack(scan, findings)
    agility = compute_agility(findings)
    orders = build_work_orders(findings)
    gate = evaluate_gate(findings, _drift_events(scan_id, drift))
    sarif = gate_to_sarif(gate, scan_id=scan_id)
    materials = join_materials_to_source(
        [row for row in findings if is_material(row)],
        [row for row in findings if not is_material(row)],
    )
    try:
        from cbom.generator import CbomGenerator

        cbom = CbomGenerator().from_records(
            findings,
            name=scan.target_location or "cryptoscan-target",
            version=(scan.target_commit or "unknown")[:12],
        )
        settings = get_settings()
        if settings.SECRET_KEY:
            cbom = CbomGenerator().sign(cbom, settings.SECRET_KEY)
    except Exception:
        cbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}

    engine = _policy_engine()
    citations = []
    for finding in findings:
        evaluation = finding.get("policy_evaluation") or {}
        for rule in evaluation.get("rules_evaluated") or []:
            if str(rule.get("evaluation_result") or "").upper() == "FAIL":
                citations.append(
                    {
                        "evidence_id": finding.get("evidence_id"),
                        "rule_id": rule.get("rule_id"),
                        "message": rule.get("message"),
                        "algorithm": finding.get("algorithm"),
                        "purpose": finding.get("purpose"),
                    }
                )
    policy = {**engine.pack_descriptor(), "citations": citations}
    blob = build_audit_zip(
        evidence_pack=pack,
        cbom=cbom,
        work_orders=orders,
        agility=agility,
        gate=gate,
        sarif=sarif,
        policy=policy,
        materials={"count": len(materials), "materials": materials},
    )
    return Response(
        content=blob,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="cryptoscan-audit-{scan_id}.zip"'},
    )


@router.get("/scans/{scan_id}/transfer")
def export_scan_transfer(
    scan_id: str,
    user: str = Depends(require_auditor),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    """Export this scan + evidence as a digest-verified transfer payload."""
    from shared_models.chrono import iso_utc

    from evidence.pack.scan_transfer import export_transfer

    scan = _require_scan(scan_id, scans)
    rows = evidence.get_all_for_scan(scan_id)
    records = []
    for row in rows:
        item = evidence_to_dict(row)
        item["previous_hash"] = getattr(row, "previous_hash", None)
        item["provenance"] = getattr(row, "provenance", None)
        records.append(item)
    scan_payload = scan_to_dict(scan)
    scan_payload["scan_start"] = iso_utc(scan.scan_start) if getattr(scan, "scan_start", None) else None
    scan_payload["scan_end"] = iso_utc(scan.scan_end) if getattr(scan, "scan_end", None) else None
    return export_transfer(scan=scan_payload, records=records)


@router.post("/scans/import")
def import_scan_transfer(
    body: dict,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Verify and import a transfer payload from another instance.

    Idempotent: a scan_id that already exists is reported, never duplicated.
    """
    from db.models.evidence_record import EvidenceRecord
    from db.models.scan import Scan
    from evidence.pack.scan_transfer import SCAN_FIELDS, records_for_import, verify_transfer
    from shared_models.chrono import parse_iso, utcnow

    verdict = verify_transfer(body)
    if not verdict["valid"]:
        raise HTTPException(
            status_code=400,
            detail={"message": "transfer verification failed", "errors": verdict["errors"]},
        )
    scan_id = str(verdict["scan_id"])
    if db.get(Scan, scan_id) is not None:
        return {"imported": False, "reason": "scan_already_present", "scan_id": scan_id, "records": 0}
    scan_payload = body.get("scan") or {}
    column_values = {}
    for field in SCAN_FIELDS:
        value = scan_payload.get(field)
        if value is None:
            continue
        column_values[field] = parse_iso(value) if field in {"scan_start", "scan_end"} else value
    scan = Scan(id=scan_id, **column_values)
    if scan.scan_start is None:
        scan.scan_start = utcnow()  # honest fallback: verification passed but no start recorded
    db.add(scan)
    db.flush()
    for row in records_for_import(body):
        db.add(EvidenceRecord(scan_id=scan_id, **row))
    db.flush()
    return {"imported": True, "scan_id": scan_id, "records": verdict["record_count"], "verification": verdict}


@router.get("/scans/{scan_id}/quantum")
def get_quantum(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    _require_scan(scan_id, scans)
    return analyze_quantum_risk(_findings(scan_id, evidence))


@router.get("/scans/{scan_id}/remediation")
def get_remediation(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
):
    _require_scan(scan_id, scans)
    return suggest_remediations(_findings(scan_id, evidence))


@router.get("/scans/{scan_id}/report")
def get_report(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
    drift: DriftRepository = Depends(get_drift_repository),
):
    scan = _require_scan(scan_id, scans)
    findings = _findings(scan_id, evidence)
    report = render_json(
        scan=scan_to_dict(scan),
        findings=findings,
        agility=compute_agility(findings),
        quantum=analyze_quantum_risk(findings),
        gate=evaluate_gate(findings, _drift_events(scan_id, drift)),
    )
    return report


@router.get("/scans/{scan_id}/report.html")
def get_report_html(
    scan_id: str,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
    drift: DriftRepository = Depends(get_drift_repository),
):
    scan = _require_scan(scan_id, scans)
    findings = _findings(scan_id, evidence)
    report = render_json(
        scan=scan_to_dict(scan),
        findings=findings,
        agility=compute_agility(findings),
        quantum=analyze_quantum_risk(findings),
        gate=evaluate_gate(findings, _drift_events(scan_id, drift)),
    )
    return Response(
        content=render_html(report),
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="cryptoscan-report-{scan_id}.html"'},
    )
