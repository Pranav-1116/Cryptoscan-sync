"""Evidence packs, CI gate, agility, work-orders, materials, CRA/NIST zip."""

from __future__ import annotations

from db.tenancy import filtered_get

from pathlib import Path

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
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

import logging

logger = logging.getLogger(__name__)


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
    # standard | strict | lenient (see drift.core.gate.apply_gate_profile)
    profile: Literal["standard", "strict", "lenient"] = "standard"


def _policy_engine() -> PolicyEngine:
    rules_dir = Path(__file__).resolve().parents[3] / "policy" / "rule_definitions"
    return PolicyEngine(str(rules_dir))


def _require_scan(scan_id: str, scans: ScanRepository):
    scan = scans.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _findings(scan_id: str, evidence: EvidenceRepository) -> list[dict]:
    # intelligence/agility/work-order/risk consumers see live findings only;
    # retracted evidence (soft-deleted) must not drive migration planning
    return [
        evidence_to_dict(row)
        for row in evidence.get_all_for_scan(scan_id, include_deleted=False)
    ]


def _drift_events(scan_id: str, drift: DriftRepository) -> list[dict]:
    events, _ = drift.list_events(scan_id=scan_id, page=1, page_size=500)
    return [drift_to_dict(event) for event in events]


def _pack_analysis(scan) -> dict | None:
    """Scan-level analysis that auditors need next to the records — bounded and covered by the pack signature."""
    stats = getattr(scan, "statistics", None) or {}
    out: dict = {}
    if stats.get("evidence_sources"):
        out["evidence_sources"] = stats["evidence_sources"]
    cascade = stats.get("cascade") or {}
    if cascade:
        out["cascade"] = {
            "summary": cascade.get("summary"),
            "systems": (cascade.get("systems") or [])[:200],
            "migration_waves": cascade.get("migration_waves") or [],
            "weak_parameters": (cascade.get("weak_parameters") or [])[:300],
            "libraries": (cascade.get("libraries") or [])[:200],
            "truncated": cascade.get("truncated"),
        }
    rec = stats.get("key_reconciliation") or {}
    if rec:
        out["key_reconciliation"] = {k: rec.get(k) for k in ("summary", "source_scans", "previous_inventory_scan", "new_orphans", "new_unaccounted", "removed", "orphans", "not_in_inventory")}
    return out or None


def _build_pack(scan, findings: list[dict]) -> dict:
    settings = get_settings()
    engine = _policy_engine()
    analysis = _pack_analysis(scan)
    return build_evidence_pack(
        scan=scan_to_dict(scan),
        records=findings,
        policy=engine.pack_descriptor(),
        secret=settings.SECRET_KEY,
        extra={"analysis": analysis} if analysis else None,
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


def _gate_for(
    scan_id: str,
    scans,
    evidence,
    drift,
    require_baseline: bool = False,
    profile: str = "standard",
) -> dict:
    scan = _require_scan(scan_id, scans)
    findings = _findings(scan_id, evidence)
    events = _drift_events(scan_id, drift)
    stored = (scan.statistics or {}).get("gate") if isinstance(scan.statistics, dict) else None
    gate = evaluate_gate(findings, events, require_baseline=require_baseline)
    if profile and profile.lower() != "standard":
        from drift.core.gate import apply_gate_profile

        gate = apply_gate_profile(gate, profile)
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
    request: Request,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
    drift: DriftRepository = Depends(get_drift_repository),
    db=Depends(get_db_session),
):
    """Evaluate the CI gate under a policy profile and record the outcome.

    Recording is fail-open: if the trail cannot be written the decision is
    still returned — CI never breaks because of the log.
    """
    gate = _gate_for(
        body.scan_id, scans, evidence, drift,
        require_baseline=body.require_baseline, profile=body.profile,
    )
    gate["recorded"] = False
    try:
        from db.repositories.gate_evaluation_repository import GateEvaluationRepository

        scan = scans.get_by_id(body.scan_id)
        GateEvaluationRepository(db).record(
            scan_id=body.scan_id,
            decision=str(gate.get("decision") or "UNKNOWN"),
            profile=str(gate.get("profile") or body.profile or "standard"),
            blocking_count=len(gate.get("blocking") or []),
            warning_count=len(gate.get("warnings") or []),
            target_location=getattr(scan, "target_location", None),
            actor=user,
        )
        db.commit()
        gate["recorded"] = True
    except Exception:
        logger.debug("gate_evaluation_not_recorded", exc_info=True)
        try:
            db.rollback()
        except Exception as rollback_exc:
            logger.warning(
                "gate_evaluation_rollback_failed",
                extra={"error_type": type(rollback_exc).__name__},
            )
    return gate


@router.get("/ci/gate-evaluations")
def ci_gate_evaluations(
    days: int = 30,
    user: str = Depends(get_current_user),
    db=Depends(get_db_session),
):
    """Blocked-deployments roll-up over recorded CI gate calls."""
    from db.repositories.gate_evaluation_repository import GateEvaluationRepository

    return GateEvaluationRepository(db).stats(days=min(max(1, days), 365))


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

    from evidence.pack.scan_transfer import export_transfer, verify_transfer

    scan = _require_scan(scan_id, scans)
    rows = evidence.get_all_for_scan(scan_id)
    records = []
    for row in rows:
        item = evidence_to_dict(row)
        if item["redacted_projection"]:
            raise HTTPException(
                status_code=409,
                detail="Historical evidence contains raw fields; full-fidelity transfer is unavailable until reissued",
            )
        item.pop("redacted_projection")
        item["previous_hash"] = getattr(row, "previous_hash", None)
        item["provenance"] = getattr(row, "provenance", None)
        records.append(item)
    scan_payload = scan_to_dict(scan)
    scan_payload["scan_start"] = iso_utc(scan.scan_start) if getattr(scan, "scan_start", None) else None
    scan_payload["scan_end"] = iso_utc(scan.scan_end) if getattr(scan, "scan_end", None) else None
    payload = export_transfer(scan=scan_payload, records=records)
    verdict = verify_transfer(payload)
    if not verdict["valid"]:
        raise HTTPException(status_code=409, detail={
            "message": "Scan evidence cannot be transferred with a valid content commitment",
            "errors": verdict["errors"],
        })
    return payload


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
    if filtered_get(db, Scan, scan_id) is not None:
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


def _rendered_report(scan_id, scans, evidence, drift, template: str | None, requirements: str | None):
    scan = _require_scan(scan_id, scans)
    findings = _findings(scan_id, evidence)
    pack_hash = None
    try:
        pack_hash = _policy_engine().pack_hash()
    except Exception:
        logger.debug("policy_pack_hash_unavailable", exc_info=True)
    report = render_json(
        scan=scan_to_dict(scan),
        findings=findings,
        agility=compute_agility(findings),
        quantum=analyze_quantum_risk(findings),
        gate=evaluate_gate(findings, _drift_events(scan_id, drift)),
        template_id=template,
        selected_requirements=[r.strip() for r in (requirements or "").split(",") if r.strip()] or None,
        policy_pack_hash=pack_hash,
        payment=_payment_crypto_block(),
    )
    report = _maybe_sign_report(report)
    return report


def _payment_crypto_block() -> dict | None:
    """Open payment/HSM findings + key summary for the report (best effort).

    Honest absence: if the payment tables are empty the report simply carries
    no payment section — never a guessed PASS.
    """
    try:
        from db.connection.session import SessionLocal
        from db.repositories.payment_crypto_repository import PaymentCryptoRepository

        session = SessionLocal()
        try:
            repo = PaymentCryptoRepository(session)
            keys = repo.list_keys()
            open_rows = [row for row in repo.list_findings(status="OPEN")]
            if not keys and not open_rows:
                return None
            from payment_crypto.forecast import ExpiryForecaster

            forecast = ExpiryForecaster().forecast(
                [{"key_id": key.key_id, "expiry_at": key.expiry_at.isoformat() if key.expiry_at else None}
                 for key in keys],
                ceremonies=[{"key_id": row.key_id, "status": row.status or "HELD",
                             "held_at": row.held_at.isoformat() if row.held_at else None}
                            for row in repo.list_ceremonies()],
            )
            return {
                "summary": {
                    "keys_total": len(keys),
                    "active_weak_algorithm_keys": sum(
                        1 for key in keys
                        if key.state == "ACTIVE"
                        and (key.algorithm or "").upper() in {"DES", "SINGLE_DES", "TRIPLE_DES", "2KEY_TRIPLE_DES"}
                    ),
                    "ceremonies_total": len(repo.list_ceremonies()),
                    "rotations_next_90d": forecast.get("upcoming_count"),
                },
                "upcoming_rotations": forecast.get("upcoming", [])[:5],
                "findings": [{
                    "rule_id": row.rule_id, "key_id": row.key_id, "severity": row.severity,
                    "blocking": row.blocking, "message": row.message,
                } for row in open_rows],
            }
        finally:
            session.close()
    except Exception:
        logger.debug("payment_crypto_block_unavailable", exc_info=True)
        return None


def _maybe_sign_report(report: dict) -> dict:
    """Attach a real RS256 signature when REPORT_SIGNING_KEY is configured.

    No key configured -> the report carries no signature (honest absence,
    never an HMAC dressed up as a signature). Key configured but unusable ->
    the failure is reported on the report itself, not swallowed.
    """
    settings = get_settings()
    signing_key = (getattr(settings, "REPORT_SIGNING_KEY", "") or "").strip()
    if not signing_key:
        return report
    try:
        from reporting.signing import sign_report

        return sign_report(
            report,
            signing_key,
            key_id=(getattr(settings, "REPORT_SIGNING_KEY_ID", "") or "").strip() or None,
        )
    except Exception:
        logger.warning("report_signing_failed", exc_info=True)
        report["signature"] = {"alg": None, "error": "signing failed — see server logs"}
        return report


@router.get("/scans/{scan_id}/report")
def get_report(
    scan_id: str,
    template: str | None = None,
    requirements: str | None = None,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
    drift: DriftRepository = Depends(get_drift_repository),
):
    """Compliance report; add ?template=<id> for a requirement-by-requirement
    evaluation with attestation and a tamper-detection hash.
    ?template=custom&requirements=4.2.1,CC6.1 selects individual requirements.
    """
    try:
        return _rendered_report(scan_id, scans, evidence, drift, template, requirements)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class ReportVerifyBody(BaseModel):
    report: dict
    public_key: str  # PEM (public) — issuer-published key


@router.post("/report/verify")
def verify_report_signature(
    body: ReportVerifyBody,
    user: str = Depends(get_current_user),
):
    """Verify a report's PKI signature against the issuer's public key (offline-verifiable too)."""
    from reporting.signing import verify_report

    return verify_report(body.report, body.public_key)


@router.get("/report-templates")
def list_report_templates(user: str = Depends(get_current_user)):
    from reporting.report_templates import template_metadata

    return {"templates": template_metadata()}


@router.get("/scans/{scan_id}/report.html")
def get_report_html(
    scan_id: str,
    template: str | None = None,
    requirements: str | None = None,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
    drift: DriftRepository = Depends(get_drift_repository),
):
    try:
        report = _rendered_report(scan_id, scans, evidence, drift, template, requirements)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return Response(
        content=render_html(report),
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="cryptoscan-report-{scan_id}.html"'},
    )


@router.get("/scans/{scan_id}/report.pdf")
def get_report_pdf(
    scan_id: str,
    template: str | None = None,
    requirements: str | None = None,
    user: str = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scan_repository),
    evidence: EvidenceRepository = Depends(get_evidence_repository),
    drift: DriftRepository = Depends(get_drift_repository),
):
    """Deterministic PDF rendering of the compliance report (same content as
    the JSON/HTML report; signing still applies to the JSON source of truth).
    """
    from reporting.pdf_export import render_report_pdf

    try:
        report = _rendered_report(scan_id, scans, evidence, drift, template, requirements)
        payload = render_report_pdf(report)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return Response(
        content=bytes(payload),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="cryptoscan-report-{scan_id}.pdf"'},
    )
