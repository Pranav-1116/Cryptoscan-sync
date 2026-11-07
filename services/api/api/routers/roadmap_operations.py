"""Roadmap operations API — governance, deployment controls, discovery
qualification, external validation, and estate coverage (roadmap items 5, 6, 9,
10 plus the standing external-only rule), all through the datastore.

Persistence rules these endpoints enforce:

* governance transitions run through :mod:`shared_models.governance` only —
  there is no direct state write, and the ticket returned verifies its own
  hash-chained audit;
* deployment readiness is computed from filed attestations + the custody map;
  no attestations is "not verified", never "ready";
* a support claim is answered from filed qualification records — a collector
  with no records may claim nothing;
* external validations are filed evidence of acts performed OUTSIDE the
  platform. The platform never marks them done; the register returns
  ``NOT_FILED`` honestly;
* coverage is computed from a filed collection batch. No batch filed → the
  endpoint says so — a failed read never prints zeros.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.models import (
    CoverageReport,
    GateFiling,
    DeploymentAttestation,
    DeploymentCustodyEntry,
    DiscoveryQualification,
    ExternalValidation,
    GovernanceTicket,
)
from shared_models.deployment_controls import (
    CUSTODY_CLASSES,
    MODES,
    attest,
    deployment_readiness,
)
from shared_models.discovery_qualification import (
    qualification,
    qualification_summary,
    support_claim,
)
from shared_models.estate_coverage import coverage_intelligence
from shared_models.external_validation import (
    file_validation,
    validation_status,
)
from shared_models.acceptance_gates import (
    file_gate_evidence,
    gates_status,
)
from shared_models.collector_contract import (
    collector_contract,
    collection_report,
)
from shared_models.compliance_mapping import (
    assessment as compliance_assessment,
    compliance_status,
)
from shared_models.cross_bom_reconciliation import (
    attribute_operation,
    bom_claim,
    reconcile,
)
from shared_models.finding_lifecycle import (
    assign as assign_finding,
    confirm_incident,
    finding_digest,
    finding_record,
)
from shared_models.governance import (
    create_ticket,
    transition,
    verify_audit,
)
from shared_models.observation_intake import (
    ingest_observations,
    rebuild_projection,
)
from shared_models.migration_plan import (
    asset_state,
    make_plan,
    validate_migration,
)
from shared_models.twin_investigation import investigate_certificate
from shared_models.graph_projection import build_projection
from shared_models.evidence_reprocessing import (
    original_intact,
    reprocess,
)
from shared_models.vendor_lifecycle import (
    deployed_exposure,
    least_ready_suppliers,
    supplier_readiness,
    supplier_risk,
)
from shared_models.supplier_concentration import supplier_concentration
from shared_models.production_qualification import (
    file_result as file_qualification_result,
    qualification_status,
)
from shared_models.asset_alias import (
    merge_duplicates,
    resolve_all,
)

router = APIRouter(prefix="/intelligence", tags=["intelligence"])

#: the ten discovery target families the roadmap names
TARGET_FAMILIES: tuple[str, ...] = (
    "linux-openssl-engine", "windows-capi-cng-schannel", "java-jce",
    "pkcs11-hsm", "cloud-kms", "network-tls", "database-crypto",
    "container-runtime", "ci-cd-pipeline", "pki-certificate-authority",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _when(value: str, field: str) -> datetime:
    """Parse an ISO timestamp for a datetime column — never trust the driver."""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=(
            f"{field} must be an ISO-8601 timestamp")) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


# ---------------------------------------------------------------- governance

class GovernanceStart(BaseModel):
    subject: str
    role: str
    actor: str


class GovernanceTransition(BaseModel):
    action: str
    role: str
    actor: str
    evidence_ids: list[str] = Field(default_factory=list)
    expires_at: Optional[str] = None
    note: Optional[str] = None
    assignee: Optional[str] = None


def _ticket_body(row: GovernanceTicket) -> dict[str, Any]:
    body = dict(row.document or {})
    body.setdefault("ticket_id", row.ticket_id)
    body.setdefault("subject", row.subject)
    body.setdefault("state", row.state)
    body.setdefault("assignee", row.assignee)
    return body


@router.post("/governance/tickets")
def api_start_ticket(body: GovernanceStart,
                     _user: Any = Depends(get_current_user),
                     session: Session = Depends(get_db_session)) -> dict:
    try:
        ticket = create_ticket(
            ticket_id=f"GOV-{(session.query(GovernanceTicket).count() + 1):03d}",
            subject=body.subject, opened_by=body.actor, role=body.role,
            now=_now())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.add(GovernanceTicket(
        ticket_id=ticket["ticket_id"], subject=ticket["subject"],
        state=ticket["state"], assignee=ticket.get("assignee"),
        document=ticket))
    session.commit()
    return ticket


@router.post("/governance/tickets/{ticket_id}/transition")
def api_transition_ticket(ticket_id: str, body: GovernanceTransition,
                          _user: Any = Depends(get_current_user),
                          session: Session = Depends(get_db_session)) -> dict:
    row = session.query(GovernanceTicket).filter_by(ticket_id=ticket_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="ticket not found")
    try:
        updated = transition(
            _ticket_body(row), body.action, actor=body.actor, role=body.role,
            now=_now(), evidence_ids=body.evidence_ids,
            expires_at=body.expires_at, note=body.note,
            assignee=body.assignee)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    row.state = updated["state"]
    row.assignee = updated.get("assignee")
    row.document = updated
    session.commit()
    return updated


@router.get("/governance/tickets/{ticket_id}")
def api_get_ticket(ticket_id: str,
                   _user: Any = Depends(get_current_user),
                   session: Session = Depends(get_db_session)) -> dict:
    row = session.query(GovernanceTicket).filter_by(ticket_id=ticket_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="ticket not found")
    ticket = _ticket_body(row)
    report = verify_audit(ticket)
    return {"ticket": ticket, "audit_verified": report["verified"],
            "audit_problem": report.get("problem")}


@router.get("/governance/tickets")
def api_list_tickets(
        _user: Any = Depends(get_current_user),
        session: Session = Depends(get_db_session)) -> dict:
    rows = session.query(GovernanceTicket).order_by(
        GovernanceTicket.created_at).all()
    return {"tickets": [_ticket_body(r) for r in rows], "count": len(rows)}


# ------------------------------------------------------- deployment controls

class AttestationIn(BaseModel):
    control: str
    status: str
    evidence_ids: list[str] = Field(default_factory=list)
    observed_at: str
    actor: str
    note: Optional[str] = None


class CustodyEntryIn(BaseModel):
    custody_class: str
    controller: str
    location: str


@router.post("/deployment/attestations")
def api_file_attestation(body: AttestationIn,
                         _user: Any = Depends(get_current_user),
                         session: Session = Depends(get_db_session)) -> dict:
    try:
        record = attest(control=body.control, evidence_ids=body.evidence_ids,
                        observed_at=body.observed_at, actor=body.actor,
                        status=body.status, note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.add(DeploymentAttestation(
        control=record["control"], status=record["status"],
        evidence_ids=list(record["evidence_ids"]),
        observed_at=_when(body.observed_at, "observed_at"),
        actor=record["actor"], note=record["note"]))
    session.commit()
    return record


@router.put("/deployment/custody")
def api_set_custody(entries: list[CustodyEntryIn],
                    _user: Any = Depends(get_current_user),
                    session: Session = Depends(get_db_session)) -> dict:
    classes = {e.custody_class for e in entries}
    unknown = classes - set(CUSTODY_CLASSES)
    if unknown:
        raise HTTPException(status_code=422, detail=(
            f"unknown custody class(es) {sorted(unknown)}; expected one of "
            f"{list(CUSTODY_CLASSES)}"))
    session.query(DeploymentCustodyEntry).delete()
    for entry in entries:
        session.add(DeploymentCustodyEntry(
            custody_class=entry.custody_class, controller=entry.controller,
            location=entry.location))
    session.commit()
    return {"stored": len(entries),
            "note": ("the bank keeps control of its database, evidence and "
                     "crypto metadata")}


@router.get("/deployment/readiness")
def api_deployment_readiness(
        mode: str = Query("ON_PREM"),
        _user: Any = Depends(get_current_user),
        session: Session = Depends(get_db_session)) -> dict:
    attestations = [
        {"control": r.control, "status": r.status,
         "evidence_ids": list(r.evidence_ids or []),
         "observed_at": r.observed_at, "actor": r.actor, "note": r.note}
        for r in session.query(DeploymentAttestation).order_by(
            DeploymentAttestation.observed_at)]
    custody: dict[str, Any] = {}
    for r in session.query(DeploymentCustodyEntry):
        custody[r.custody_class] = {"controller": r.controller,
                                    "location": r.location}
    report = deployment_readiness(
        attestations=attestations, mode=mode, offered_modes=list(MODES),
        custody=custody or None, now=datetime.now(timezone.utc))
    report["source"] = (
        "filed attestations and custody map" if attestations or custody else
        "no attestations filed — not verified, never ready")
    return report


# --------------------------------------------------- discovery qualification

class QualificationIn(BaseModel):
    collector: str
    family: str
    state: str
    evidence_ids: list[str] = Field(default_factory=list)
    observed_at: Optional[str] = None
    reason: Optional[str] = None


@router.post("/qualification")
def api_file_qualification(body: QualificationIn,
                           _user: Any = Depends(get_current_user),
                           session: Session = Depends(get_db_session)) -> dict:
    try:
        record = qualification(
            collector=body.collector, family=body.family, state=body.state,
            evidence_ids=body.evidence_ids, observed_at=body.observed_at,
            reason=body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.add(DiscoveryQualification(
        collector=record["collector"], family=record["family"],
        state=record["state"], evidence_ids=list(record["evidence_ids"]),
        observed_at=(_when(body.observed_at, "observed_at")
                     if body.observed_at else None),
        reason=record["reason"]))
    session.commit()
    return record


def _qualification_records(session: Session) -> list[dict[str, Any]]:
    rows = session.query(DiscoveryQualification).order_by(
        DiscoveryQualification.created_at).all()
    return [{"collector": r.collector, "family": r.family, "state": r.state,
             "evidence_ids": list(r.evidence_ids or []),
             "observed_at": r.observed_at, "reason": r.reason}
            for r in rows]


@router.get("/qualification/summary")
def api_qualification_summary(
        families: str = Query(""),
        _user: Any = Depends(get_current_user),
        session: Session = Depends(get_db_session)) -> dict:
    wanted = tuple(f.strip() for f in families.split(",") if f.strip()) or tuple(
        TARGET_FAMILIES)
    return qualification_summary(_qualification_records(session), wanted)


@router.get("/qualification/claim")
def api_qualification_claim(
        collector: str = Query(...),
        family: str = Query(...),
        _user: Any = Depends(get_current_user),
        session: Session = Depends(get_db_session)) -> dict:
    return support_claim(_qualification_records(session),
                         collector=collector, family=family)


# ------------------------------------------------------ external validation

class ExternalValidationIn(BaseModel):
    kind: str
    performed_by: str
    evidence_ids: list[str] = Field(default_factory=list)
    performed_at: str
    scope: str
    result: str = "PASSED"
    note: Optional[str] = None


@router.post("/external-validations")
def api_file_external_validation(
        body: ExternalValidationIn,
        _user: Any = Depends(get_current_user),
        session: Session = Depends(get_db_session)) -> dict:
    try:
        row = file_validation(
            kind=body.kind, performed_by=body.performed_by,
            evidence_ids=body.evidence_ids, performed_at=body.performed_at,
            scope=body.scope, result=body.result, note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.add(ExternalValidation(
        kind=row["kind"], performed_by=row["performed_by"],
        evidence_ids=list(row["evidence_ids"]),
        performed_at=_when(body.performed_at, "performed_at"),
        scope=row["scope"], result=row["result"], note=row["note"]))
    session.commit()
    return {"filed": True, "kind": row["kind"],
            "note": ("the act was performed outside this platform; this filing "
                     "records the evidence, it does not perform the act")}


@router.get("/external-validations")
def api_external_validation_register(
        _user: Any = Depends(get_current_user),
        session: Session = Depends(get_db_session)) -> dict:
    rows = [{"kind": r.kind, "performed_by": r.performed_by,
             "evidence_ids": list(r.evidence_ids or []),
             "performed_at": r.performed_at, "scope": r.scope,
             "result": r.result, "note": r.note}
            for r in session.query(ExternalValidation).order_by(
                ExternalValidation.performed_at)]
    return validation_status(rows)


# ------------------------------------------------------------ estate coverage

class CoverageOutcomeIn(BaseModel):
    plane: str
    status: str
    expected: int = 0
    collected: int = 0
    reason: str = ""
    impact: str = ""


class CoverageBatchIn(BaseModel):
    batch_id: str
    captured_at: str
    authorized_targets: Optional[int] = None
    discovered_assets: Optional[int] = None
    outcomes: list[CoverageOutcomeIn] = Field(default_factory=list)
    unknown_assets: Optional[int] = None
    stale_evidence_assets: Optional[int] = None
    access_denied_targets: Optional[int] = None
    unverified_relationships: Optional[int] = None
    unsupported_types: list[str] = Field(default_factory=list)


@router.post("/coverage")
def api_file_coverage_batch(
        body: CoverageBatchIn,
        _user: Any = Depends(get_current_user),
        session: Session = Depends(get_db_session)) -> dict:
    if session.query(CoverageReport).filter_by(batch_id=body.batch_id).first():
        raise HTTPException(status_code=409, detail=(
            f"batch {body.batch_id} is already filed: a collection run is "
            f"filed once"))
    outcomes = [o.model_dump() for o in body.outcomes]
    if body.authorized_targets is not None and not outcomes:
        raise HTTPException(status_code=422, detail=(
            "a batch that names authorized targets must carry outcome rows: "
            "a count with no rows behind it is the zero this model refuses"))
    if any(o["status"] not in {"COMPLETE", "PARTIAL", "FAILED",
                               "NOT_ATTEMPTED", "NO_TARGET"}
           for o in outcomes):
        raise HTTPException(status_code=422, detail=(
            "outcome status must be COMPLETE, PARTIAL, FAILED, NOT_ATTEMPTED "
            "or NO_TARGET (the coverage model's vocabulary)"))
    document = {"outcomes": outcomes,
                "unknown_assets": body.unknown_assets,
                "stale_evidence_assets": body.stale_evidence_assets,
                "access_denied_targets": body.access_denied_targets,
                "unverified_relationships": body.unverified_relationships,
                "unsupported_types": list(body.unsupported_types)}
    session.add(CoverageReport(
        batch_id=body.batch_id,
        captured_at=_when(body.captured_at, "captured_at"),
        authorized_targets=body.authorized_targets,
        discovered_assets=body.discovered_assets, document=document))
    session.commit()
    return {"filed": True, "batch_id": body.batch_id}


@router.get("/coverage")
def api_estate_coverage(
        batch_id: str = Query(""),
        _user: Any = Depends(get_current_user),
        session: Session = Depends(get_db_session)) -> dict:
    if batch_id:
        row = session.query(CoverageReport).filter_by(batch_id=batch_id).first()
    else:
        row = session.query(CoverageReport).order_by(
            CoverageReport.captured_at.desc()).first()
    if row is None:
        return {"status": "NOT_FILED", "is_clean_result": False,
                "reason": ("no collection batch has been filed: the platform "
                           "holds no coverage readings — no readings is not "
                           "clean coverage"),
                "verdict": "COVERAGE_INCOMPLETE",
                "coverage_percent": None, "gaps": [],
                "percent_note": "never computed over unfiled readings",
                "batch_id": None}
    document = dict(row.document or {})
    report = coverage_intelligence(
        authorized_targets=row.authorized_targets or 0,
        discovered_assets=row.discovered_assets or 0,
        collector_outcomes=document.get("outcomes") or [],
        unknown_assets=document.get("unknown_assets") or 0,
        stale_evidence=document.get("stale_evidence_assets") or 0,
        access_denied_targets=document.get("access_denied_targets") or 0,
        unverified_relationships=document.get("unverified_relationships") or 0,
        unsupported_types=document.get("unsupported_types") or [],
    )
    report["batch_id"] = row.batch_id
    report["status"] = "FILED"
    return report


# --------------------------------------------- gap analysis §G findings

class FindingIn(BaseModel):
    finding_id: str
    pattern_id: str
    tenant_id: str
    affected_asset_ids: list[str] = Field(default_factory=list)
    affected_system_ids: list[str] = Field(default_factory=list)
    severity: str
    confidence: str
    first_seen: str
    last_seen: str
    evidence_ids: list[str] = Field(default_factory=list)
    observed_change: str
    expected_state: str
    reason: str
    not_proven: str
    recommended_investigation: str
    change_class: str = "CONFIGURATION_CHANGE"
    owner: Optional[str] = None
    status: str = "OPEN"


class FindingConfirm(BaseModel):
    incident_ref: str
    actor: str
    at: str
    evidence_ids: list[str] = Field(default_factory=list)


class FindingAssign(BaseModel):
    owner: str
    actor: str


@router.post("/findings")
def api_file_finding(body: FindingIn,
                     session: Session = Depends(get_db_session),
                     _user: Any = Depends(get_current_user)) -> dict:
    try:
        record = finding_record(**body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record["digest"] = finding_digest(record)
    return record


@router.post("/findings/confirm")
def api_confirm_finding(body: FindingConfirm,
                        session: Session = Depends(get_db_session),
                        _user: Any = Depends(get_current_user)) -> dict:
    """Confirmation is a human act with incident evidence — never automatic."""
    if not body.incident_ref.strip() or not body.actor.strip():
        raise HTTPException(status_code=422, detail=(
            "incident_ref and a named actor are mandatory: a pattern never "
            "automatically becomes a confirmed compromise"))
    return {"confirmation_required": True,
            "note": ("confirmation is applied to a stored finding record via "
                     "confirm_incident: this endpoint documents the act, the "
                     "engine never confirms its own pattern")}


@router.post("/findings/assign")
def api_assign_finding(body: FindingAssign,
                       finding: FindingIn,
                       session: Session = Depends(get_db_session),
                       _user: Any = Depends(get_current_user)) -> dict:
    try:
        record = finding_record(**finding.model_dump())
        updated = assign_finding(record, owner=body.owner, actor=body.actor)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return updated


# ------------------------------------ gap analysis §E cross-BOM reconciliation

class BomClaimIn(BaseModel):
    bom: str
    subject: str
    claim_kind: str
    relationship: str
    target: str
    evidence_ids: list[str] = Field(default_factory=list)
    observed_at: Optional[str] = None
    note: Optional[str] = None


class ReconciliationIn(BaseModel):
    subject: str
    claims: list[BomClaimIn] = Field(default_factory=list)


class AttributionIn(BaseModel):
    component: str
    operation: str
    claims: list[BomClaimIn] = Field(default_factory=list)


@router.post("/reconciliation")
def api_reconcile_boms(body: ReconciliationIn,
                       session: Session = Depends(get_db_session),
                       _user: Any = Depends(get_current_user)) -> dict:
    try:
        claims = [bom_claim(**c.model_dump()) for c in body.claims]
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return reconcile(subject=body.subject, claims=claims)


@router.post("/reconciliation/attribution")
def api_attribute_operation(body: AttributionIn,
                            session: Session = Depends(get_db_session),
                            _user: Any = Depends(get_current_user)) -> dict:
    try:
        claims = [bom_claim(**c.model_dump()) for c in body.claims]
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return attribute_operation(component=body.component,
                               operation=body.operation, claims=claims)


# ---------------------------- gap analysis §F digital twin investigator journey

class JourneyIn(BaseModel):
    certificate_id: str
    usage_edges: list[dict[str, Any]] = Field(default_factory=list)
    dependency_edges: list[dict[str, Any]] = Field(default_factory=list)
    ownership: dict[str, str] = Field(default_factory=dict)
    expiry: Optional[str] = None


@router.post("/investigation/certificate")
def api_investigate_certificate(body: JourneyIn,
                                session: Session = Depends(get_db_session),
                                _user: Any = Depends(get_current_user)) -> dict:
    return investigate_certificate(
        certificate_id=body.certificate_id, usage_edges=body.usage_edges,
        dependency_edges=body.dependency_edges, ownership=body.ownership,
        expiry=body.expiry)


# -------------------------------- gap analysis §H migration plan and validation

class MigrationPlanIn(BaseModel):
    plan_id: str
    policy_version: str
    algorithm_profiles: list[dict[str, Any]] = Field(default_factory=list)
    source_snapshot: dict[str, Any]
    assumptions: list[str] = Field(default_factory=list)
    cost_model: dict[str, Any] = Field(default_factory=dict)
    approvals: list[dict[str, Any]] = Field(default_factory=list)
    waves: list[dict[str, Any]] = Field(default_factory=list)
    blockers: list[dict[str, Any]] = Field(default_factory=list)


class MigrationValidationIn(BaseModel):
    asset: str
    claimed_state: str
    before_state: str
    evidence_ids: list[str] = Field(default_factory=list)
    validated_at: str
    validator: str


@router.post("/migration/plans")
def api_make_migration_plan(body: MigrationPlanIn,
                            session: Session = Depends(get_db_session),
                            _user: Any = Depends(get_current_user)) -> dict:
    try:
        return make_plan(**body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/migration/validate")
def api_validate_migration(body: MigrationValidationIn,
                           session: Session = Depends(get_db_session),
                           _user: Any = Depends(get_current_user)) -> dict:
    try:
        return validate_migration(**body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# --------------------------------------- gap analysis §6 acceptance gate filings

class GateFilingIn(BaseModel):
    gate: str
    evidence_ids: list[str] = Field(default_factory=list)
    performed_by: str
    performed_at: str
    result: str = "PASSED"
    synthetic: bool = False
    note: Optional[str] = None


@router.post("/gates")
def api_file_gate_evidence(body: GateFilingIn,
                           session: Session = Depends(get_db_session),
                           _user: Any = Depends(get_current_user)) -> dict:
    try:
        row = file_gate_evidence(
            gate=body.gate, evidence_ids=body.evidence_ids,
            performed_by=body.performed_by, performed_at=body.performed_at,
            result=body.result, synthetic=body.synthetic, note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.add(GateFiling(
        gate=row["gate"], performed_by=row["performed_by"],
        evidence_ids=list(row["evidence_ids"]),
        performed_at=_when(body.performed_at, "performed_at"),
        result=row["result"], synthetic=row["synthetic"], note=row["note"]))
    session.commit()
    return {"filed": True, "gate": row["gate"],
            "note": ("a gate passes on filed evidence: this filing is the "
                     "evidence, the status is computed from all filings")}


@router.get("/gates")
def api_gates_status(session: Session = Depends(get_db_session),
                     _user: Any = Depends(get_current_user)) -> dict:
    rows = [{"gate": r.gate, "performed_by": r.performed_by,
             "evidence_ids": list(r.evidence_ids or []),
             "performed_at": r.performed_at, "result": r.result,
             "synthetic": r.synthetic, "note": r.note}
            for r in session.query(GateFiling).order_by(GateFiling.performed_at)]
    return gates_status(rows)


# ----------------------------------- gap analysis §D collector standard contract

class CollectorContractIn(BaseModel):
    collector_id: str
    version: str
    supported_asset_types: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    data_sensitivity: str
    signature: dict[str, Any] = Field(default_factory=dict)


class CollectionReportIn(BaseModel):
    contract: CollectorContractIn
    started_at: str
    ended_at: str
    target_scope: str
    state: str
    assets_found: list[dict[str, Any]] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    coverage_metrics: dict[str, Any] = Field(default_factory=dict)
    zero_reason: Optional[str] = None
    note: Optional[str] = None


@router.post("/collector-contracts")
def api_collection_report(body: CollectionReportIn,
                          session: Session = Depends(get_db_session),
                          _user: Any = Depends(get_current_user)) -> dict:
    """Publish a collector contract and one run report against it.

    A zero-asset result without FOUND_NOTHING / NO_PERMISSION / FAILED /
    UNSUPPORTED_TARGET is refused: an unexplained zero is not a measurement.
    """
    try:
        contract = collector_contract(**body.contract.model_dump())
        return collection_report(
            contract=contract, started_at=body.started_at,
            ended_at=body.ended_at, target_scope=body.target_scope,
            state=body.state, assets_found=body.assets_found,
            evidence_ids=body.evidence_ids,
            coverage_metrics=body.coverage_metrics,
            zero_reason=body.zero_reason, note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# ------------------------------ gap analysis §C intake idempotency + projection

class IntakeIn(BaseModel):
    observations: list[dict[str, Any]] = Field(default_factory=list)


@router.post("/observations/intake")
def api_observation_intake(body: IntakeIn,
                           session: Session = Depends(get_db_session),
                           _user: Any = Depends(get_current_user)) -> dict:
    """Collapse duplicate observations and digest the logical graph.

    Duplicates merge with unioned evidence (a re-run is not new estate), and
    the graph digest is the reproducibility proof for the projection rebuild.
    """
    try:
        intake = ingest_observations(body.observations)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    intake["projection"] = rebuild_projection(intake)
    return intake


# ---------------------------------- gap analysis §I compliance mapping

class ComplianceRequirementIn(BaseModel):
    requirement_id: str
    framework: str
    clause: str
    text: str


class ComplianceAssessmentIn(BaseModel):
    requirement_id: str
    policy_match: Optional[bool] = None
    evidence_ids: list[str] = Field(default_factory=list)
    assessed_by: str
    outcome: str
    note: Optional[str] = None


class ComplianceQuery(BaseModel):
    requirements: list[ComplianceRequirementIn] = Field(default_factory=list)
    assessments: list[dict[str, Any]] = Field(default_factory=list)


@router.post("/compliance/assessments")
def api_compliance_assessment(body: ComplianceAssessmentIn,
                              session: Session = Depends(get_db_session),
                              _user: Any = Depends(get_current_user)) -> dict:
    try:
        return compliance_assessment(
            requirement_id=body.requirement_id,
            policy_match=body.policy_match, evidence_ids=body.evidence_ids,
            assessed_by=body.assessed_by, outcome=body.outcome,
            note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/compliance/status")
def api_compliance_status(body: ComplianceQuery,
                          session: Session = Depends(get_db_session),
                          _user: Any = Depends(get_current_user)) -> dict:
    requirements = []
    for req in body.requirements:
        try:
            requirements.append({
                "requirement_id": req.requirement_id,
                "framework": req.framework, "clause": req.clause,
                "text": req.text,
            })
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    return compliance_status(requirements=requirements,
                             assessments=body.assessments)


# ---------------- gap analysis §C rebuildable projection / §5 reprocessing ----

class GraphProjectionIn(BaseModel):
    assets: list[dict[str, Any]] = Field(default_factory=list)
    relationships: list[dict[str, Any]] = Field(default_factory=list)


@router.post("/graph-projection")
def api_graph_projection(body: GraphProjectionIn,
                         session: Session = Depends(get_db_session),
                         _user: Any = Depends(get_current_user)) -> dict:
    """Rebuild the logical graph from authoritative rows.

    Same rows in any order rebuild the same digest (gap analysis §C:
    'Rebuilding Neo4j from authoritative records produces the same logical
    graph'); edges without evidence links come back UNKNOWN, never proven.
    """
    try:
        return build_projection(assets=body.assets,
                                relationships=body.relationships)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


class ReprocessIn(BaseModel):
    record: dict[str, Any]
    normalizer_version: str
    normalized_crypto: dict[str, Any]
    at: Optional[str] = None


@router.post("/evidence-reprocess")
def api_evidence_reprocess(body: ReprocessIn,
                           session: Session = Depends(get_db_session),
                           _user: Any = Depends(get_current_user)) -> dict:
    """Re-normalize a retained original observation without losing it.

    The response carries the new record and the original-intact verdict —
    the §5 acceptance check, computed per call.
    """
    try:
        out = reprocess(body.record,
                        normalizer_version=body.normalizer_version,
                        normalized_crypto=body.normalized_crypto,
                        at=body.at)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"record": out,
            "original_intact": original_intact(body.record, out)}


# ---------------- gap analysis Phase 5 vendor lifecycle / supplier risk -------

class VendorExposureIn(BaseModel):
    deployments: list[dict[str, Any]] = Field(default_factory=list)
    support_records: list[dict[str, Any]] = Field(default_factory=list)
    as_of: Optional[str] = None


class VendorRiskIn(VendorExposureIn):
    vendor: str = ""
    changes: list[dict[str, Any]] = Field(default_factory=list)


@router.post("/vendor-exposure")
def api_vendor_exposure(body: VendorExposureIn,
                        session: Session = Depends(get_db_session),
                        _user: Any = Depends(get_current_user)) -> dict:
    try:
        return deployed_exposure(deployments=body.deployments,
                                 support_records=body.support_records,
                                 as_of=body.as_of)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/vendor-risk")
def api_vendor_risk(body: VendorRiskIn,
                    session: Session = Depends(get_db_session),
                    _user: Any = Depends(get_current_user)) -> dict:
    """Evidence-linked supplier-risk drivers — never one blended number."""
    try:
        exposure = deployed_exposure(deployments=body.deployments,
                                     support_records=body.support_records,
                                     as_of=body.as_of)
        return supplier_risk(vendor=body.vendor,
                             deployments_report=exposure,
                             changes=body.changes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# ---------------- gap analysis Phase 2 asset aliases / duplicate resolution ---

class AliasResolveIn(BaseModel):
    keys: list[str] = Field(default_factory=list)
    aliases: list[dict[str, Any]] = Field(default_factory=list)


class AliasMergeIn(BaseModel):
    keys: list[str] = Field(default_factory=list)
    canonical_key: str
    actor: str
    reason: str
    evidence_ref: str
    at: Optional[str] = None


@router.post("/asset-alias/resolve")
def api_asset_alias_resolve(body: AliasResolveIn,
                            session: Session = Depends(get_db_session),
                            _user: Any = Depends(get_current_user)) -> dict:
    try:
        return resolve_all(body.keys, body.aliases)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/asset-alias/merge")
def api_asset_alias_merge(body: AliasMergeIn,
                          session: Session = Depends(get_db_session),
                          _user: Any = Depends(get_current_user)) -> dict:
    """Compute a duplicate-resolution merge record — every original key is
    preserved as an alias; the call never deletes identity."""
    try:
        return merge_duplicates(keys=body.keys,
                                canonical_key=body.canonical_key,
                                actor=body.actor, reason=body.reason,
                                evidence_ref=body.evidence_ref, at=body.at)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# ---- PQC ICT supply-chain analysis: concentration + supplier readiness -------

class SupplierConcentrationIn(BaseModel):
    dependencies: list[dict[str, Any]] = Field(default_factory=list)
    as_of: Optional[str] = None


class SupplierReadinessIn(BaseModel):
    vendor: str
    product: Optional[str] = None
    responses: list[dict[str, Any]] = Field(default_factory=list)
    as_of: Optional[str] = None


class LeastReadyIn(BaseModel):
    assessments: list[dict[str, Any]] = Field(default_factory=list)


@router.post("/supplier-concentration")
def api_supplier_concentration(body: SupplierConcentrationIn,
                               session: Session = Depends(get_db_session),
                               _user: Any = Depends(get_current_user)) -> dict:
    """Named concentration clusters — never one blended number (§6)."""
    try:
        return supplier_concentration(dependencies=body.dependencies,
                                      as_of=body.as_of)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/supplier-readiness")
def api_supplier_readiness(body: SupplierReadinessIn,
                           session: Session = Depends(get_db_session),
                           _user: Any = Depends(get_current_user)) -> dict:
    """One supplier's questionnaire result — evidence-backed, never assumed.
    A vendor claim of testing is not test evidence."""
    try:
        return supplier_readiness(vendor=body.vendor, product=body.product,
                                  responses=body.responses, as_of=body.as_of)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/supplier-readiness/least-ready")
def api_least_ready_suppliers(body: LeastReadyIn,
                              session: Session = Depends(get_db_session),
                              _user: Any = Depends(get_current_user)) -> dict:
    """Name the pacing constraints: the estate is bound by its least-ready
    critical suppliers — never an average readiness score."""
    return least_ready_suppliers(body.assessments)


# ---- Phase-6 production-qualification register (external-only honesty) ------

class QualificationFileIn(BaseModel):
    activity: str
    evidence_ids: list[str] = Field(default_factory=list)
    performed_by: str
    performed_at: str
    result: str
    synthetic: bool = False
    note: Optional[str] = None


class QualificationStatusIn(BaseModel):
    rows: list[dict[str, Any]] = Field(default_factory=list)


@router.post("/production-qualification/file")
def api_file_production_qualification(
        body: QualificationFileIn,
        session: Session = Depends(get_db_session),
        _user: Any = Depends(get_current_user)) -> dict:
    """File evidence of one Phase-6 activity. Real-environment activities
    refuse synthetic evidence and refuse the platform as performer; a
    synthetic result files but never reads QUALIFIED."""
    try:
        return file_qualification_result(
            activity=body.activity, evidence_ids=body.evidence_ids,
            performed_by=body.performed_by, performed_at=body.performed_at,
            result=body.result, synthetic=body.synthetic, note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/production-qualification/status")
def api_production_qualification_status(
        body: QualificationStatusIn,
        session: Session = Depends(get_db_session),
        _user: Any = Depends(get_current_user)) -> dict:
    """Per-activity register state: NOT_FILED is 'no evidence the platform
    holds' — never passed, never not applicable."""
    try:
        return qualification_status(body.rows)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
