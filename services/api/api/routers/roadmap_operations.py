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
from shared_models.governance import (
    create_ticket,
    transition,
    verify_audit,
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
