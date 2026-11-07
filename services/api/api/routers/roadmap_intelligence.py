"""Intelligence API — the roadmap models wired to live estate rows.

This router is the service layer over the shared intelligence models
(``threat_intelligence``, ``risk_dimensions``, ``pqc_claims``,
``scenario_simulation``): it derives their inputs from real database rows and
returns what they compute, with the same honesty rules the models enforce:

* a detector that has no evidence source in this database is listed as **not
  fired, with a reason** — silence is never a clean result;
* ``GET /intelligence/risk/{asset_id}`` takes the quantum threat horizon as a
  required policy input (the platform hides no national threat policy in a
  default) and reports dimensions it cannot derive as UNKNOWN, never zero;
* ``POST /intelligence/simulation`` refuses to run without an explicitly
  selected versioned snapshot (a ``graph_snapshots`` row), labels the output
  hypothetical, and keeps proven and assumed dependencies apart — snapshot
  edges without evidence references classify as UNKNOWN and are never shown as
  proven.

Everything here is read-only: findings are detections, simulations are
projections, and nothing on this router changes estate state.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.models.certificate import Certificate
from db.models.crypto_asset import CryptoAsset
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.models.crypto_live import CryptoLiveState
from db.models.roadmap_coverage import CoverageReport
from db.models.evidence_record import EvidenceRecord
from db.models.graph_snapshot import GraphSnapshot
from shared_models.algorithm_registry import parse_algorithm
from shared_models.pqc_claims import claim as pqc_claim, pqc_claim_report
from shared_models.risk_dimensions import (
    risk_profile,
    score_business_criticality,
    score_certificate_trust,
    score_crypto_risk,
    score_discovery_coverage,
    score_evidence_confidence,
    score_quantum_urgency,
    score_vendor_risk,
)
from shared_models.scenario_simulation import SCENARIOS, run_scenario
from shared_models.threat_intelligence import (
    THREAT_CLASSES,
    detect_certificate_risk,
    detect_weak_algorithm_exposure,
    threat_report,
)

router = APIRouter(tags=["intelligence"])

#: read caps so one huge estate degrades honestly instead of OOMing the API
CERT_CAP = 2000
LIVE_CAP = 5000

#: the usage tokens that upgrade a sighting beyond capability/static evidence
LIVE_USAGE_TOKENS = ("NEGOTIATED", "OBSERVED")
CONFIG_USAGE_TOKENS = ("CONFIGURED",)

#: PQC name tokens for stage derivation
PQ_TOKENS = ("ML-KEM", "MLKEM", "ML-DSA", "MLDSA", "SLH-DSA", "SPHINCS",
             "KYBER", "DILITHIUM", "FALCON", "HQC", "BIKE", "X25519MLKEM")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _usage_state_for(live: CryptoLiveState | None, algorithm: str) -> str | None:
    """The strongest recorded usage state for one algorithm on one live state.

    The live-state JSON shapes are tolerant (dicts of name → state-ish values,
    or lists), matching how the twin engine scans them. Nothing is upgraded on
    presence alone: a name in ``algorithms`` without a usage signal stays a
    capability sighting and is reported as such.
    """
    if live is None:
        return None
    upper = algorithm.upper()
    for field in ("usage", "protocols"):
        container = getattr(live, field, None)
        if not isinstance(container, dict):
            continue
        for key, value in container.items():
            text = f"{key} {value if isinstance(value, str) else ''}".upper()
            if upper not in text:
                continue
            if any(token in text for token in LIVE_USAGE_TOKENS):
                return "OBSERVED" if "OBSERVED" in text else "NEGOTIATED"
            if any(token in text for token in CONFIG_USAGE_TOKENS):
                return "CONFIGURED"
    return None


def _iter_algorithms(live: CryptoLiveState) -> list[str]:
    names: list[str] = []
    container = live.algorithms
    if isinstance(container, dict):
        names = [str(k) for k in container.keys()]
    elif isinstance(container, list):
        for item in container:
            names.append(item if isinstance(item, str) else str((item or {}).get("name") or ""))
    return [n for n in names if n.strip()]


@router.get("/intelligence/findings")
def intelligence_findings(
    db: Session = Depends(get_db_session),
    _user: Any = Depends(get_current_user),
) -> dict[str, Any]:
    """Threat findings derived from real rows, and an honest map of what did not run.

    Detectors without a joinable evidence source in this database are listed in
    ``detectors_not_fired`` with the reason — the nine classes are all named, so
    an empty class is an explained absence, never a silent clean result.
    """
    now = _now()
    findings: list[dict[str, Any]] = []

    certs = db.execute(
        select(Certificate).order_by(Certificate.fingerprint_sha256).limit(CERT_CAP)
    ).scalars().all()
    for cert in certs:
        findings.extend(detect_certificate_risk(
            asset=cert.subject or cert.fingerprint_sha256,
            certificate={"days_until_expiry": cert.days_until_expiry},
            evidence_ids=[cert.fingerprint_sha256]))

    live_rows = db.execute(
        select(CryptoLiveState).order_by(CryptoLiveState.asset_id).limit(LIVE_CAP)
    ).scalars().all()
    for live in live_rows:
        for name in _iter_algorithms(live):
            info = parse_algorithm(name)
            usage_state = _usage_state_for(live, name)
            if usage_state is None:
                continue  # capability/static sighting: not exposure
            findings.extend(detect_weak_algorithm_exposure(
                asset=live.asset_id, algorithm=name,
                algorithm_info=info.to_dict(),
                usage_state=usage_state,
                evidence_ids=[f"live:{live.asset_id}"]))

    fired = {f["class"] for f in findings}
    sources = {
        "CERTIFICATE_RISK": f"certificate rows scanned: {len(certs)} (cap {CERT_CAP})",
        "WEAK_ALGORITHM_EXPOSURE": (
            f"live-state usage/protocol signals scanned across {len(live_rows)} "
            f"states (cap {LIVE_CAP}); capability-only sightings are not exposure"),
    }
    not_fired = {
        name: sources.get(name, "no joinable before/after or advisory source in "
                               "this database: this detector did not run here")
        for name in THREAT_CLASSES if name not in fired
    }
    report = threat_report(findings)
    report["detectors_fired"] = sorted(fired)
    report["detectors_not_fired"] = not_fired
    report["sources"] = sources
    report["note"] += ("; a class absent from this response is explained in "
                       "detectors_not_fired and is never an all-clear")
    return report


@router.get("/intelligence/risk/{asset_id}")
def intelligence_risk(
    asset_id: str,
    quantum_threat_horizon_years: float = Query(
        ...,
        description="Policy input: the year horizon for cryptographically "
                    "relevant quantum computers. Required — the platform hides "
                    "no threat policy in a default."),
    data_shelf_life_years: float = Query(0.0),
    migration_lead_time_years: float = Query(0.0),
    db: Session = Depends(get_db_session),
    _user: Any = Depends(get_current_user),
) -> dict[str, Any]:
    """The five risk dimensions for one crypto asset, explainable and separate.

    Dimensions this database cannot yet back (dependency blast radius, vendor
    standing) are returned as UNKNOWN with a named reason — never as zero.
    """
    now = _now()
    row = db.get(CryptoAsset, asset_id)
    live = db.execute(
        select(CryptoLiveState).where(CryptoLiveState.asset_id == asset_id)
    ).scalars().first()
    if row is None and live is None:
        raise HTTPException(status_code=404, detail="asset not found in this estate")

    algorithm = (row.algorithm if row is not None else None) or (
        (_iter_algorithms(live) or [""])[0] if live is not None else "")
    info = parse_algorithm(algorithm).to_dict()
    if row is not None and row.key_size:
        info["key_size"] = row.key_size
    usage_state = _usage_state_for(live, algorithm) or (
        "SUPPORTED" if live is not None and _iter_algorithms(live) else None)

    evidence_records: list[dict[str, Any]] = []
    if row is not None:
        links = db.execute(
            select(CryptoAssetEvidence, EvidenceRecord)
            .join(EvidenceRecord, EvidenceRecord.id == CryptoAssetEvidence.evidence_id)
            .where(CryptoAssetEvidence.asset_id == row.id)
        ).all()
        for _link, record in links:
            evidence_records.append({
                "evidence_type": "STATIC_OBSERVED",
                "confidence": record.confidence or "UNKNOWN",
                "observed_at": (record.created_at.isoformat()
                                if getattr(record, "created_at", None) else None),
                "evidence_id": record.id,
            })
    else:
        evidence_records.append({
            "evidence_type": "STATIC_OBSERVED",
            "confidence": getattr(live, "confidence", None) or "UNKNOWN",
            "observed_at": (live.last_seen.isoformat()
                            if live is not None and live.last_seen else None),
            "evidence_id": f"live:{asset_id}" if live is not None else None,
        })

    crypto = score_crypto_risk(algorithm_info=info, usage_state=usage_state,
                               evidence_ids=[r["evidence_id"] for r in evidence_records
                                             if r.get("evidence_id")])
    urgency = score_quantum_urgency(
        algorithm_info=info, usage_state=usage_state,
        data_shelf_life_years=data_shelf_life_years,
        migration_lead_time_years=migration_lead_time_years,
        quantum_threat_horizon_years=quantum_threat_horizon_years)
    confidence = score_evidence_confidence(records=evidence_records, now=now)
    dependency = {
        "dimension": "OPERATIONAL_DEPENDENCY", "score": None, "band": "UNKNOWN",
        "sense": "risk", "factors": [], "evidence_ids": [], "known": False,
        "reason": ("the dependency blast radius is not joined in this endpoint "
                   "yet: unknown, never assumed zero"),
    }
    vendor = score_vendor_risk(vendor=None)
    business = score_business_criticality(business_tier=None)
    certificate = score_certificate_trust()
    coverage_row = db.execute(
        select(CoverageReport).order_by(CoverageReport.captured_at.desc())
        .limit(1)).scalar_one_or_none()
    if coverage_row is not None:
        document = dict(coverage_row.document or {})
        outcomes = document.get("outcomes") or []
        expected_total = sum(int(o.get("expected") or 0) for o in outcomes)
        collected_total = sum(int(o.get("collected") or 0) for o in outcomes)
        coverage = score_discovery_coverage(
            coverage_percent=(round(100.0 * collected_total / expected_total, 2)
                              if expected_total else None),
            unknown_assets=document.get("unknown_assets"),
            access_denied_targets=document.get("access_denied_targets"),
            evidence_ids=[f"coverage:{coverage_row.batch_id}"])
    else:
        coverage = score_discovery_coverage()

    profile = risk_profile(crypto_risk=crypto, quantum_urgency=urgency,
                           business_criticality=business,
                           operational_dependency=dependency,
                           vendor_risk=vendor, certificate_trust=certificate,
                           evidence_confidence=confidence,
                           discovery_coverage=coverage)
    profile["asset_id"] = asset_id
    profile["algorithm"] = algorithm or None
    profile["usage_state"] = usage_state
    return profile


@router.get("/intelligence/pqc/claims")
def intelligence_pqc_claims(
    subject: Optional[str] = Query(None, description="one subject; omit for all"),
    db: Session = Depends(get_db_session),
    _user: Any = Depends(get_current_user),
) -> dict[str, Any]:
    """Migration-stage claims derived from what the estate actually recorded.

    The stages are separate by construction: an algorithm present in a live
    state is ``SUPPORT_AVAILABLE`` and nothing more; a usage signal is
    ``RUNTIME_OBSERVED`` or ``NETWORK_NEGOTIATED``; and ``MIGRATION_VALIDATED``
    stays ``NOT_CLAIMED`` with its honest reason until post-implementation
    validation evidence is filed — because a library supporting ML-KEM is not
    PQC readiness.
    """
    query = select(CryptoLiveState).order_by(CryptoLiveState.asset_id).limit(LIVE_CAP)
    if subject:
        query = query.where(CryptoLiveState.asset_id == subject)
    rows = db.execute(query).scalars().all()

    claims: list[dict[str, Any]] = []
    for live in rows:
        observed_at = (live.last_seen.isoformat() if live.last_seen
                       else datetime.now(timezone.utc).isoformat())
        names = _iter_algorithms(live)
        pq_names = [n for n in names
                    if any(tok in n.upper() for tok in PQ_TOKENS)]
        if pq_names:
            claims.append(pqc_claim(
                stage="SUPPORT_AVAILABLE", subject=live.asset_id,
                evidence_ids=[f"live:{live.asset_id}"],
                evidence_type="STATIC_OBSERVED", observed_at=observed_at,
                algorithm=pq_names[0]))
        for name in pq_names:
            usage_state = _usage_state_for(live, name)
            if usage_state in {"OBSERVED", "NEGOTIATED"}:
                stage = ("NETWORK_NEGOTIATED" if usage_state == "NEGOTIATED"
                         else "RUNTIME_OBSERVED")
                claims.append(pqc_claim(
                    stage=stage, subject=live.asset_id,
                    evidence_ids=[f"live:{live.asset_id}"],
                    evidence_type=("NETWORK_ACTIVE_OBSERVED"
                                   if stage == "NETWORK_NEGOTIATED"
                                   else "RUNTIME_OBSERVED"),
                    observed_at=observed_at, algorithm=name))
            elif usage_state == "CONFIGURED":
                claims.append(pqc_claim(
                    stage="CONFIGURED", subject=live.asset_id,
                    evidence_ids=[f"live:{live.asset_id}"],
                    evidence_type="CONFIGURED", observed_at=observed_at,
                    algorithm=name))

    report = pqc_claim_report(claims, now=_now())
    report["derived_from"] = (
        "claims derived from recorded live-state evidence only; "
        "MIGRATION_VALIDATED is never derived — it requires filed "
        "post-implementation validation evidence")
    return report


class SimulationRequest(BaseModel):
    scenario: str = Field(..., description="one of the twelve roadmap scenarios")
    focal_asset: str
    snapshot_id: Optional[str] = None
    snapshot_version: Optional[int] = None


@router.post("/intelligence/simulation")
def intelligence_simulation(
    body: SimulationRequest,
    db: Session = Depends(get_db_session),
    _user: Any = Depends(get_current_user),
) -> dict[str, Any]:
    """Run one scenario over one selected versioned snapshot. Read-only.

    The snapshot is mandatory and explicit (id or version): there is no
    "current state" in a simulator. Edges come from the snapshot's stored
    edge set; a stored edge without evidence references classifies as UNKNOWN
    provenance and lands in ``assumed_dependencies`` — never proven.
    """
    if body.scenario not in SCENARIOS:
        raise HTTPException(status_code=422, detail={
            "error": "unknown scenario",
            "expected": sorted(SCENARIOS),
        })
    if not body.snapshot_id and body.snapshot_version is None:
        raise HTTPException(status_code=422, detail={
            "error": "a scenario runs against a selected versioned snapshot: "
                     "pass snapshot_id or snapshot_version",
        })
    query = select(GraphSnapshot)
    if body.snapshot_id:
        query = query.where(GraphSnapshot.id == body.snapshot_id)
    else:
        query = query.where(GraphSnapshot.version == body.snapshot_version)
    snapshot_row = db.execute(query.order_by(GraphSnapshot.version.desc())
                              .limit(1)).scalars().first()
    if snapshot_row is None:
        raise HTTPException(status_code=404, detail="snapshot not found")

    edges = [
        {"subject": e.get("from"), "predicate": e.get("label") or "related",
         "object": e.get("to"), "basis": "IMPORTED",
         "evidence_ids": e.get("evidence_ids") or []}
        for e in (snapshot_row.edges or [])
        if isinstance(e, dict) and e.get("from") and e.get("to")
    ]
    captured_at = getattr(snapshot_row, "created_at", None)
    if captured_at is None:
        raise HTTPException(status_code=422, detail={
            "error": "the selected snapshot has no capture timestamp: a "
                     "simulation without one cannot say what it simulated",
        })
    result = run_scenario(
        scenario=body.scenario,
        snapshot={
            "snapshot_id": body.snapshot_id or str(snapshot_row.id),
            "version": snapshot_row.version,
            "captured_at": captured_at.isoformat() if captured_at else None,
        },
        focal_asset=body.focal_asset,
        edges=edges,
    )
    result["evidence_note"] = (
        "provenance derives from per-edge evidence references in the stored "
        "snapshot; an edge without them classifies as UNKNOWN and is listed as "
        "assumed — an unknown chain is never shown as proven")
    return result


@router.get("/intelligence/overview")
def intelligence_overview(
    _user: Any = Depends(get_current_user),
) -> dict[str, Any]:
    """What this router serves and the honesty rules it runs under — for the
    workbench and for audits."""
    return {
        "schema": "cryptoscan.intelligence-api/1",
        "endpoints": {
            "GET /intelligence/findings": (
                "threat findings from real rows, plus an explained map of "
                "detectors that did not run"),
            "GET /intelligence/risk/{asset_id}": (
                "five separate risk dimensions; the quantum threat horizon is "
                "a required policy input; unknown dimensions are never zero"),
            "GET /intelligence/pqc/claims": (
                "migration-stage claims derived from recorded evidence; "
                "support is never readiness"),
            "POST /intelligence/simulation": (
                "one of the twelve scenarios over one selected versioned "
                "snapshot; hypothetical, proven vs assumed kept apart"),
        },
        "scenarios": sorted(SCENARIOS),
        "threat_classes": list(THREAT_CLASSES),
        "note": ("read-only: findings are detections and simulations are "
                 "projections; nothing here declares a compromise or changes "
                 "estate state"),
    }
