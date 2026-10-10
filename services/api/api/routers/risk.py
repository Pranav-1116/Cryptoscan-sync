"""Unified Risk Engine.

Normalizes Technical + Crypto + PQC + Exposure + Business Criticality +
Dependency Impact + Evidence Confidence + Threat into one deterministic score
per asset and across the estate (enterprise-blueprint item #3).

This endpoint is the single risk contract the CMDB and executive views consume.
It reuses the authoritative unified inventory (``collect_inventory``) so the
scores are computed over the SAME persisted, deduplicated rows shown on the
CMDB — no separate, divergent dataset.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from api.routers.inventory import collect_inventory
from db.models.vulnerability import Vulnerability
from db.repositories.drift_repository import DriftRepository
from db.repositories.evidence_repository import EvidenceRepository
from db.repositories.system_repository import SystemRepository
from shared_models.algorithm_registry import parse_algorithm
from universal_platform.risk import (
    CALCULATION_VERSION,
    UNIFIED_FACTORS,
    from_asset,
    unified_risk,
    unified_weights,
)

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/unified")
def unified_inventory_risk(
    asset_type: str | None = None,
    risk: str | None = None,
    limit: int = Query(500, ge=1, le=1000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Unified risk for every asset in the authoritative inventory + estate rollup.

    Filters mirror the CMDB (asset_type / risk level) so the views stay in sync.
    """
    rows = collect_inventory(db, limit=limit)
    if asset_type:
        rows = [r for r in rows if r["asset_type"].lower() == asset_type.lower()]
    if risk:
        rows = [r for r in rows if r["risk"] and r["risk"].lower() == risk.lower()]

    scored: list[dict[str, Any]] = []
    for r in rows:
        score = from_asset(r)
        scored.append({
            "id": r["id"],
            "name": r.get("name"),
            "asset_type": r["asset_type"],
            "score": score["score"],
            "level": score["level"],
            "factors": score["factors"],
            "missing": score["missing"],
        })
    estate = _estate_rollup(scored)
    return {
        "assets": scored,
        "count": len(scored),
        "estate": estate,
        "factors": list(UNIFIED_FACTORS.keys()),
        "source": "unified_risk_engine",
    }


# --------------------------------------------------------------------------- #
# Report 64 P0 — system-level unified risk: the SAME 8-factor contract,
# derived from a system's persisted observations (evidence, drift,
# vulnerabilities, dependencies, criticality). Every factor level is a pure
# function of stored state; unknown is 0 and reported, never guessed.
# --------------------------------------------------------------------------- #

_DESIGNATION_LEVEL = {
    "DISALLOWED": 4,
    "DEPRECATED": 3,
    "RESTRICTED": 3,
    "ALLOWED": 0,
}
_SEVERITY_LEVEL = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_CONFIDENCE_LEVEL = {"HIGH": 4, "CONFIRMED": 4, "MEDIUM": 2, "LIKELY": 2, "LOW": 1, "TENTATIVE": 1}


def _ratio_level(ratio: float) -> int:
    if ratio <= 0:
        return 0
    if ratio <= 0.25:
        return 1
    if ratio <= 0.50:
        return 2
    if ratio <= 0.75:
        return 3
    return 4


def system_factor_levels(
    system: Any,
    evidence_rows: list[Any],
    drift_events: list[Any],
    vulnerabilities: list[Any],
) -> tuple[dict[str, int], dict[str, Any]]:
    """Derive the 8 blueprint factor levels for one system (0–4, honest).

    ``evidence_rows`` are EvidenceRecords from the system's latest scan,
    ``drift_events`` its open drift events, ``vulnerabilities`` its CVE rows.
    Returns ``(levels, signals)`` — signals carries the raw counts the levels
    were derived from, so the decomposition is self-describing.
    """
    total = len(evidence_rows)

    crypto = 0
    quantum_weight = 0.0
    fail_rows = 0
    conf = 0
    unknown_algorithms = 0
    for row in evidence_rows:
        info = parse_algorithm(row.algorithm or "")
        if not info.recognized or not info.canonical:
            unknown_algorithms += 1
        status = str(getattr(info, "status", "") or "").upper()
        level = _DESIGNATION_LEVEL.get(status, 0)
        # key below the registry minimum is weak even for an allowed family
        if (info.min_key_size and row.key_size
                and int(row.key_size) < int(info.min_key_size)):
            level = max(level, 3)
        crypto = max(crypto, level)
        # shor = broken by CRQC; grover = security halved (half weight)
        impact = str(getattr(info, "quantum_impact", "") or "").lower()
        if impact == "shor":
            quantum_weight += 1.0
        elif impact == "grover":
            quantum_weight += 0.5
        if str(row.compliance_status or "").upper() == "FAIL":
            fail_rows += 1
        conf = max(conf, _CONFIDENCE_LEVEL.get(str(row.confidence or "").upper(), 0))

    pqc_ratio = (quantum_weight / total) if total else 0.0
    if pqc_ratio <= 0:
        pqc = 0
    elif pqc_ratio <= 0.25:
        pqc = 2
    elif pqc_ratio <= 0.5:
        pqc = 3
    else:
        pqc = 4

    fail_ratio = (fail_rows / total) if total else 0.0
    drift_level = max(
        (_SEVERITY_LEVEL.get(str(e.severity or "").upper(), 0) for e in drift_events),
        default=0,
    )
    threat = max(
        (_SEVERITY_LEVEL.get(str(v.severity or "").upper(), 0) for v in vulnerabilities),
        default=0,
    )

    env = str(system.environment or "").lower()
    exposure = 4 if env in {"prod", "production", "internet", "public", "dmz"} else (
        2 if env in {"staging", "stage", "preprod", "external"} else 0)
    if system.cloud_provider:
        exposure = max(exposure, 3)  # externally hosted surface

    criticality = str(system.criticality or "").upper()
    business = 4 if criticality in {"TIER-1", "CRITICAL", "P0", "SEV1"} else (
        3 if criticality in {"HIGH", "TIER-2", "P1", "SEV2"} else (
            2 if criticality in {"MEDIUM", "TIER-3", "P2", "SEV3"} else (
                1 if criticality in {"LOW", "P3", "SEV4"} else 0)))

    return (
        {
            "technical": max(_ratio_level(fail_ratio), drift_level),
            "crypto": crypto,
            "pqc": pqc,
            "exposure": exposure,
            "business_criticality": business,
            "dependency_impact": min(4, len(system.outgoing or [])),
            "evidence_confidence": conf,
            "threat": threat,
        },
        {
            "evidence_rows": total,
            "fail_rows": fail_rows,
            "fail_ratio": round(fail_ratio, 3),
            "quantum_weighted_ratio": round(pqc_ratio, 3),
            "unknown_algorithms": unknown_algorithms,
            "open_drift_events": len(drift_events),
            "worst_open_drift_severity": max(
                (str(e.severity or "").upper() for e in drift_events), default=None
            ),
            "worst_cve_severity": max(
                (str(v.severity or "").upper() for v in vulnerabilities), default=None
            ),
            "outgoing_dependencies": len(system.outgoing or []),
            "environment": system.environment,
            "criticality": system.criticality,
            "cloud_provider": system.cloud_provider,
        },
    )


def _system_assessment(db: Session, system: Any) -> dict[str, Any]:
    scan_id = system.last_scan_id
    evidence_rows = (
        EvidenceRepository(db).get_all_for_scan(scan_id, include_deleted=False)
        if scan_id else []
    )
    drift_events: list[Any] = []
    if scan_id:
        drift_events, _ = DriftRepository(db).list_events(
            status="OPEN", scan_id=scan_id, page_size=200
        )
    vulnerabilities = []
    if scan_id:
        vulnerabilities = list(
            db.execute(
                select(Vulnerability).where(Vulnerability.scan_id == scan_id)
            ).scalars().all()
        )
    levels, signals = system_factor_levels(system, evidence_rows, drift_events, vulnerabilities)
    assessment = unified_risk(levels)
    assessment.update({
        "system_id": str(system.id),
        "system_name": system.name,
        "scan_id": scan_id,
        "evidence_count": len(evidence_rows),
        "levels": levels,
        "signals": signals,
        "open_drift_events": len(drift_events),
        "vulnerability_count": len(vulnerabilities),
    })
    return assessment


@router.get("/systems/{system_id}")
def system_unified_risk(
    system_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Unified 8-factor risk assessment for one system (report 64 P0).

    Same contract as ``/risk/unified`` (asset view) but derived from the
    system's persisted observations: latest-scan evidence, open drift
    events, CVEs, dependency edges, environment and criticality. The full
    decomposition is returned — the response itself is the calculation
    audit trail (deterministic, versioned via ``calculation_version``).
    """
    system = SystemRepository(db).get_by_id(system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    return _system_assessment(db, system)


@router.get("/systems")
def systems_unified_risk(
    limit: int = Query(200, ge=1, le=500),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Every system scored with the unified model, ranked by risk (desc)."""
    repo = SystemRepository(db)
    rows, total = repo.list_systems(page=1, page_size=limit)
    assessments = [_system_assessment(db, s) for s in rows]
    assessments.sort(key=lambda a: a["score"], reverse=True)
    weights, weights_source = unified_weights()
    by_level = {lv: sum(1 for a in assessments if a["level"] == lv)
                for lv in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    mean = round(sum(a["score"] for a in assessments) / len(assessments), 1) if assessments else 0.0
    return {
        "systems": assessments,
        "count": len(assessments),
        "total_systems": total,
        "estate": {
            "score": mean,
            "level": assessments[0]["level"] if assessments else "LOW",
            "by_level": by_level,
        },
        "weights": weights,
        "weights_source": weights_source,
        "calculation_version": CALCULATION_VERSION,
        "factors": list(UNIFIED_FACTORS.keys()),
    }


def _estate_rollup(scored: list[dict[str, Any]]) -> dict[str, Any]:
    if not scored:
        return {"score": 0.0, "level": "LOW", "count": 0, "by_level": {}}
    mean = round(sum(s["score"] for s in scored) / len(scored), 1)
    return {
        "score": mean,
        "level": _level_for(mean),
        "count": len(scored),
        "by_level": {lv: sum(1 for s in scored if s["level"] == lv)
                     for lv in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
    }


def _level_for(score: float) -> str:
    for name, floor in (("CRITICAL", 80), ("HIGH", 60), ("MEDIUM", 40), ("LOW", 0)):
        if score >= floor:
            return name
    return "LOW"
