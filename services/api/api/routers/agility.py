"""System-level 6-factor agility and migration readiness."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from agility.readiness import readiness_from_system
from agility.roadmap import build_roadmap, portfolio_trend
from agility.simulation import available_actions, simulate_improvements
from agility.system_score import pqc_exposure
from agility.trajectory import analyze_history
from agility.system_score import calculate_agility_score
from api.dependencies import get_current_user, get_db_session
from db.models.system import System
from db.repositories.maturity_repository import MaturityRepository
from db.repositories.system_repository import SystemRepository

router = APIRouter(tags=["agility"])


def _evidence_for(db: Session, system_id: str) -> list[dict]:
    assets = SystemRepository(db).assets_for(system_id)
    rows = []
    for asset in assets:
        rows.append(
            {
                "algorithm": asset.algorithm,
                "purpose": asset.purpose,
                "file_path": asset.file_path,
                "is_hardcoded_key": asset.is_hardcoded_key,
                "confidence": asset.confidence,
                "finding_data": {"metadata": {"library": (asset.libraries or [None])[0] if asset.libraries else None}},
            }
        )
    return rows


def _score_system(db: Session, system: System) -> dict:
    deps = SystemRepository(db).dependencies_for(system.id)
    extra = system.extra or {}
    payload = system.to_dict()
    score = calculate_agility_score(_evidence_for(db, system.id), payload)
    ready = readiness_from_system(
        payload,
        agility_score=score["agility_score"],
        dependency_count=len(deps),
    )
    score["readiness_score"] = ready["readiness_score"]
    score["readiness_category"] = ready["readiness_category"]
    score["readiness"] = ready
    score["system_id"] = system.id
    score["system"] = system.name
    MaturityRepository(db).save_agility(system.id, score)
    return score


@router.get("/agility")
def list_agility(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    systems, _ = SystemRepository(db).list_systems(page=1, page_size=500)
    rows = []
    for system in systems:
        latest = MaturityRepository(db).latest_agility(system.id)
        if latest:
            item = latest.to_dict()
            item["system"] = system.name
            rows.append(item)
        else:
            rows.append(_score_system(db, system))
    repo = MaturityRepository(db)
    for row in rows:
        previous = repo.previous_agility(str(row.get("system_id") or ""))
        if previous is not None:
            row["previous_agility_score"] = previous.agility_score
            row["score_delta"] = int(row.get("agility_score") or 0) - previous.agility_score
    scores = [int(row.get("agility_score") or 0) for row in rows]
    avg = round(sum(scores) / len(scores), 1) if scores else 0
    dist = {"EXCELLENT": 0, "GOOD": 0, "MODERATE": 0, "POOR": 0, "CRITICAL": 0}
    for row in rows:
        dist[str(row.get("category") or "CRITICAL")] = dist.get(str(row.get("category") or "CRITICAL"), 0) + 1
    return {
        "systems": rows,
        "average": avg,
        "distribution": dist,
        "trend": portfolio_trend(rows),
    }


@router.get("/systems/{system_id}/agility")
def get_system_agility(system_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    system = db.get(System, system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    latest = MaturityRepository(db).latest_agility(system_id)
    if latest:
        payload = latest.to_dict()
        payload["system"] = system.name
        return payload
    return _score_system(db, system)


@router.post("/systems/{system_id}/agility/recalculate")
def recalculate(system_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    system = db.get(System, system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    return _score_system(db, system)


@router.get("/agility/roadmap")
def agility_roadmap(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Deterministic migration sequencing across the portfolio."""
    systems, _ = SystemRepository(db).list_systems(page=1, page_size=500)
    entries = []
    for system in systems:
        latest = MaturityRepository(db).latest_agility(system.id)
        if latest is None:
            _score_system(db, system)  # populates history; use the fresh row
            latest = MaturityRepository(db).latest_agility(system.id)
        if latest is None:
            continue
        readiness = latest.readiness if isinstance(latest.readiness, dict) else {}
        entries.append(
            {
                "system_id": system.id,
                "system": system.name,
                "agility_score": latest.agility_score,
                "agility_category": latest.category,
                "readiness_score": latest.readiness_score,
                "readiness_category": latest.readiness_category,
                "wave": readiness.get("wave"),
                "dependency_count": len(SystemRepository(db).dependencies_for(system.id)),
            }
        )
    return build_roadmap(entries)


@router.get("/systems/{system_id}/agility/history")
def agility_history(system_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Saved score rows over time + trajectory classification."""
    system = db.get(System, system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    rows = MaturityRepository(db).agility_history(system_id)
    history = [
        {
            "calculated_at": row.calculated_at.isoformat() if row.calculated_at else None,
            "agility_score": row.agility_score,
            "category": row.category,
            "readiness_score": row.readiness_score,
            "readiness_category": row.readiness_category,
            "factor_scores": row.factor_scores,
            "calculation_version": row.calculation_version,
        }
        for row in rows
    ]
    return {
        "system_id": system_id,
        "system": system.name,
        "count": len(history),
        "history": history,
        "trajectory": analyze_history(history),
    }


class AgilitySimulateRequest(BaseModel):
    actions: list[str] = []


@router.post("/systems/{system_id}/agility/simulate")
def agility_simulate(
    body: AgilitySimulateRequest, system_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)
):
    """What-if projection through the real scoring engine. Nothing is persisted."""
    system = db.get(System, system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    result = simulate_improvements(_evidence_for(db, system_id), system.to_dict(), body.actions)
    result["available_actions"] = available_actions()
    result["system_id"] = system_id
    result["system"] = system.name
    return result


@router.get("/agility/pqc")
def agility_pqc(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Portfolio-wide post-quantum exposure, computed live from crypto assets."""
    systems, _ = SystemRepository(db).list_systems(page=1, page_size=500)
    per_system = []
    total_vulnerable_sites = 0
    vulnerable_algorithms: set[str] = set()
    hybrid_systems = 0
    for system in systems:
        repo = SystemRepository(db)
        evidence = _evidence_for(db, system.id)
        if not evidence:
            continue
        exposure = pqc_exposure(evidence, system.to_dict())
        total_vulnerable_sites += exposure["quantum_vulnerable_sites"]
        vulnerable_algorithms.update(exposure["quantum_vulnerable_algorithms"])
        if exposure["hybrid_support"]:
            hybrid_systems += 1
        per_system.append(
            {
                "system_id": system.id,
                "system": system.name,
                "quantum_vulnerable_sites": exposure["quantum_vulnerable_sites"],
                "quantum_vulnerable_algorithms": exposure["quantum_vulnerable_algorithms"],
                "hybrid_support": exposure["hybrid_support"],
                "sites": len(evidence),
            }
        )
    per_system.sort(key=lambda row: (-row["quantum_vulnerable_sites"], row["system"]))
    return {
        "systems": per_system,
        "total_systems_with_assets": len(per_system),
        "total_quantum_vulnerable_sites": total_vulnerable_sites,
        "quantum_vulnerable_algorithms": sorted(vulnerable_algorithms),
        "hybrid_systems": hybrid_systems,
        "note": "computed live from crypto assets; asymmetric algorithms require PQC migration",
    }


@router.get("/readiness")
def list_readiness(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    systems, _ = SystemRepository(db).list_systems(page=1, page_size=500)
    waves = {"READY_NOW": [], "READY_WITH_PREP": [], "NOT_READY": [], "BLOCKED": []}
    for system in systems:
        latest = MaturityRepository(db).latest_agility(system.id)
        if latest and latest.readiness_category:
            item = {
                "system_id": system.id,
                "system": system.name,
                "readiness_score": latest.readiness_score,
                "readiness_category": latest.readiness_category,
                "agility_score": latest.agility_score,
            }
        else:
            scored = _score_system(db, system)
            item = {
                "system_id": system.id,
                "system": system.name,
                "readiness_score": scored["readiness_score"],
                "readiness_category": scored["readiness_category"],
                "agility_score": scored["agility_score"],
            }
        waves.setdefault(item["readiness_category"], []).append(item)
    return {"waves": waves, "systems": [item for bucket in waves.values() for item in bucket]}
