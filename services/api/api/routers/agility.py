"""System-level 6-factor agility and migration readiness."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from agility.readiness import readiness_from_system
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
    scores = [int(row.get("agility_score") or 0) for row in rows]
    avg = round(sum(scores) / len(scores), 1) if scores else 0
    dist = {"EXCELLENT": 0, "GOOD": 0, "MODERATE": 0, "POOR": 0, "CRITICAL": 0}
    for row in rows:
        dist[str(row.get("category") or "CRITICAL")] = dist.get(str(row.get("category") or "CRITICAL"), 0) + 1
    return {"systems": rows, "average": avg, "distribution": dist}


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
