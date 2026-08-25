"""Advanced analytics over stored assets, findings, and systems."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.models.crypto_asset import CryptoAsset
from db.models.evidence_record import EvidenceRecord
from db.models.system import System
from quantum.risk import analyze_quantum_risk
from reporting.analytics import build_analytics

router = APIRouter(prefix="/analytics", tags=["analytics"])


def _payload(db: Session) -> dict:
    assets = [row.to_dict() for row in db.execute(select(CryptoAsset).limit(2000)).scalars()]
    findings = [
        {
            "algorithm": row.algorithm,
            "compliance_status": row.compliance_status,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "file_path": row.file_path,
            "key_size": row.key_size,
            "purpose": row.purpose,
        }
        for row in db.execute(select(EvidenceRecord).limit(4000)).scalars()
    ]
    systems = [row.to_dict() for row in db.execute(select(System).limit(500)).scalars()]
    quantum = analyze_quantum_risk(assets, systems=systems)
    return build_analytics(assets=assets, findings=findings, systems=systems, quantum=quantum)


@router.get("")
def overview(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return _payload(db)


@router.get("/trends")
def trends(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    data = _payload(db)
    return {"trends": data["trends"], "compliance": data["compliance"]}


@router.get("/heatmap")
def heatmap(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"heatmap": _payload(db)["heatmap"]}


@router.get("/forecast")
def forecast(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return _payload(db)["forecast"]


@router.get("/recommendations")
def recs(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"recommendations": _payload(db)["recommendations"]}


@router.get("/executive")
def executive(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return _payload(db)["executive"]
