"""Universal Cryptography Scanner — live crypto API surface.

Event ingestion (certificates, algorithms, libraries, protocols, keys,
capabilities, unknown crypto operations), live state (§34), timeline
(point-in-time reconstruction), versioned CycloneDX CBOM (§35), PQC risk.

The database is the current truth: every ingest persists state + the
immutable event journal through CryptoRepository. No key material is ever
accepted — payloads carry metadata and algorithm identifiers only.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.dependencies import get_current_user, get_db_session
from api.security.rbac import require_permission
from sqlalchemy.orm import Session

from db.repositories.crypto_repository import CryptoRepository

from universal_crypto.live.engine import LiveCryptoEngine
from universal_crypto.live.events import CryptoEvent
from universal_crypto.models import CryptoEventType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/crypto", tags=["crypto"])

_ENGINE: Optional[LiveCryptoEngine] = None


class CryptoEventRequest(BaseModel):
    event_type: CryptoEventType
    asset_id: str = "default"
    source: str = "live"
    observed_at: Optional[str] = None
    payload: dict[str, Any] = Field(default_factory=dict)


def _engine() -> LiveCryptoEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = LiveCryptoEngine()
    return _ENGINE


def _persist_ingest(db: Session, engine: LiveCryptoEngine,
                    result: dict[str, Any], event: CryptoEvent) -> None:
    repo = CryptoRepository(db)
    state = engine.state(event.asset_id)
    state_dict = state.to_dict()
    state_dict["cbom"] = result["cbom"]
    state_dict["last_event"] = event.event_type.value
    state_dict["last_seen"] = event.observed_at.isoformat()
    repo.upsert_state(state_dict)
    risk = result["risk"]
    repo.update_risk(event.asset_id, score=int(risk["score"]),
                     level=str(risk["level"]))
    repo.append_event({
        "event_type": event.event_type.value,
        "asset_id": event.asset_id,
        "source": event.source,
        "observed_at": event.observed_at,
        "cbom_version": result["cbom_version"],
        "risk_score": int(risk["score"]),
        "payload": event.payload,
    })
    db.commit()


# ── ingestion (§34) ────────────────────────────────────────────────────

@router.post("/live/events")
def ingest_event(
    body: CryptoEventRequest,
    user: str = Depends(require_permission("crypto.ingest")),
    db: Session = Depends(get_db_session),
):
    event = CryptoEvent(
        event_type=body.event_type,
        asset_id=body.asset_id,
        source=body.source,
        observed_at=body.observed_at or datetime.now(timezone.utc),
        payload=body.payload,
    )
    result = _engine().ingest(event)
    _persist_ingest(db, _engine(), result, event)
    return {
        "event_type": event.event_type.value,
        "asset_id": event.asset_id,
        "changed": result["event"]["change"]["changed"],
        "risk": result["risk"],
        "readiness": result["readiness"],
        "agility": result["agility"],
        "cbom_version": result["cbom_version"],
    }


# ── live state (§34) ───────────────────────────────────────────────────

@router.get("/live/state")
def live_state(
    user: str = Depends(require_permission("crypto.read")),
    db: Session = Depends(get_db_session),
):
    rows = CryptoRepository(db).list_states()
    return {"assets": [r.state_dict() for r in rows], "total_count": len(rows)}


@router.get("/live/state/{asset_id}")
def asset_state(
    asset_id: str,
    user: str = Depends(require_permission("crypto.read")),
    db: Session = Depends(get_db_session),
):
    row = CryptoRepository(db).get_state(asset_id)
    if row is None:
        raise HTTPException(status_code=404, detail="crypto state not found")
    return row.state_dict()


@router.get("/live/risk-summary")
def risk_summary(
    user: str = Depends(require_permission("crypto.read")),
    db: Session = Depends(get_db_session),
):
    rows = CryptoRepository(db).list_states()
    return {
        "assets": [{
            "asset_id": r.asset_id,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "readiness": r.readiness,
            "cbom_version": r.cbom_version,
        } for r in rows],
        "total_count": len(rows),
    }


# ── timeline (§34 reconstruction) ──────────────────────────────────────

@router.get("/live/timeline")
def event_timeline(
    asset_id: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
    user: str = Depends(require_permission("crypto.read")),
    db: Session = Depends(get_db_session),
):
    repo = CryptoRepository(db)
    rows, total = repo.list_events(asset_id=asset_id, event_type=event_type,
                                   page=page, page_size=page_size)
    return {"events": [r.event_dict() for r in rows],
            "total_count": total, "page": page}


# ── versioned CBOM (§35) ───────────────────────────────────────────────

@router.get("/live/{asset_id}/cbom")
def live_cbom(
    asset_id: str,
    user: str = Depends(require_permission("crypto.read")),
    db: Session = Depends(get_db_session),
):
    row = CryptoRepository(db).get_state(asset_id)
    if row is None:
        raise HTTPException(status_code=404, detail="crypto state not found")
    if not row.cbom:
        raise HTTPException(status_code=404, detail="no CBOM yet")
    return {"cbom": row.cbom, "version": row.cbom_version}


# ── accuracy platform (§33) ────────────────────────────────────────────

@router.get("/accuracy")
def accuracy_overview(
    user: str = Depends(require_permission("crypto.read")),
):
    from universal_crypto.accuracy import AccuracyPlatform, default_detector

    platform = AccuracyPlatform()
    detector = default_detector()
    return {name: platform.evaluate_dataset(name, detector)["metrics"]["overall"]
            for name in platform.dataset_names()}


# ── one-shot §36 scan + what-if simulation ─────────────────────────────

class ScanRequest(BaseModel):
    inputs: dict[str, Any] = Field(default_factory=dict)


class SimulateRequest(BaseModel):
    current_algorithm: str
    target_algorithm: str
    protocol: str = ""
    library: str = ""
    hardware: str = ""
    usage: bool = True
    current_agility: int = 50
    asset_id: str = "default"


@router.post("/scan")
def run_scan(
    body: ScanRequest,
    user: str = Depends(require_permission("crypto.manage")),
):
    """One-shot §36 pipeline: full scan bundle → observations/findings/
    quantum/readiness/agility/graph/unknown-crypto report."""
    from universal_crypto.engine import UniversalCryptoEngine
    return UniversalCryptoEngine().scan(body.inputs)


@router.post("/simulate")
def simulate_migration(
    body: SimulateRequest,
    user: str = Depends(require_permission("crypto.manage")),
):
    """What-if migration: project readiness/quantum/agility/risk impact."""
    from universal_crypto.simulator import MigrationSimulator
    return MigrationSimulator().simulate(
        asset_id=body.asset_id,
        current_algorithm=body.current_algorithm,
        target_algorithm=body.target_algorithm,
        protocol=body.protocol,
        library=body.library,
        hardware=body.hardware,
        usage=body.usage,
        current_agility=body.current_agility,
    )
