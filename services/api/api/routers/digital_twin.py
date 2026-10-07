"""Cryptographic Digital Twin — the estate replica, its scenarios and fidelity.

The twin is the live crypto estate replica: ``crypto_live_states`` (current
state, versioned CBOM) plus the ``crypto_live_events`` journal (time-travel).
This router exposes what a twin owes its operator:

* ``GET  /digital-twin``            — replica overview (what the twin holds)
* ``GET  /digital-twin/fidelity``   — how well the twin tracks the estate
* ``GET  /digital-twin/scenarios``  — the ten deterministic scenario types
* ``POST /digital-twin/simulate``   — run one scenario (reads, never mutates)
* ``GET  /digital-twin/timeline/{asset_id}`` — the journal (time-travel)

Simulation is read-only by construction: the engine receives plain dicts
built from ORM rows, mutates nothing, and returns honest unknowns alongside
every computed impact. A scenario result is an operational projection, not
an action; nothing here applies, deploys or re-keys anything.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from agility.twin_scenarios import SCENARIOS, run_scenario, twin_fidelity
from api.dependencies import get_current_user, get_db_session
from db.models.certificate import Certificate
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.models.crypto_live import CryptoLiveEventRow, CryptoLiveState
from db.models.evidence_record import EvidenceRecord
from db.models.network_scan_target import NetworkScanTarget
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.models.system_dependency import SystemDependency
from db.models.vendor import SystemVendor, Vendor

router = APIRouter(tags=["digital-twin"])

#: Journal rows per timeline response — bounded so one chatty asset cannot
#: produce an unbounded payload.
TIMELINE_LIMIT = 500

#: Read caps for the snapshot sections. The twin must degrade honestly on a
#: huge estate rather than OOM the API; the fidelity report names the caps.
SNAPSHOT_CAPS = {
    "certificates": 20000,
    "evidence": 20000,
    "endpoints": 20000,
}


def _split_endpoint(endpoint: str) -> tuple[str, str]:
    """'host:port' → (host, port). Bare host keeps port as ''."""
    if ":" in endpoint:
        host, _, port = endpoint.rpartition(":")
        return host, port
    return endpoint, ""


def _snapshot(db: Session) -> dict:
    """Adapt ORM rows into the engine's plain-dict estate snapshot.

    Every section tolerates absence: the engine treats missing data as an
    honest unknown, so an estate that has never run a network scan still
    gets protocol scenarios — with the gap named, not papered over.
    """
    states = db.query(CryptoLiveState).all()
    asset_ids = [s.asset_id for s in states]

    last_events: dict[str, datetime] = {}
    event_counts: dict[str, int] = {}
    if asset_ids:
        for asset_id, observed in db.query(
            CryptoLiveEventRow.asset_id, func.max(CryptoLiveEventRow.observed_at)
        ).filter(CryptoLiveEventRow.asset_id.in_(asset_ids)).group_by(
            CryptoLiveEventRow.asset_id
        ).all():
            last_events[asset_id] = observed
        for asset_id, count in db.query(
            CryptoLiveEventRow.asset_id, func.count(CryptoLiveEventRow.id)
        ).filter(CryptoLiveEventRow.asset_id.in_(asset_ids)).group_by(
            CryptoLiveEventRow.asset_id
        ).all():
            event_counts[asset_id] = int(count)

    assets = []
    for state in states:
        last_at = last_events.get(state.asset_id) or state.last_seen
        assets.append({
            "asset_id": state.asset_id,
            "cbom_version": state.cbom_version,
            "algorithms": state.algorithms or {},
            "quantum_status": state.quantum_status or {},
            "capabilities": state.capabilities or {},
            "usage": state.usage or {},
            "protocols": state.protocols or {},
            "libraries": state.libraries or {},
            "certificates": state.certificates or {},
            "readiness": state.readiness,
            "agility": state.agility,
            "risk_score": state.risk_score,
            "risk_level": state.risk_level,
            "last_event_at": last_at.isoformat() if last_at else None,
            "event_count": event_counts.get(state.asset_id, 0),
        })

    system_vendors = db.query(SystemVendor).all()
    systems = [
        {
            "id": system.id,
            "name": system.name,
            "environment": system.environment,
            "criticality": system.criticality,
            "agility": system.current_agility_score,
            "readiness": system.migration_readiness_category,
            "coverage_status": system.coverage_status,
            "last_scanned_at": (system.last_scanned_at.isoformat()
                                if system.last_scanned_at else None),
            "vendor_ids": [sv.vendor_id for sv in system_vendors
                           if sv.system_id == system.id],
        }
        for system in db.query(System).all()
    ]

    certificates = [
        {
            "fingerprint_sha256": c.fingerprint_sha256,
            "subject": c.subject,
            "issuer": c.issuer,
            "not_after": c.not_after.isoformat() if c.not_after else None,
            "public_key_algorithm": c.public_key_algorithm,
            "public_key_size": c.public_key_size,
            "expiry_status": c.expiry_status,
            "days_until_expiry": c.days_until_expiry,
            "renewal_status": c.renewal_status,
        }
        for c in db.query(Certificate).limit(SNAPSHOT_CAPS["certificates"]).all()
    ]

    # Evidence → system linkage runs the real chain:
    # evidence_records → crypto_asset_evidence → crypto_assets → system_assets.
    evidence_rows = (
        db.query(EvidenceRecord, SystemAsset.system_id)
        .outerjoin(CryptoAssetEvidence,
                   CryptoAssetEvidence.evidence_id == EvidenceRecord.id)
        .outerjoin(SystemAsset,
                   SystemAsset.asset_id == CryptoAssetEvidence.asset_id)
        .order_by(EvidenceRecord.created_at.desc())
        .limit(SNAPSHOT_CAPS["evidence"]).all()
    )
    evidence = [
        {
            "id": record.id,
            "system_id": system_id,
            "algorithm": record.algorithm,
            "key_size": record.key_size,
            "is_hardcoded_key": bool(record.is_hardcoded_key),
            "file_path": record.file_path,
            "confidence": record.confidence,
        }
        for record, system_id in evidence_rows
    ]

    dependencies = [
        {"source": dep.parent_id, "target": dep.child_id, "type": dep.relation}
        for dep in db.query(SystemDependency).limit(50000).all()
    ]

    network_endpoints = []
    for target in db.query(NetworkScanTarget).limit(
            SNAPSHOT_CAPS["endpoints"]).all():
        host, port = _split_endpoint(target.endpoint or "")
        network_endpoints.append({
            "host": host, "port": port,
            "system_id": target.system_id,
            # TLS version detail lives in scan-run results, not the target
            # row; the protocol scenario reports the gap honestly.
            "protocol": None, "version": None,
        })

    return {
        "assets": assets,
        "systems": systems,
        "certificates": certificates,
        "vendors": [
            {"id": v.id, "name": v.name, "criticality": v.criticality,
             "vendor_type": v.vendor_type}
            for v in db.query(Vendor).all()
        ],
        "system_vendors": [
            {"system_id": sv.system_id, "vendor_id": sv.vendor_id,
             "dependency_type": sv.dependency_type}
            for sv in system_vendors
        ],
        "evidence": evidence,
        "dependencies": dependencies,
        "network_endpoints": network_endpoints,
    }


class SimulateRequest(BaseModel):
    scenario: str
    params: dict | None = None


@router.get("/digital-twin")
def digital_twin_overview(user: str = Depends(get_current_user),
                           db: Session = Depends(get_db_session)):
    """Replica overview: what the twin holds, how fresh, how classified."""
    snapshot = _snapshot(db)
    assets = snapshot["assets"]
    quantum_mix: dict[str, int] = {"vulnerable": 0, "ready": 0, "unknown": 0}
    for asset in assets:
        status = asset.get("quantum_status") or {}
        verdict = str((status.get("status") or status.get("verdict") or "")).lower()
        if "vulnerab" in verdict or "at_risk" in verdict:
            quantum_mix["vulnerable"] += 1
        elif "ready" in verdict:
            quantum_mix["ready"] += 1
        else:
            quantum_mix["unknown"] += 1
    return {
        "schema": "cryptoscan.digital-twin/1",
        "twin_assets": len(assets),
        "systems": len(snapshot["systems"]),
        "certificates": len(snapshot["certificates"]),
        "evidence_records": len(snapshot["evidence"]),
        "dependency_edges": len(snapshot["dependencies"]),
        "network_endpoints": len(snapshot["network_endpoints"]),
        "quantum_mix": quantum_mix,
        "scenarios_available": sorted(SCENARIOS),
        "fidelity": twin_fidelity(snapshot, now=datetime.now(timezone.utc)),
    }


@router.get("/digital-twin/fidelity")
def digital_twin_fidelity(user: str = Depends(get_current_user),
                          db: Session = Depends(get_db_session)):
    """Measured twin-vs-estate tracking, with honest unknowns."""
    return twin_fidelity(_snapshot(db), now=datetime.now(timezone.utc))


@router.get("/digital-twin/scenarios")
def digital_twin_scenarios(user: str = Depends(get_current_user)):
    """The ten deterministic scenario types and their inputs."""
    return {
        "scenario_count": len(SCENARIOS),
        "scenarios": [
            {"id": sid, "name": entry["name"], "description": entry["description"],
             "inputs": entry["inputs"]}
            for sid, entry in sorted(SCENARIOS.items())
        ],
    }


@router.post("/digital-twin/simulate")
def digital_twin_simulate(body: SimulateRequest,
                          user: str = Depends(get_current_user),
                          db: Session = Depends(get_db_session)):
    """Run one scenario. Reads the estate; mutates nothing."""
    try:
        return run_scenario(body.scenario, _snapshot(db),
                            now=datetime.now(timezone.utc),
                            params=body.params or {})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/digital-twin/timeline/{asset_id}")
def digital_twin_timeline(asset_id: str,
                          user: str = Depends(get_current_user),
                          db: Session = Depends(get_db_session)):
    """The immutable journal for one asset — the twin's time-travel."""
    state = (
        db.query(CryptoLiveState)
        .filter(CryptoLiveState.asset_id == asset_id).first()
    )
    events = (
        db.query(CryptoLiveEventRow)
        .filter(CryptoLiveEventRow.asset_id == asset_id)
        .order_by(CryptoLiveEventRow.observed_at.desc(),
                  CryptoLiveEventRow.id.desc())
        .limit(TIMELINE_LIMIT).all()
    )
    if state is None and not events:
        raise HTTPException(status_code=404, detail="asset not found in the twin")
    return {
        "asset_id": asset_id,
        "current_cbom_version": state.cbom_version if state else None,
        "quantum_status": state.quantum_status if state else None,
        "risk": {"score": state.risk_score, "level": state.risk_level} if state else None,
        "events": [
            {
                "event_type": e.event_type,
                "source": e.source,
                "observed_at": e.observed_at.isoformat() if e.observed_at else None,
                "cbom_version": e.cbom_version,
                "risk_score": e.risk_score,
            }
            for e in events
        ],
        "truncated_to": TIMELINE_LIMIT,
    }
