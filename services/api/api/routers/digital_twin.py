"""Cryptographic Digital Twin — the estate replica, its scenarios and fidelity.

The twin is the live crypto estate replica: ``crypto_live_states`` (current
state, versioned CBOM) plus the ``crypto_live_events`` journal (time-travel).
This router exposes what a twin owes its operator:

* ``GET  /digital-twin``            — replica overview (what the twin holds)
* ``GET  /digital-twin/fidelity``   — how well the twin tracks the estate
* ``GET  /digital-twin/reconciliation`` — twin's algorithms vs its evidence
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

from agility.twin_scenarios import SCENARIOS, run_scenario, reconcile, twin_fidelity
from api.dependencies import get_current_user, get_db_session
from db.models.certificate import Certificate
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.models.crypto_live import CryptoLiveEventRow, CryptoLiveState
from db.models.evidence_record import EvidenceRecord
from db.models.graph_snapshot import GraphSnapshot
from db.models.hardware_live import HardwareAsset
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
    "hardware": 20000,
    "systems": 20000,
    "system_vendors": 20000,
    "vendors": 20000,
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

    system_vendors = db.query(SystemVendor).limit(
        SNAPSHOT_CAPS["system_vendors"]).all()
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
        for system in db.query(System).limit(SNAPSHOT_CAPS["systems"]).all()
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
    # distinct(): an evidence record reachable through two assets of the same
    # system must not appear twice. The row list is capped; the exact
    # per-algorithm counts for reconciliation come from the GROUP BY below.
    evidence_rows = (
        db.query(EvidenceRecord, SystemAsset.system_id)
        .outerjoin(CryptoAssetEvidence,
                   CryptoAssetEvidence.evidence_id == EvidenceRecord.id)
        .outerjoin(SystemAsset,
                   SystemAsset.asset_id == CryptoAssetEvidence.asset_id)
        .distinct()
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

    # Exact per-algorithm evidence counts, unbounded and cheap — the GROUP BY
    # keeps reconciliation correct even when the capped evidence-row list
    # above had to truncate on a very large estate.
    evidence_algorithm_counts = {
        algorithm: int(count)
        for algorithm, count in db.query(
            EvidenceRecord.algorithm, func.count(EvidenceRecord.id)
        ).group_by(EvidenceRecord.algorithm).all()
        if algorithm
    }

    dependencies = [
        {"source": dep.parent_id, "target": dep.child_id, "type": dep.relation}
        for dep in db.query(SystemDependency).limit(50000).all()
    ]
    dependency_source = "system_dependencies"
    if not dependencies:
        # Estates that maintain their dependency graph in the graph engine
        # (versioned graph_snapshots) get their edges from the latest
        # snapshot instead — attack paths work on both shapes of estate.
        snap = (
            db.query(GraphSnapshot)
            .order_by(GraphSnapshot.version.desc()).first()
        )
        if snap and snap.edges:
            dependencies = [
                {"source": str(edge.get("from")),
                 "target": str(edge.get("to")),
                 "type": str(edge.get("label") or "graph")}
                for edge in snap.edges
                if edge.get("from") and edge.get("to")
            ]
            dependency_source = f"graph_snapshot:v{snap.version}"
    if not dependencies:
        dependency_source = "none"

    # Observed endpoints come from stored network scans — the same derivation
    # the NBOM uses (newest run wins per endpoint), so the twin and the NBOM
    # can never disagree about what was seen on the wire.
    from api.routers.cbom import _gather_network_inventory

    network_endpoints = []
    for ep in _gather_network_inventory(db)["endpoints"]:
        network_endpoints.append({
            "host": ep.get("host"), "port": ep.get("port"),
            "protocol": ep.get("protocol"), "version": ep.get("tls_version"),
            "cipher_suite": ep.get("cipher_suite"),
            "observed": bool(ep.get("observed", True)),
            "certificate_subject": (ep.get("certificate") or {}).get("subject"),
        })
    observed_keys = {f"{e['host']}:{e['port']}" for e in network_endpoints}
    # Registered scan targets that no run has observed yet still count as
    # endpoints — intent without observation carries no protocol version,
    # and the protocol scenario reports that gap honestly. Registered
    # host:port → system linkage is also stamped onto observed endpoints so
    # certificate and endpoint cascades can name the owning system.
    registered = db.query(NetworkScanTarget).limit(
        SNAPSHOT_CAPS["endpoints"]).all()
    registered_system = {
        f"{_split_endpoint(t.endpoint or '')[0]}:{_split_endpoint(t.endpoint or '')[1]}":
        t.system_id for t in registered}
    for endpoint in network_endpoints:
        if endpoint.get("system_id") is None:
            endpoint["system_id"] = registered_system.get(
                f"{endpoint.get('host')}:{endpoint.get('port')}")
    for target in registered:
        host, port = _split_endpoint(target.endpoint or "")
        if f"{host}:{port}" in observed_keys:
            continue
        network_endpoints.append({
            "host": host, "port": port,
            "system_id": target.system_id,
            "protocol": None, "version": None, "observed": False,
            "certificate_subject": None,
        })

    # The hardware fleet from the live hardware engine — agents and authorized
    # management APIs feed it; the twin only reads. HSM observations carry
    # the scanner's declared PQC capability, never vendor marketing claims.
    hardware = [
        {
            "asset_id": hw.asset_id,
            "agent_id": hw.agent_id,
            "manufacturer": hw.manufacturer,
            "model": hw.model,
            "device_type": hw.device_type,
            "firmware": hw.firmware,
            "hsm": hw.hsm,
            "capabilities": hw.capabilities,
            "crypto_capabilities": hw.crypto_capabilities,
            "last_seen": hw.last_seen.isoformat() if hw.last_seen else None,
            "risk_score": hw.risk_score,
            "risk_level": hw.risk_level,
        }
        for hw in db.query(HardwareAsset).limit(SNAPSHOT_CAPS["hardware"]).all()
    ]

    return {
        "assets": assets,
        "systems": systems,
        "certificates": certificates,
        "vendors": [
            {"id": v.id, "name": v.name, "criticality": v.criticality,
             "vendor_type": v.vendor_type}
            for v in db.query(Vendor).limit(SNAPSHOT_CAPS["vendors"]).all()
        ],
        "system_vendors": [
            {"system_id": sv.system_id, "vendor_id": sv.vendor_id,
             "dependency_type": sv.dependency_type}
            for sv in system_vendors
        ],
        "evidence": evidence,
        "evidence_algorithm_counts": evidence_algorithm_counts,
        "dependencies": dependencies,
        "dependency_source": dependency_source,
        "network_endpoints": network_endpoints,
        "hardware": hardware,
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
    endpoints = snapshot["network_endpoints"]
    hardware = snapshot.get("hardware") or []
    hardware_hsms = sum(
        1 for hw in hardware
        if str(hw.get("device_type") or "").lower() == "hsm" or hw.get("hsm")
    )
    return {
        "schema": "cryptoscan.digital-twin/1",
        "twin_assets": len(assets),
        "systems": len(snapshot["systems"]),
        "certificates": len(snapshot["certificates"]),
        # unique records, not (record, system) linkage rows: the snapshot's
        # evidence list carries one row per linked system for per-system
        # attribution, and a record linked to two systems is still one record.
        "evidence_records": len({e.get("id") for e in snapshot["evidence"]}),
        "dependency_edges": len(snapshot["dependencies"]),
        "dependency_source": snapshot.get("dependency_source"),
        "network_endpoints": len(endpoints),
        "network_endpoints_observed": sum(
            1 for e in endpoints if e.get("observed")),
        "hardware_assets": len(hardware),
        "hardware_hsms": hardware_hsms,
        "quantum_mix": quantum_mix,
        "scenarios_available": sorted(SCENARIOS),
        "fidelity": twin_fidelity(snapshot, now=datetime.now(timezone.utc)),
    }


@router.get("/digital-twin/fidelity")
def digital_twin_fidelity(user: str = Depends(get_current_user),
                          db: Session = Depends(get_db_session)):
    """Measured twin-vs-estate tracking, with honest unknowns."""
    return twin_fidelity(_snapshot(db), now=datetime.now(timezone.utc))


@router.get("/digital-twin/reconciliation")
def digital_twin_reconciliation(user: str = Depends(get_current_user),
                                db: Session = Depends(get_db_session)):
    """Diff the twin's algorithm inventory against its own evidence store.

    Catches the twin lagging its inputs: families scanners keep finding that
    no twin asset reflects, and twin claims nothing currently backs. This is
    twin-vs-stored-evidence — matching *reality* still needs a fresh scan,
    and the result says so.
    """
    return reconcile(_snapshot(db), now=datetime.now(timezone.utc))


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
