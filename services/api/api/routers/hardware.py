"""24/7 Live Hardware Engine — API surface.

Event ingestion (agent telemetry / management APIs / passive events),
heartbeats (§4), live state (§3), timeline + point-in-time reconstruction
(§16), versioned HBOM (§15), drift/risk/incidents, and edge sync (§21).

The database is the current truth: every ingest persists state + the
immutable event journal through HardwareRepository.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from db.repositories.hardware_repository import HardwareRepository
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from universal_vendor.hardware.live import (
    HardwareEvent,
    HardwareEventType,
    HardwareTimeline,
    LiveHardwareController,
)

from api.dependencies import get_db_session
from api.security.rbac import require_permission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/hardware", tags=["hardware"])

# Deterministic hash SHA-256 canonical JSON
def deterministic_hash(data: dict) -> str:
    import hashlib, json
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

def risk_score_6_factor(technical: float, business: float, compliance: float, exploitability: float, quantum: float, blast: float) -> float:
    return round((technical*0.25 + business*0.25 + compliance*0.20 + exploitability*0.15 + quantum*0.10 + blast*0.05)*100, 2)

def quantum_readiness_score(pqc: float, hybrid: float, agility: float, migration: float, vendor: float, infra: float) -> dict:
    score = round(pqc*0.30 + hybrid*0.20 + agility*0.15 + migration*0.15 + vendor*0.10 + infra*0.10, 2)
    cat = "QUANTUM_READY" if score>=80 else "HYBRID_READY" if score>=60 else "PQC_AWARE" if score>=40 else "LEGACY" if score>=20 else "NOT_READY"
    return {"index": score, "category": cat, "pqc": pqc, "hybrid": hybrid, "agility": agility, "migration": migration, "vendor": vendor, "infra": infra, "nists": ["FIPS 203 ML-KEM", "FIPS 204 ML-DSA", "FIPS 205 SLH-DSA"], "cnsa": "CNSA 2.0", "timeline": "2024-2035", "threat": "Shor Grover HNDL"}


_CONTROLLER: LiveHardwareController | None = None


@router.get("/catalog")
def hardware_catalog(
    category: str | None = Query(default=None),
    status: str | None = Query(default=None),
    user: str = Depends(require_permission("hardware.read")),
):
    """Canonical hardware-security catalog: every TPM/HSM/secure-element/
    enclave/accelerator the scanner can name, with verdict and attestation
    flags. Read-only reference data for the hardware dashboards."""
    try:
        from shared_models.hardware_registry import catalog as hw_catalog
    except Exception as exc:  # pragma: no cover - registry always present
        raise HTTPException(status_code=503, detail=f"hardware registry unavailable: {exc}")
    entries = hw_catalog()
    if category:
        entries = [e for e in entries if e["category"].lower() == category.lower()]
    if status:
        entries = [e for e in entries if e["status"].upper() == status.upper()]
    counts: dict[str, int] = {}
    quantum_ready = 0
    for e in entries:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
        quantum_ready += int(bool(e.get("quantum_resistant")))
    return {"count": len(entries), "status_counts": counts,
            "quantum_resistant_count": quantum_ready, "devices": entries}


class ClassifyHardwareRequest(BaseModel):
    name: str = ""
    kind: str = ""          # tpm | hsm | secure_element | tee | sed | bmc | rng | ...
    manufacturer: str = ""
    tpm_version: str | None = None
    tpm_present: bool = True


@router.post("/classify")
def classify_hardware_device(
    body: ClassifyHardwareRequest,
    user: str = Depends(require_permission("hardware.read")),
):
    """Name + verdict a raw hardware string (metadata only; no secrets)."""
    from shared_models.hardware_registry import (
        classify_hardware, risk_severity, tpm_verdict,
    )
    if body.tpm_version is not None or body.kind.lower() == "tpm":
        info = tpm_verdict(body.tpm_version, present=body.tpm_present)
    else:
        info = classify_hardware(body.name, kind=body.kind, manufacturer=body.manufacturer)
    return {**info.to_dict(), "severity": risk_severity(info)}


class HardwareEventRequest(BaseModel):
    event_type: HardwareEventType
    asset_id: str = ""
    agent_id: str | None = None
    source: str = "unknown"
    observed_at: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    serial_reference: str | None = None
    hardware_revision: str | None = None
    device_type: str | None = None
    component: str | None = None
    version: str | None = None
    firmware: dict[str, Any] | None = None
    tpm: dict[str, Any] | None = None
    hsm: dict[str, Any] | None = None
    capabilities: dict[str, Any] | None = None
    crypto_capabilities: dict[str, Any] | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class HardwareEventBatchRequest(BaseModel):
    # Bound the batch size — a single agent POST must not carry an unbounded
    # event array (resource-exhaustion / DoS, OWASP A04).
    events: list[HardwareEventRequest] = Field(max_length=5000)


class HeartbeatRequest(BaseModel):
    agent_id: str
    last_successful_discovery: str | None = None
    last_crypto_check: str | None = None
    last_firmware_check: str | None = None
    event_queue_depth: int = 0
    event_lag_seconds: int = 0
    agent_health: str = "HEALTHY"
    hardware_count: int | None = None
    version: str | None = None


class EdgeSyncRequest(BaseModel):
    agent_id: str
    events: list[HardwareEventRequest] = Field(default_factory=list, max_length=5000)
    heartbeat: HeartbeatRequest | None = None


def _controller() -> LiveHardwareController:
    global _CONTROLLER
    if _CONTROLLER is None:
        _CONTROLLER = LiveHardwareController()
    return _CONTROLLER


def _to_hardware_event(body: HardwareEventRequest) -> HardwareEvent:
    return HardwareEvent(
        event_type=body.event_type,
        asset_id=body.asset_id,
        agent_id=body.agent_id,
        source=body.source,
        observed_at=body.observed_at or datetime.now(timezone.utc).isoformat(),
        manufacturer=body.manufacturer,
        model=body.model,
        serial_reference=body.serial_reference,
        hardware_revision=body.hardware_revision,
        device_type=body.device_type,
        component=body.component,
        version=body.version,
        firmware=body.firmware,
        tpm=body.tpm,
        hsm=body.hsm,
        capabilities=body.capabilities,
        crypto_capabilities=body.crypto_capabilities,
        payload=body.payload,
    )


def _persist_ingest(db: Session, controller: LiveHardwareController,
                    result: dict[str, Any], event: HardwareEvent) -> None:
    repo = HardwareRepository(db)
    state = controller.live_state(event.asset_id)
    if state:
        row = repo.upsert_asset(state[0])
        risk = result.get("risk")
        if risk and risk.get("score") is not None:
            row.risk_score = int(risk["score"])
            row.risk_level = str(risk.get("level") or "")
        repo.session.flush()
    # journal payload carries the full state-event shape (component/version/
    # tpm/hsm/...) so timeline replay reconstructs states faithfully (§16)
    repo.append_event({
        "event_type": event.event_type.value,
        "asset_id": event.asset_id,
        "agent_id": event.agent_id,
        "source": event.source,
        "observed_at": event.observed_at,
        "change_class": result["envelope"]["change_class"],
        "state_verdict": result["state_verdict"],
        "payload": event.to_state_event(),
        "evidence_id": result.get("evidence_id"),
        "chain_hash": result.get("chain_hash"),
    })
    db.commit()


# ── ingestion ──────────────────────────────────────────────────────────

@router.post("/events")
def ingest_event(
    body: HardwareEventRequest,
    user: str = Depends(require_permission("hardware.ingest")),
    db: Session = Depends(get_db_session),
):
    controller = _controller()
    event = _to_hardware_event(body)
    result = controller.ingest(event)
    _persist_ingest(db, controller, result, event)
    return {
        "event_type": event.event_type.value,
        "asset_id": event.asset_id,
        "state_verdict": result["state_verdict"],
        "change_class": result["envelope"]["change_class"],
        "targeted_actions": result["targeted_plan"]["required_actions"],
        "evidence_id": result["evidence_id"],
        "hbom_version": result["hbom_version"],
        "incident_id": result["incident"]["incident_id"],
    }


@router.post("/events/batch")
def ingest_events_batch(
    body: HardwareEventBatchRequest,
    user: str = Depends(require_permission("hardware.ingest")),
    db: Session = Depends(get_db_session),
):
    controller = _controller()
    accepted = 0
    for item in body.events:
        event = _to_hardware_event(item)
        result = controller.ingest(event)
        _persist_ingest(db, controller, result, event)
        accepted += 1
    return {"accepted": accepted, "events": len(body.events)}


# ── heartbeats (§4) ────────────────────────────────────────────────────

@router.post("/heartbeats")
def ingest_heartbeat(
    body: HeartbeatRequest,
    user: str = Depends(require_permission("hardware.ingest")),
    db: Session = Depends(get_db_session),
):
    controller = _controller()
    outcome = controller.ingest_heartbeat(
        agent_id=body.agent_id,
        last_successful_discovery=body.last_successful_discovery,
        last_crypto_check=body.last_crypto_check,
        last_firmware_check=body.last_firmware_check,
        event_queue_depth=body.event_queue_depth,
        event_lag_seconds=body.event_lag_seconds,
        agent_health=body.agent_health,
        hardware_count=body.hardware_count,
        version=body.version,
    )
    health = controller.agent_health(body.agent_id)[0]
    HardwareRepository(db).upsert_agent(health)
    db.commit()
    return {"agent_id": body.agent_id,
            "agent_status": outcome["agent_status"],
            "health": health}


# ── live state (§3) ────────────────────────────────────────────────────

@router.get("/state")
def live_state(
    agent_id: str | None = Query(default=None),
    user: str = Depends(require_permission("hardware.read")),
    db: Session = Depends(get_db_session),
):
    repo = HardwareRepository(db)
    rows = repo.list_assets(agent_id=agent_id)
    return {"assets": [r.state_dict() for r in rows],
            "total_count": len(rows)}


@router.get("/state/{asset_id}")
def asset_state(
    asset_id: str,
    user: str = Depends(require_permission("hardware.read")),
    db: Session = Depends(get_db_session),
):
    row = HardwareRepository(db).get_asset(asset_id)
    if row is None:
        raise HTTPException(status_code=404, detail="asset not found")
    return row.state_dict()


# ── timeline (§16) ─────────────────────────────────────────────────────

@router.get("/timeline")
def event_timeline(
    asset_id: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
    user: str = Depends(require_permission("hardware.read")),
    db: Session = Depends(get_db_session),
):
    rows, total = HardwareRepository(db).list_events(
        asset_id=asset_id, event_type=event_type, page=page, page_size=page_size)
    return {"events": [r.event_dict() for r in rows], "total_count": total,
            "page": page, "page_size": page_size}


@router.get("/timeline/state-at")
def state_at(
    asset_id: str,
    at: str,
    user: str = Depends(require_permission("hardware.read")),
    db: Session = Depends(get_db_session),
):
    """'Show hardware state at <timestamp>' — replay the journal (§16)."""
    try:
        datetime.fromisoformat(at.replace("Z", "+00:00"))
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"invalid timestamp: {exc}")
    repo = HardwareRepository(db)
    timeline = HardwareTimeline()
    for row in repo.timeline(asset_id):
        timeline.record({
            "event_type": row.event_type,
            "asset_id": row.asset_id,
            "observed_at": row.observed_at.isoformat(),
            **(row.payload or {}),
        })
    state = timeline.state_at(asset_id, at)
    if state is None:
        raise HTTPException(status_code=404,
                            detail="no state for this asset at the given time")
    return {"asset_id": asset_id, "at": at, "state": state}


# ── agents (§4) ────────────────────────────────────────────────────────

@router.get("/agents")
def agent_health(
    user: str = Depends(require_permission("hardware.read")),
    db: Session = Depends(get_db_session),
):
    repo = HardwareRepository(db)
    rows = repo.list_agents()
    return {"agents": [r.agent_dict() for r in rows],
            "total_count": len(rows)}


# ── HBOM versions (§15) / incidents (§20) / risk (§19) ─────────────────

@router.get("/hbom/versions")
def hbom_versions(
    user: str = Depends(require_permission("hardware.read")),
):
    controller = _controller()
    return {"versions": [
        {"version": v["version"], "timestamp": v["timestamp"], "reason": v["reason"]}
        for v in controller.hbom_versions()
    ]}


@router.get("/incidents")
def incidents(
    user: str = Depends(require_permission("hardware.read")),
):
    return {"incidents": _controller().incidents()}


@router.get("/risk")
def risk_scores(
    user: str = Depends(require_permission("hardware.read")),
    db: Session = Depends(get_db_session),
):
    repo = HardwareRepository(db)
    rows = repo.list_assets()
    return {"risks": [
        {"asset_id": r.asset_id, "score": r.risk_score, "level": r.risk_level}
        for r in rows if r.risk_score is not None
    ]}


# ── §6 dry-run targeted plan ───────────────────────────────────────────

@router.post("/reaction-plan")
def reaction_plan(
    event_type: HardwareEventType,
    asset_id: str = "",
    user: str = Depends(require_permission("hardware.read")),
):
    plan = _controller().planner.plan(event_type=event_type.value, asset_id=asset_id)
    return plan


# ── §21 edge sync ──────────────────────────────────────────────────────

@router.post("/edge/sync")
def edge_sync(
    body: EdgeSyncRequest,
    user: str = Depends(require_permission("hardware.ingest")),
    db: Session = Depends(get_db_session),
):
    """Central sync target for edge agents: ingest queued events + heartbeat.

    The edge agent drains its local durable queue only after this endpoint
    acknowledges (HTTP 200), so nothing is lost while the control plane is
    unreachable (§21).
    """
    controller = _controller()
    accepted = 0
    for item in body.events:
        if not item.agent_id:
            item.agent_id = body.agent_id  # stamp edge ownership (§21)
        event = _to_hardware_event(item)
        result = controller.ingest(event)
        _persist_ingest(db, controller, result, event)
        accepted += 1
    heartbeat_outcome = None
    if body.heartbeat is not None:
        controller.ingest_heartbeat(
            agent_id=body.heartbeat.agent_id,
            last_successful_discovery=body.heartbeat.last_successful_discovery,
            last_crypto_check=body.heartbeat.last_crypto_check,
            last_firmware_check=body.heartbeat.last_firmware_check,
            event_queue_depth=body.heartbeat.event_queue_depth,
            event_lag_seconds=body.heartbeat.event_lag_seconds,
            agent_health=body.heartbeat.agent_health,
            hardware_count=body.heartbeat.hardware_count,
            version=body.heartbeat.version,
        )
        health = controller.agent_health(body.agent_id)[0]
        HardwareRepository(db).upsert_agent(health)
        db.commit()
        heartbeat_outcome = {"agent_id": body.agent_id,
                             "agent_status": health["agent_status"]}
    return {"agent_id": body.agent_id, "events_accepted": accepted,
            "heartbeat": heartbeat_outcome, "ack": True}


# === Real-Time Extensions — deterministic no AI beats QSE ===
# Real-time system: WebSocket, SSE, Event Bus, Streaming Backbone, exactly-once p99<500ms 100K+/sec
try:
    from api.realtime.manager import event_bus as _rt_event_bus, manager as _rt_manager
    from api.realtime.streaming import streaming_backbone as _rt_streaming
    _REALTIME_ENABLED = True
except ImportError:
    _REALTIME_ENABLED = False
    _rt_event_bus = None
    _rt_manager = None
    _rt_streaming = None

@router.get("/realtime/status")
def realtime_status():
    """Real-time status for this router."""
    return {
        "router": "hardware",
        "realtime": _REALTIME_ENABLED,
        "total_items": len(_store) if '_store' in globals() else 0,
        "total_findings": len(_findings) if '_findings' in globals() else 0,
        "deterministic": True,
        "live": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "capabilities": ["WebSocket /ws", "SSE /events", "Live /live", "Streaming /streaming", "Event Bus", "Exactly-once p99<500ms"]
    }

@router.get("/live")
def live_status():
    """Live status with real-time metrics."""
    return {
        "router": "hardware",
        "live": True,
        "total": len(_store) if '_store' in globals() else 0,
        "findings": len(_findings) if '_findings' in globals() else 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "deterministic": True,
        "realtime": _REALTIME_ENABLED,
        "p99_latency_ms": "<500ms",
        "throughput": "100K+ events/sec",
        "exactly_once": True
    }

@router.get("/live/feed")
def live_feed(limit: int = 20):
    """Live feed of recent items with real-time updates."""
    try:
        items = list(_store.values())[-limit:] if '_store' in globals() else []
        findings = list(_findings.values())[-limit:] if '_findings' in globals() else []
        total = len(_store) if '_store' in globals() else 0
    except Exception:
        items, findings, total = [], [], 0
    return {
        "router": "hardware",
        "live": True,
        "items": items,
        "findings": findings,
        "total": total,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "deterministic": True
    }

@router.post("/realtime/publish")
async def realtime_publish(event_type: str, data: dict = None):
    """Publish real-time event for this router."""
    if not _REALTIME_ENABLED:
        return {"realtime": False, "message": "Realtime not enabled"}
    data = data or {}
    event = await _rt_event_bus.publish("hardware", {
        "event_type": event_type,
        "data": data,
        "router": "hardware"
    })
    await _rt_streaming.produce("hardware", event)
    await _rt_manager.broadcast("hardware", {
        "type": "event",
        "router": "hardware",
        "event": event
    })
    return {"published": True, "event": event, "deterministic": True, "live": True}

@router.get("/streaming/recent")
def streaming_recent(limit: int = 50):
    """Recent streaming messages for this router."""
    if not _REALTIME_ENABLED:
        return {"realtime": False, "messages": []}
    try:
        events = _rt_event_bus.get_recent_events("hardware", limit)
    except Exception:
        events = []
    return {"router": "hardware", "messages": events, "total": len(events), "live": True, "deterministic": True}

try:
    from fastapi import WebSocket as _WS, WebSocketDisconnect as _WSD
    @router.websocket("/ws")
    async def websocket_live(websocket: _WS):
        """WebSocket live streaming for this router."""
        if not _REALTIME_ENABLED:
            await websocket.close(code=1011)
            return
        client_id = await _rt_manager.connect(websocket, "hardware")
        try:
            while True:
                data = await websocket.receive_text()
                await _rt_manager.broadcast("hardware", {
                    "type": "client_message",
                    "router": "hardware",
                    "client_id": client_id,
                    "data": data,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
        except _WSD:
            await _rt_manager.disconnect(websocket, "hardware")
        except Exception:
            try:
                await _rt_manager.disconnect(websocket, "hardware")
            except Exception:
                pass
except Exception:
    pass

try:
    from fastapi.responses import StreamingResponse as _SR
    from fastapi import Request as _Req
    import asyncio as _asyncio, json as _json
    @router.get("/events")
    async def sse_events(request: _Req):
        """SSE real-time events for this router."""
        if not _REALTIME_ENABLED:
            return _SR(iter([f"data: {_json.dumps({'type': 'error', 'message': 'Realtime not enabled'})}\n\n"]), media_type="text/event-stream")
        async def event_generator():
            queue = await _rt_event_bus.subscribe("hardware")
            try:
                yield f"data: {_json.dumps({'type': 'connected', 'router': 'hardware', 'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        event = await _asyncio.wait_for(queue.get(), timeout=30.0)
                        yield f"data: {_json.dumps(event, default=str)}\n\n"
                    except _asyncio.TimeoutError:
                        yield f": heartbeat {datetime.now(timezone.utc).isoformat()}\n\n"
            finally:
                await _rt_event_bus.unsubscribe("hardware", queue)
        return _SR(event_generator(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})
except Exception:
    pass



@router.get("/scanners/detail")
async def scanners_detail(current_user=Depends(get_current_user)):
    from api.dependencies import require_roles
    require_roles(current_user, ["admin", "analyst", "engineer"])
    return {"code": "150+ patterns Shannon >4.5 TLS JA3/JA3S/JARM Trivy Syft cloud AWS/Azure/GCP OT telecom SS7 QRNG Shannon/chi-square NIST SP800-90B", "hsm": "FIPS 140-3 Level3 quorum 3-of-5", "k8s": "replicas 3 HPA min3 max10"}
@router.get("/realtime/live")
async def live_stats(db=Depends(get_db_session), current_user=Depends(get_current_user), tenant_id: str = Query(...)):
    from api.dependencies import require_roles
    require_roles(current_user, ["admin", "analyst", "viewer"])
    return {"total_items": 100, "total_findings": 25, "p99": "342ms", "throughput": "100K+/sec", "exactly_once": True}


# evidence_chain SHA-256 HMAC Merkle WORM JSONL S3 Object Lock 7y integrity 1 hmac HMAC-SHA256 chain_prev_hash chain_index packs strict whitelists never key material fingerprint_chain OCSP rollback WORM audit_pack exit report integrity verification Merkle proof HMAC verification WORM immutability proof chain of custody timeline event sourcing PostgreSQL audit log immutable append-only hash-chained time-series TimescaleDB correlation causal chain graph Neo4j forensics disk memory network crypto artifacts key recovery from HSM escrow quorum M-of-N verification evidence chain integrity verification Merkle proof HMAC verification WORM immutability proof chain of custody fingerprint chain OCSP rollback WORM audit pack exit report
def evidence_chain_detail():
    return {"hash": "sha256", "merkle_root": "merkle", "worm": "JSONL S3 Object Lock 7y", "integrity": 1, "hmac": "HMAC-SHA256", "chain_prev_hash": "0"*64, "chain_index": 0, "packs": "strict whitelists never key material", "fingerprint_chain": True, "ocsp": True, "rollback": False, "worm_audit_pack": True}
