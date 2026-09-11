"""Telecom realtime crypto-posture API.

International carrier estates: carriers (PLMN, country, legal entity) →
network functions (5G SBA / EPC / IMS / signaling / NDS/IP) → live probes.
Realtime story: every scan pass diffs against the previous state
(telecom_scanner.realtime) and publishes ``telecom.event`` frames onto the
platform event bus, so SSE clients see posture changes as they happen —
reachability loss, verdict changes, certificate expiries, recoveries.

Permissions follow the platform matrix conventions: surfaces are
findings.read (every role); registry changes are telecom.manage; accepting
operator-side probe results (IKE/IPsec from inside the carrier network,
probes behind NAT) is telecom.ingest; triggering scans is scan.trigger.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.security.rbac import require_permission

router = APIRouter(prefix="/telecom", tags=["telecom"])

# ------------------------------------------------------------ snapshot store
# Last scan/ingest result, kept in memory for the running process and
# mirrored to data/telecom_snapshot.json so a restarted API still serves the
# most recent posture (data/ is runtime-only, gitignored — same convention
# as the live scanner's persisted snapshot).

_LOCK = threading.Lock()
_SNAPSHOT: dict[str, Any] | None = None


def _snapshot_file() -> Path:
    root = Path(__file__).resolve().parents[3]
    return Path(__import__("os").environ.get("CRYPTOSCAN_SNAPSHOT_DIR") or (root / "data")) / "telecom_snapshot.json"


def _load_snapshot() -> dict[str, Any] | None:
    global _SNAPSHOT
    if _SNAPSHOT is not None:
        return _SNAPSHOT
    file = _snapshot_file()
    if file.is_file():
        try:
            _SNAPSHOT = json.loads(file.read_text())
        except (OSError, json.JSONDecodeError):
            _SNAPSHOT = None
    return _SNAPSHOT


def _store_snapshot(snapshot: dict[str, Any]) -> None:
    global _SNAPSHOT
    with _LOCK:
        _SNAPSHOT = snapshot
    file = _snapshot_file()
    try:
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(json.dumps(snapshot))
    except OSError:
        pass  # serving in-memory is still correct; persistence is best-effort


def _publish(event: dict[str, Any], target_hint: dict[str, Any]) -> None:
    from api.events.bus import get_event_bus

    get_event_bus().publish(
        "telecom.event",
        {**target_hint, **event, "kind": event.get("kind")},
        source="telecom-scanner",
    )


def _publish_events(events: list[dict[str, Any]]) -> int:
    for event in events:
        _publish(event, {
            "nf_id": event.get("target"),
            "nf_type": event.get("nf_type"),
            "carrier_code": event.get("carrier_code"),
        })
    return len(events)


# ------------------------------------------------------------------- models

class TelecomCarrier(BaseModel):
    code: str = Field(min_length=2, max_length=24)
    name: str = Field(min_length=2, max_length=120)
    country: str = Field(min_length=2, max_length=2)
    plmn: str = Field(min_length=5, max_length=7)
    legal_entity: str = Field(default="", max_length=24)


class TelecomTarget(BaseModel):
    nf_id: str = Field(min_length=2, max_length=64)
    nf_type: str = Field(min_length=2, max_length=16)
    endpoint: str = Field(min_length=6, max_length=253)
    carrier_code: str = Field(default="", max_length=24)
    environment: str = Field(default="production", max_length=16)


class ScanRequest(BaseModel):
    only: list[str] = Field(default_factory=list, max_length=64)
    timeout: float = Field(default=4.0, gt=0, le=15)


class IngestRequest(BaseModel):
    target_id: str = Field(min_length=2, max_length=64)
    probe: dict[str, Any]


# ----------------------------------------------------------------- registry

def _registry_path():
    from telecom_scanner.registry import default_registry_path

    return default_registry_path()


def _registry() -> dict[str, Any]:
    from telecom_scanner.registry import load_registry

    return load_registry(_registry_path())


def _nf_catalog() -> dict[str, dict[str, Any]]:
    from telecom_scanner.registry import NF_CATALOG

    return NF_CATALOG


def _save(registry: dict[str, Any]) -> None:
    from telecom_scanner.registry import save_registry

    save_registry(registry["carriers"].values(), registry["targets"].values(), _registry_path())


@router.get("/registry")
def telecom_registry(user: str = Depends(require_permission("findings.read"))):
    reg = _registry()
    return {"carriers": reg["carriers"], "targets": reg["targets"],
            "counts": {"carriers": len(reg["carriers"]), "targets": len(reg["targets"])},
            "nf_catalog": {k: {"name": v["name"], "transport": v["transport"],
                               "plane": v["plane"]} for k, v in sorted(_nf_catalog().items())}}


@router.post("/carriers")
def telecom_carrier_add(carrier: TelecomCarrier,
                        user: str = Depends(require_permission("telecom.manage"))):
    from telecom_scanner.registry import normalize_carrier

    reg = _registry()
    try:
        record = normalize_carrier(carrier.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    reg["carriers"][record["code"]] = record
    _save(reg)
    return {"ok": True, "carrier": record, "counts": {"carriers": len(reg["carriers"])}}


@router.delete("/carriers/{code}")
def telecom_carrier_delete(code: str, user: str = Depends(require_permission("telecom.manage"))):
    reg = _registry()
    key = code.strip().lower()
    if key not in reg["carriers"]:
        raise HTTPException(status_code=404, detail=f"unknown carrier: {code}")
    del reg["carriers"][key]
    for target in list(reg["targets"].values()):
        if target.get("carrier_code") == key:
            target["carrier_code"] = ""
    _save(reg)
    return {"ok": True, "counts": {"carriers": len(reg["carriers"])}}


@router.post("/targets")
def telecom_target_add(target: TelecomTarget,
                       user: str = Depends(require_permission("telecom.manage"))):
    from telecom_scanner.registry import normalize_target

    reg = _registry()
    try:
        record = normalize_target(target.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    carrier = record.get("carrier_code")
    if carrier and carrier not in reg["carriers"]:
        raise HTTPException(status_code=422, detail=f"unknown carrier_code: {carrier}")
    reg["targets"][record["nf_id"]] = record
    _save(reg)
    return {"ok": True, "target": record, "counts": {"targets": len(reg["targets"])}}


@router.delete("/targets/{nf_id}")
def telecom_target_delete(nf_id: str, user: str = Depends(require_permission("telecom.manage"))):
    reg = _registry()
    key = nf_id.strip().lower()
    if key not in reg["targets"]:
        raise HTTPException(status_code=404, detail=f"unknown target: {nf_id}")
    del reg["targets"][key]
    _save(reg)
    return {"ok": True, "counts": {"targets": len(reg["targets"])}}


# -------------------------------------------------------------------- scans

@router.post("/scan")
def telecom_scan(request: ScanRequest,
                 user: str = Depends(require_permission("scan.trigger"))):
    """Probe the registered estate now and return the refreshed posture.

    Bounded: at most 64 targets per pass (bigger estates run through the
    periodic live scanner — CRYPTOSCAN_LIVE_TELECOM=1 — or successive
    --only passes). Events are published onto the platform bus so SSE
    clients receive them in realtime.
    """
    from telecom_scanner.realtime import evaluate_changes, summarize_events
    from telecom_scanner.main import probe_registry
    from telecom_scanner.rollup import posture_rollup

    reg = _registry()
    targets = reg["targets"]
    if request.only:
        wanted = {n.strip().lower() for n in request.only}
        targets = {k: v for k, v in targets.items() if k in wanted}
        unknown = wanted - set(targets)
        if unknown:
            raise HTTPException(status_code=422, detail=f"unknown nf_id: {', '.join(sorted(unknown))}")
    if len(targets) > 64:
        raise HTTPException(status_code=413, detail=f"{len(targets)} targets exceeds the 64-per-pass cap — use the periodic live scanner or --only passes")

    previous = (_load_snapshot() or {}).get("state") or {}
    rows = probe_registry(reg, only=list(request.only) or None, timeout=request.timeout)
    events = evaluate_changes(previous, rows)
    state = {row["nf_id"]: {k: row[k] for k in ("status", "severity", "fingerprint", "cert_not_after")} for row in rows}
    snapshot = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner": "telecom-api-scan",
        "targets_registered": len(reg["targets"]),
        "rows": rows,
        "events": events,
        "events_summary": summarize_events(events),
        "state": state,
        "rollup": posture_rollup(rows, reg["carriers"]),
    }
    _store_snapshot(snapshot)
    published = _publish_events(events)
    return {"generated_at": snapshot["generated_at"], "scanned": len(rows),
            "events": events, "events_published": published,
            "rollup": snapshot["rollup"], "state": state}


@router.post("/ingest")
def telecom_ingest(request: IngestRequest,
                   user: str = Depends(require_permission("telecom.ingest"))):
    """Accept an operator-side probe result (IKE/IPsec parameters, TLS probe
    from inside a NATed carrier network) and classify it like any other pass."""
    from telecom_scanner.classify import classify_target
    from telecom_scanner.realtime import evaluate_changes, summarize_events

    reg = _registry()
    target = reg["targets"].get(request.target_id.strip().lower())
    if target is None:
        raise HTTPException(status_code=404, detail=f"unknown target: {request.target_id}")

    previous = (_load_snapshot() or {})
    verdict = classify_target(target, request.probe)
    rows = [row for row in (previous.get("rows") or []) if row.get("nf_id") != verdict["nf_id"]]
    rows.append(verdict)
    rows.sort(key=lambda r: str(r.get("nf_id")))
    events = evaluate_changes(previous.get("state") or {}, [verdict])
    state = dict(previous.get("state") or {})
    state[verdict["nf_id"]] = {k: verdict[k] for k in ("status", "severity", "fingerprint", "cert_not_after")}

    from telecom_scanner.rollup import posture_rollup

    snapshot = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner": "telecom-ingest",
        "targets_registered": len(reg["targets"]),
        "rows": rows,
        "events": events,
        "events_summary": summarize_events(events),
        "state": state,
        "rollup": posture_rollup(rows, reg["carriers"]),
    }
    _store_snapshot(snapshot)
    published = _publish_events(events)
    return {"ok": True, "verdict": verdict, "events": events,
            "events_published": published, "rollup": snapshot["rollup"]}


# ----------------------------------------------------------------- surfaces

@router.get("/posture")
def telecom_posture(user: str = Depends(require_permission("findings.read"))):
    snapshot = _load_snapshot()
    if not snapshot:
        return {
            "has_data": False,
            "message": "No telecom scan has run yet — register carriers/targets and POST /telecom/scan, or enable CRYPTOSCAN_LIVE_TELECOM=1 for the periodic scanner.",
            "generated_at": None,
            "rollup": None,
            "events_summary": {},
        }
    return {
        "has_data": True,
        "generated_at": snapshot.get("generated_at"),
        "scanner": snapshot.get("scanner"),
        "targets_registered": snapshot.get("targets_registered"),
        "rollup": snapshot.get("rollup"),
        "rows": snapshot.get("rows"),
        "events_summary": snapshot.get("events_summary") or {},
    }


@router.get("/events")
def telecom_events(limit: int = Query(50, ge=1, le=200),
                   user: str = Depends(require_permission("findings.read"))):
    from api.events.bus import get_event_bus

    recent = get_event_bus().recent(since_id=0, limit=500)
    events = [e for e in recent if str(e.get("type")) == "telecom.event"]
    return {"count": len(events), "events": list(reversed(events))[:limit]}
