"""HBOM workspace — Hardware Bill of Materials (docs/boms/01_PRODUCT_SPEC.md §3).

Hardware assets, firmware, hardware security components and infrastructure
dependencies. Every section reads the persisted hardware estate (agent
observations and pinned snapshots); an empty section is an honest empty
state, never a fabricated hardware inventory.

Working rule from the spec governs this surface and is not narrated on
screen: the HBOM never exposes HSM key material, private keys, secrets or
device credentials. Agent-supplied metadata blobs are projected through a
safe-key allowlist; anything named like a secret is dropped structurally,
and serial references are masked.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.models.hardware_live import HardwareAsset, HardwareAgentRow, HardwareEventRow
from db.models.hbom_snapshot import HbomSnapshot

router = APIRouter(prefix="/hbom/workspace")

#: Anything named like this is dropped from every projection, whatever its
#: value. Key material and device credentials never enter a response.
_DENY = re.compile(r"key|secret|credential|password|passwd|token|\bpin\b|auth|private", re.IGNORECASE)

_SAFE_FIRMWARE = {"version", "vendor", "release_date", "status", "end_of_life",
                  "lifecycle", "support_status", "signed", "secure_boot"}
_SAFE_TPM = {"version", "manufacturer", "present", "secure_boot", "ek_present",
             "activated", "owned", "status"}
_SAFE_HSM = {"vendor", "model", "firmware", "version", "mode", "approval",
             "fips_level", "partition_count", "status"}
_SAFE_CAPS = {"algorithms", "acceleration", "instructions", "features", "location",
              "site", "cpu", "architecture", "secure_boot", "virtual"}


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if hasattr(value, "isoformat") else (str(value) if value else None)


def _freshness(seen: Any) -> str:
    if not seen:
        return "NOT_COLLECTED"
    try:
        ts = seen if isinstance(seen, datetime) else datetime.fromisoformat(str(seen))
    except ValueError:
        return "NOT_COLLECTED"
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - ts).days
    if age <= 90:
        return "CURRENT"
    if age <= 365:
        return "STALE"
    return "EXPIRED"


def _mask_serial(serial: Optional[str]) -> Optional[str]:
    """Masked reference only — the full identifier never leaves this layer."""
    if not serial:
        return None
    tail = str(serial)[-4:] if len(str(serial)) > 4 else ""
    return f"••••{tail}" if tail else "••••"


def _project(blob: Optional[dict], allowed: set[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in (blob or {}).items():
        if key not in allowed or _DENY.search(key):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            out[key] = value
        elif isinstance(value, list) and all(isinstance(x, (str, int, float, bool)) for x in value):
            out[key] = value
    return out


def _category(device_type: Optional[str]) -> str:
    t = (device_type or "other").lower()
    if t in {"server", "compute", "vm", "host", "blade"}:
        return "SERVER_COMPUTE"
    if "hsm" in t:
        return "HSM"
    if "tpm" in t or "secure" in t:
        return "TPM_SECURE_ELEMENT"
    if t in {"network", "switch", "router", "firewall", "load_balancer"}:
        return "NETWORK"
    if t in {"storage", "san", "nas"}:
        return "STORAGE"
    return "OTHER"


def _lifecycle(asset: HardwareAsset, firmware: Dict[str, Any]) -> tuple[str, str]:
    for key in ("lifecycle", "support_status", "end_of_life"):
        raw = firmware.get(key)
        if isinstance(raw, str) and raw.strip():
            value = raw.strip().upper().replace(" ", "_")
            if "END" in value or "EOL" in value:
                return "END_OF_LIFE", f"firmware record states {key}={raw.strip()}"
            if "SUPPORT" in value or value in {"ACTIVE", "GA"}:
                return "SUPPORTED", f"firmware record states {key}={raw.strip()}"
            return "UNKNOWN", f"firmware record states {key}={raw.strip()} without a recognised meaning"
        if isinstance(raw, bool) and key == "end_of_life":
            return ("END_OF_LIFE", "firmware record flags end_of_life") if raw else ("SUPPORTED", "firmware record does not flag end_of_life")
    return "UNKNOWN", "no stored lifecycle record — unknown, never assumed supported"


def _asset_row(asset: HardwareAsset) -> dict[str, Any]:
    firmware = _project(asset.firmware, _SAFE_FIRMWARE)
    tpm = _project(asset.tpm, _SAFE_TPM)
    hsm = _project(asset.hsm, _SAFE_HSM)
    caps = _project(asset.capabilities, _SAFE_CAPS)
    crypto = _project(asset.crypto_capabilities, _SAFE_CAPS | {"key_size", "key_sizes", "curves", "modes"})
    life, life_basis = _lifecycle(asset, firmware)
    evidence_history = asset.evidence_history or []
    return {
        "asset_id": asset.asset_id,
        "manufacturer": asset.manufacturer or None,
        "model": asset.model or None,
        "serial_reference": _mask_serial(asset.serial_reference),
        "firmware": firmware.get("version"),
        "category": _category(asset.device_type),
        "device_type": asset.device_type,
        "location": caps.get("location") or caps.get("site"),
        "crypto_capabilities": crypto,
        "lifecycle": life,
        "lifecycle_basis": life_basis,
        "evidence": {
            "agent_id": asset.agent_id,
            "last_seen": _iso(asset.last_seen),
            "fingerprinted": bool(asset.current_fingerprint),
            "evidence_records": len(evidence_history),
            "freshness": _freshness(asset.last_seen),
        },
    }


# ── response contracts (the untyped ratchet only goes down) ───────────


class HbomEvidence(BaseModel):
    agent_id: Optional[str] = None
    last_seen: Optional[str] = None
    fingerprinted: bool = False
    evidence_records: int = 0
    freshness: str


class HbomAssetRow(BaseModel):
    asset_id: str
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_reference: Optional[str] = None
    firmware: Optional[str] = None
    category: str
    device_type: Optional[str] = None
    location: Optional[str] = None
    crypto_capabilities: Dict[str, Any] = {}
    lifecycle: str
    lifecycle_basis: str
    evidence: HbomEvidence


class AssetInventory(BaseModel):
    state: str
    total: int
    rows: List[HbomAssetRow]


class AssetDetail(BaseModel):
    asset: HbomAssetRow
    tpm: Dict[str, Any] = {}
    hsm: Dict[str, Any] = {}
    firmware_detail: Dict[str, Any] = {}
    secure_boot: Optional[bool] = None
    cpu_acceleration: Dict[str, Any] = {}
    hardware_dependencies: List[Dict[str, Any]] = []
    related: Dict[str, Any] = {}
    firmware_history: List[Dict[str, Any]] = []
    evidence_history: List[Dict[str, Any]] = []


class Overview(BaseModel):
    state: str
    assets: int = 0
    categories: Dict[str, int] = {}
    lifecycle: Dict[str, int] = {}
    manufacturers: Dict[str, int] = {}
    firmware_collected: int = 0
    tpm_present: int = 0
    hsm_present: int = 0
    crypto_capable: int = 0
    agents: int = 0
    snapshots: int = 0
    read: Dict[str, Any] = {}


class CategoryInventory(BaseModel):
    state: str
    total: int
    rows: List[HbomAssetRow]


class FirmwareRow(BaseModel):
    asset_id: str
    model: Optional[str] = None
    firmware: Optional[str] = None
    firmware_detail: Dict[str, Any] = {}
    last_firmware_check: Optional[str] = None
    freshness: str
    change_events: int = 0


class FirmwareInventory(BaseModel):
    state: str
    total: int
    rows: List[FirmwareRow]


class CryptoCapRow(BaseModel):
    asset_id: str
    model: Optional[str] = None
    capabilities: Dict[str, Any] = {}
    usage_state: str = "capability_detected"
    basis: str = "hardware capability as reported — capability is never drawn as use"


class CryptoCapInventory(BaseModel):
    state: str
    total: int
    rows: List[CryptoCapRow]


class LifecycleRow(BaseModel):
    asset_id: str
    model: Optional[str] = None
    lifecycle: str
    lifecycle_basis: str
    last_seen: Optional[str] = None
    freshness: str


class LifecycleInventory(BaseModel):
    state: str
    total: int
    rows: List[LifecycleRow]


class EvidenceRow(BaseModel):
    asset_id: str
    agent_id: Optional[str] = None
    source: Optional[str] = None
    event_type: Optional[str] = None
    observed_at: Optional[str] = None
    change_class: Optional[str] = None
    evidence_id: Optional[str] = None
    freshness: str


class EvidenceInventory(BaseModel):
    state: str
    total: int
    collection_coverage: Dict[str, int] = {}
    rows: List[EvidenceRow]


class HistoryRow(BaseModel):
    asset_id: str
    event_type: str
    change_class: Optional[str] = None
    observed_at: Optional[str] = None
    source: Optional[str] = None


class HistoryInventory(BaseModel):
    state: str
    total: int
    rows: List[HistoryRow]


class SnapshotRow(BaseModel):
    snapshot_id: str
    content_hash: str
    component_count: int
    generator: str
    environment: Optional[str] = None
    snapshotted_at: Optional[str] = None


class ExportInventory(BaseModel):
    state: str
    snapshots: List[SnapshotRow]
    export_path: str
    note: str = ("the pinned snapshot is content-addressed; a hash proves the "
                 "bytes are unchanged, not that the estate is healthy")


# ── operations ────────────────────────────────────────────────────────


@router.get("/overview", response_model=Overview)
def hbom_workspace_overview(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    assets = db.execute(select(HardwareAsset)).scalars().all()
    agents = db.execute(select(HardwareAgentRow)).scalars().all()
    snapshots = db.execute(select(HbomSnapshot)).scalars().all()
    rows = [_asset_row(a) for a in assets]
    return {
        "state": "OBSERVED" if assets else "NO_RECORDS",
        "assets": len(assets),
        "categories": dict(Counter(r["category"] for r in rows)),
        "lifecycle": dict(Counter(r["lifecycle"] for r in rows)),
        "manufacturers": dict(Counter(str(r["manufacturer"] or "NOT_COLLECTED") for r in rows)),
        "firmware_collected": sum(1 for r in rows if r["firmware"]),
        "tpm_present": sum(1 for a in assets if _project(a.tpm, _SAFE_TPM).get("present") or a.tpm),
        "hsm_present": sum(1 for a in assets if a.hsm),
        "crypto_capable": sum(1 for r in rows if r["crypto_capabilities"]),
        "agents": len(agents),
        "snapshots": len(snapshots),
        "read": {
            "events": len(db.execute(select(HardwareEventRow)).scalars().all()),
            "agents_reporting": sum(1 for a in agents if a.last_heartbeat),
        },
    }


@router.get("/assets", response_model=AssetInventory)
def hbom_workspace_assets(
    q: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    lifecycle: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    user: str = Depends(get_current_user), db: Session = Depends(get_db_session),
):
    assets = db.execute(select(HardwareAsset)).scalars().all()
    out = [_asset_row(a) for a in assets]
    if q:
        needle = q.lower()
        out = [r for r in out if needle in str(r["asset_id"]).lower()
               or needle in str(r["manufacturer"] or "").lower()
               or needle in str(r["model"] or "").lower()]
    if category:
        out = [r for r in out if r["category"] == category.upper()]
    if lifecycle:
        out = [r for r in out if r["lifecycle"] == lifecycle.upper()]
    out.sort(key=lambda r: str(r["asset_id"]))
    return {"state": "OBSERVED" if out else ("EMPTY" if not assets else "FILTERED_EMPTY"),
            "total": len(out), "rows": out[:limit]}


@router.get("/assets/{asset_id:path}", response_model=AssetDetail)
def hbom_workspace_asset_detail(
    asset_id: str,
    user: str = Depends(get_current_user), db: Session = Depends(get_db_session),
):
    asset = db.execute(select(HardwareAsset).where(HardwareAsset.asset_id == asset_id)).scalars().first()
    if asset is None:
        raise HTTPException(status_code=404, detail="hardware asset not in the stored estate")
    row = _asset_row(asset)
    events = db.execute(select(HardwareEventRow).where(
        HardwareEventRow.asset_id == asset_id).order_by(
        HardwareEventRow.observed_at.desc()).limit(50)).scalars().all()
    caps = _project(asset.capabilities, _SAFE_CAPS)
    crypto = _project(asset.crypto_capabilities, _SAFE_CAPS | {"key_size", "key_sizes", "curves", "modes"})
    return {
        "asset": row,
        "tpm": _project(asset.tpm, _SAFE_TPM),
        "hsm": _project(asset.hsm, _SAFE_HSM),
        "firmware_detail": _project(asset.firmware, _SAFE_FIRMWARE),
        "secure_boot": caps.get("secure_boot") if isinstance(caps.get("secure_boot"), bool) else None,
        "cpu_acceleration": {k: v for k, v in crypto.items() if k in {"acceleration", "instructions", "algorithms"}},
        "hardware_dependencies": [],
        # links are claimed only where a stored relationship exists
        "related": {"cbom": [], "techbom": [],
                    "_note": "no stored cross-BOM link rows name this hardware asset"},
        "firmware_history": [{
            "observed_at": _iso(e.observed_at),
            "change_class": e.change_class,
            "event_type": e.event_type,
        } for e in events if e.event_type in {"firmware_change", "firmware-check", "FIRMWARE_CHANGE", "change"} or e.change_class],
        "evidence_history": [{
            "event_type": e.event_type,
            "source": e.source,
            "observed_at": _iso(e.observed_at),
            "evidence_id": e.evidence_id,
        } for e in events[:20]],
    }


def _category_inventory(db: Session, wanted: set[str], label: str) -> dict[str, Any]:
    assets = db.execute(select(HardwareAsset)).scalars().all()
    rows = [_asset_row(a) for a in assets if _category(a.device_type) in wanted]
    return {"state": "OBSERVED" if rows else f"NO_{label}", "total": len(rows), "rows": rows}


@router.get("/compute", response_model=CategoryInventory)
def hbom_workspace_compute(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return _category_inventory(db, {"SERVER_COMPUTE"}, "SERVERS_OR_COMPUTE")


@router.get("/hsm", response_model=CategoryInventory)
def hbom_workspace_hsm(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return _category_inventory(db, {"HSM"}, "HSM_RECORDS")


@router.get("/tpm", response_model=CategoryInventory)
def hbom_workspace_tpm(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return _category_inventory(db, {"TPM_SECURE_ELEMENT"}, "TPM_RECORDS")


@router.get("/network", response_model=CategoryInventory)
def hbom_workspace_network(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return _category_inventory(db, {"NETWORK"}, "NETWORK_HARDWARE")


@router.get("/storage", response_model=CategoryInventory)
def hbom_workspace_storage(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return _category_inventory(db, {"STORAGE"}, "STORAGE_HARDWARE")


@router.get("/firmware", response_model=FirmwareInventory)
def hbom_workspace_firmware(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    assets = db.execute(select(HardwareAsset)).scalars().all()
    events = db.execute(select(HardwareEventRow)).scalars().all()
    changes = Counter(e.asset_id for e in events if e.change_class or "firmware" in str(e.event_type or "").lower())
    rows = []
    for a in assets:
        fw = _project(a.firmware, _SAFE_FIRMWARE)
        rows.append({
            "asset_id": a.asset_id,
            "model": a.model or None,
            "firmware": fw.get("version"),
            "firmware_detail": fw,
            "last_firmware_check": _iso(a.last_firmware_check),
            "freshness": _freshness(a.last_firmware_check),
            "change_events": changes.get(a.asset_id, 0),
        })
    return {"state": "OBSERVED" if rows else "NO_FIRMWARE_RECORDS",
            "total": len(rows), "rows": rows}


@router.get("/crypto", response_model=CryptoCapInventory)
def hbom_workspace_crypto(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    assets = db.execute(select(HardwareAsset)).scalars().all()
    rows = []
    for a in assets:
        crypto = _project(a.crypto_capabilities, _SAFE_CAPS | {"key_size", "key_sizes", "curves", "modes"})
        if not crypto:
            continue
        rows.append({
            "asset_id": a.asset_id,
            "model": a.model or None,
            "capabilities": crypto,
        })
    return {"state": "OBSERVED" if rows else "NO_CRYPTO_CAPABILITIES",
            "total": len(rows), "rows": rows}


@router.get("/lifecycle", response_model=LifecycleInventory)
def hbom_workspace_lifecycle(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    assets = db.execute(select(HardwareAsset)).scalars().all()
    rows = [{
        "asset_id": a.asset_id,
        "model": a.model or None,
        "lifecycle": _asset_row(a)["lifecycle"],
        "lifecycle_basis": _asset_row(a)["lifecycle_basis"],
        "last_seen": _iso(a.last_seen),
        "freshness": _freshness(a.last_seen),
    } for a in assets]
    return {"state": "OBSERVED" if rows else "NO_LIFECYCLE_RECORDS",
            "total": len(rows), "rows": rows}


@router.get("/evidence", response_model=EvidenceInventory)
def hbom_workspace_evidence(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    assets = db.execute(select(HardwareAsset)).scalars().all()
    agents = db.execute(select(HardwareAgentRow)).scalars().all()
    events = db.execute(select(HardwareEventRow).order_by(
        HardwareEventRow.observed_at.desc()).limit(500)).scalars().all()
    rows = [{
        "asset_id": e.asset_id,
        "agent_id": e.agent_id,
        "source": e.source,
        "event_type": e.event_type,
        "observed_at": _iso(e.observed_at),
        "change_class": e.change_class,
        "evidence_id": e.evidence_id,
        "freshness": _freshness(e.observed_at),
    } for e in events]
    return {
        "state": "OBSERVED" if rows else "NO_EVIDENCE_RECORDS",
        "total": len(rows),
        "collection_coverage": {
            "assets": len(assets),
            "assets_with_fingerprint": sum(1 for a in assets if a.current_fingerprint),
            "assets_with_agent": sum(1 for a in assets if a.agent_id),
            "agents": len(agents),
            "agents_reporting": sum(1 for a in agents if a.last_heartbeat),
        },
        "rows": rows,
    }


@router.get("/history", response_model=HistoryInventory)
def hbom_workspace_history(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    events = db.execute(select(HardwareEventRow).order_by(
        HardwareEventRow.observed_at.desc()).limit(500)).scalars().all()
    rows = [{
        "asset_id": e.asset_id,
        "event_type": e.event_type,
        "change_class": e.change_class,
        "observed_at": _iso(e.observed_at),
        "source": e.source,
    } for e in events]
    return {"state": "OBSERVED" if rows else "NO_HISTORY", "total": len(rows), "rows": rows}


@router.get("/export", response_model=ExportInventory)
def hbom_workspace_export(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    snapshots = db.execute(select(HbomSnapshot).order_by(
        HbomSnapshot.snapshotted_at.desc()).limit(50)).scalars().all()
    rows = [{
        "snapshot_id": str(s.id),
        "content_hash": s.content_hash,
        "component_count": s.component_count,
        "generator": s.generator,
        "environment": s.environment or None,
        "snapshotted_at": _iso(s.snapshotted_at),
    } for s in snapshots]
    return {"state": "OBSERVED" if rows else "NO_SNAPSHOTS",
            "snapshots": rows,
            "export_path": "/api/v1/hbom/snapshots"}
