"""Shared asset detail — one canonical detail surface (docs/boms/01_PRODUCT_SPEC.md §7).

Every BOM record follows the same detail-page structure: a header record,
the asset information fields (Asset ID · Environment · Category · Owner ·
Source · Last observed), a cross-BOM relationships panel (SBOM · CBOM ·
HBOM · NBOM · VBOM · TechBOM — each linked / not established / unknown /
primary record, never conflated), and nine detail tabs (Overview,
Components, Cryptography, Hardware, Network, Vendors, Dependencies,
Evidence, History).

Working rules govern this surface and are not narrated on screen: a
relationship is established only where stored evidence establishes it; a
component's capability is never proof the application performs the
operation; a port scan alone proves nothing about negotiated
cryptography; hardware metadata is projected through safe summary fields
only — no firmware, TPM, HSM, key, secret or credential material ever
leaves this router.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from cbom.nbom import probe_to_endpoint
from db.models.crypto_asset import CryptoAsset
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.models.runtime_finding import RuntimeFinding
from db.models.evidence_record import EvidenceRecord
from db.models.hardware_live import HardwareAsset
from db.models.network_scan_run import NetworkScanRun
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.models.system_dependency import SystemDependency
from db.models.vendor import SystemVendor, Vendor
from db.models.vendor_crypto import VendorCryptoInventory
from db.models.vendor_profile import VendorProfileRevision

router = APIRouter(prefix="/asset-detail")

BOMS = ("TechBOM", "SBOM", "CBOM", "HBOM", "NBOM", "VBOM")

#: The secret-name filter — the shared detail may never emit these. Kept
#: identical in spirit to the HBOM workspace's _DENY projection.
_DENY = ("key", "secret", "credential", "password", "passwd", "token", "pin", "auth", "private")


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


def _mask_serial(serial: Optional[str]) -> str:
    if not serial:
        return ""
    tail = str(serial)[-4:]
    return f"••••{tail}"


def _runtime_algorithms(db: Session) -> set:
    """Algorithms a runtime observation NAMED — the only route to
    operation_observed (the CBOM contract)."""
    return {str(r.algorithm or "").upper()
            for r in db.execute(select(RuntimeFinding)).scalars().all() if r.algorithm}


def _safe_name(value: Any) -> bool:
    return not any(word in str(value).lower() for word in _DENY)


# --------------------------------------------------------------------------- #
# Resolution
# --------------------------------------------------------------------------- #

def _resolve(db: Session, asset_ref: str) -> Dict[str, Any]:
    """One canonical asset -> its stored record. 404 when not stored."""
    kind, _, ident = asset_ref.partition(":")
    if kind == "app":
        rec = db.get(System, ident)
        if rec is None:
            raise HTTPException(status_code=404, detail="asset not found in the canonical registry")
        return {"kind": kind, "ident": ident, "record": rec, "name": rec.name,
                "category": "SOFTWARE", "environment": rec.environment or "",
                "owner": rec.owner or "", "description": rec.description or "",
                "source": "System registry",
                "last_observed": _iso(getattr(rec, "updated_at", None))}
    if kind == "crypto":
        rec = db.get(CryptoAsset, ident)
        if rec is None:
            raise HTTPException(status_code=404, detail="asset not found in the canonical registry")
        return {"kind": kind, "ident": ident, "record": rec,
                "name": f"{rec.algorithm or ''} {rec.key_size or ''}".strip() or rec.id,
                "category": "CRYPTO", "environment": rec.file_path or "",
                "owner": rec.owner or "", "description": f"crypto asset · {rec.purpose or 'purpose not recorded'}",
                "source": "Crypto asset inventory",
                "last_observed": _iso(getattr(rec, "updated_at", None))}
    if kind == "hw":
        rec = db.execute(select(HardwareAsset).where(HardwareAsset.asset_id == ident)).scalars().first()
        if rec is None:
            raise HTTPException(status_code=404, detail="asset not found in the canonical registry")
        return {"kind": kind, "ident": ident, "record": rec, "name": rec.model or rec.asset_id,
                "category": "HARDWARE", "environment": "",
                "owner": getattr(rec, "owner", "") or "", "description": rec.device_type or "",
                "source": "Hardware asset inventory",
                "last_observed": _iso(rec.last_seen) or _iso(rec.first_seen)}
    if kind == "net":
        row = _endpoint_row(db, ident)
        if row is None:
            raise HTTPException(status_code=404, detail="asset not found in the canonical registry")
        return {"kind": kind, "ident": ident, "record": row, "name": ident,
                "category": "NETWORK", "environment": "",
                "owner": "", "description": f"{row.get('protocol') or ''} {row.get('service') or ''}".strip(),
                "source": "Network scan observation",
                "last_observed": row.get("observed_at")}
    if kind == "vendor":
        rec = db.get(Vendor, ident)
        if rec is None:
            raise HTTPException(status_code=404, detail="asset not found in the canonical registry")
        return {"kind": kind, "ident": ident, "record": rec, "name": rec.name,
                "category": "SUPPLIER", "environment": "",
                "owner": getattr(rec, "primary_contact", "") or "",
                "description": getattr(rec, "vendor_type", "") or "",
                "source": "Vendor registry",
                "last_observed": _iso(getattr(rec, "updated_at", None))}
    raise HTTPException(status_code=404, detail="unknown asset reference — expected app:, crypto:, hw:, net: or vendor:")


def _endpoint_row(db: Session, endpoint: str) -> Optional[Dict[str, Any]]:
    runs = db.execute(select(NetworkScanRun).order_by(NetworkScanRun.created_at.desc())).scalars().all()
    best: Optional[Dict[str, Any]] = None
    for run in runs:
        for probe in (run.result or {}).get("probes") or []:
            row = probe_to_endpoint(probe)
            if not row:
                continue
            key = f"{row.get('host') or ''}:{row.get('port') or ''}"
            if key == endpoint and best is None:
                row["endpoint"] = key
                row["observed_at"] = _iso(getattr(run, "created_at", None))
                best = row
    return best


# --------------------------------------------------------------------------- #
# Cross-BOM panel (spec §7 vocabulary — never conflated)
# --------------------------------------------------------------------------- #

def _cross_bom(db: Session, ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    kind = ctx["kind"]
    ident = ctx["ident"]

    def linked(bom: str, basis: str) -> Dict[str, str]:
        return {"bom": bom, "state": "LINKED", "basis": basis}

    def none(bom: str) -> Dict[str, str]:
        return {"bom": bom, "state": "NOT_ESTABLISHED",
                "basis": "no stored relationship establishes this link"}

    out: List[Dict[str, str]] = [
        {"bom": "TechBOM", "state": "PRIMARY_RECORD",
         "basis": "the canonical asset record lives in the technology inventory"},
    ]

    if kind == "app":
        has_crypto = db.execute(select(SystemAsset).where(SystemAsset.system_id == ident)).scalars().first()
        has_vendor = db.execute(select(SystemVendor).where(SystemVendor.system_id == ident)).scalars().first()
        out.append(linked("SBOM", "this system materializes into the SBOM layer"))
        out.append(linked("CBOM", "a stored system_assets link establishes this link") if has_crypto else none("CBOM"))
        out.append(linked("VBOM", "a stored SystemVendor link establishes this link") if has_vendor else none("VBOM"))
        out.append(none("HBOM"))
        out.append(none("NBOM"))
    elif kind == "crypto":
        has_system = db.execute(select(SystemAsset).where(SystemAsset.asset_id == ident)).scalars().first()
        out.append(linked("CBOM", "this crypto asset materializes into the CBOM layer"))
        out.append(linked("SBOM", "a stored system_assets link establishes this link") if has_system else none("SBOM"))
        out.append(none("HBOM"))
        out.append(none("NBOM"))
        out.append(none("VBOM"))
    elif kind == "hw":
        out.append(linked("HBOM", "this device materializes into the HBOM layer"))
        out.append(none("SBOM"))
        out.append(none("CBOM"))
        out.append(none("NBOM"))
        out.append(none("VBOM"))
    elif kind == "net":
        out.append(linked("NBOM", "this endpoint is a stored network observation"))
        out.append(none("SBOM"))
        out.append(none("CBOM"))
        out.append(none("HBOM"))
        out.append(none("VBOM"))
    elif kind == "vendor":
        has_system = db.execute(select(SystemVendor).where(SystemVendor.vendor_id == ident)).scalars().first()
        out.append(linked("VBOM", "this supplier materializes into the vendor layer"))
        out.append(linked("SBOM", "a stored SystemVendor link establishes this link") if has_system else none("SBOM"))
        out.append(none("CBOM"))
        out.append(none("HBOM"))
        out.append(none("NBOM"))
    return out


# --------------------------------------------------------------------------- #
# Contracts
# --------------------------------------------------------------------------- #

class BomRelationOut(BaseModel):
    bom: str
    state: str
    basis: str


class HeaderOut(BaseModel):
    asset_ref: str
    name: str
    status: str
    description: str
    asset_id: str
    environment: str
    category: str
    owner: str
    source: str
    last_observed: Optional[str] = None
    primary_bom: str = "TechBOM"
    related: List[BomRelationOut]
    chips: List[str]
    evidence: Dict[str, str]


class TabResponse(BaseModel):
    asset_ref: str
    tab: str
    rows: List[Dict[str, Any]]
    note: str


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #

@router.get("/{asset_ref}", response_model=HeaderOut)
def asset_header(
    asset_ref: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> HeaderOut:
    ctx = _resolve(db, asset_ref)
    related = _cross_bom(db, ctx)
    chips = [f"{r['bom']} {r['state'].lower().replace('_', ' ')}"
             for r in related if r["state"] in ("LINKED", "PRIMARY_RECORD")]
    evidence = _evidence_for(db, ctx)
    return HeaderOut(
        asset_ref=asset_ref, name=ctx["name"],
        status=f"{evidence['state']} · {evidence['freshness']}",
        description=ctx["description"],
        asset_id=asset_ref, environment=ctx["environment"], category=ctx["category"],
        owner=ctx["owner"], source=ctx["source"], last_observed=ctx["last_observed"],
        related=[BomRelationOut(**r) for r in related], chips=chips, evidence=evidence,
    )


def _evidence_for(db: Session, ctx: Dict[str, Any]) -> Dict[str, str]:
    kind, ident = ctx["kind"], ctx["ident"]
    if kind == "crypto":
        rec = ctx["record"]
        if (str(rec.algorithm or "").upper() in _runtime_algorithms(db)
                and (rec.occurrence_count or 0) > 0):
            return {"state": "MEASURED", "freshness": _freshness(getattr(rec, "updated_at", None)),
                    "basis": "a runtime observation named this algorithm"}
        return {"state": "INFERRED", "freshness": _freshness(getattr(rec, "updated_at", None)),
                "basis": "discovered by analysis — requires validation"}
    if kind == "hw":
        rec = ctx["record"]
        if rec.last_verified or rec.current_fingerprint:
            return {"state": "MEASURED", "freshness": _freshness(rec.last_verified),
                    "basis": "agent verification or stored fingerprint"}
        if rec.evidence_history or rec.first_seen:
            return {"state": "IMPORTED", "freshness": _freshness(rec.first_seen),
                    "basis": "recorded from an estate observation"}
        return {"state": "UNKNOWN", "freshness": "NOT_COLLECTED",
                "basis": "no collector evidence recorded for this device"}
    if kind == "net":
        row = ctx["record"]
        if row.get("observed"):
            return {"state": "MEASURED", "freshness": _freshness(row.get("observed_at")),
                    "basis": "observed by an authorized network scan"}
        return {"state": "UNKNOWN", "freshness": _freshness(row.get("observed_at")),
                "basis": "no handshake or response observed — a port scan alone proves nothing"}
    if kind == "vendor":
        prof = db.execute(select(VendorProfileRevision).where(
            VendorProfileRevision.vendor_id == ident).limit(1)).scalars().first()
        if prof is not None:
            return {"state": "IMPORTED", "freshness": _freshness(prof.captured_at),
                    "basis": "vendor profile supplied to the registry"}
        return {"state": "UNKNOWN", "freshness": "NOT_COLLECTED",
                "basis": "no profile, assessment or collector evidence recorded"}
    return {"state": "UNKNOWN", "freshness": "NOT_COLLECTED",
            "basis": "registration only — no collector evidence recorded for this asset"}


# --------------------------------------------------------------------------- #
# The nine detail tabs
# --------------------------------------------------------------------------- #

@router.get("/{asset_ref}/overview", response_model=TabResponse)
def tab_overview(asset_ref: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)) -> TabResponse:
    ctx = _resolve(db, asset_ref)
    evidence = _evidence_for(db, ctx)
    related = _cross_bom(db, ctx)
    rows = [{
        "field": field, "value": value
    } for field, value in [
        ("Asset ID", asset_ref), ("Environment", ctx["environment"] or "—"),
        ("Category", ctx["category"]), ("Owner", ctx["owner"] or "—"),
        ("Source", ctx["source"]), ("Last observed", ctx["last_observed"] or "—"),
        ("Evidence", f"{evidence['state']} · {evidence['freshness']}"),
        ("Relationships", "; ".join(f"{r['bom']}={r['state']}" for r in related)),
    ]]
    return TabResponse(asset_ref=asset_ref, tab="overview", rows=rows,
                       note="the asset information fields as stored")


@router.get("/{asset_ref}/components", response_model=TabResponse)
def tab_components(asset_ref: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)) -> TabResponse:
    ctx = _resolve(db, asset_ref)
    kind, ident = ctx["kind"], ctx["ident"]
    rows: List[Dict[str, Any]] = []
    if kind == "app":
        for link in db.execute(select(SystemAsset).where(SystemAsset.system_id == ident)).scalars().all():
            c = db.get(CryptoAsset, link.asset_id)
            if c is not None:
                rows.append({"component_ref": f"crypto:{c.id}", "name": c.algorithm or c.id,
                             "type": "crypto", "version": c.key_size or "", "evidence": "stored system_assets link"})
    if kind == "crypto":
        rows.append({"component_ref": asset_ref, "name": ctx["name"], "type": "crypto",
                     "version": ctx["record"].key_size or "", "evidence": "the record itself"})
    return TabResponse(
        asset_ref=asset_ref, tab="components", rows=rows,
        note=("verified sub-components only — a package name match is never a component "
              "decomposition") if rows else
             "no stored component decomposition for this asset — not an empty claim",
    )


@router.get("/{asset_ref}/cryptography", response_model=TabResponse)
def tab_cryptography(asset_ref: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)) -> TabResponse:
    ctx = _resolve(db, asset_ref)
    kind, ident = ctx["kind"], ctx["ident"]
    rows: List[Dict[str, Any]] = []
    runtime = _runtime_algorithms(db)
    if kind == "app":
        for link in db.execute(select(SystemAsset).where(SystemAsset.system_id == ident)).scalars().all():
            c = db.get(CryptoAsset, link.asset_id)
            if c is None:
                continue
            observed = str(c.algorithm or "").upper() in runtime
            rows.append({
                "crypto_ref": f"crypto:{c.id}", "algorithm": c.algorithm or "",
                "key_size": c.key_size, "mode": c.mode or "", "purpose": c.purpose or "",
                "usage_state": "operation_observed" if observed else "capability_detected",
                "basis": ("runtime observation named this algorithm" if observed else
                          "inventory record only — capability is never operation"),
            })
    elif kind == "crypto":
        rec = ctx["record"]
        observed = str(rec.algorithm or "").upper() in runtime
        rows.append({
            "crypto_ref": asset_ref, "algorithm": rec.algorithm or "", "key_size": rec.key_size,
            "mode": rec.mode or "", "purpose": rec.purpose or "",
            "usage_state": "operation_observed" if observed else "capability_detected",
            "basis": ("runtime observation named this algorithm" if observed else
                      "inventory record only — capability is never operation"),
        })
    elif kind == "net":
        row = ctx["record"]
        if row.get("observed"):
            rows.append({
                "crypto_ref": asset_ref, "algorithm": row.get("tls_version") or "",
                "key_size": None, "mode": row.get("cipher_suite") or "", "purpose": "tls",
                "usage_state": "operation_observed",
                "basis": "the handshake was observed by an authorized scan",
            })
        else:
            rows.append({
                "crypto_ref": asset_ref, "algorithm": "unknown", "key_size": None,
                "mode": "unknown", "purpose": "tls", "usage_state": "unknown",
                "basis": "a port scan alone does not prove the negotiated cryptographic configuration",
            })
    elif kind == "hw":
        rec = ctx["record"]
        for label, present in (("HSM capability", bool(rec.hsm)), ("TPM capability", bool(rec.tpm))):
            if present:
                rows.append({"crypto_ref": asset_ref, "algorithm": label, "key_size": None,
                             "mode": "capability_detected", "purpose": "key storage",
                             "usage_state": "capability_detected",
                             "basis": "stored capability metadata — never key material, never proof of use"})
    elif kind == "vendor":
        for row in db.execute(select(VendorCryptoInventory).where(VendorCryptoInventory.vendor_id == ident)).scalars().all():
            rows.append({
                "crypto_ref": f"vendor-crypto:{row.id}", "algorithm": row.algorithm or "",
                "key_size": row.key_size, "mode": row.mode or "", "purpose": row.crypto_use_case or "",
                "usage_state": "vendor_declared",
                "basis": "a vendor declaration is evidence about the vendor, not about bank use",
            })
    return TabResponse(asset_ref=asset_ref, tab="cryptography", rows=rows,
                       note="usage states are never equated: capability_detected ≠ configuration_observed ≠ operation_observed")


@router.get("/{asset_ref}/hardware", response_model=TabResponse)
def tab_hardware(asset_ref: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)) -> TabResponse:
    ctx = _resolve(db, asset_ref)
    rows: List[Dict[str, Any]] = []
    if ctx["kind"] == "hw":
        rec = ctx["record"]
        firmware_version = ""
        if isinstance(rec.firmware, dict):
            firmware_version = str(rec.firmware.get("version") or "")
        rows.append({
            "asset_ref": asset_ref, "manufacturer": rec.manufacturer or "",
            "model": rec.model or "", "device_type": rec.device_type or "",
            "serial": _mask_serial(rec.serial_reference),
            "firmware_version": firmware_version,
            "risk_level": rec.risk_level or "UNKNOWN",
            "first_seen": _iso(rec.first_seen), "last_seen": _iso(rec.last_seen),
            "last_verified": _iso(rec.last_verified),
        })
    return TabResponse(
        asset_ref=asset_ref, tab="hardware", rows=rows,
        note=("safe summary fields only — serials masked; no firmware, TPM, HSM, "
              "key, secret or credential material is ever exposed here")
        if rows else "no stored hardware record for this asset — a hardware link is not established",
    )


@router.get("/{asset_ref}/network", response_model=TabResponse)
def tab_network(asset_ref: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)) -> TabResponse:
    ctx = _resolve(db, asset_ref)
    rows: List[Dict[str, Any]] = []
    if ctx["kind"] == "net":
        row = ctx["record"]
        cert = row.get("certificate") or {}
        rows.append({
            "endpoint": row.get("endpoint"), "protocol": row.get("protocol") or "",
            "service": row.get("service") or "",
            "tls_version": row.get("tls_version") if row.get("observed") else "unknown",
            "cipher_suite": row.get("cipher_suite") if row.get("observed") else "unknown",
            "certificate_subject": cert.get("subject") or "",
            "certificate_fingerprint": cert.get("fingerprint_sha256") or "",
            "observed": bool(row.get("observed")),
            "basis": ("observed by an authorized network scan" if row.get("observed")
                      else "a port scan alone does not prove the negotiated cryptographic configuration"),
        })
    return TabResponse(
        asset_ref=asset_ref, tab="network", rows=rows,
        note="observed handshakes report negotiated facts; everything else reports unknown"
        if rows else "no stored network observation for this asset — a network link is not established",
    )


@router.get("/{asset_ref}/vendors", response_model=TabResponse)
def tab_vendors(asset_ref: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)) -> TabResponse:
    ctx = _resolve(db, asset_ref)
    kind, ident = ctx["kind"], ctx["ident"]
    rows: List[Dict[str, Any]] = []
    if kind == "app":
        for link in db.execute(select(SystemVendor).where(SystemVendor.system_id == ident)).scalars().all():
            v = db.get(Vendor, link.vendor_id)
            if v is not None:
                rows.append({"vendor_ref": f"vendor:{v.id}", "name": v.name,
                             "vendor_type": getattr(v, "vendor_type", "") or "",
                             "criticality": getattr(v, "criticality", "") or "",
                             "dependency_type": getattr(link, "dependency_type", "") or "",
                             "basis": "stored SystemVendor link"})
    elif kind == "vendor":
        rec = ctx["record"]
        for link in db.execute(select(SystemVendor).where(SystemVendor.vendor_id == ident)).scalars().all():
            s = db.get(System, link.system_id)
            if s is not None:
                rows.append({"vendor_ref": asset_ref, "name": rec.name,
                             "supplies_system": f"app:{s.id}", "system_name": s.name,
                             "basis": "stored SystemVendor link — verified bank asset, not a public association"})
    return TabResponse(
        asset_ref=asset_ref, tab="vendors", rows=rows,
        note="verified supplier links only — a public association is never bank use"
        if rows else "no stored supplier relationship for this asset",
    )


@router.get("/{asset_ref}/dependencies", response_model=TabResponse)
def tab_dependencies(asset_ref: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)) -> TabResponse:
    ctx = _resolve(db, asset_ref)
    kind, ident = ctx["kind"], ctx["ident"]
    rows: List[Dict[str, Any]] = []
    if kind == "app":
        for row in db.execute(select(SystemDependency).where(
                (SystemDependency.parent_id == ident) | (SystemDependency.child_id == ident))).scalars().all():
            rows.append({"from": f"app:{row.parent_id}", "to": f"app:{row.child_id}",
                         "type": "system_dependency", "evidence": "stored SystemDependency row"})
    if kind in ("app", "crypto"):
        col = SystemAsset.system_id if kind == "app" else SystemAsset.asset_id
        for row in db.execute(select(SystemAsset).where(col == ident)).scalars().all():
            rows.append({"from": f"app:{row.system_id}", "to": f"crypto:{row.asset_id}",
                         "type": "system_asset", "evidence": "stored system_assets link"})
    if kind in ("app", "vendor"):
        col = SystemVendor.system_id if kind == "app" else SystemVendor.vendor_id
        for row in db.execute(select(SystemVendor).where(col == ident)).scalars().all():
            rows.append({"from": f"app:{row.system_id}", "to": f"vendor:{row.vendor_id}",
                         "type": "system_vendor", "evidence": "stored SystemVendor link"})
    return TabResponse(
        asset_ref=asset_ref, tab="dependencies", rows=rows,
        note="verified dependency paths only — a shared name is not a relationship"
        if rows else "no stored dependency path for this asset",
    )


@router.get("/{asset_ref}/evidence", response_model=TabResponse)
def tab_evidence(asset_ref: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)) -> TabResponse:
    ctx = _resolve(db, asset_ref)
    kind, ident = ctx["kind"], ctx["ident"]
    rows: List[Dict[str, Any]] = []
    if kind == "crypto":
        for link in db.execute(select(CryptoAssetEvidence).where(CryptoAssetEvidence.asset_id == ident)).scalars().all():
            ev = db.get(EvidenceRecord, link.evidence_id)
            if ev is not None:
                rows.append({"evidence_id": ev.id, "algorithm": ev.algorithm or "",
                             "confidence": ev.confidence or "", "content_hash": ev.content_hash or "",
                             "chain_position": ev.chain_position,
                             "file_path": ev.file_path if _safe_name(ev.file_path) else "withheld",
                             "captured_at": _iso(getattr(ev, "created_at", None)),
                             "freshness": _freshness(getattr(ev, "created_at", None))})
    elif kind == "hw":
        rec = ctx["record"]
        history = rec.evidence_history or []
        rows.append({"evidence_id": "evidence_history", "algorithm": "",
                     "confidence": "MEASURED" if rec.last_verified else "IMPORTED",
                     "content_hash": rec.current_fingerprint or "",
                     "chain_position": len(history),
                     "file_path": "", "captured_at": _iso(rec.last_verified) or _iso(rec.first_seen),
                     "freshness": _freshness(rec.last_verified or rec.first_seen)})
    elif kind == "vendor":
        for prof in db.execute(select(VendorProfileRevision).where(VendorProfileRevision.vendor_id == ident)
                               .order_by(VendorProfileRevision.revision.desc()).limit(10)).scalars().all():
            rows.append({"evidence_id": f"rev:{prof.revision}", "algorithm": "",
                         "confidence": prof.status or "", "content_hash": prof.content_sha256 or "",
                         "chain_position": prof.revision,
                         "file_path": "", "captured_at": _iso(prof.captured_at),
                         "freshness": _freshness(prof.captured_at)})
    elif kind == "net":
        row = ctx["record"]
        rows.append({"evidence_id": "network-observation", "algorithm": row.get("tls_version") or "",
                     "confidence": "MEASURED" if row.get("observed") else "UNKNOWN",
                     "content_hash": (row.get("certificate") or {}).get("fingerprint_sha256") or "",
                     "chain_position": 0, "file_path": "",
                     "captured_at": row.get("observed_at"),
                     "freshness": _freshness(row.get("observed_at"))})
    return TabResponse(
        asset_ref=asset_ref, tab="evidence", rows=rows,
        note="source, timestamp and digest as recorded — freshness follows the shared policy"
        if rows else "no stored evidence for this asset — evidence is insufficient, not absent of risk",
    )


@router.get("/{asset_ref}/history", response_model=TabResponse)
def tab_history(asset_ref: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)) -> TabResponse:
    ctx = _resolve(db, asset_ref)
    rec = ctx.get("record")
    rows: List[Dict[str, Any]] = []
    created = _iso(getattr(rec, "created_at", None)) if rec is not None and not isinstance(rec, dict) else None
    updated = _iso(getattr(rec, "updated_at", None)) if rec is not None and not isinstance(rec, dict) else None
    if created or updated:
        rows.append({"event": "record timestamps", "captured_at": updated or created,
                     "created_at": created, "updated_at": updated, "basis": "the stored row"})
    if ctx["kind"] == "hw" and isinstance(rec, HardwareAsset):
        for label, ts in (("first seen", rec.first_seen), ("last seen", rec.last_seen),
                          ("last verified", rec.last_verified), ("last firmware check", rec.last_firmware_check),
                          ("last crypto check", rec.last_crypto_check)):
            if ts:
                rows.append({"event": label, "captured_at": _iso(ts), "created_at": None,
                             "updated_at": None, "basis": "hardware lifecycle timestamps"})
    return TabResponse(
        asset_ref=asset_ref, tab="history", rows=rows,
        note="stored timestamps and events only — no history is invented"
        if rows else "no stored change history for this asset",
    )
