"""VBOM workspace — Vendor Bill of Materials (docs/boms/01_PRODUCT_SPEC.md §5).

Which suppliers provide technology and how supplier products affect the
bank's technology and cryptographic estate. Every section reads the stored
vendor registry, system-vendor links, vendor profiles and vendor crypto
inventory; an empty section is an honest empty state, never a fabricated
supplier list.

Working rule from the spec governs this surface and is not narrated on
screen: a bank does not use a vendor product just because that vendor is
publicly associated with the bank. Every relationship carries one of four
states — CONFIRMED (a stored system-vendor link), IMPORTED (the record
arrived as an import), PUBLICLY_REPORTED (the record itself says so), or
UNKNOWN — and they are never collapsed. Bank-asset counts include verified
links only. A vendor PQC claim is REPORTED until the bank verifies it.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.models.system import System
from db.models.vendor import SystemVendor, Vendor
from db.models.vendor_crypto import VendorCryptoInventory
from db.models.vendor_profile import VendorProfileRevision

router = APIRouter(prefix="/vbom/workspace", tags=["vbom-workspace"])


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


def _association(vendor: Vendor, links: list, profile_row: Any) -> tuple[str, str]:
    """The working rule as a function: public association never implies use."""
    if links:
        return "CONFIRMED", "a stored system-vendor link names this relationship"
    if profile_row is not None and str(getattr(profile_row, "source", "") or "").lower() in {"import", "imported"}:
        return "IMPORTED", "the vendor record arrived as an imported document"
    extra = vendor.extra_json or {}
    marker = str(extra.get("association_state") or extra.get("association") or "").upper()
    if marker in {"PUBLICLY_REPORTED", "IMPORTED", "CONFIRMED"}:
        return marker, f"the stored record marks this association {marker.lower().replace('_', ' ')}"
    return "UNKNOWN", "no stored relationship or import marker — public association never implies bank use"


def _pqc_roadmap(rows: list) -> tuple[str, str]:
    """A vendor PQC claim is REPORTED until the bank verifies it."""
    if any(r.verified_at for r in rows):
        return "CONFIRMED", "a bank verification is recorded against the vendor's PQC claim"
    if any(r.pqc_ready or r.source_document for r in rows):
        return "REPORTED", "the vendor published a PQC claim; no bank verification recorded"
    return "UNKNOWN", "no PQC claim recorded — unknown, never assumed ready"


def _profile_dict(profile_row: Any) -> dict[str, Any]:
    return (getattr(profile_row, "profile_json", None) or {}) if profile_row is not None else {}


def _components(profile: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for c in (profile.get("components") or []):
        if not isinstance(c, dict):
            continue
        out.append({
            "component_id": c.get("component_id"),
            "name": c.get("name"),
            "version": c.get("version"),
            "component_type": c.get("component_type"),
            "license_model": c.get("license_model"),
            "support_level": c.get("support_level"),
            "eol_date": c.get("eol_date"),
            "replacement_product": c.get("replacement_product"),
            "criticality": c.get("criticality"),
        })
    return out


def _vendor_pack(db: Session) -> list[dict[str, Any]]:
    vendors = db.execute(select(Vendor)).scalars().all()
    packs = []
    for v in vendors:
        links = db.execute(select(SystemVendor).where(SystemVendor.vendor_id == v.id)).scalars().all()
        profile_row = db.execute(select(VendorProfileRevision).where(
            VendorProfileRevision.vendor_id == v.id).order_by(
            VendorProfileRevision.revision.desc()).limit(1)).scalars().first()
        crypto = db.execute(select(VendorCryptoInventory).where(
            VendorCryptoInventory.vendor_id == v.id)).scalars().all()
        association, association_basis = _association(v, links, profile_row)
        pqc_state, pqc_basis = _pqc_roadmap(crypto)
        packs.append({
            "vendor": v,
            "links": links,
            "profile_row": profile_row,
            "profile": _profile_dict(profile_row),
            "crypto": crypto,
            "association": association,
            "association_basis": association_basis,
            "pqc_state": pqc_state,
            "pqc_basis": pqc_basis,
        })
    return packs


def _product_rows(pack: dict[str, Any]) -> list[dict[str, Any]]:
    """One inventory row per recorded product; a vendor with none stays one
    honest row with NOT_COLLECTED, never a fabricated product."""
    components = _components(pack["profile"])
    v: Vendor = pack["vendor"]
    common = {
        "vendor": v.name,
        "vendor_id": str(v.id),
        "category": (v.vendor_type or "UNKNOWN"),
        "bank_assets": len(pack["links"]),
        "association_state": pack["association"],
        "association_basis": pack["association_basis"],
        "pqc_roadmap": pack["pqc_state"],
        "evidence": ({"profile_status": pack["profile_row"].status,
                      "source": pack["profile_row"].source,
                      "captured_at": _iso(pack["profile_row"].captured_at),
                      "freshness": _freshness(pack["profile_row"].captured_at)}
                     if pack["profile_row"] is not None else
                     {"profile_status": "NOT_COLLECTED", "source": None,
                      "captured_at": None, "freshness": "NOT_COLLECTED"}),
        "last_reviewed": _iso(getattr(pack["profile_row"], "captured_at", None)) if pack["profile_row"] is not None else None,
    }
    rows = []
    for c in components or [None]:
        if c is None:
            rows.append({**common, "product": None, "version": None,
                         "support_lifecycle": "UNKNOWN",
                         "crypto_dependency": "NOT_COLLECTED"})
        else:
            eol = c.get("eol_date")
            support = c.get("support_level")
            lifecycle = ("END_OF_LIFE" if eol else
                         "SUPPORTED" if support else "UNKNOWN")
            crypto_names = sorted({str(r.algorithm) for r in pack["crypto"] if r.algorithm})
            rows.append({**common, "product": c.get("name"), "version": c.get("version"),
                         "support_lifecycle": lifecycle,
                         "support_level": support,
                         "eol_date": eol,
                         "crypto_dependency": ", ".join(crypto_names) or "NOT_COLLECTED"})
    return rows


# ── response contracts (the untyped ratchet only goes down) ───────────


class EvidenceMeta(BaseModel):
    profile_status: str
    source: Optional[str] = None
    captured_at: Optional[str] = None
    freshness: str


class VendorRow(BaseModel):
    vendor: str
    vendor_id: str
    product: Optional[str] = None
    version: Optional[str] = None
    category: str
    bank_assets: int
    association_state: str
    association_basis: str
    support_lifecycle: str
    support_level: Optional[str] = None
    eol_date: Optional[str] = None
    crypto_dependency: str
    pqc_roadmap: str
    evidence: EvidenceMeta
    last_reviewed: Optional[str] = None


class VendorInventory(BaseModel):
    state: str
    total: int
    rows: List[VendorRow]


class Overview(BaseModel):
    state: str
    vendors: int = 0
    association: Dict[str, int] = {}
    categories: Dict[str, int] = {}
    linked_vendors: int = 0
    verified_links: int = 0
    profile_status: Dict[str, int] = {}
    pqc_roadmap: Dict[str, int] = {}
    crypto_inventory_rows: int = 0
    read: Dict[str, Any] = {}


class ProductRow(BaseModel):
    vendor: str
    vendor_id: str
    component_id: Optional[str] = None
    name: Optional[str] = None
    version: Optional[str] = None
    component_type: Optional[str] = None
    license_model: Optional[str] = None
    support_level: Optional[str] = None
    eol_date: Optional[str] = None
    replacement_product: Optional[str] = None


class ProductInventory(BaseModel):
    state: str
    total: int
    rows: List[ProductRow]


class RelationshipRow(BaseModel):
    vendor: str
    vendor_id: str
    system_id: Optional[str] = None
    system_name: Optional[str] = None
    dependency_type: Optional[str] = None
    association_state: str
    association_basis: str


class RelationshipInventory(BaseModel):
    state: str
    total: int
    rows: List[RelationshipRow]


class LifecycleRow(BaseModel):
    vendor: str
    product: Optional[str] = None
    version: Optional[str] = None
    support_level: Optional[str] = None
    eol_date: Optional[str] = None
    replacement_product: Optional[str] = None
    lifecycle: str


class LifecycleInventory(BaseModel):
    state: str
    total: int
    rows: List[LifecycleRow]


class SecurityRow(BaseModel):
    vendor: str
    vendor_id: str
    assessments: List[Dict[str, Any]] = []
    certifications: List[Dict[str, Any]] = []
    incidents: List[Dict[str, Any]] = []


class SecurityInventory(BaseModel):
    state: str
    total: int
    rows: List[SecurityRow]


class CryptoDepRow(BaseModel):
    vendor: str
    vendor_id: str
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    mode: Optional[str] = None
    crypto_use_case: Optional[str] = None
    key_management: Optional[str] = None
    pqc_ready: bool = False
    discovery_method: Optional[str] = None
    confidence: Optional[str] = None
    verified: bool = False
    source_document: Optional[str] = None


class CryptoDepInventory(BaseModel):
    state: str
    total: int
    rows: List[CryptoDepRow]


class PqcRoadmapRow(BaseModel):
    vendor: str
    vendor_id: str
    pqc_roadmap: str
    basis: str
    claims: int
    verified_claims: int


class PqcRoadmapInventory(BaseModel):
    state: str
    total: int
    rows: List[PqcRoadmapRow]


class ExposureRow(BaseModel):
    vendor: str
    vendor_id: str
    sub_vendors: List[Dict[str, Any]] = []
    integration_points: List[Dict[str, Any]] = []
    concentration_flags: Dict[str, Any] = {}


class ExposureInventory(BaseModel):
    state: str
    total: int
    rows: List[ExposureRow]


class ContractRow(BaseModel):
    vendor: str
    vendor_id: str
    contracts: List[Dict[str, Any]] = []
    service_level_agreements: List[Dict[str, Any]] = []
    contract_end_date: Optional[str] = None


class ContractInventory(BaseModel):
    state: str
    total: int
    rows: List[ContractRow]


class EvidenceRow(BaseModel):
    vendor: str
    vendor_id: str
    evidence_id: Optional[str] = None
    evidence_type: Optional[str] = None
    evidence_reference: Optional[str] = None
    status: Optional[str] = None
    source_system: Optional[str] = None
    collection_method: Optional[str] = None
    captured_at: Optional[str] = None
    expires_at: Optional[str] = None
    freshness: str


class EvidenceInventory(BaseModel):
    state: str
    total: int
    rows: List[EvidenceRow]


class HistoryRow(BaseModel):
    vendor: str
    vendor_id: str
    revision: int
    status: str
    source: str
    captured_at: Optional[str] = None
    reviewed_by: Optional[str] = None


class HistoryInventory(BaseModel):
    state: str
    total: int
    rows: List[HistoryRow]


class VendorIdentityOut(BaseModel):
    id: str
    name: str
    legal_name: Optional[str] = None
    display_name: Optional[str] = None
    vendor_type: Optional[str] = None
    criticality: Optional[str] = None
    integration_type: Optional[str] = None
    headquarters_location: Optional[str] = None


class VendorDetail(BaseModel):
    vendor: VendorIdentityOut
    association_state: str
    association_basis: str
    products: List[Dict[str, Any]] = []
    bank_assets: List[Dict[str, Any]] = []
    contracts: List[Dict[str, Any]] = []
    service_level_agreements: List[Dict[str, Any]] = []
    contract_end_date: Optional[str] = None
    support: Dict[str, Any] = {}
    pqc_roadmap: Dict[str, Any] = {}
    supply_chain_exposure: Dict[str, Any] = {}
    evidence: List[Dict[str, Any]] = []
    approval_history: List[Dict[str, Any]] = []
    links: Dict[str, Any] = {}


class ExportFormat(BaseModel):
    format: str
    path: str
    state: str


class ExportInventory(BaseModel):
    formats: List[ExportFormat]
    note: str = ("the VBOM exports the stored relationship states as recorded — "
                 "publicly reported associations stay publicly reported in the "
                 "document too")


# ── operations ────────────────────────────────────────────────────────


@router.get("/overview", response_model=Overview)
def vbom_workspace_overview(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    packs = _vendor_pack(db)
    association = Counter(p["association"] for p in packs)
    categories = Counter(str(p["vendor"].vendor_type or "UNKNOWN") for p in packs)
    profiles = Counter((p["profile_row"].status if p["profile_row"] is not None else "NOT_COLLECTED") for p in packs)
    pqc = Counter(p["pqc_state"] for p in packs)
    return {
        "state": "OBSERVED" if packs else "NO_RECORDS",
        "vendors": len(packs),
        "association": dict(association),
        "categories": dict(categories),
        "linked_vendors": sum(1 for p in packs if p["links"]),
        "verified_links": sum(len(p["links"]) for p in packs),
        "profile_status": dict(profiles),
        "pqc_roadmap": dict(pqc),
        "crypto_inventory_rows": sum(len(p["crypto"]) for p in packs),
        "read": {
            "systems": len(db.execute(select(System)).scalars().all()),
            "profile_revisions": len(db.execute(select(VendorProfileRevision)).scalars().all()),
        },
    }


@router.get("/vendors", response_model=VendorInventory)
def vbom_workspace_vendors(
    q: Optional[str] = Query(None),
    association: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    user: str = Depends(get_current_user), db: Session = Depends(get_db_session),
):
    packs = _vendor_pack(db)
    out: list[dict[str, Any]] = []
    for p in packs:
        out.extend(_product_rows(p))
    if q:
        needle = q.lower()
        out = [r for r in out if needle in str(r["vendor"]).lower()
               or needle in str(r["product"] or "").lower()]
    if association:
        out = [r for r in out if r["association_state"] == association.upper()]
    out.sort(key=lambda r: (str(r["vendor"]), str(r["product"] or "")))
    return {"state": "OBSERVED" if out else ("EMPTY" if not packs else "FILTERED_EMPTY"),
            "total": len(out), "rows": out[:limit]}


@router.get("/vendors/{vendor_id}", response_model=VendorDetail)
def vbom_workspace_vendor_detail(
    vendor_id: str,
    user: str = Depends(get_current_user), db: Session = Depends(get_db_session),
):
    pack = next((p for p in _vendor_pack(db) if str(p["vendor"].id) == vendor_id), None)
    if pack is None:
        raise HTTPException(status_code=404, detail="vendor not in the stored registry")
    v: Vendor = pack["vendor"]
    profile = pack["profile"]
    systems = []
    if pack["links"]:
        ids = [l.system_id for l in pack["links"]]
        names = {s.id: s.name for s in db.execute(select(System).where(System.id.in_(ids))).scalars().all()}
        systems = [{"system_id": l.system_id, "system_name": names.get(l.system_id),
                    "dependency_type": l.dependency_type} for l in pack["links"]]
    deps = profile.get("dependencies") or {}
    evidence = [{
        "evidence_id": e.get("evidence_id"), "evidence_type": e.get("evidence_type"),
        "evidence_reference": e.get("evidence_reference"), "status": e.get("status"),
        "source_system": e.get("source_system"), "collection_method": e.get("collection_method"),
        "captured_at": e.get("captured_at"), "expires_at": e.get("expires_at"),
    } for e in (profile.get("evidence") or []) if isinstance(e, dict)]
    return {
        "vendor": {
            "id": str(v.id), "name": v.name,
            "legal_name": (profile.get("identity") or {}).get("legal_name"),
            "display_name": v.name,
            "vendor_type": v.vendor_type, "criticality": v.criticality,
            "integration_type": v.integration_type,
            "headquarters_location": (profile.get("identity") or {}).get("headquarters_location"),
        },
        "association_state": pack["association"],
        "association_basis": pack["association_basis"],
        "products": _components(profile),
        "bank_assets": systems,
        "contracts": profile.get("contracts") or [],
        "service_level_agreements": profile.get("service_level_agreements") or [],
        "contract_end_date": _iso(v.contract_end_date),
        "support": {
            "components": [c for c in _components(profile) if c.get("support_level") or c.get("eol_date")],
        },
        "pqc_roadmap": {"state": pack["pqc_state"], "basis": pack["pqc_basis"],
                        "claims": [{"algorithm": r.algorithm, "pqc_ready": bool(r.pqc_ready),
                                    "verified_at": _iso(r.verified_at),
                                    "source_document": r.source_document}
                                   for r in pack["crypto"] if r.pqc_ready or r.verified_at or r.source_document]},
        "supply_chain_exposure": {
            "sub_vendors": deps.get("sub_vendors") or [],
            "integration_points": deps.get("integration_points") or [],
            "concentration_risk": deps.get("concentration_risk"),
            "single_point_of_failure": deps.get("single_point_of_failure"),
        },
        "evidence": evidence,
        "approval_history": [{
            "revision": r.revision, "status": r.status, "source": r.source,
            "captured_at": _iso(r.captured_at), "reviewed_by": r.reviewed_by,
        } for r in db.execute(select(VendorProfileRevision).where(
            VendorProfileRevision.vendor_id == v.id).order_by(
            VendorProfileRevision.revision.desc()).limit(20)).scalars().all()],
        "links": {
            # cross-BOM links are claimed only where a stored relationship exists
            "sbom": [], "cbom": [], "hbom": [],
            "_note": "no stored cross-BOM link rows name this vendor",
        },
    }


@router.get("/products", response_model=ProductInventory)
def vbom_workspace_products(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = []
    for p in _vendor_pack(db):
        v: Vendor = p["vendor"]
        for c in _components(p["profile"]):
            rows.append({"vendor": v.name, "vendor_id": str(v.id), **c})
    return {"state": "OBSERVED" if rows else "NO_PRODUCTS",
            "total": len(rows), "rows": rows[:500]}


@router.get("/relationships", response_model=RelationshipInventory)
def vbom_workspace_relationships(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = []
    for p in _vendor_pack(db):
        v: Vendor = p["vendor"]
        if p["links"]:
            ids = [l.system_id for l in p["links"]]
            names = {s.id: s.name for s in db.execute(select(System).where(System.id.in_(ids))).scalars().all()}
            for l in p["links"]:
                rows.append({"vendor": v.name, "vendor_id": str(v.id),
                             "system_id": l.system_id, "system_name": names.get(l.system_id),
                             "dependency_type": l.dependency_type,
                             "association_state": p["association"], "association_basis": p["association_basis"]})
        else:
            rows.append({"vendor": v.name, "vendor_id": str(v.id),
                         "system_id": None, "system_name": None, "dependency_type": None,
                         "association_state": p["association"], "association_basis": p["association_basis"]})
    return {"state": "OBSERVED" if rows else "NO_RELATIONSHIPS",
            "total": len(rows), "rows": rows[:500]}


@router.get("/lifecycle", response_model=LifecycleInventory)
def vbom_workspace_lifecycle(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = []
    for p in _vendor_pack(db):
        for c in _components(p["profile"]):
            rows.append({
                "vendor": p["vendor"].name,
                "product": c.get("name"), "version": c.get("version"),
                "support_level": c.get("support_level"), "eol_date": c.get("eol_date"),
                "replacement_product": c.get("replacement_product"),
                "lifecycle": ("END_OF_LIFE" if c.get("eol_date") else
                              "SUPPORTED" if c.get("support_level") else "UNKNOWN"),
            })
    return {"state": "OBSERVED" if rows else "NO_LIFECYCLE_RECORDS",
            "total": len(rows), "rows": rows[:500]}


@router.get("/security", response_model=SecurityInventory)
def vbom_workspace_security(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = []
    for p in _vendor_pack(db):
        sc = p["profile"].get("security_compliance") or {}
        rows.append({
            "vendor": p["vendor"].name, "vendor_id": str(p["vendor"].id),
            "assessments": [a for a in (sc.get("assessments") or []) if isinstance(a, dict)],
            "certifications": [c for c in (sc.get("certifications") or []) if isinstance(c, dict)],
            "incidents": [i for i in ((p["profile"].get("incident_history") or {}).get("incidents") or []) if isinstance(i, dict)],
        })
    return {"state": "OBSERVED" if rows else "NO_SECURITY_RECORDS",
            "total": len(rows), "rows": rows[:200]}


@router.get("/crypto", response_model=CryptoDepInventory)
def vbom_workspace_crypto(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = []
    for p in _vendor_pack(db):
        for r in p["crypto"]:
            rows.append({
                "vendor": p["vendor"].name, "vendor_id": str(p["vendor"].id),
                "algorithm": r.algorithm, "key_size": r.key_size, "mode": r.mode,
                "crypto_use_case": r.crypto_use_case, "key_management": r.key_management,
                "pqc_ready": bool(r.pqc_ready), "discovery_method": r.discovery_method,
                "confidence": r.confidence, "verified": bool(r.verified_at),
                "source_document": r.source_document,
            })
    return {"state": "OBSERVED" if rows else "NO_VENDOR_CRYPTO_RECORDS",
            "total": len(rows), "rows": rows[:500]}


@router.get("/pqc", response_model=PqcRoadmapInventory)
def vbom_workspace_pqc(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = [{
        "vendor": p["vendor"].name, "vendor_id": str(p["vendor"].id),
        "pqc_roadmap": p["pqc_state"], "basis": p["pqc_basis"],
        "claims": sum(1 for r in p["crypto"] if r.pqc_ready or r.verified_at or r.source_document),
        "verified_claims": sum(1 for r in p["crypto"] if r.verified_at),
    } for p in _vendor_pack(db)]
    return {"state": "OBSERVED" if rows else "NO_PQC_RECORDS",
            "total": len(rows), "rows": rows[:500]}


@router.get("/exposure", response_model=ExposureInventory)
def vbom_workspace_exposure(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = []
    for p in _vendor_pack(db):
        deps = p["profile"].get("dependencies") or {}
        rows.append({
            "vendor": p["vendor"].name, "vendor_id": str(p["vendor"].id),
            "sub_vendors": [s for s in (deps.get("sub_vendors") or []) if isinstance(s, dict)],
            "integration_points": [i for i in (deps.get("integration_points") or []) if isinstance(i, dict)],
            "concentration_flags": {
                "critical_dependency": deps.get("critical_dependency"),
                "single_point_of_failure": deps.get("single_point_of_failure"),
                "concentration_risk": deps.get("concentration_risk"),
            },
        })
    return {"state": "OBSERVED" if rows else "NO_EXPOSURE_RECORDS",
            "total": len(rows), "rows": rows[:200]}


@router.get("/contracts", response_model=ContractInventory)
def vbom_workspace_contracts(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = [{
        "vendor": p["vendor"].name, "vendor_id": str(p["vendor"].id),
        "contracts": [c for c in (p["profile"].get("contracts") or []) if isinstance(c, dict)],
        "service_level_agreements": [s for s in (p["profile"].get("service_level_agreements") or []) if isinstance(s, dict)],
        "contract_end_date": _iso(p["vendor"].contract_end_date),
    } for p in _vendor_pack(db)]
    return {"state": "OBSERVED" if rows else "NO_CONTRACT_RECORDS",
            "total": len(rows), "rows": rows[:200]}


@router.get("/evidence", response_model=EvidenceInventory)
def vbom_workspace_evidence(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = []
    for p in _vendor_pack(db):
        for e in (p["profile"].get("evidence") or []):
            if not isinstance(e, dict):
                continue
            rows.append({
                "vendor": p["vendor"].name, "vendor_id": str(p["vendor"].id),
                "evidence_id": e.get("evidence_id"), "evidence_type": e.get("evidence_type"),
                "evidence_reference": e.get("evidence_reference"), "status": e.get("status"),
                "source_system": e.get("source_system"), "collection_method": e.get("collection_method"),
                "captured_at": e.get("captured_at"), "expires_at": e.get("expires_at"),
                "freshness": _freshness(e.get("captured_at")),
            })
    return {"state": "OBSERVED" if rows else "NO_EVIDENCE_RECORDS",
            "total": len(rows), "rows": rows[:500]}


@router.get("/history", response_model=HistoryInventory)
def vbom_workspace_history(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = []
    revisions = db.execute(select(VendorProfileRevision).order_by(
        VendorProfileRevision.captured_at.desc()).limit(500)).scalars().all()
    names = {str(v.id): v.name for v in db.execute(select(Vendor)).scalars().all()}
    for r in revisions:
        rows.append({
            "vendor": names.get(str(r.vendor_id), str(r.vendor_id)),
            "vendor_id": str(r.vendor_id),
            "revision": r.revision, "status": r.status, "source": r.source,
            "captured_at": _iso(r.captured_at), "reviewed_by": r.reviewed_by,
        })
    return {"state": "OBSERVED" if rows else "NO_HISTORY", "total": len(rows), "rows": rows}


@router.get("/export", response_model=ExportInventory)
def vbom_workspace_export(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {
        "formats": [
            {"format": "ZELNX-VBOM", "path": "/api/v1/vendor-bom?fmt=native", "state": "AVAILABLE"},
            {"format": "CycloneDX-style", "path": "/api/v1/vendor-bom?fmt=cyclonedx", "state": "AVAILABLE"},
        ],
    }
