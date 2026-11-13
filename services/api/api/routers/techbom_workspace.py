"""TechBOM workspace — Technology Bill of Materials (docs/boms/01_PRODUCT_SPEC.md §6).

The cross-estate entry point: one canonical technology inventory linking
software, cryptography, hardware, network and vendors, plus the six-BOM
reconciliation screens (spec §9). Every section reads the stored estate
through the same materializer families the live Technology BOM reads.

Working rules from the spec govern this surface and are not narrated on
screen: a relationship is only established where stored evidence
establishes it (system_assets, SystemVendor, SystemDependency) — a name
match or a shared layer never becomes a link; the reconciliation engine
connects records only when the evidence establishes the relationship and
must not assume the application performs an operation a component is
capable of. Evidence states are Measured / Imported / Inferred / Unknown /
Contradicted with freshness current / stale / expired / not collected.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from cbom.nbom import probe_to_endpoint
from db.models.crypto_asset import CryptoAsset
from db.models.cryptographic_fact import CryptographicFact
from db.models.hardware_live import HardwareAsset
from db.models.network_scan_run import NetworkScanRun
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.models.system_dependency import SystemDependency
from db.models.vendor import SystemVendor, Vendor
from db.models.vendor_profile import VendorProfileRevision
from db.models.technology_bom_snapshot import TechnologyBomSnapshot

router = APIRouter(prefix="/techbom/workspace", tags=["techbom-workspace"])

BOMS = ("SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TechBOM")


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if hasattr(value, "isoformat") else (str(value) if value else None)


def _freshness(seen: Any) -> str:
    """current / stale / expired / not_collected — the shared BOM policy."""
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


def _evidence(state: str, seen: Any, basis: str) -> Dict[str, Any]:
    return {"state": state, "freshness": _freshness(seen), "basis": basis}


# --------------------------------------------------------------------------- #
# One estate read -> canonical rows (the inventory is one list, never six)
# --------------------------------------------------------------------------- #

def _estate(db: Session) -> Dict[str, Any]:
    """Read the stored estate once. Real rows only; nothing is inferred here."""
    systems = db.execute(select(System)).scalars().all()
    crypto = db.execute(select(CryptoAsset)).scalars().all()
    hardware = db.execute(select(HardwareAsset)).scalars().all()
    vendors = db.execute(select(Vendor)).scalars().all()
    sa_rows = db.execute(select(SystemAsset)).scalars().all()
    sv_rows = db.execute(select(SystemVendor)).scalars().all()
    sd_rows = db.execute(select(SystemDependency)).scalars().all()
    profiles = db.execute(select(VendorProfileRevision)).scalars().all()
    facts = db.execute(select(CryptographicFact)).scalars().all()
    runs = db.execute(select(NetworkScanRun).order_by(NetworkScanRun.created_at.desc())).scalars().all()

    # NBOM endpoints through the one probe->endpoint contract (shared with the
    # NBOM workspace, the cross-BOM query and the offline probe script).
    endpoints: list[Dict[str, Any]] = []
    observed_at: Dict[str, Any] = {}
    for run in runs:
        probes = (run.result or {}).get("probes") or []
        run_at = _iso(getattr(run, "created_at", None))
        for probe in probes:
            row = probe_to_endpoint(probe)
            if not row:
                continue
            key = f"{row.get('host') or ''}:{row.get('port') or ''}"
            row["endpoint"] = key
            if key not in observed_at:
                endpoints.append(row)
                observed_at[key] = run_at
            elif run_at and (observed_at.get(key) or "") < run_at:
                observed_at[key] = run_at
    return {
        "systems": systems, "crypto": crypto, "hardware": hardware, "vendors": vendors,
        "sa_rows": sa_rows, "sv_rows": sv_rows, "sd_rows": sd_rows,
        "profiles": profiles, "facts": facts, "endpoints": endpoints,
        "endpoints_observed_at": observed_at,
    }


def _links(estate: Dict[str, Any]) -> Dict[str, Any]:
    """Verified relationship indexes. A link exists only where a stored row
    establishes it — name matches are never promoted to links."""
    crypto_to_systems: Dict[str, set] = {}
    system_to_crypto: Dict[str, set] = {}
    for row in estate["sa_rows"]:
        crypto_to_systems.setdefault(str(row.asset_id), set()).add(str(row.system_id))
        system_to_crypto.setdefault(str(row.system_id), set()).add(str(row.asset_id))
    vendor_to_systems: Dict[str, set] = {}
    system_to_vendors: Dict[str, set] = {}
    for row in estate["sv_rows"]:
        vendor_to_systems.setdefault(str(row.vendor_id), set()).add(str(row.system_id))
        system_to_vendors.setdefault(str(row.system_id), set()).add(str(row.vendor_id))
    system_deps: Dict[str, int] = {}
    for row in estate["sd_rows"]:
        system_deps[str(row.parent_id)] = system_deps.get(str(row.parent_id), 0) + 1
        system_deps[str(row.child_id)] = system_deps.get(str(row.child_id), 0) + 1
    profile_by_vendor: Dict[str, list] = {}
    for row in estate["profiles"]:
        profile_by_vendor.setdefault(str(row.vendor_id), []).append(row)
    verified_facts = {str(f.file_path) for f in estate["facts"] if f.verified_at}
    return {
        "crypto_to_systems": crypto_to_systems, "system_to_crypto": system_to_crypto,
        "vendor_to_systems": vendor_to_systems, "system_to_vendors": system_to_vendors,
        "system_deps": system_deps, "profile_by_vendor": profile_by_vendor,
        "verified_fact_paths": verified_facts,
    }


def _related(primary: str, linked: list[str]) -> Dict[str, str]:
    """Cross-BOM relationship states for one asset (spec §7 vocabulary):
    primary record / linked / not established / unknown — never conflated."""
    out: Dict[str, str] = {bom: "NOT_ESTABLISHED" for bom in BOMS}
    out[primary] = "PRIMARY_RECORD"
    for bom in linked:
        out[bom] = "LINKED"
    return out


def _inventory_rows(estate: Dict[str, Any], links: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    for s in estate["systems"]:
        dep_count = links["system_deps"].get(str(s.id), 0) + len(links["system_to_crypto"].get(str(s.id), set())) \
            + len(links["system_to_vendors"].get(str(s.id), set()))
        linked: list[str] = []
        if links["system_to_crypto"].get(str(s.id)):
            linked.append("CBOM")
        if links["system_to_vendors"].get(str(s.id)):
            linked.append("VBOM")
        rows.append({
            "asset_ref": f"app:{s.id}", "name": s.name, "category": "SOFTWARE",
            "vendor": getattr(s, "supplier", "") or "", "product_version": getattr(s, "version", "") or "",
            "environment": s.environment or "", "related": _related("SBOM", linked),
            "dependencies": dep_count,
            "evidence": _evidence("UNKNOWN", None, "registration only — no collector evidence recorded for this system"),
            "last_observed": _iso(getattr(s, "updated_at", None)),
        })

    for c in estate["crypto"]:
        systems = links["crypto_to_systems"].get(str(c.id), set())
        linked = ["SBOM"] if systems else []
        observed = _iso(getattr(c, "updated_at", None)) or _iso(getattr(c, "created_at", None))
        if str(c.file_path or "") in links["verified_fact_paths"] and c.file_path:
            ev = _evidence("MEASURED", observed, "a verified cryptographic fact records this path")
        elif getattr(c, "source_document", None):
            ev = _evidence("IMPORTED", observed, "declared in a supplied document")
        else:
            ev = _evidence("INFERRED", observed, "discovered by analysis — requires validation")
        rows.append({
            "asset_ref": f"crypto:{c.id}", "name": c.algorithm or c.id, "category": "CRYPTO",
            "vendor": "", "product_version": f"{c.algorithm or ''} {c.key_size or ''}".strip(),
            "environment": getattr(c, "hostname", "") or "", "related": _related("CBOM", linked),
            "dependencies": len(systems), "evidence": ev, "last_observed": observed,
        })

    for h in estate["hardware"]:
        observed = _iso(h.last_seen) or _iso(h.first_seen)
        if h.last_verified or h.current_fingerprint:
            ev = _evidence("MEASURED", h.last_verified or observed, "agent verification or stored fingerprint")
        elif h.evidence_history or h.first_seen:
            ev = _evidence("IMPORTED", observed, "recorded from an estate observation")
        else:
            ev = _evidence("UNKNOWN", None, "no collector evidence recorded for this device")
        rows.append({
            "asset_ref": f"hw:{h.asset_id}", "name": h.model or h.asset_id, "category": "HARDWARE",
            "vendor": h.manufacturer or "", "product_version": h.device_type or "",
            "environment": "", "related": _related("HBOM", []),
            "dependencies": 0, "evidence": ev, "last_observed": observed,
        })

    for e in estate["endpoints"]:
        key = e.get("endpoint") or ""
        observed = estate["endpoints_observed_at"].get(key)
        ev = (_evidence("MEASURED", observed, "observed by an authorized network scan")
              if e.get("observed")
              else _evidence("UNKNOWN", observed, "no handshake or response observed — a port scan alone proves nothing"))
        rows.append({
            "asset_ref": f"net:{key}", "name": key, "category": "NETWORK",
            "vendor": "", "product_version": e.get("service") or "", "environment": "",
            "related": _related("NBOM", []), "dependencies": 0,
            "evidence": ev, "last_observed": observed,
        })

    for v in estate["vendors"]:
        linked = ["SBOM"] if links["vendor_to_systems"].get(str(v.id)) else []
        profiles = links["profile_by_vendor"].get(str(v.id), [])
        captured = max((_iso(p.captured_at) for p in profiles), default=None)
        ev = (_evidence("IMPORTED", captured, "vendor profile supplied to the registry")
              if profiles else _evidence("UNKNOWN", None, "no profile, assessment or collector evidence recorded"))
        rows.append({
            "asset_ref": f"vendor:{v.id}", "name": v.name, "category": "SUPPLIER",
            "vendor": v.name, "product_version": getattr(v, "product", "") or "",
            "environment": "", "related": _related("VBOM", linked),
            "dependencies": len(links["vendor_to_systems"].get(str(v.id), set())),
            "evidence": ev, "last_observed": captured or _iso(getattr(v, "updated_at", None)),
        })
    return rows


# --------------------------------------------------------------------------- #
# Contracts
# --------------------------------------------------------------------------- #

class EvidenceOut(BaseModel):
    state: str
    freshness: str
    basis: str


class InventoryRowOut(BaseModel):
    asset_ref: str
    name: str
    category: str
    vendor: str = ""
    product_version: str = ""
    environment: str = ""
    related: Dict[str, str]
    dependencies: int = 0
    evidence: EvidenceOut
    last_observed: Optional[str] = None


class InventoryResponse(BaseModel):
    state: str = "techbom-inventory"
    total: int
    rows: List[InventoryRowOut]
    note: str


class OverviewResponse(BaseModel):
    state: str = "techbom-overview"
    environment: str
    total_assets: int
    category_counts: Dict[str, int]
    layers: Dict[str, int]
    related_bom_coverage: Dict[str, int]
    dependency_edges: int
    verified_links: Dict[str, int]
    evidence_states: Dict[str, int]
    note: str


class RelatedOut(BaseModel):
    bom: str
    state: str
    basis: str


class AssetDetailOut(BaseModel):
    asset_ref: str
    name: str
    category: str
    environment: str = ""
    owner: str = ""
    source: str
    last_observed: Optional[str] = None
    related: List[RelatedOut]
    dependencies: List[Dict[str, Any]]
    evidence: EvidenceOut


class LayerOut(BaseModel):
    layer: str
    label: str
    count: int
    source: str


class LayersResponse(BaseModel):
    state: str = "techbom-layers"
    rows: List[LayerOut]
    note: str


class RelationshipOut(BaseModel):
    source: str
    target: str
    type: str
    evidence: str


class RelationshipsResponse(BaseModel):
    state: str = "techbom-relationships"
    total: int
    rows: List[RelationshipOut]
    note: str


class RegistryResponse(BaseModel):
    state: str
    total: int
    rows: List[Dict[str, Any]]
    note: str


class ReconciliationScreenOut(BaseModel):
    screen: str
    question: str
    count: int
    rows: List[Dict[str, Any]]


class ReconciliationResponse(BaseModel):
    state: str = "techbom-reconciliation"
    screens: List[ReconciliationScreenOut]
    rule: str


class ExportFormatOut(BaseModel):
    format: str
    path: str
    state: str


class ExportResponse(BaseModel):
    state: str = "techbom-export"
    formats: List[ExportFormatOut]
    note: str


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #

@router.get("/overview", response_model=OverviewResponse)
def techbom_overview(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> OverviewResponse:
    estate = _estate(db)
    links = _links(estate)
    rows = _inventory_rows(estate, links)
    category_counts: Dict[str, int] = {}
    evidence_states: Dict[str, int] = {}
    related_coverage: Dict[str, int] = {bom: 0 for bom in BOMS}
    for row in rows:
        category_counts[row["category"]] = category_counts.get(row["category"], 0) + 1
        evidence_states[row["evidence"]["state"]] = evidence_states.get(row["evidence"]["state"], 0) + 1
        for bom, state in row["related"].items():
            if state in ("PRIMARY_RECORD", "LINKED"):
                related_coverage[bom] = related_coverage.get(bom, 0) + 1
    return OverviewResponse(
        environment=_environment_name(db),
        total_assets=len(rows),
        category_counts=category_counts,
        layers={
            "SBOM": category_counts.get("SOFTWARE", 0),
            "CBOM": category_counts.get("CRYPTO", 0),
            "HBOM": category_counts.get("HARDWARE", 0),
            "NBOM": category_counts.get("NETWORK", 0),
            "VBOM": category_counts.get("SUPPLIER", 0),
        },
        related_bom_coverage=related_coverage,
        dependency_edges=len(estate["sd_rows"]),
        verified_links={
            "system_crypto": len(estate["sa_rows"]),
            "system_vendor": len(estate["sv_rows"]),
            "system_dependency": len(estate["sd_rows"]),
        },
        evidence_states=evidence_states,
        note=("every asset row is a stored record; relationships count only verified links "
              "(system_assets, SystemVendor, SystemDependency)"),
    )


def _environment_name(db: Session) -> str:
    row = db.execute(select(System.environment).limit(1)).first()
    return (row[0] if row and row[0] else "default")


@router.get("/inventory", response_model=InventoryResponse)
def techbom_inventory(
    q: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> InventoryResponse:
    estate = _estate(db)
    links = _links(estate)
    rows = _inventory_rows(estate, links)
    if category:
        rows = [r for r in rows if r["category"] == category.upper()]
    if q:
        needle = q.lower()
        rows = [r for r in rows if needle in (r["name"] or "").lower()
                or needle in (r["asset_ref"] or "").lower()
                or needle in (r["vendor"] or "").lower()
                or needle in (r["product_version"] or "").lower()]
    return InventoryResponse(
        total=len(rows), rows=[InventoryRowOut(**r) for r in rows],
        note="canonical technology inventory — Related BOMs cite primary records and verified links only",
    )


@router.get("/inventory/{asset_ref:path}", response_model=AssetDetailOut)
def techbom_asset_detail(
    asset_ref: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> AssetDetailOut:
    estate = _estate(db)
    links = _links(estate)
    rows = _inventory_rows(estate, links)
    row = next((r for r in rows if r["asset_ref"] == asset_ref), None)
    if row is None:
        raise HTTPException(status_code=404, detail="asset not found in the stored technology inventory")

    basis = {
        "PRIMARY_RECORD": "this asset is a record of that BOM",
        "LINKED": "a stored relationship establishes this link",
        "NOT_ESTABLISHED": "no stored relationship establishes this link",
    }
    related = [RelatedOut(bom=bom, state=state, basis=basis.get(state, state))
               for bom, state in row["related"].items()]

    deps: List[Dict[str, Any]] = []
    kind, _, ident = row["asset_ref"].partition(":")
    if kind == "app":
        for link in sorted(links["system_to_crypto"].get(ident, set())):
            deps.append({"to": f"crypto:{link}", "type": "system_asset", "evidence": "stored system_assets link"})
        for link in sorted(links["system_to_vendors"].get(ident, set())):
            deps.append({"to": f"vendor:{link}", "type": "system_vendor", "evidence": "stored SystemVendor link"})
    elif kind == "crypto":
        for link in sorted(links["crypto_to_systems"].get(ident, set())):
            deps.append({"to": f"app:{link}", "type": "system_asset", "evidence": "stored system_assets link"})
    elif kind == "vendor":
        for link in sorted(links["vendor_to_systems"].get(ident, set())):
            deps.append({"to": f"app:{link}", "type": "system_vendor", "evidence": "stored SystemVendor link"})

    return AssetDetailOut(
        asset_ref=row["asset_ref"], name=row["name"], category=row["category"],
        environment=row["environment"], owner=row["vendor"],
        source=row["category"][0] + row["category"][1:].lower() + " record",
        last_observed=row["last_observed"], related=related, dependencies=deps,
        evidence=EvidenceOut(**row["evidence"]),
    )


@router.get("/applications", response_model=RegistryResponse)
def techbom_applications(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> RegistryResponse:
    estate = _estate(db)
    links = _links(estate)
    rows = []
    for s in estate["systems"]:
        rows.append({
            "id": f"app:{s.id}", "name": s.name, "version": getattr(s, "version", "") or "",
            "owner": s.owner or "", "environment": s.environment or "",
            "criticality": s.criticality or "",
            "crypto_assets": len(links["system_to_crypto"].get(str(s.id), set())),
            "vendors": len(links["system_to_vendors"].get(str(s.id), set())),
            "dependencies": links["system_deps"].get(str(s.id), 0),
        })
    return RegistryResponse(state="techbom-applications", total=len(rows), rows=rows,
                            note="registered systems and their verified links")


@router.get("/infrastructure", response_model=RegistryResponse)
def techbom_infrastructure(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> RegistryResponse:
    estate = _estate(db)
    rows: List[Dict[str, Any]] = []
    for h in estate["hardware"]:
        rows.append({
            "kind": "HARDWARE", "id": f"hw:{h.asset_id}", "name": h.model or h.asset_id,
            "detail": h.device_type or "", "vendor": h.manufacturer or "",
            "last_seen": _iso(h.last_seen),
            "lifecycle": "UNKNOWN",  # never assumed supported — see the HBOM lifecycle rules
        })
    for e in estate["endpoints"]:
        key = e.get("endpoint") or ""
        rows.append({
            "kind": "NETWORK", "id": f"net:{key}", "name": key,
            "detail": f"{e.get('protocol') or ''} {e.get('service') or ''}".strip(),
            "vendor": "", "last_seen": estate["endpoints_observed_at"].get(key),
            "lifecycle": "UNKNOWN",
        })
    return RegistryResponse(state="techbom-infrastructure", total=len(rows), rows=rows,
                            note="hardware and network inventory as stored — lifecycle is UNKNOWN where not recorded")


@router.get("/layers", response_model=LayersResponse)
def techbom_layers(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> LayersResponse:
    estate = _estate(db)
    links = _links(estate)
    rows = _inventory_rows(estate, links)
    counts: Dict[str, int] = {}
    for row in rows:
        counts[row["category"]] = counts.get(row["category"], 0) + 1
    out = [
        LayerOut(layer="SBOM", label="Software", count=counts.get("SOFTWARE", 0), source="registered systems + scanned packages"),
        LayerOut(layer="CBOM", label="Cryptography", count=counts.get("CRYPTO", 0), source="crypto assets"),
        LayerOut(layer="HBOM", label="Hardware", count=counts.get("HARDWARE", 0), source="hardware assets"),
        LayerOut(layer="NBOM", label="Network", count=counts.get("NETWORK", 0), source="stored network scan runs"),
        LayerOut(layer="VBOM", label="Suppliers", count=counts.get("SUPPLIER", 0), source="vendor registry"),
    ]
    return LayersResponse(rows=out, note="one asset model, materialized per layer — a row's layer is its primary record")


@router.get("/relationships", response_model=RelationshipsResponse)
def techbom_relationships(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> RelationshipsResponse:
    estate = _estate(db)
    rows: List[Dict[str, Any]] = []
    for link in estate["sa_rows"]:
        rows.append({"source": f"crypto:{link.asset_id}", "target": f"app:{link.system_id}",
                     "type": "system_asset", "evidence": "stored system_assets link"})
    for link in estate["sv_rows"]:
        rows.append({"source": f"app:{link.system_id}", "target": f"vendor:{link.vendor_id}",
                     "type": "system_vendor", "evidence": "stored SystemVendor link"})
    for link in estate["sd_rows"]:
        rows.append({"source": f"app:{link.parent_id}", "target": f"app:{link.child_id}",
                     "type": "system_dependency", "evidence": "stored SystemDependency row"})
    return RelationshipsResponse(
        total=len(rows), rows=[RelationshipOut(**r) for r in rows],
        note="verified relationships only — a shared name or layer is not a relationship",
    )


@router.get("/reconciliation", response_model=ReconciliationResponse)
def techbom_reconciliation(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> ReconciliationResponse:
    """The ten reconciliation screens (spec §9). The engine connects records
    only where the evidence establishes the relationship; it never assumes an
    application performs an operation a component is capable of."""
    estate = _estate(db)
    links = _links(estate)
    rows = _inventory_rows(estate, links)

    # 1. Duplicate asset detection — same name+version under different identities.
    by_identity: Dict[tuple, list] = {}
    for row in rows:
        by_identity.setdefault((row["name"].lower(), (row["product_version"] or "").lower(), row["category"]), []).append(row)
    duplicates = [
        {"name": k[0], "version": k[1], "category": k[2], "identities": [r["asset_ref"] for r in v]}
        for k, v in by_identity.items() if len(v) > 1 and k[0]
    ]

    # 2. Unmatched SBOM components — no verified link out of the SBOM.
    unmatched_sbom = [
        {"asset_ref": r["asset_ref"], "name": r["name"]}
        for r in rows if r["category"] == "SOFTWARE" and r["dependencies"] == 0
    ]

    # 3. CBOM assets without a mapped software or hardware owner.
    cbom_unowned = [
        {"asset_ref": r["asset_ref"], "name": r["name"]}
        for r in rows if r["category"] == "CRYPTO" and not links["crypto_to_systems"].get(r["asset_ref"].partition(":")[2])
    ]

    # 4. HBOM devices without an approved system mapping — no system-hardware
    #    link table exists, so every device is honestly unmapped.
    hbom_unmapped = [{"asset_ref": r["asset_ref"], "name": r["name"]}
                     for r in rows if r["category"] == "HARDWARE"]

    # 5. NBOM endpoints without a known service owner.
    nbom_unowned = [{"asset_ref": r["asset_ref"], "name": r["name"]}
                    for r in rows if r["category"] == "NETWORK"]

    # 6. VBOM products without a verified bank-asset relationship.
    vbom_unlinked = [
        {"asset_ref": r["asset_ref"], "name": r["name"]}
        for r in rows if r["category"] == "SUPPLIER"
        and not links["vendor_to_systems"].get(r["asset_ref"].partition(":")[2])
    ]

    # 7. Conflicting versions and metadata — same identity family, different version.
    by_name: Dict[tuple, set] = {}
    for row in rows:
        if row["name"]:
            by_name.setdefault((row["name"].lower(), row["category"]), set()).add(row["product_version"] or "")
    conflicts = [
        {"name": k[0], "category": k[1], "versions": sorted(v)}
        for k, v in by_name.items() if len(v) > 1
    ]

    # 8. Missing evidence.
    missing_evidence = [
        {"asset_ref": r["asset_ref"], "name": r["name"]}
        for r in rows if r["evidence"]["state"] == "UNKNOWN"
    ]

    # 9. Stale BOM records.
    stale = [
        {"asset_ref": r["asset_ref"], "name": r["name"], "freshness": r["evidence"]["freshness"]}
        for r in rows if r["evidence"]["freshness"] in ("STALE", "EXPIRED")
    ]

    # 10. Cross-BOM relationship validation — the verified edges themselves.
    validated = [
        {"source": f"crypto:{l.asset_id}", "target": f"app:{l.system_id}", "type": "system_asset"}
        for l in estate["sa_rows"]
    ] + [
        {"source": f"app:{l.system_id}", "target": f"vendor:{l.vendor_id}", "type": "system_vendor"}
        for l in estate["sv_rows"]
    ]

    screens = [
        ReconciliationScreenOut(screen="duplicate_asset_detection", question="Duplicate asset detection", count=len(duplicates), rows=duplicates),
        ReconciliationScreenOut(screen="unmatched_sbom_components", question="Unmatched SBOM components", count=len(unmatched_sbom), rows=unmatched_sbom),
        ReconciliationScreenOut(screen="cbom_assets_without_owner", question="CBOM assets without a mapped software or hardware owner", count=len(cbom_unowned), rows=cbom_unowned),
        ReconciliationScreenOut(screen="hbom_devices_without_mapping", question="HBOM devices without an approved system mapping", count=len(hbom_unmapped), rows=hbom_unmapped),
        ReconciliationScreenOut(screen="nbom_endpoints_without_owner", question="NBOM endpoints without a known service owner", count=len(nbom_unowned), rows=nbom_unowned),
        ReconciliationScreenOut(screen="vbom_products_without_relationship", question="VBOM products without a verified bank-asset relationship", count=len(vbom_unlinked), rows=vbom_unlinked),
        ReconciliationScreenOut(screen="conflicting_versions", question="Conflicting versions and metadata", count=len(conflicts), rows=conflicts),
        ReconciliationScreenOut(screen="missing_evidence", question="Missing evidence", count=len(missing_evidence), rows=missing_evidence),
        ReconciliationScreenOut(screen="stale_records", question="Stale BOM records", count=len(stale), rows=stale),
        ReconciliationScreenOut(screen="relationship_validation", question="Cross-BOM relationship validation", count=len(validated), rows=validated),
    ]
    return ReconciliationResponse(
        screens=screens,
        rule=("records are connected only where stored evidence establishes the "
              "relationship; a component's capability is never taken as proof the "
              "application performs the operation"),
    )


@router.get("/lifecycle", response_model=RegistryResponse)
def techbom_lifecycle(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> RegistryResponse:
    estate = _estate(db)
    rows: List[Dict[str, Any]] = []
    for v in estate["vendors"]:
        rows.append({"asset_ref": f"vendor:{v.id}", "name": v.name, "kind": "SUPPLIER",
                     "lifecycle": getattr(v, "lifecycle", "") or "UNKNOWN",
                     "risk_level": getattr(v, "risk_level", "") or "UNKNOWN"})
    for h in estate["hardware"]:
        rows.append({"asset_ref": f"hw:{h.asset_id}", "name": h.model or h.asset_id, "kind": "HARDWARE",
                     "lifecycle": "UNKNOWN", "risk_level": h.risk_level or "UNKNOWN",
                     "last_verified": _iso(h.last_verified)})
    return RegistryResponse(state="techbom-lifecycle", total=len(rows), rows=rows,
                            note="an unrecorded lifecycle is UNKNOWN, never assumed supported")


@router.get("/evidence", response_model=RegistryResponse)
def techbom_evidence(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> RegistryResponse:
    estate = _estate(db)
    links = _links(estate)
    rows = [
        {"asset_ref": r["asset_ref"], "name": r["name"], "category": r["category"],
         "evidence_state": r["evidence"]["state"], "freshness": r["evidence"]["freshness"],
         "basis": r["evidence"]["basis"], "last_observed": r["last_observed"]}
        for r in _inventory_rows(estate, links)
    ]
    return RegistryResponse(state="techbom-evidence", total=len(rows), rows=rows,
                            note="Measured / Imported / Inferred / Unknown / Contradicted with freshness")


@router.get("/history", response_model=RegistryResponse)
def techbom_history(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> RegistryResponse:
    snaps = db.execute(select(TechnologyBomSnapshot).order_by(
        TechnologyBomSnapshot.version.desc()).limit(50)).scalars().all()
    rows = [{"version": s.version, "snapshot_id": s.snapshot_id,
             "state": s.state, "captured_at": _iso(s.captured_at),
             "total_components": s.total_components,
             "content_sha256": s.content_sha256} for s in snaps]
    return RegistryResponse(state="techbom-history", total=len(rows), rows=rows,
                            note="captured snapshots as stored")


@router.get("/export", response_model=ExportResponse)
def techbom_export(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> ExportResponse:
    return ExportResponse(
        formats=[
            ExportFormatOut(format="technology-bom json", path="/api/v1/technology-bom", state="AVAILABLE"),
            ExportFormatOut(format="technology-bom csv", path="/api/v1/technology-bom/export/csv", state="AVAILABLE"),
            ExportFormatOut(format="vbom zelnx", path="/api/v1/technology-bom/export?fmt=zelnx", state="AVAILABLE"),
        ],
        note="exports carry the stored relationship states as recorded — publicly reported stays publicly reported",
    )
