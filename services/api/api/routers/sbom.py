"""SBOM workspace — Software Bill of Materials (docs/boms/01_PRODUCT_SPEC.md §1).

What software exists, which components it contains and how components depend on
each other. Every section reads stored scans or stored SBOM documents; an empty
section is an honest empty state, never a fabricated package list.

Working rules from the spec govern this surface and are not narrated on screen:
an SBOM entry never proves runtime cryptographic use, and CBOM links are only
claimed where evidence establishes them (usage state is computed, never assumed:
manifest declarations are capability at most, and ``operation_observed`` requires
a durable monitor observation naming the same algorithm).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from hashlib import sha256
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from api.software_inventory import latest_scan_software
from db.models.binary_scan import BinaryScanRecord
from db.models.container_scan import ContainerScan
from db.models.crypto_live import CryptoLiveState
from db.models.scan import Scan
from db.models.software_supply_chain import ReleaseSbomBinding
from db.models.technology_bom_snapshot import TechnologyBomSnapshot
from db.models.vulnerability import Vulnerability

router = APIRouter(prefix="/sbom", tags=["sbom"])

SECTION_NAMES = (
    "overview", "inventory", "components", "dependencies", "licenses",
    "vulnerabilities", "versions", "containers", "binaries", "evidence",
    "history", "export",
)


# ─────────────────────────────────────────────────────────── helpers ──

def _inventory(db: Session) -> dict[str, Any]:
    inventory = latest_scan_software(db)
    scan_id = inventory.get("scan_id")
    if scan_id:
        scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalars().first()
        inventory["tenant_id"] = scan.tenant_id if scan else None
    return inventory


def _rows(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    return [r for r in (inventory.get("components") or []) if isinstance(r, dict)]


def _canonical_ref(scan_id: str, coordinate: str) -> str:
    """Route-safe, scan-qualified identity for a stored SBOM component."""
    return f"sbom:{scan_id}:{sha256(coordinate.encode('utf-8')).hexdigest()}"


def _purl(row: dict[str, Any]) -> Optional[str]:
    """Package URL when the ecosystem is one we can spell honestly."""
    ecosystem = str(row.get("ecosystem") or "").strip().lower()
    name = str(row.get("name") or "").strip()
    version = str(row.get("version") or "").strip()
    scheme = {
        "npm": "pkg:npm", "pypi": "pkg:pypi", "maven": "pkg:maven",
        "go": "pkg:golang", "golang": "pkg:golang", "cargo": "pkg:cargo",
        "gem": "pkg:gem", "nuget": "pkg:nuget", "apk": "pkg:apk",
        "deb": "pkg:deb", "rpm": "pkg:rpm",
    }.get(ecosystem)
    if not scheme or not name:
        return None
    purl = f"{scheme}/{name}"
    return f"{purl}@{version}" if version else purl


def _vuln_index(db: Session) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rows = db.execute(select(Vulnerability)).scalars().all()
    for v in rows:
        index[str(v.package).lower()].append({
            "cve": v.cve,
            "severity": v.severity,
            "affected": v.affected,
            "package_version": v.package_version,
            "summary": v.summary,
            "scan_id": v.scan_id,
        })
    return index


def _runtime_algorithms(db: Session) -> dict[tuple[str | None, str], set[str]]:
    """Directly attributed component observations; algorithm alone is not a link.

    A monitor's algorithm-only state cannot establish operation on every SBOM
    package with the same name. A collector must cite the exact scan component
    using the scan-qualified ``sbom:<scan_id>:<coordinate-digest>`` reference
    in the same tenant.
    """
    out: dict[tuple[str | None, str], set[str]] = defaultdict(set)
    for state in db.execute(select(CryptoLiveState)).scalars().all():
        ref = str(state.asset_id or "")
        if not ref.startswith("sbom:") or state.last_event != "MONITOR_OBSERVED":
            continue
        for name in state.algorithms if isinstance(state.algorithms, list) else []:
            key = str(name).strip().lower()
            if key:
                out[(state.tenant_id, ref)].add(key)
    return out


def _usage_state(row: dict[str, Any], runtime: dict[tuple[str | None, str], set[str]],
                 *, scan_id: str, tenant_id: str | None) -> list[dict[str, Any]]:
    origin = str(row.get("origin") or "")
    out = []
    ref = _canonical_ref(scan_id, str(row.get("coordinate") or ""))
    linked = runtime.get((tenant_id, ref), set())
    for algo in row.get("algorithms") or []:
        key = str(algo).strip().lower()
        observed_by = [ref] if key in linked else []
        if observed_by:
            state, evidence = "operation_observed", observed_by
        elif origin == "MANIFEST_DECLARED":
            state, evidence = "capability_detected", []
        else:
            # seen in code, but no operation was observed at runtime
            state, evidence = "configuration_observed", []
        out.append({"algorithm": str(algo), "usage_state": state,
                    "basis": origin or "UNKNOWN", "runtime_evidence": evidence})
    return out


def _inventory_row(row: dict[str, Any], vulns: dict[str, list[dict[str, Any]]],
                   scan_at: Any, scan_id: str) -> dict[str, Any]:
    matched = vulns.get(str(row.get("name") or "").lower()) or []
    severity = None
    if matched:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        severity = min(matched, key=lambda v: order.get(str(v["severity"]).upper(), 9))["severity"]
    return {
        "coordinate": row.get("coordinate"),
        "asset_ref": _canonical_ref(scan_id, str(row.get("coordinate") or "")),
        "component_type": row.get("component_type"),
        "name": row.get("name"),
        "version": row.get("version"),
        "ecosystem": row.get("ecosystem") or ("library" if row.get("component_type") == "library" else ""),
        "purl": _purl(row),
        "application": row.get("application"),
        "source": row.get("origin"),
        "license": row.get("license"),  # scanners do not collect licenses yet
        "vulnerability": {"count": len(matched), "max_severity": severity} if matched else {"count": 0, "max_severity": None},
        "evidence": {
            "type": row.get("evidence_type") or ("MANIFEST" if row.get("declared_in") else None),
            "declared_in": row.get("declared_in"),
            "confidence": row.get("confidence"),
        },
        "last_observed": scan_at,
        "dependency_type": row.get("dependency_type"),
        "crypto_bearing": bool(row.get("crypto_bearing")),
    }


# ─────────────────────────────────────────────────────────── sections ──

# ── response contracts (the untyped ratchet only goes down: new routes
# arrive typed so the console's payload claims are machine-checked) ──────


class VulnRef(BaseModel):
    package: str
    cve: str
    severity: str
    summary: Optional[str] = None
    package_version: Optional[str] = None
    affected: Optional[str] = None
    scan_id: Optional[str] = None


class RowVuln(BaseModel):
    count: int
    max_severity: Optional[str] = None


class RowEvidence(BaseModel):
    type: Optional[str] = None
    declared_in: Optional[str] = None
    confidence: Optional[str] = None


class SbomRow(BaseModel):
    coordinate: str
    asset_ref: str
    component_type: Optional[str] = None
    name: str
    version: Optional[str] = None
    ecosystem: Optional[str] = None
    purl: Optional[str] = None
    application: Optional[str] = None
    source: Optional[str] = None
    license: Optional[str] = None
    vulnerability: RowVuln
    evidence: RowEvidence
    last_observed: Optional[str] = None
    dependency_type: Optional[str] = None
    crypto_bearing: bool = False


class UsageState(BaseModel):
    algorithm: str
    usage_state: str
    basis: str
    runtime_evidence: List[str]


class Deps(BaseModel):
    direct: List[Dict[str, str]]
    transitive: List[Dict[str, str]]
    unresolved_parent: bool


class Flags(BaseModel):
    declared_but_unused: bool
    used_but_undeclared: bool


class ComponentDetail(BaseModel):
    component: SbomRow
    usage_states: List[UsageState]
    supplier: Optional[str] = None
    dependencies: Deps
    vulnerabilities: List[VulnRef]
    manifests: List[str]
    versions: List[str]
    flags: Flags


class Overview(BaseModel):
    state: str
    scan_id: Optional[str] = None
    observed_at: Optional[str] = None
    component_count: int = 0
    package_count: int = 0
    library_count: int = 0
    ecosystems: Dict[str, int] = {}
    sources: Dict[str, int] = {}
    dependency_edges: int = 0
    unresolved_dependencies: int = 0
    license: Dict[str, int] = {}
    vulnerability: Dict[str, Any] = {}
    containers: int = 0
    binaries: int = 0
    stored_documents: int = 0
    history_snapshots: int = 0
    sections: Dict[str, bool] = {}


class Inventory(BaseModel):
    state: str
    scan_id: Optional[str] = None
    total: int
    rows: List[SbomRow]


class DepEdge(BaseModel):
    source: str
    target: str
    type: str


class DependencyTree(BaseModel):
    state: str
    edges: List[DepEdge]
    roots: List[str]
    unresolved: int


class LicenseInventory(BaseModel):
    state: str
    counts: Dict[str, int]
    collected: int
    total: int
    note: str


class VulnInventory(BaseModel):
    state: str
    matched: List[VulnRef]
    unmatched: List[VulnRef]
    by_severity: Dict[str, int]
    note: str


class VersionRow(BaseModel):
    coordinate: str
    name: str
    versions: List[str] = []
    declared_but_unused: bool = False
    used_but_undeclared: bool = False


class VersionInventory(BaseModel):
    state: str
    multi_version: List[VersionRow]
    drift_signals: List[VersionRow]


class ContainerRow(BaseModel):
    scan_id: Optional[str] = None
    target: str
    package_count: int = 0
    library_count: int = 0
    vuln_count: int = 0
    created_at: Optional[str] = None


class ContainerInventory(BaseModel):
    rows: List[ContainerRow]
    total: int


class BinaryRow(BaseModel):
    artifact_id: str
    target: str
    format: str
    sha256: Optional[str] = None
    status: str
    files_walked: int = 0
    created_at: Optional[str] = None


class BinaryInventory(BaseModel):
    rows: List[BinaryRow]
    total: int


class EvidenceDocument(BaseModel):
    sbom_sha256: str
    sbom_artifact_id: str
    component_count: int = 0
    unresolved_component_count: int = 0
    assertion_source: Optional[str] = None
    created_at: Optional[str] = None


class EvidenceInventory(BaseModel):
    state: str
    component_evidence: Dict[str, int]
    documents: List[EvidenceDocument]


class SnapshotRow(BaseModel):
    snapshot_id: str
    version: int
    created_at: Optional[str] = None


class HistoryInventory(BaseModel):
    snapshots: List[SnapshotRow]
    compare_path: str


class ExportFormat(BaseModel):
    format: str
    validator: str
    state: str


class ExportInventory(BaseModel):
    formats: List[ExportFormat]
    stored_documents: int
    unresolved_components: int
    export_path: str


@router.get("/overview", response_model=Overview)
def sbom_overview(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    inventory = _inventory(db)
    rows = _rows(inventory)
    vulns = _vuln_index(db)
    edges = inventory.get("edges") or []
    raw = inventory.get("completed_at")
    scan_at = raw.isoformat() if hasattr(raw, "isoformat") else raw
    ecosystems = Counter(str(r.get("ecosystem") or "unknown") for r in rows)
    sources = Counter(str(r.get("origin") or "UNKNOWN") for r in rows)
    with_license = sum(1 for r in rows if r.get("license"))
    matched = sum(1 for r in rows if vulns.get(str(r.get("name") or "").lower()))
    severity = Counter()
    for r in rows:
        for v in vulns.get(str(r.get("name") or "").lower()) or []:
            severity[str(v["severity"]).upper()] += 1
    containers = db.execute(select(ContainerScan)).scalars().all()
    binaries = db.execute(select(BinaryScanRecord)).scalars().all()
    documents = db.execute(select(ReleaseSbomBinding)).scalars().all()
    snapshots = db.execute(select(TechnologyBomSnapshot)).scalars().all()
    return {
        "state": inventory.get("state"),
        "scan_id": inventory.get("scan_id"),
        "observed_at": scan_at,
        "component_count": len(rows),
        "package_count": sum(1 for r in rows if r.get("component_type") == "package"),
        "library_count": sum(1 for r in rows if r.get("component_type") == "library"),
        "ecosystems": dict(ecosystems),
        "sources": dict(sources),
        "dependency_edges": len(edges),
        "unresolved_dependencies": sum(1 for r in rows if r.get("unresolved")),
        "license": {"with_license": with_license, "without_license": len(rows) - with_license},
        "vulnerability": {"components_with_findings": matched, "by_severity": dict(severity)},
        "containers": len(containers),
        "binaries": len(binaries),
        "stored_documents": len(documents),
        "history_snapshots": len(snapshots),
        "sections": {name: True for name in SECTION_NAMES},
    }


@router.get("/components", response_model=Inventory)
def sbom_components(
    q: Optional[str] = Query(None),
    ecosystem: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    dependency_type: Optional[str] = Query(None),
    crypto_bearing: Optional[bool] = Query(None),
    sort: str = Query("name"),
    limit: int = Query(200, ge=1, le=1000),
    user: str = Depends(get_current_user), db: Session = Depends(get_db_session),
):
    inventory = _inventory(db)
    rows = _rows(inventory)
    vulns = _vuln_index(db)
    raw = inventory.get("completed_at")
    scan_at = raw.isoformat() if hasattr(raw, "isoformat") else raw
    out = [_inventory_row(r, vulns, scan_at,
                          str(inventory.get("scan_id") or "")) for r in rows]
    if q:
        needle = q.lower()
        out = [r for r in out if needle in str(r["name"]).lower()
               or needle in str(r["coordinate"]).lower()
               or needle in str(r["version"]).lower()]
    if ecosystem:
        out = [r for r in out if str(r["ecosystem"]).lower() == ecosystem.lower()]
    if source:
        out = [r for r in out if str(r["source"]).upper() == source.upper()]
    if dependency_type:
        out = [r for r in out if str(r["dependency_type"]).lower() == dependency_type.lower()]
    if crypto_bearing is not None:
        out = [r for r in out if r["crypto_bearing"] == crypto_bearing]
    if sort in {"name", "version", "vulnerability"}:
        if sort == "vulnerability":
            out.sort(key=lambda r: r["vulnerability"]["count"], reverse=True)
        else:
            out.sort(key=lambda r: (str(r[sort] or ""), str(r["name"] or "")))
    return {
        "state": inventory.get("state"),
        "scan_id": inventory.get("scan_id"),
        "total": len(out),
        "rows": out[:limit],
    }


@router.get("/components/{coordinate:path}", response_model=ComponentDetail)
def sbom_component_detail(
    coordinate: str,
    user: str = Depends(get_current_user), db: Session = Depends(get_db_session),
):
    inventory = _inventory(db)
    rows = _rows(inventory)
    vulns = _vuln_index(db)
    runtime = _runtime_algorithms(db)
    raw = inventory.get("completed_at")
    scan_at = raw.isoformat() if hasattr(raw, "isoformat") else raw
    match = next((r for r in rows if str(r.get("coordinate")) == coordinate), None)
    if match is None:
        raise HTTPException(status_code=404, detail="component not in the stored inventory")
    edges = inventory.get("edges") or []
    direct = [e for e in edges if e.get("source") == coordinate]
    children = {e.get("target") for e in direct}
    transitive = [e for e in edges if e.get("source") in children]
    return {
        "component": _inventory_row(match, vulns, scan_at,
                                    str(inventory.get("scan_id") or "")),
        "usage_states": _usage_state(match, runtime,
                                      scan_id=str(inventory.get("scan_id") or ""),
                                      tenant_id=inventory.get("tenant_id")),
        "supplier": match.get("supplier"),  # None where scanners did not collect it
        "dependencies": {
            "direct": direct,
            "transitive": transitive,
            "unresolved_parent": bool(match.get("unresolved")),
        },
        "vulnerabilities": vulns.get(str(match.get("name") or "").lower()) or [],
        "manifests": match.get("manifests") or [],
        "versions": match.get("versions") or [],
        "flags": {
            "declared_but_unused": bool(match.get("declared_but_unused")),
            "used_but_undeclared": bool(match.get("used_but_undeclared")),
        },
    }


@router.get("/dependencies", response_model=DependencyTree)
def sbom_dependencies(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    inventory = _inventory(db)
    rows = _rows(inventory)
    edges = inventory.get("edges") or []
    named = {str(r.get("coordinate")) for r in rows}
    children = {e.get("target") for e in edges}
    return {
        "state": inventory.get("state"),
        "edges": edges,
        "roots": sorted(named - children),
        "unresolved": sum(1 for r in rows if r.get("unresolved")),
    }


@router.get("/licenses", response_model=LicenseInventory)
def sbom_licenses(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    inventory = _inventory(db)
    rows = _rows(inventory)
    counts: Counter = Counter()
    for r in rows:
        value = str(r.get("license") or "").strip()
        counts[value or "NOT_COLLECTED"] += 1
    return {
        "state": inventory.get("state"),
        "counts": dict(counts),
        "collected": sum(v for k, v in counts.items() if k != "NOT_COLLECTED"),
        "total": len(rows),
        "note": ("license fields are reported by the scanner where the source "
                 "supplied one; a missing license is NOT_COLLECTED, never MIT"),
    }


@router.get("/vulnerabilities", response_model=VulnInventory)
def sbom_vulnerabilities(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    inventory = _inventory(db)
    rows = _rows(inventory)
    vulns = _vuln_index(db)
    names = {str(r.get("name") or "").lower() for r in rows}
    matched, unmatched = [], []
    for package, items in vulns.items():
        for item in items:
            record = {"package": package, **item}
            (matched if package in names else unmatched).append(record)
    severity = Counter(str(v["severity"]).upper() for v in matched)
    return {
        "state": inventory.get("state"),
        "matched": matched,
        "unmatched": unmatched,
        "by_severity": dict(severity),
        "note": "unmatched records name packages the stored inventory does not contain",
    }


@router.get("/versions", response_model=VersionInventory)
def sbom_versions(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    inventory = _inventory(db)
    rows = _rows(inventory)
    multi = [r for r in rows if len(r.get("versions") or []) > 1]
    drift = [r for r in rows if r.get("declared_but_unused") or r.get("used_but_undeclared")]
    return {
        "state": inventory.get("state"),
        "multi_version": [
            {"coordinate": r.get("coordinate"), "name": r.get("name"),
             "versions": r.get("versions")} for r in multi],
        "drift_signals": [
            {"coordinate": r.get("coordinate"), "name": r.get("name"),
             "declared_but_unused": bool(r.get("declared_but_unused")),
             "used_but_undeclared": bool(r.get("used_but_undeclared"))} for r in drift],
    }


@router.get("/containers", response_model=ContainerInventory)
def sbom_containers(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = db.execute(select(ContainerScan).order_by(ContainerScan.created_at.desc()).limit(200)).scalars().all()
    return {
        "rows": [{
            "scan_id": r.scan_id,
            "target": r.target,
            "package_count": r.package_count,
            "library_count": r.library_count,
            "vuln_count": r.vuln_count,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        } for r in rows],
        "total": len(rows),
    }


@router.get("/binaries", response_model=BinaryInventory)
def sbom_binaries(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = db.execute(select(BinaryScanRecord).order_by(BinaryScanRecord.created_at.desc()).limit(200)).scalars().all()
    return {
        "rows": [{
            "artifact_id": r.artifact_id,
            "target": r.target,
            "format": r.format,
            "sha256": r.sha256,
            "status": r.status,
            "files_walked": r.files_walked,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        } for r in rows],
        "total": len(rows),
    }


@router.get("/evidence", response_model=EvidenceInventory)
def sbom_evidence(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    inventory = _inventory(db)
    rows = _rows(inventory)
    documents = db.execute(select(ReleaseSbomBinding).order_by(
        ReleaseSbomBinding.created_at.desc()).limit(200)).scalars().all()
    sources: Counter = Counter()
    for r in rows:
        sources[str(r.get("evidence_type") or r.get("origin") or "UNKNOWN")] += 1
    return {
        "state": inventory.get("state"),
        "component_evidence": dict(sources),
        "documents": [{
            "sbom_sha256": d.sbom_sha256,
            "sbom_artifact_id": d.sbom_artifact_id,
            "component_count": d.component_count,
            "unresolved_component_count": getattr(d, "unresolved_component_count", 0),
            "assertion_source": getattr(d, "assertion_source", None),
            "created_at": d.created_at.isoformat() if d.created_at else None,
        } for d in documents],
    }


@router.get("/history", response_model=HistoryInventory)
def sbom_history(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = db.execute(select(TechnologyBomSnapshot).order_by(
        TechnologyBomSnapshot.version.desc()).limit(50)).scalars().all()
    return {
        "snapshots": [{
            "snapshot_id": r.snapshot_id,
            "version": r.version,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        } for r in rows],
        "compare_path": "/api/v1/techbom/compare",
    }


@router.get("/export", response_model=ExportInventory)
def sbom_export(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    documents = db.execute(select(ReleaseSbomBinding)).scalars().all()
    formats = [
        {"format": "CycloneDX 1.5", "validator": "cbom.cyclonedx15", "state": "AVAILABLE"},
        {"format": "CycloneDX 1.6", "validator": "cbom.cyclonedx16", "state": "AVAILABLE"},
        {"format": "SPDX 2.3", "validator": "devsecops.sbom", "state": "AVAILABLE"},
    ]
    return {
        "formats": formats,
        "stored_documents": len(documents),
        "unresolved_components": sum(int(getattr(d, "unresolved_component_count", 0) or 0)
                                     for d in documents),
        "export_path": "/api/v1/techbom/export",
    }
