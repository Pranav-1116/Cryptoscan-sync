"""CBOM workspace — Cryptography Bill of Materials (docs/boms/01_PRODUCT_SPEC.md §2).

Cryptographic assets, algorithms, libraries, certificates, key metadata and
evidence of cryptographic usage. Every section reads stored scan records,
stored facts, stored certificates and runtime observations; an empty section
is an honest empty state, never a fabricated crypto inventory.

Working rules from the spec govern this surface and are not narrated on screen:
capability_detected, configuration_observed and operation_observed are distinct
states, never equivalents; key metadata is surfaced, key material never is; a
library that supports an algorithm is not evidence that the application uses it.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.models.certificate import Certificate
from db.models.crypto_asset import CryptoAsset
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.models.crypto_live import CryptoLiveState
from db.models.cryptographic_fact import CryptographicFact
from db.models.pqc_migration import PqcMigrationWave
from db.models.runtime_finding import RuntimeFinding

router = APIRouter(prefix="/cbom/workspace", tags=["cbom-workspace"])


# ── shared honesty helpers ────────────────────────────────────────────


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if hasattr(value, "isoformat") else (str(value) if value else None)


def _freshness(seen: Any) -> str:
    """current / stale / expired / not_collected — never a guessed date."""
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


#: Quantum-relevant algorithm families. Classification of the ALGORITHM, not a
#: claim about the application's migration state.
def _pqc_family(algorithm: str) -> str:
    a = (algorithm or "").upper()
    if any(t in a for t in ("ML-KEM", "ML-DSA", "SLH-DSA", "XMSS", "LMS", "KYBER", "DILITHIUM", "SPHINCS", "FALCON")):
        return "QUANTUM_RESISTANT"
    if any(t in a for t in ("RSA", "DSA", "DH", "ECDH", "ECDSA", "ECDHE", "ELGamal", "ELGAMAL", "ECC", "CURVE25519", "ED25519", "ED448", "X25519", "X448")):
        return "MIGRATION_RELEVANT"
    if any(t in a for t in ("AES", "SHA", "HMAC", "CHACHA", "POLY1305", "CMAC", "GCM", "KECCAK", "BLAKE")):
        return "SYMMETRIC_OR_HASH"
    return "UNVERIFIED"


#: One evidence vocabulary for the whole BOM family (spec §8).
def _evidence_status(*, runtime_seen: bool, scanner_bounded: bool, conflicts: bool,
                     observation_count: int) -> tuple[str, str]:
    if conflicts:
        return "CONTRADICTED", "records disagree on the algorithm at this location"
    if runtime_seen and observation_count > 0:
        return "MEASURED", "a runtime observation named this algorithm"
    if scanner_bounded:
        return "INFERRED", "static scan located the reference; use is inferred, not measured"
    return "UNKNOWN", "no bounded observation method recorded"


def _usage_state(algorithm: str, runtime_algos: set[str], *, from_code: bool,
                 from_manifest: bool) -> dict[str, Any]:
    if (algorithm or "").upper() in runtime_algos:
        return {"usage_state": "operation_observed",
                "basis": "runtime observation named this algorithm"}
    if from_code:
        return {"usage_state": "configuration_observed",
                "basis": "code references it; no operation observed"}
    if from_manifest:
        return {"usage_state": "capability_detected",
                "basis": "declared by a manifest or library capability only"}
    return {"usage_state": "capability_detected", "basis": "capability record only"}


def _runtime_by_asset(db: Session) -> dict[tuple[str | None, str], set[str]]:
    """Only an exact canonical asset reference can establish usage on it.

    Algorithm-only monitor states are useful global observations, but say
    nothing about which code location or component performed the operation.
    """
    out: dict[tuple[str | None, str], set[str]] = defaultdict(set)
    for state in db.execute(select(CryptoLiveState)).scalars().all():
        ref = str(state.asset_id or "")
        if not ref.startswith(("crypto:", "fact:")) or state.last_event != "MONITOR_OBSERVED":
            continue
        for algorithm in state.algorithms if isinstance(state.algorithms, list) else []:
            key = str(algorithm).strip().upper()
            if key:
                out[(state.tenant_id, ref)].add(key)
    return out


def _runtime_algorithms(db: Session) -> set[str]:
    """Algorithms named by durable monitor observations (uppercased).

    Only monitor-observed state counts as runtime evidence; declarations never
    promote themselves here. Same guard as the SBOM workspace: a non-list
    payload is not an algorithm list.
    """
    out: set[str] = set()
    for state in db.execute(select(CryptoLiveState)).scalars().all():
        names = state.algorithms if isinstance(state.algorithms, list) else []
        for algo in names:
            key = str(algo).strip().upper()
            if key:
                out.add(key)
    return out


def _conflict_locations(db: Session) -> set[str]:
    """Locations where stored records name more than one algorithm family."""
    by_loc: dict[str, set[str]] = defaultdict(set)
    for row in db.execute(select(CryptoAsset)).scalars().all():
        by_loc[str(row.file_path)].add(str(row.algorithm or "").upper())
    return {loc for loc, algos in by_loc.items() if len({a.split("-")[0] for a in algos if a}) > 1}


def _asset_row(row: CryptoAsset,
               runtime_by_asset: dict[tuple[str | None, str], set[str]],
               conflicts: set[str]) -> dict[str, Any]:
    libraries = [str(x) for x in (row.libraries or []) if x]
    runtime_algos = runtime_by_asset.get((row.tenant_id, f"crypto:{row.id}"), set())
    usage = _usage_state(str(row.algorithm or ""), runtime_algos,
                         from_code=True, from_manifest=False)
    evidence_status, evidence_basis = _evidence_status(
        runtime_seen=str(row.algorithm or "").upper() in runtime_algos,
        scanner_bounded=bool(row.scanner_ids),
        conflicts=str(row.file_path) in conflicts,
        observation_count=1 if str(row.algorithm or "").upper() in runtime_algos else 0,
    )
    return {
        "asset_id": str(row.id),
        "algorithm": row.algorithm,
        "operation": row.purpose,
        "mode": row.mode,
        "implementation": libraries,
        "location": f"{row.file_path}:{row.line_number}" if row.line_number else row.file_path,
        "file_path": row.file_path,
        "source_language": row.source_language,
        # key METADATA only — the key material itself is never returned
        "key_metadata": {
            "size": row.key_size,
            "hardcoded_material_flag": bool(row.is_hardcoded_key),
            "named_reference": "PRESENT" if row.asset_key else None,
        },
        "evidence_status": evidence_status,
        "evidence_basis": evidence_basis,
        "usage": usage,
        "pqc_family": _pqc_family(str(row.algorithm or "")),
        "confidence": row.confidence,
        "occurrence_count": row.occurrence_count,
        "last_observed": _iso(getattr(row, "updated_at", None) or getattr(row, "created_at", None)),
        "freshness": _freshness(getattr(row, "updated_at", None) or getattr(row, "created_at", None)),
    }


# ── response contracts (the untyped ratchet only goes down) ───────────


class KeyMetadata(BaseModel):
    size: Optional[int] = None
    hardcoded_material_flag: bool = False
    named_reference: Optional[str] = None


class CryptoAssetRow(BaseModel):
    asset_id: str
    algorithm: Optional[str] = None
    operation: Optional[str] = None
    mode: Optional[str] = None
    implementation: List[str] = []
    location: Optional[str] = None
    file_path: Optional[str] = None
    source_language: Optional[str] = None
    key_metadata: KeyMetadata
    evidence_status: str
    evidence_basis: str
    usage: Dict[str, str]
    pqc_family: str
    confidence: Optional[str] = None
    occurrence_count: int = 1
    last_observed: Optional[str] = None
    freshness: str


class AssetInventory(BaseModel):
    state: str
    total: int
    rows: List[CryptoAssetRow]


class AssetDetail(BaseModel):
    asset: CryptoAssetRow
    certificates: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    associated_assets: List[Dict[str, Any]] = []
    history: List[Dict[str, Any]] = []
    techbom_links: List[Dict[str, Any]] = []
    pqc: Dict[str, Any] = {}


class Overview(BaseModel):
    state: str
    assets: int = 0
    algorithms: Dict[str, int] = {}
    operations: Dict[str, int] = {}
    libraries: int = 0
    certificates: Dict[str, int] = {}
    key_metadata: Dict[str, int] = {}
    runtime_observed_algorithms: int = 0
    protocols: Dict[str, int] = {}
    pqc: Dict[str, int] = {}
    evidence_status: Dict[str, int] = {}
    read: Dict[str, Any] = {}


class AlgorithmRow(BaseModel):
    algorithm: str
    assets: int
    operations: Dict[str, int] = {}
    key_sizes: List[int] = []
    usage_states: Dict[str, int] = {}
    pqc_family: str
    evidence_status: Dict[str, int] = {}


class AlgorithmIntelligence(BaseModel):
    state: str
    rows: List[AlgorithmRow]


class LibraryRow(BaseModel):
    name: str
    kind: str
    algorithms: List[str] = []
    usage_state: str
    basis: str
    crypto_bearing_components: int = 0


class LibraryInventory(BaseModel):
    state: str
    rows: List[LibraryRow]


class CertificateRow(BaseModel):
    fingerprint_sha256: str
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    public_key_algorithm: Optional[str] = None
    public_key_size: Optional[int] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    expiry_status: Optional[str] = None
    days_until_expiry: Optional[int] = None
    revocation_status: Optional[str] = None
    renewal_status: Optional[str] = None
    is_self_signed: bool = False
    san_count: int = 0
    pqc_family: str
    freshness: str


class CertificateInventory(BaseModel):
    state: str
    total: int
    rows: List[CertificateRow]


class KeyMetadataRow(BaseModel):
    location: str
    algorithm: Optional[str] = None
    size: Optional[int] = None
    mode: Optional[str] = None
    named_reference: Optional[str] = None
    hardcoded_material_flag: bool = False
    note: str = "key metadata only — key material is never collected into this view"


class KeyInventory(BaseModel):
    state: str
    total: int
    hardcoded_flagged: int
    rows: List[KeyMetadataRow]


class OperationRow(BaseModel):
    operation: str
    static_references: int = 0
    observed_operations: int = 0
    usage_state: str
    basis: str


class OperationInventory(BaseModel):
    state: str
    rows: List[OperationRow]


class ProtocolRow(BaseModel):
    protocol: str
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    hostname: Optional[str] = None
    observation_count: int = 1
    weak_tls: bool = False
    registry_status: Optional[str] = None
    quantum_impact: Optional[str] = None
    last_seen: Optional[str] = None
    freshness: str
    note: str = ("supported, configured and negotiated are kept apart; "
                 "a scan that saw a protocol supported proves nothing about what is in use")


class ProtocolInventory(BaseModel):
    state: str
    total: int
    rows: List[ProtocolRow]


class PqcReadiness(BaseModel):
    state: str
    by_family: Dict[str, int] = {}
    certificate_keys: Dict[str, int] = {}
    migration_waves: List[Dict[str, Any]] = []
    note: str = ("a library that supports a quantum-resistant algorithm is not "
                 "evidence the application uses it; wave absence is absence of a plan")


class CryptoDependency(BaseModel):
    source: str
    target: str
    type: str


class DependencyInventory(BaseModel):
    state: str
    edges: List[CryptoDependency]
    roots: List[str]
    unresolved: int


class EvidenceRow(BaseModel):
    asset_id: str
    algorithm: Optional[str] = None
    observation_method: str
    observation_count: int = 0
    scanners: List[str] = []
    evidence_status: str
    evidence_basis: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    freshness: str


class EvidenceInventory(BaseModel):
    state: str
    total: int
    rows: List[EvidenceRow]


class HistoryRow(BaseModel):
    algorithm: Optional[str] = None
    location: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    observation_count: int = 0
    freshness: str


class HistoryInventory(BaseModel):
    state: str
    rows: List[HistoryRow]
    note: str = "first/last observation per stored fact; events are immutable records"


class ExportFormat(BaseModel):
    format: str
    validator: str
    state: str


class ExportInventory(BaseModel):
    formats: List[ExportFormat]
    signed_variants: List[str]
    export_path: str
    note: str = ("the signed export carries an external signature over the exact "
                 "payload; a signature is integrity provenance, not a risk score")


# ── operations ────────────────────────────────────────────────────────


@router.get("/overview", response_model=Overview)
def cbom_workspace_overview(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    assets = db.execute(select(CryptoAsset)).scalars().all()
    facts = db.execute(select(CryptographicFact)).scalars().all()
    certs = db.execute(select(Certificate)).scalars().all()
    runtime = _runtime_algorithms(db)
    runtime_by_asset = _runtime_by_asset(db)
    protocols = db.execute(select(RuntimeFinding)).scalars().all()
    waves = db.execute(select(PqcMigrationWave)).scalars().all()
    conflicts = _conflict_locations(db)
    algo = Counter(str(a.algorithm or "UNKNOWN") for a in assets)
    ops = Counter(str(a.purpose or "UNKNOWN") for a in assets)
    cert_state = Counter(str(c.expiry_status or "UNKNOWN") for c in certs)
    pqc = Counter(_pqc_family(str(a.algorithm or "")) for a in assets)
    evidence = Counter()
    for a in assets:
        status = _asset_row(a, runtime_by_asset, conflicts)["evidence_status"]
        evidence[status] += 1
    proto = Counter("TLS" if (r.tls_version or "").startswith("TLS") else
                    "SSH" if "ssh" in str(r.extra or {}).lower() or "SSH" in str(r.algorithm or "") else
                    "IPsec" if "ipsec" in str(r.extra or {}).lower() or "IKE" in str(r.algorithm or "").upper() else
                    "other" for r in protocols)
    return {
        "state": "OBSERVED" if assets else ("FACTS_ONLY" if facts else "NO_RECORDS"),
        "assets": len(assets),
        "algorithms": dict(algo),
        "operations": dict(ops),
        "libraries": len({lib for a in assets for lib in (a.libraries or []) if lib}),
        "certificates": dict(cert_state),
        "key_metadata": {
            "with_size": sum(1 for a in assets if a.key_size),
            "hardcoded_material_flagged": sum(1 for a in assets if a.is_hardcoded_key),
            "named_reference": sum(1 for a in assets if a.asset_key),
        },
        "runtime_observed_algorithms": len(runtime),
        "protocols": dict(proto),
        "pqc": dict(pqc),
        "evidence_status": dict(evidence),
        "read": {
            "facts": len(facts),
            "certificates": len(certs),
            "protocol_observations": len(protocols),
            "migration_waves": len(waves),
            "conflict_locations": len(conflicts),
        },
    }


@router.get("/assets", response_model=AssetInventory)
def cbom_workspace_assets(
    q: Optional[str] = Query(None),
    algorithm: Optional[str] = Query(None),
    operation: Optional[str] = Query(None),
    evidence_status: Optional[str] = Query(None),
    sort: str = Query("algorithm"),
    limit: int = Query(200, ge=1, le=1000),
    user: str = Depends(get_current_user), db: Session = Depends(get_db_session),
):
    assets = db.execute(select(CryptoAsset)).scalars().all()
    runtime = _runtime_by_asset(db)
    conflicts = _conflict_locations(db)
    out = [_asset_row(a, runtime, conflicts) for a in assets]
    if q:
        needle = q.lower()
        out = [r for r in out if needle in str(r["algorithm"] or "").lower()
               or needle in str(r["location"] or "").lower()
               or needle in str(r["implementation"] or "").lower()]
    if algorithm:
        out = [r for r in out if str(r["algorithm"] or "").upper() == algorithm.upper()]
    if operation:
        out = [r for r in out if str(r["operation"] or "").lower() == operation.lower()]
    if evidence_status:
        out = [r for r in out if r["evidence_status"] == evidence_status.upper()]
    if sort in {"algorithm", "operation", "location", "evidence_status"}:
        out.sort(key=lambda r: (str(r.get(sort) or ""), str(r["asset_id"])))
    return {"state": "OBSERVED" if out else ("EMPTY" if not assets else "FILTERED_EMPTY"),
            "total": len(out), "rows": out[:limit]}


@router.get("/assets/{asset_id}", response_model=AssetDetail)
def cbom_workspace_asset_detail(
    asset_id: str,
    user: str = Depends(get_current_user), db: Session = Depends(get_db_session),
):
    asset = db.execute(select(CryptoAsset).where(CryptoAsset.id == asset_id)).scalars().first()
    if asset is None:
        raise HTTPException(status_code=404, detail="crypto asset not in the stored inventory")
    runtime = _runtime_by_asset(db)
    conflicts = _conflict_locations(db)
    row = _asset_row(asset, runtime, conflicts)
    evidence_rows = db.execute(select(CryptoAssetEvidence).where(
        CryptoAssetEvidence.asset_id == asset_id)).scalars().all()
    facts = db.execute(select(CryptographicFact).where(
        CryptographicFact.algorithm == asset.algorithm)).scalars().all()
    history = [{"location": f.file_path, "first_seen": _iso(f.first_seen), "last_seen": _iso(f.last_seen),
                "observation_count": f.observation_count, "is_current": f.is_current} for f in facts[:50]]
    return {
        "asset": row,
        # certificate metadata if collected — never assumed to relate without a record
        "certificates": [],
        "evidence": [{
            "evidence_id": str(e.evidence_id),
            "asset_id": str(e.asset_id),
            "observation_method": "scanner evidence record",
        } for e in evidence_rows],
        "associated_assets": [{
            "type": "software", "ref": asset.file_path,
            "note": "location as recorded; component join is claimed only where the inventory resolved it",
        }],
        "history": history,
        "techbom_links": [],
        "pqc": {
            "family": row["pqc_family"],
            "migration_relevance": ("this algorithm family is in scope for post-quantum migration"
                                    if row["pqc_family"] == "MIGRATION_RELEVANT" else
                                    "algorithm family classified; migration state is tracked separately"),
        },
    }


@router.get("/algorithms", response_model=AlgorithmIntelligence)
def cbom_workspace_algorithms(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    assets = db.execute(select(CryptoAsset)).scalars().all()
    runtime = _runtime_by_asset(db)
    conflicts = _conflict_locations(db)
    by_algo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in assets:
        by_algo[str(a.algorithm or "UNKNOWN")].append(_asset_row(a, runtime, conflicts))
    rows = []
    for name in sorted(by_algo):
        items = by_algo[name]
        rows.append({
            "algorithm": name,
            "assets": len(items),
            "operations": dict(Counter(str(i["operation"] or "UNKNOWN") for i in items)),
            "key_sizes": sorted({int(i["key_metadata"]["size"]) for i in items if i["key_metadata"]["size"]}),
            "usage_states": dict(Counter(i["usage"]["usage_state"] for i in items)),
            "pqc_family": _pqc_family(name),
            "evidence_status": dict(Counter(i["evidence_status"] for i in items)),
        })
    return {"state": "OBSERVED" if rows else "NO_RECORDS", "rows": rows}


@router.get("/libraries", response_model=LibraryInventory)
def cbom_workspace_libraries(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    assets = db.execute(select(CryptoAsset)).scalars().all()
    seen: dict[str, dict[str, Any]] = {}
    for a in assets:
        for lib in (a.libraries or []):
            if not lib:
                continue
            entry = seen.setdefault(str(lib), {"algorithms": set(), "n": 0})
            entry["algorithms"].add(str(a.algorithm or ""))
            entry["n"] += 1
    rows = []
    for name in sorted(seen):
        entry = seen[name]
        # a LIBRARY capability is at most capability_detected; the asset rows carry
        # the code-level configuration state, the library row never upgrades it
        rows.append({
            "name": name,
            "kind": "implementation",
            "algorithms": sorted(x for x in entry["algorithms"] if x),
            "usage_state": "capability_detected",
            "basis": "library capability; use is claimed on the asset rows with their own evidence",
            "crypto_bearing_components": entry["n"],
        })
    return {"state": "OBSERVED" if rows else "NO_RECORDS", "rows": rows}


@router.get("/certificates", response_model=CertificateInventory)
def cbom_workspace_certificates(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    certs = db.execute(select(Certificate).order_by(Certificate.not_after.desc()).limit(500)).scalars().all()
    rows = [{
        "fingerprint_sha256": c.fingerprint_sha256,
        "subject": c.subject,
        "issuer": c.issuer,
        "serial_number": c.serial_number,
        "public_key_algorithm": c.public_key_algorithm,
        "public_key_size": c.public_key_size,
        "not_before": _iso(c.not_before),
        "not_after": _iso(c.not_after),
        "expiry_status": c.expiry_status,
        "days_until_expiry": c.days_until_expiry,
        "revocation_status": c.revocation_status,
        "renewal_status": c.renewal_status,
        "is_self_signed": bool(c.is_self_signed),
        "san_count": len(c.san or []),
        "pqc_family": _pqc_family(str(c.public_key_algorithm or "")),
        "freshness": _freshness(c.revocation_checked_at or c.not_after),
    } for c in certs]
    return {"state": "OBSERVED" if rows else "NO_CERTIFICATES", "total": len(rows), "rows": rows}


@router.get("/keys", response_model=KeyInventory)
def cbom_workspace_keys(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    assets = db.execute(select(CryptoAsset)).scalars().all()
    rows = [{
        "location": f"{a.file_path}:{a.line_number}" if a.line_number else a.file_path,
        "algorithm": a.algorithm,
        "size": a.key_size,
        "mode": a.mode,
        "named_reference": "PRESENT" if a.asset_key else None,
        "hardcoded_material_flag": bool(a.is_hardcoded_key),
    } for a in assets if a.key_size or a.asset_key or a.is_hardcoded_key]
    return {"state": "OBSERVED" if rows else "NO_KEY_METADATA",
            "total": len(rows),
            "hardcoded_flagged": sum(1 for r in rows if r["hardcoded_material_flag"]),
            "rows": rows[:500]}


@router.get("/operations", response_model=OperationInventory)
def cbom_workspace_operations(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    assets = db.execute(select(CryptoAsset)).scalars().all()
    facts = db.execute(select(CryptographicFact)).scalars().all()
    runtime = _runtime_by_asset(db)
    static_ops = Counter(str(a.purpose or "UNKNOWN") for a in assets)
    observed = Counter()
    for f in facts:
        linked = runtime.get((f.tenant_id, f"fact:{f.id}"), set())
        if str(f.algorithm or "").upper() in linked:
            observed[str(f.purpose or "UNKNOWN")] += int(f.observation_count or 0)
    rows = []
    for op in sorted(set(static_ops) | set(observed)):
        if observed.get(op):
            state, basis = ("operation_observed",
                            "runtime observations recorded operations naming this purpose")
        elif static_ops.get(op):
            state, basis = "configuration_observed", \
                "code references this purpose; no operation attributed to it"
        else:
            state, basis = "unknown", "records do not say"
        rows.append({"operation": op, "static_references": static_ops.get(op, 0),
                     "observed_operations": observed.get(op, 0),
                     "usage_state": state, "basis": basis})
    return {"state": "OBSERVED" if rows else "NO_RECORDS", "rows": rows}


@router.get("/protocols", response_model=ProtocolInventory)
def cbom_workspace_protocols(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows_db = db.execute(select(RuntimeFinding).order_by(
        RuntimeFinding.last_seen_at.desc()).limit(500)).scalars().all()
    rows = []
    for r in rows_db:
        algo = str(r.algorithm or "")
        proto = ("TLS" if (r.tls_version or "").startswith("TLS")
                 else "SSH" if "SSH" in algo.upper() or "ssh" in str(r.extra or {}).lower()
                 else "IPsec" if "IKE" in algo.upper() or "ipsec" in str(r.extra or {}).lower()
                 else "other")
        rows.append({
            "protocol": proto,
            "tls_version": r.tls_version,
            "cipher_suite": r.cipher_suite,
            "algorithm": r.algorithm,
            "key_size": r.key_size,
            "hostname": r.hostname,
            "observation_count": r.observation_count,
            "weak_tls": bool(r.weak_tls),
            "registry_status": r.status,
            "quantum_impact": r.quantum_impact,
            "last_seen": _iso(r.last_seen_at),
            "freshness": _freshness(r.last_seen_at),
        })
    return {"state": "OBSERVED" if rows else "NO_PROTOCOL_OBSERVATIONS",
            "total": len(rows), "rows": rows}


@router.get("/pqc", response_model=PqcReadiness)
def cbom_workspace_pqc(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    assets = db.execute(select(CryptoAsset)).scalars().all()
    certs = db.execute(select(Certificate)).scalars().all()
    waves = db.execute(select(PqcMigrationWave)).scalars().all()
    families = Counter(_pqc_family(str(a.algorithm or "")) for a in assets)
    cert_families = Counter(_pqc_family(str(c.public_key_algorithm or "")) for c in certs)
    return {
        "state": "OBSERVED" if assets or certs else "NO_RECORDS",
        "by_family": dict(families),
        "certificate_keys": dict(cert_families),
        "migration_waves": [{
            "wave_key": w.wave_key, "title": w.title, "status": w.status,
            "planned_window": w.planned_window,
        } for w in waves],
    }


@router.get("/dependencies", response_model=DependencyInventory)
def cbom_workspace_dependencies(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    assets = db.execute(select(CryptoAsset)).scalars().all()
    edges = []
    roots = set()
    for a in assets:
        src = f"crypto:{a.algorithm or 'UNKNOWN'}"
        roots.add(src)
        for lib in (a.libraries or []):
            if lib:
                edges.append({"source": src, "target": f"library:{lib}", "type": "implemented_by"})
    named = roots | {e["target"] for e in edges}
    children = {e["target"] for e in edges}
    return {"state": "OBSERVED" if edges else "NO_RECORDS",
            "edges": edges[:1000],
            "roots": sorted(named - children),
            "unresolved": sum(1 for a in assets if not (a.libraries or []))}


@router.get("/evidence", response_model=EvidenceInventory)
def cbom_workspace_evidence(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    facts = db.execute(select(CryptographicFact)).scalars().all()
    runtime = _runtime_by_asset(db)
    rows = []
    for f in facts:
        scanners = [str(s) for s in (f.scanners or []) if s]
        linked = runtime.get((f.tenant_id, f"fact:{f.id}"), set())
        status, basis = _evidence_status(
            runtime_seen=str(f.algorithm or "").upper() in linked,
            scanner_bounded=bool(scanners),
            conflicts=False,
            observation_count=int(f.observation_count or 0),
        )
        rows.append({
            "asset_id": str(f.id),
            "algorithm": f.algorithm,
            "observation_method": ", ".join(sorted(set(scanners))) or "NOT_COLLECTED",
            "observation_count": int(f.observation_count or 0),
            "scanners": sorted(set(scanners)),
            "evidence_status": status,
            "evidence_basis": basis,
            "first_seen": _iso(f.first_seen),
            "last_seen": _iso(f.last_seen),
            "freshness": _freshness(f.last_seen),
        })
    rows.sort(key=lambda r: str(r["last_seen"] or ""), reverse=True)
    return {"state": "OBSERVED" if rows else "NO_EVIDENCE_RECORDS",
            "total": len(rows), "rows": rows[:500]}


@router.get("/history", response_model=HistoryInventory)
def cbom_workspace_history(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    facts = db.execute(select(CryptographicFact).order_by(
        CryptographicFact.last_seen.desc()).limit(500)).scalars().all()
    rows = [{
        "algorithm": f.algorithm,
        "location": f.file_path,
        "first_seen": _iso(f.first_seen),
        "last_seen": _iso(f.last_seen),
        "observation_count": int(f.observation_count or 0),
        "freshness": _freshness(f.last_seen),
    } for f in facts]
    return {"state": "OBSERVED" if rows else "NO_HISTORY", "rows": rows}


@router.get("/export", response_model=ExportInventory)
def cbom_workspace_export(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {
        "formats": [
            {"format": "CycloneDX 1.5", "validator": "cbom.cyclonedx15", "state": "AVAILABLE"},
            {"format": "CycloneDX 1.6", "validator": "cbom.cyclonedx16", "state": "AVAILABLE"},
        ],
        "signed_variants": ["JWS"],
        "export_path": "/api/v1/cbom/scan/{scan_id}/snapshot",
    }
