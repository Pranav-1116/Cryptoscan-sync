"""NBOM workspace — Network Bill of Materials (docs/boms/01_PRODUCT_SPEC.md §4).

Network endpoints, protocols, connections and network cryptographic
configuration. Every section reads stored network scan probes through the
one probe→endpoint contract (``cbom.nbom.probe_to_endpoint``); an empty
section is an honest empty state, never a fabricated network inventory.

Working rule from the spec governs this surface and is not narrated on
screen: a port scan or endpoint inventory alone does not prove the
negotiated cryptographic configuration. Negotiated TLS version and cipher
suite are rendered only where a handshake was actually observed
(``observed`` True from an OK/TLS_OK probe, or a runtime session record);
everywhere else the state is ``unknown`` — never "none", never "plaintext",
never a healthy default.
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
from cbom.nbom import probe_to_endpoint
from db.models.certificate import Certificate
from db.models.network_scan_run import NetworkScanRun
from db.models.runtime_finding import RuntimeFinding

router = APIRouter(prefix="/nbom/workspace")

UNKNOWN = "unknown"


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


def _endpoint_history(db: Session) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Newest run wins per endpoint; first/last seen come from the run rows.

    Returns the endpoint rows (one per endpoint) plus a history map of
    every run that recorded each endpoint — observation history, never a
    guessed timeline.
    """
    runs = db.execute(select(NetworkScanRun).order_by(
        NetworkScanRun.created_at.desc(), NetworkScanRun.id)).scalars().all()
    endpoints: dict[str, dict[str, Any]] = {}
    history: dict[str, dict[str, Any]] = defaultdict(lambda: {"first_seen": None, "last_seen": None, "runs": 0})
    for run in runs:
        for probe in ((run.result or {}).get("probes") or []):
            raw = str(probe.get("endpoint") or "").strip()
            if not raw:
                continue
            entry = history[raw]
            entry["runs"] += 1
            at = _iso(run.created_at)
            if at:
                entry["last_seen"] = max(entry["last_seen"] or "", at) or at
                entry["first_seen"] = entry["first_seen"] or at
            if raw not in endpoints:
                mapped = probe_to_endpoint(probe)
                if not mapped:
                    continue
                mapped["endpoint"] = raw
                mapped["scan_run_id"] = run.id
                mapped["recorded_at"] = at
                mapped["status"] = str(probe.get("status") or "").strip().upper()
                endpoints[raw] = mapped
    rows = list(endpoints.values())
    for row in rows:
        entry = history.get(row["endpoint"], {})
        row["first_observed"] = entry.get("first_seen")
        row["last_observed"] = entry.get("last_seen") or row.get("recorded_at")
    return rows, {k: dict(v) for k, v in history.items()}


def _negotiated(row: dict[str, Any]) -> dict[str, Any]:
    """The working rule: negotiated crypto only where a handshake was observed."""
    if row.get("observed") and (row.get("tls_version") or row.get("cipher_suite")):
        return {"state": "OBSERVED",
                "tls_version": row.get("tls_version"),
                "cipher_suite": row.get("cipher_suite"),
                "basis": "a successful handshake was recorded by the collector"}
    return {"state": UNKNOWN,
            "tls_version": UNKNOWN,
            "cipher_suite": UNKNOWN,
            "basis": ("no successful handshake recorded — a port scan or endpoint "
                      "inventory alone does not prove the negotiated cryptographic "
                      "configuration")}


def _endpoint_row(row: dict[str, Any]) -> dict[str, Any]:
    cert = row.get("certificate") or {}
    negotiated = _negotiated(row)
    return {
        "endpoint": row["endpoint"],
        "host": row.get("host"),
        "port": row.get("port"),
        "protocol": row.get("protocol"),
        "service": row.get("service"),
        "tls_version": negotiated["tls_version"],
        "cipher_suite": negotiated["cipher_suite"],
        "negotiation": {"state": negotiated["state"], "basis": negotiated["basis"]},
        "certificate": ({
            "subject": cert.get("subject"),
            "fingerprint_sha256": cert.get("fingerprint_sha256"),
            "issuer": cert.get("issuer"),
            "public_key_algorithm": cert.get("public_key_algorithm"),
            "public_key_size": cert.get("public_key_size"),
            "expiry_status": cert.get("expiry_status"),
        } if cert.get("fingerprint_sha256") or cert.get("subject") else None),
        "source": "network-scanner",
        "scan_run_id": row.get("scan_run_id"),
        "first_observed": row.get("first_observed"),
        "last_observed": row.get("last_observed"),
        "freshness": _freshness(row.get("last_observed")),
    }


# ── response contracts (the untyped ratchet only goes down) ───────────


class Negotiation(BaseModel):
    state: str
    basis: str


class CertRef(BaseModel):
    subject: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    issuer: Optional[str] = None
    public_key_algorithm: Optional[str] = None
    public_key_size: Optional[int] = None
    expiry_status: Optional[str] = None


class EndpointRow(BaseModel):
    endpoint: str
    host: Optional[str] = None
    port: Optional[Any] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    tls_version: str
    cipher_suite: str
    negotiation: Negotiation
    certificate: Optional[CertRef] = None
    source: str = "network-scanner"
    scan_run_id: Optional[str] = None
    first_observed: Optional[str] = None
    last_observed: Optional[str] = None
    freshness: str


class EndpointInventory(BaseModel):
    state: str
    total: int
    rows: List[EndpointRow]


class EndpointDetail(BaseModel):
    endpoint: EndpointRow
    observations: List[Dict[str, Any]] = []
    dependencies: List[Dict[str, Any]] = []
    certificate_detail: Optional[Dict[str, Any]] = None
    related: Dict[str, Any] = {}
    evidence: Dict[str, Any] = {}


class Overview(BaseModel):
    state: str
    endpoints: int = 0
    observed_handshakes: int = 0
    negotiation_unknown: int = 0
    protocols: Dict[str, int] = {}
    certificates: int = 0
    scan_runs: int = 0
    read: Dict[str, Any] = {}


class HostRow(BaseModel):
    host: str
    endpoints: int
    ports: List[Any] = []
    protocols: Dict[str, int] = {}
    observed: int = 0
    unknown_negotiation: int = 0
    last_observed: Optional[str] = None
    freshness: str


class HostInventory(BaseModel):
    state: str
    total: int
    rows: List[HostRow]


class ServiceRow(BaseModel):
    endpoint: str
    host: Optional[str] = None
    port: Optional[Any] = None
    service: Optional[str] = None
    protocol: Optional[str] = None
    negotiation_state: str
    last_observed: Optional[str] = None


class ServiceInventory(BaseModel):
    state: str
    total: int
    rows: List[ServiceRow]


class ProtocolRow(BaseModel):
    endpoint: str
    host: Optional[str] = None
    port: Optional[Any] = None
    tls_version: str
    cipher_suite: str
    negotiation: Negotiation
    status: Optional[str] = None
    last_observed: Optional[str] = None


class ProtocolInventory(BaseModel):
    state: str
    total: int
    observed: int
    unknown: int
    rows: List[ProtocolRow]


class CertificateExposure(BaseModel):
    state: str
    total: int
    rows: List[Dict[str, Any]]


class DependencyEdge(BaseModel):
    source: str
    target: str
    type: str


class DependencyInventory(BaseModel):
    state: str
    edges: List[DependencyEdge]
    roots: List[str]


class ChangeRow(BaseModel):
    endpoint: str
    scan_run_id: Optional[str] = None
    recorded_at: Optional[str] = None
    runs: int = 0


class ChangeInventory(BaseModel):
    state: str
    total: int
    rows: List[ChangeRow]


class EvidenceRow(BaseModel):
    endpoint: str
    source: str
    method: str
    status: Optional[str] = None
    last_observed: Optional[str] = None
    freshness: str


class EvidenceInventory(BaseModel):
    state: str
    total: int
    rows: List[EvidenceRow]


class HistoryRow(BaseModel):
    scan_run_id: str
    target_kind: Optional[str] = None
    verdict: Optional[str] = None
    probed: Optional[int] = None
    ok: Optional[int] = None
    created_at: Optional[str] = None


class HistoryInventory(BaseModel):
    state: str
    total: int
    rows: List[HistoryRow]


class ExportFormat(BaseModel):
    format: str
    validator: str
    state: str


class ExportInventory(BaseModel):
    formats: List[ExportFormat]
    export_path: str
    note: str = ("the NBOM exports as the scanner recorded it — endpoints the "
                 "collector could not establish stay unknown in the document too")


# ── operations ────────────────────────────────────────────────────────


@router.get("/overview", response_model=Overview)
def nbom_workspace_overview(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows, _ = _endpoint_history(db)
    mapped = [_endpoint_row(r) for r in rows]
    runs = db.execute(select(NetworkScanRun)).scalars().all()
    return {
        "state": "OBSERVED" if mapped else "NO_RECORDS",
        "endpoints": len(mapped),
        "observed_handshakes": sum(1 for r in mapped if r["negotiation"]["state"] == "OBSERVED"),
        "negotiation_unknown": sum(1 for r in mapped if r["negotiation"]["state"] == UNKNOWN),
        "protocols": dict(Counter(str(r["protocol"] or "UNKNOWN") for r in mapped)),
        "certificates": sum(1 for r in mapped if r["certificate"]),
        "scan_runs": len(runs),
        "read": {
            "probe_rows": sum(len(((run.result or {}).get("probes") or [])) for run in runs),
            "runtime_sessions": len(db.execute(select(RuntimeFinding)).scalars().all()),
        },
    }


@router.get("/endpoints", response_model=EndpointInventory)
def nbom_workspace_endpoints(
    q: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    negotiation: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    user: str = Depends(get_current_user), db: Session = Depends(get_db_session),
):
    rows, _ = _endpoint_history(db)
    out = [_endpoint_row(r) for r in rows]
    if q:
        needle = q.lower()
        out = [r for r in out if needle in str(r["endpoint"]).lower()
               or needle in str(r["service"] or "").lower()]
    if protocol:
        out = [r for r in out if str(r["protocol"] or "").lower() == protocol.lower()]
    if negotiation:
        out = [r for r in out if r["negotiation"]["state"] == negotiation.upper()]
    out.sort(key=lambda r: str(r["endpoint"]))
    return {"state": "OBSERVED" if out else ("EMPTY" if not rows else "FILTERED_EMPTY"),
            "total": len(out), "rows": out[:limit]}


@router.get("/endpoints/{endpoint:path}", response_model=EndpointDetail)
def nbom_workspace_endpoint_detail(
    endpoint: str,
    user: str = Depends(get_current_user), db: Session = Depends(get_db_session),
):
    rows, history = _endpoint_history(db)
    match = next((r for r in rows if r["endpoint"] == endpoint), None)
    if match is None:
        raise HTTPException(status_code=404, detail="endpoint not in the stored inventory")
    row = _endpoint_row(match)
    sessions = db.execute(select(RuntimeFinding).where(
        RuntimeFinding.kind == "session").order_by(
        RuntimeFinding.last_seen_at.desc()).limit(50)).scalars().all()
    host = match.get("host") or ""
    related_sessions = [s for s in sessions if host and host in str(s.hostname or "")]
    cert_detail = None
    cert = match.get("certificate") or {}
    fingerprint = cert.get("fingerprint_sha256")
    if fingerprint:
        stored = db.execute(select(Certificate).where(
            Certificate.fingerprint_sha256 == fingerprint)).scalars().first()
        if stored is not None:
            cert_detail = {
                "subject": stored.subject, "issuer": stored.issuer,
                "public_key_algorithm": stored.public_key_algorithm,
                "public_key_size": stored.public_key_size,
                "not_before": _iso(stored.not_before), "not_after": _iso(stored.not_after),
                "expiry_status": stored.expiry_status,
                "revocation_status": stored.revocation_status,
                "san_count": len(stored.san or []),
            }
    return {
        "endpoint": row,
        "observations": [{
            "kind": "runtime-session",
            "tls_version": s.tls_version,
            "cipher_suite": s.cipher_suite,
            "algorithm": s.algorithm,
            "last_seen": _iso(s.last_seen_at),
            "observation_count": s.observation_count,
        } for s in related_sessions],
        "dependencies": [{
            "type": "served_by", "target": f"certificate:{fingerprint}"
        }] if fingerprint else [],
        "certificate_detail": cert_detail,
        "related": {"cbom": [], "techbom": [],
                    "_note": "no stored cross-BOM link rows name this endpoint"},
        "evidence": {
            "source": "network-scanner",
            "method": "active probe (handshake attempted; only OK/TLS_OK counts as observed)",
            "scan_run_id": match.get("scan_run_id"),
            "first_observed": row["first_observed"],
            "last_observed": row["last_observed"],
            "runs": history.get(endpoint, {}).get("runs", 0),
        },
    }


@router.get("/assets", response_model=HostInventory)
def nbom_workspace_assets(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows, _ = _endpoint_history(db)
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_host[str(r.get("host") or "UNKNOWN")].append(_endpoint_row(r))
    out = []
    for host in sorted(by_host):
        items = by_host[host]
        out.append({
            "host": host,
            "endpoints": len(items),
            "ports": [i["port"] for i in items],
            "protocols": dict(Counter(str(i["protocol"] or "UNKNOWN") for i in items)),
            "observed": sum(1 for i in items if i["negotiation"]["state"] == "OBSERVED"),
            "unknown_negotiation": sum(1 for i in items if i["negotiation"]["state"] == UNKNOWN),
            "last_observed": max((str(i["last_observed"] or "") for i in items), default="") or None,
            "freshness": _freshness(max((str(i["last_observed"] or "") for i in items), default="") or None),
        })
    return {"state": "OBSERVED" if out else "NO_HOSTS", "total": len(out), "rows": out}


@router.get("/services", response_model=ServiceInventory)
def nbom_workspace_services(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows, _ = _endpoint_history(db)
    out = [{
        "endpoint": r["endpoint"],
        "host": r["host"],
        "port": r["port"],
        "service": r["service"],
        "protocol": r["protocol"],
        "negotiation_state": r["negotiation"]["state"],
        "last_observed": r["last_observed"],
    } for r in sorted(rows, key=lambda r: str(r["endpoint"]))]
    return {"state": "OBSERVED" if out else "NO_SERVICES", "total": len(out), "rows": out[:500]}


def _protocol_rows(rows: list[dict[str, Any]], needle: str) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        proto = str(r.get("protocol") or "").lower()
        if needle not in proto:
            continue
        mapped = _endpoint_row(r)
        out.append({
            "endpoint": mapped["endpoint"],
            "host": mapped["host"],
            "port": mapped["port"],
            "tls_version": mapped["tls_version"],
            "cipher_suite": mapped["cipher_suite"],
            "negotiation": mapped["negotiation"],
            "status": r.get("status"),
            "last_observed": mapped["last_observed"],
        })
    return out


@router.get("/tls", response_model=ProtocolInventory)
def nbom_workspace_tls(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows, _ = _endpoint_history(db)
    # TLS is the default protocol mapping; include explicit starttls forms too
    out = []
    for r in rows:
        proto = str(r.get("protocol") or "").lower()
        if "tls" in proto or proto in {"https", "smtp", "imap", "pop3", "ldap", "ftp"}:
            out.extend(_protocol_rows([r], proto or "tls"))
    observed = sum(1 for r in out if r["negotiation"]["state"] == "OBSERVED")
    return {"state": "OBSERVED" if out else "NO_TLS_OBSERVATIONS",
            "total": len(out), "observed": observed, "unknown": len(out) - observed,
            "rows": out[:500]}


@router.get("/ssh", response_model=ProtocolInventory)
def nbom_workspace_ssh(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows, _ = _endpoint_history(db)
    out = _protocol_rows(rows, "ssh")
    observed = sum(1 for r in out if r["negotiation"]["state"] == "OBSERVED")
    return {"state": "OBSERVED" if out else "NO_SSH_OBSERVATIONS",
            "total": len(out), "observed": observed, "unknown": len(out) - observed,
            "rows": out[:500]}


@router.get("/ipsec", response_model=ProtocolInventory)
def nbom_workspace_ipsec(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows, _ = _endpoint_history(db)
    out = [r for r in _protocol_rows(rows, "ipsec") + _protocol_rows(rows, "ike")
           + _protocol_rows(rows, "vpn")]
    observed = sum(1 for r in out if r["negotiation"]["state"] == "OBSERVED")
    return {"state": "OBSERVED" if out else "NO_IPSEC_OBSERVATIONS",
            "total": len(out), "observed": observed, "unknown": len(out) - observed,
            "rows": out[:500]}


@router.get("/certificates", response_model=CertificateExposure)
def nbom_workspace_certificates(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows, _ = _endpoint_history(db)
    out = []
    for r in rows:
        cert = r.get("certificate")
        if not cert:
            continue
        stored = None
        fingerprint = cert.get("fingerprint_sha256")
        if fingerprint:
            stored = db.execute(select(Certificate).where(
                Certificate.fingerprint_sha256 == fingerprint)).scalars().first()
        out.append({
            "endpoint": r["endpoint"],
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "fingerprint_sha256": fingerprint,
            "public_key_algorithm": cert.get("public_key_algorithm"),
            "public_key_size": cert.get("public_key_size"),
            "expiry_status": cert.get("expiry_status") or (stored.expiry_status if stored else None),
            "in_store": stored is not None,
            "last_observed": r.get("last_observed"),
        })
    return {"state": "OBSERVED" if out else "NO_CERTIFICATES_EXPOSED",
            "total": len(out), "rows": out[:500]}


@router.get("/dependencies", response_model=DependencyInventory)
def nbom_workspace_dependencies(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows, _ = _endpoint_history(db)
    edges = []
    roots = set()
    for r in rows:
        endpoint = r["endpoint"]
        roots.add(endpoint)
        host = r.get("host")
        if host:
            edges.append({"source": endpoint, "target": f"host:{host}", "type": "exposed_on"})
        cert = r.get("certificate") or {}
        if cert.get("fingerprint_sha256"):
            edges.append({"source": endpoint,
                          "target": f"certificate:{cert['fingerprint_sha256']}",
                          "type": "served_by"})
    children = {e["target"] for e in edges}
    named = roots | children
    return {"state": "OBSERVED" if edges else "NO_DEPENDENCIES",
            "edges": edges[:1000], "roots": sorted(named - children)}


@router.get("/changes", response_model=ChangeInventory)
def nbom_workspace_changes(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows, history = _endpoint_history(db)
    out = [{
        "endpoint": r["endpoint"],
        "scan_run_id": r.get("scan_run_id"),
        "recorded_at": r.get("recorded_at"),
        "runs": history.get(r["endpoint"], {}).get("runs", 0),
    } for r in sorted(rows, key=lambda r: str(r.get("recorded_at") or ""), reverse=True)]
    return {"state": "OBSERVED" if out else "NO_CHANGE_HISTORY",
            "total": len(out), "rows": out[:500]}


@router.get("/evidence", response_model=EvidenceInventory)
def nbom_workspace_evidence(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows, _ = _endpoint_history(db)
    out = [{
        "endpoint": r["endpoint"],
        "source": "network-scanner",
        "method": ("handshake observed" if r.get("observed")
                   else "probe recorded without a successful handshake"),
        "status": r.get("status"),
        "last_observed": r.get("last_observed"),
        "freshness": _freshness(r.get("last_observed")),
    } for r in rows]
    return {"state": "OBSERVED" if out else "NO_EVIDENCE_RECORDS",
            "total": len(out), "rows": out[:500]}


@router.get("/history", response_model=HistoryInventory)
def nbom_workspace_history(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    runs = db.execute(select(NetworkScanRun).order_by(
        NetworkScanRun.created_at.desc()).limit(100)).scalars().all()
    rows = [{
        "scan_run_id": str(r.id),
        "target_kind": r.target_kind,
        "verdict": r.verdict,
        "probed": r.probed,
        "ok": r.ok,
        "created_at": _iso(r.created_at),
    } for r in runs]
    return {"state": "OBSERVED" if rows else "NO_SCAN_HISTORY",
            "total": len(rows), "rows": rows}


@router.get("/export", response_model=ExportInventory)
def nbom_workspace_export(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {
        "formats": [
            {"format": "CycloneDX 1.5 NBOM", "validator": "cbom.nbom", "state": "AVAILABLE"},
        ],
        "export_path": "/api/v1/cbom/nbom",
    }
