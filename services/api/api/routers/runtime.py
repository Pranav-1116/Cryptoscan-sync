"""Ingest runtime (eBPF / mesh) crypto findings without requiring a kernel agent."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from api.dependencies import get_current_user, get_db_session
from sqlalchemy.orm import Session

router = APIRouter(tags=["runtime"])


class RuntimeFinding(BaseModel):
    process_name: str | None = None
    pid: int | None = None
    hostname: str | None = None
    function: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    algorithm: str | None = None
    key_size: int | None = None
    observation_count: int = 1
    extra: dict[str, Any] = Field(default_factory=dict)


class RuntimeFindingsBody(BaseModel):
    scanner_id: str = "ebpf-runtime-agent-v1.0"
    findings: list[RuntimeFinding] = Field(default_factory=list)


def to_evidence(item: RuntimeFinding, scanner_id: str) -> dict[str, Any]:
    algo = item.algorithm or item.tls_version or item.cipher_suite or "TLS"
    return {
        "scanner_id": scanner_id,
        "algorithm": algo,
        "purpose": "NETWORK_ENCRYPTION",
        "file_path": f"runtime://{item.hostname or 'host'}/{item.process_name or 'process'}",
        "line_number": 0,
        "source": {
            "type": "RUNTIME_PROCESS",
            "file_path": item.process_name or "process",
            "line_number": 0,
            "language": "RUNTIME",
        },
        "crypto": {
            "tls_version": item.tls_version,
            "cipher_suite": item.cipher_suite,
            "algorithm": algo,
            "purpose": "NETWORK_ENCRYPTION",
        },
        "metadata": {
            "confidence": "VERIFIED",
            "scan_method": "RUNTIME",
            "pid": item.pid,
            "function": item.function,
            "observation_count": item.observation_count,
            **item.extra,
        },
    }


WEAK_TLS_VERSIONS = {"SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLS1.0", "TLSV1.1", "TLS1.1"}


def _verdict_rows(body: RuntimeFindingsBody) -> list[dict[str, Any]]:
    """RuntimeFindings -> registry-verdict rows ready to persist."""
    from shared_models.algorithm_registry import parse_algorithm

    rows: list[dict[str, Any]] = []
    for item in body.findings:
        extra = dict(item.extra or {})
        kind = "tls-library-risk" if extra.get("kind") == "tls-library-risk" else "session"
        suite = item.cipher_suite
        version = (item.tls_version or "").upper()
        if kind == "session":
            info = parse_algorithm(str(suite or "TLS"))
            status = extra.get("suite_status") or info.status
            algorithm = info.canonical
            bulk = next((c for c in info.components if c.get("role") == "bulk_cipher"), None)
            if bulk and bulk.get("algorithm"):
                algorithm = bulk["algorithm"]
            key_size = info.key_size
            quantum = info.quantum_impact
        else:
            status = extra.get("library_status") or "UNKNOWN"
            key_size = None
            algorithm = "TLS"
            quantum = None
        rows.append(
            {
                "scanner_id": body.scanner_id,
                "kind": kind,
                "hostname": item.hostname,
                "process_name": item.process_name,
                "pid": item.pid,
                "tls_version": item.tls_version,
                "cipher_suite": suite,
                "algorithm": algorithm,
                "key_size": item.key_size if item.key_size is not None else key_size,
                "status": str(status),
                "quantum_impact": quantum,
                "weak_tls": version in WEAK_TLS_VERSIONS or str(status) in {"DISALLOWED", "DEPRECATED"},
                "observation_count": max(1, int(item.observation_count or 1)),
                "extra": extra,
            }
        )
    return rows


@router.post("/scans/runtime-findings")
def ingest_runtime_findings(
    body: RuntimeFindingsBody,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    rows = _verdict_rows(body)
    from db.repositories.runtime_finding_repository import RuntimeFindingRepository

    stored = RuntimeFindingRepository(db).upsert_many(rows)
    db.commit()
    accepted = [to_evidence(item, body.scanner_id) for item in body.findings]
    weak = [row for row in rows if row["weak_tls"]]
    return {
        "accepted": len(rows),
        "persisted": stored,
        "anomalies": len(weak),
        "scanner_id": body.scanner_id,
        "findings": accepted,
    }


@router.get("/scans/runtime-findings")
def list_runtime_findings(
    limit: int = 100,
    kind: str | None = None,
    weak_only: bool = False,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    """Recent runtime observations + aggregates (weak suites, risky libs)."""
    from db.repositories.runtime_finding_repository import RuntimeFindingRepository

    repo = RuntimeFindingRepository(db)
    rows = repo.list_recent(limit=limit, kind=kind, weak_only=weak_only)
    return {
        "summary": repo.summary(),
        "total_count": len(rows),
        "findings": [row.to_dict() for row in rows],
    }
