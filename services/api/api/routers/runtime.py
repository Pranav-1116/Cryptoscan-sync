"""Ingest runtime (eBPF / mesh) crypto findings without requiring a kernel agent."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from api.dependencies import get_current_user

router = APIRouter(tags=["runtime"])


class RuntimeFinding(BaseModel):
    process_name: str | None = None
    pid: int | None = None
    hostname: str | None = None
    function: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    algorithm: str | None = None
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


@router.post("/scans/runtime-findings")
def ingest_runtime_findings(body: RuntimeFindingsBody, user: str = Depends(get_current_user)):
    accepted = [to_evidence(item, body.scanner_id) for item in body.findings]
    weak = [
        item
        for item in accepted
        if str((item.get("crypto") or {}).get("tls_version") or "").upper() in {"TLSV1", "TLSV1.0", "TLS1.0", "SSLV3"}
    ]
    return {
        "accepted": len(accepted),
        "anomalies": len(weak),
        "scanner_id": body.scanner_id,
        "findings": accepted,
    }
