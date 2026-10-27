"""Runtime collector — sessions + process scan -> platform findings.

Converts observed TLS sessions (tap, s_client imports) and process-level
library findings into the RuntimeFinding shape consumed by
``POST /api/v1/scans/runtime-findings``, with algorithm-registry verdicts
attached (key sizes, DISALLOWED suites, quantum impact).
"""

from __future__ import annotations

from typing import Any

from shared_models.algorithm_registry import parse_algorithm

WEAK_TLS_VERSIONS = {"SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1", "SSLv2"}
WEAK_SUITE_STATUSES = {"DISALLOWED", "DEPRECATED"}


def sessions_to_findings(sessions: list[dict[str, Any]], *, scanner_id: str = "tls-tap-agent-v1.0") -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for session in sessions:
        negotiated = session.get("negotiated") or {}
        suite = negotiated.get("cipher_suite")
        version = negotiated.get("negotiated_version")
        if not suite and not session.get("error"):
            continue  # incomplete handshake, nothing to report
        info = parse_algorithm(str(suite or "TLS"))
        # for cipher suites the headline algorithm is the bulk cipher
        algorithm = info.canonical
        if info.components:
            bulk = next((c for c in info.components if c.get("role") == "bulk_cipher"), None)
            if bulk:
                algorithm = bulk.get("algorithm") or algorithm
        cert_chain = (session.get("certificate") or {}).get("chain") or []
        leaf = cert_chain[0] if cert_chain else {}
        weak_version = str(version or "") in WEAK_TLS_VERSIONS
        findings.append(
            {
                "process_name": "tls-tap",
                "hostname": session.get("sni") or session.get("upstream") or "unknown",
                "tls_version": version,
                "cipher_suite": suite,
                "algorithm": algorithm,
                "key_size": info.key_size,
                "observation_count": 1,
                "extra": {
                    "source": scanner_id,
                    "suite_status": info.status,
                    "quantum_impact": info.quantum_impact,
                    "weak_tls_version": weak_version,
                    "alpn": session.get("alpn"),
                    "cert_sha256": leaf.get("sha256_fingerprint"),
                    "cert_common_names": leaf.get("common_names") or [],
                    "client": session.get("client"),
                    "offered_suites": (session.get("offered_suites") or [])[:40],
                    "error": session.get("error"),
                },
            }
        )
    return merge_observations(findings)


def processes_to_findings(process_scan: dict[str, Any]) -> list[dict[str, Any]]:
    """Library-risk findings from a process scan -> runtime findings."""
    findings: list[dict[str, Any]] = []
    for row in process_scan.get("findings") or []:
        findings.append(
            {
                "process_name": row.get("process_name") or "process",
                "pid": row.get("pid"),
                "hostname": process_scan.get("host"),
                "algorithm": "TLS",
                "observation_count": 1,
                "extra": {
                    "source": "process-discovery-v1.0",
                    "kind": "tls-library-risk",
                    "library": row.get("library"),
                    "library_version": row.get("version"),
                    "library_status": row.get("status"),
                    "library_notes": row.get("notes"),
                    "library_name": row.get("library_name"),
                    "listening_ports": row.get("listening_ports") or [],
                    "containerized": row.get("containerized"),
                },
            }
        )
    return findings


def merge_observations(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse repeated identical observations into counts."""
    merged: dict[tuple, dict[str, Any]] = {}
    for finding in findings:
        key = (
            finding.get("hostname"),
            finding.get("tls_version"),
            finding.get("cipher_suite"),
            finding.get("pid"),
            (finding.get("extra") or {}).get("library"),
            (finding.get("extra") or {}).get("library_version"),
        )
        if key in merged:
            merged[key]["observation_count"] = merged[key].get("observation_count", 1) + 1
        else:
            merged[key] = finding
    return list(merged.values())


def collect(*, sessions: list[dict[str, Any]] | None = None, process_scan: dict[str, Any] | None = None, scanner_id: str = "runtime-agent-v1.0") -> dict[str, Any]:
    """Aggregate everything into a submit payload for the platform API."""
    session_findings = sessions_to_findings(sessions or [], scanner_id=scanner_id)
    process_findings = processes_to_findings(process_scan or {})

    weak_suites = [f for f in session_findings if (f.get("extra") or {}).get("suite_status") in WEAK_SUITE_STATUSES]
    weak_versions = [f for f in session_findings if (f.get("extra") or {}).get("weak_tls_version")]
    return {
        "scanner_id": scanner_id,
        "findings": session_findings + process_findings,
        "summary": {
            "sessions": len(sessions or []),
            "session_findings": len(session_findings),
            "process_findings": len(process_findings),
            "weak_cipher_suites": len(weak_suites),
            "weak_tls_versions": len(weak_versions),
            "risky_libraries": len(process_findings),
        },
    }
