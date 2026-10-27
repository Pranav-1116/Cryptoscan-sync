"""Normalize ORM evidence / drift rows into plain dicts."""

from __future__ import annotations

from typing import Any

from api.security.evidence_projection import project_finding


def evidence_to_dict(row: Any) -> dict[str, Any]:
    finding_data, redacted = project_finding(getattr(row, "finding_data", None))
    scanner_id = None
    if isinstance(finding_data, dict):
        scanner_id = finding_data.get("scanner_id") or (finding_data.get("metadata") or {}).get(
            "scanner_id"
        )
    return {
        "id": getattr(row, "id", None),
        "evidence_id": getattr(row, "id", None),
        "scan_id": getattr(row, "scan_id", None),
        "algorithm": getattr(row, "algorithm", None),
        "key_size": getattr(row, "key_size", None),
        "mode": getattr(row, "mode", None),
        "padding": getattr(row, "padding", None),
        "purpose": getattr(row, "purpose", None),
        "confidence": getattr(row, "confidence", None),
        "is_hardcoded_key": bool(getattr(row, "is_hardcoded_key", False)),
        "file_path": getattr(row, "file_path", None),
        "line_number": getattr(row, "line_number", None),
        "class_name": getattr(row, "class_name", None),
        "method_name": getattr(row, "method_name", None),
        "compliance_status": getattr(row, "compliance_status", None),
        "content_hash": getattr(row, "content_hash", None),
        "chain_hash": getattr(row, "chain_hash", None),
        "chain_position": getattr(row, "chain_position", None),
        "normalized_crypto": getattr(row, "normalized_crypto", None),
        "policy_evaluation": getattr(row, "policy_evaluation", None),
        "finding_data": finding_data,
        "redacted_projection": redacted,
        "scanner_id": scanner_id,
    }


def scan_to_dict(scan: Any) -> dict[str, Any]:
    return {
        "scan_id": getattr(scan, "id", None) or getattr(scan, "scan_id", None),
        "id": getattr(scan, "id", None),
        "status": getattr(scan, "status", None),
        "target_location": getattr(scan, "target_location", None),
        "target_type": getattr(scan, "target_type", None),
        "target_branch": getattr(scan, "target_branch", None),
        "target_commit": getattr(scan, "target_commit", None),
        "scanner_id": getattr(scan, "scanner_id", None),
        "scanner_version": getattr(scan, "scanner_version", None),
        "operator": getattr(scan, "operator", None),
        "manifest_hash": getattr(scan, "manifest_hash", None),
        "statistics": getattr(scan, "statistics", None),
    }


def drift_to_dict(event: Any) -> dict[str, Any]:
    details = getattr(event, "drift_details", None) or {}
    return {
        "drift_id": getattr(event, "id", None),
        "drift_type": getattr(event, "drift_type", None),
        "severity": getattr(event, "severity", None),
        "reason": details.get("reason") if isinstance(details, dict) else None,
        "algorithm": details.get("algorithm") if isinstance(details, dict) else None,
        "purpose": details.get("purpose") if isinstance(details, dict) else None,
        "file_path": details.get("file_path") if isinstance(details, dict) else None,
        "line_number": details.get("line_number") if isinstance(details, dict) else None,
        "drift_details": details,
        "resolution_status": getattr(event, "resolution_status", None),
    }


def is_material(finding: dict[str, Any]) -> bool:
    scanner = str(finding.get("scanner_id") or "")
    if scanner == "static-material-scanner":
        return True
    purpose = str(finding.get("purpose") or "").upper()
    path = str(finding.get("file_path") or "").lower()
    if purpose == "CERTIFICATE":
        return True
    return path.endswith((".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".key"))
