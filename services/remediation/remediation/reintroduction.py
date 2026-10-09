"""Reintroduction detection (audit 69 / GAP-023).

Pure logic — no database, no clock. Feed it the active retirements and one
scan's findings; it reports every retirement that the scan violates, with a
severity the alerting layer can route (Critical -> page, High -> alert,
Medium -> log). A retired algorithm reappearing is not a "new finding": it
is a broken promise, and it is labelled as one.
"""

from __future__ import annotations

from typing import Any, Iterable

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"

_SCOPES = ("FILE", "ASSET", "ALGORITHM")


def _norm(algorithm: Any) -> str:
    return str(algorithm or "").upper().replace("_", "-").strip()


def _severity(finding: dict[str, Any]) -> str:
    """Route the alert: hardcoded keys and policy failures page, warnings log."""
    if finding.get("is_hardcoded_key"):
        return CRITICAL
    status = str(finding.get("compliance_status") or "").upper()
    if status == "FAIL":
        return CRITICAL
    if status == "WARN":
        return HIGH
    # the algorithm is back but currently passes policy (e.g. config changed
    # elsewhere) — still a reintroduction of a retired primitive
    return MEDIUM


def _matches(retirement: dict[str, Any], finding: dict[str, Any]) -> bool:
    if _norm(finding.get("algorithm")) != _norm(retirement.get("algorithm")):
        return False
    scope = str(retirement.get("scope") or "FILE").upper()
    if scope == "FILE":
        return str(finding.get("file_path") or "") == str(retirement.get("file_path") or "")
    if scope == "ASSET":
        asset_ids = finding.get("asset_ids") or ()
        return bool(retirement.get("asset_id")) and retirement["asset_id"] in set(asset_ids)
    # ALGORITHM scope: the algorithm matches anywhere
    return True


def detect_reintroductions(
    retirements: Iterable[dict[str, Any]],
    findings: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return one detection per violated retirement.

    ``retirements`` — active registry entries (algorithm, scope, file_path,
                      asset_id, …); inactive entries are the caller's job to
                      filter out
    ``findings``    — one scan's evidence records (algorithm, file_path,
                      line_number, compliance_status, is_hardcoded_key,
                      optional asset_ids from the crypto-asset linkage)
    """
    detections: list[dict[str, Any]] = []
    for retirement in retirements or []:
        scope = str(retirement.get("scope") or "FILE").upper()
        if scope not in _SCOPES:
            continue  # malformed registry rows never silently match everything
        if scope == "ASSET" and not retirement.get("asset_id"):
            continue
        matched = [f for f in (findings or []) if _matches(retirement, f)]
        if not matched:
            continue
        detections.append({
            "retirement_id": retirement.get("id"),
            "algorithm": _norm(retirement.get("algorithm")),
            "scope": scope,
            "severity": max((_severity(f) for f in matched), key=_rank),
            "matched_sites": [
                {"file_path": f.get("file_path"), "line_number": f.get("line_number"),
                 "compliance_status": f.get("compliance_status"),
                 "is_hardcoded_key": bool(f.get("is_hardcoded_key"))}
                for f in matched
            ],
            "retired_at": retirement.get("retired_at"),
            "retired_by": retirement.get("retired_by"),
            "reason": retirement.get("reason"),
        })
    return detections


_SEVERITY_ORDER = {CRITICAL: 2, HIGH: 1, MEDIUM: 0}


def _rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity, -1)
