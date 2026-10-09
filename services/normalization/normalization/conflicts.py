"""Observation conflict detection (audit 50).

Two observations of the *same logical site* that disagree about the crypto
in use are a conflict — today both are stored silently and the disagreement
is invisible. This module detects the three conflict classes deterministically:

* ``ALGORITHM_MISMATCH``  — same site, different algorithms (scanner A saw
  RSA, scanner B saw ECDSA at the same file/line)
* ``PARAMETER_MISMATCH``  — same algorithm, different parameters (key size,
  mode) across scanners or scans
* ``STATUS_MISMATCH``     — same site, different compliance verdicts across
  scanners or scans (one engine's PASS vs another's FAIL)

Pure logic: no database, no clock. The findings router feeds it evidence
records from one scan (within-scan conflicts across scanners) or two scans
(between-scan conflicts — the honest replacement for "trust the newest").
"""

from __future__ import annotations

from typing import Any, Iterable

ALGORITHM_MISMATCH = "ALGORITHM_MISMATCH"
PARAMETER_MISMATCH = "PARAMETER_MISMATCH"
STATUS_MISMATCH = "STATUS_MISMATCH"


def _norm(algorithm: Any) -> str:
    return str(algorithm or "UNKNOWN").upper().replace("_", "-").strip()


def _site(finding: dict[str, Any]) -> tuple[str, int]:
    return (str(finding.get("file_path") or ""), int(finding.get("line_number") or 0))


def _params(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (finding.get("key_size"), finding.get("mode"))


def _sources(findings: list[dict[str, Any]]) -> list[str]:
    """Scanner ids when present, else scan ids — whatever distinguishes the observers."""
    keys = ("scanner_ids", "scan_ids")
    out: list[str] = []
    for key in keys:
        for f in findings:
            value = f.get(key)
            if isinstance(value, (list, tuple)) and value:
                out.extend(str(v) for v in value)
            elif isinstance(value, str) and value:
                out.append(value)
    return sorted(set(out)) or ["unknown-observer"]


def detect_conflicts(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Conflicts within one set of observations (typically one scan)."""
    by_site: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for finding in findings or []:
        if not str(finding.get("file_path") or ""):
            continue  # site-less observations cannot conflict by location
        by_site.setdefault(_site(finding), []).append(dict(finding))

    conflicts: list[dict[str, Any]] = []
    for (file_path, line_number), group in sorted(by_site.items()):
        if len(group) < 2:
            continue
        algorithms = sorted({_norm(f.get("algorithm")) for f in group})
        statuses = sorted({str(f.get("compliance_status") or "").upper() for f in group})
        # every (algorithm, parameters) pair observed at this site — a dict
        # keyed by algorithm would hide the second parameterization
        pairs = {(_norm(f.get("algorithm")), _params(f)) for f in group}

        conflict_type: str | None = None
        details: dict[str, Any] = {}
        if len(algorithms) > 1:
            conflict_type = ALGORITHM_MISMATCH
            details = {"algorithms": algorithms}
        elif len(pairs) > 1:
            conflict_type = PARAMETER_MISMATCH
            details = {"algorithm": algorithms[0],
                       "parameter_variants": [
                           {"key_size": p[1][0], "mode": p[1][1]}
                           for p in sorted(pairs, key=lambda p: (str(p[1][0]), str(p[1][1])))]}
        elif len(statuses) > 1:
            conflict_type = STATUS_MISMATCH
            details = {"compliance_statuses": statuses}

        if conflict_type is None:
            continue
        conflicts.append({
            "file_path": file_path,
            "line_number": line_number,
            "conflict_type": conflict_type,
            "observation_count": len(group),
            "observers": _sources(group),
            **details,
        })
    return conflicts


def detect_cross_scan_conflicts(
    baseline: Iterable[dict[str, Any]],
    current: Iterable[dict[str, Any]],
    *,
    baseline_scan_id: str = "",
    current_scan_id: str = "",
) -> list[dict[str, Any]]:
    """Conflicts between two scans of the same target.

    Both sides are stamped with their scan id so the report says *who*
    disagrees, not just that someone does. Sites only in one scan are not
    conflicts — that is drift's domain, not this detector's.
    """
    tagged: list[dict[str, Any]] = []
    for f in baseline or []:
        tagged.append({**dict(f), "scan_ids": [baseline_scan_id or "baseline"]})
    for f in current or []:
        tagged.append({**dict(f), "scan_ids": [current_scan_id or "current"]})
    conflicts = detect_conflicts(tagged)
    for conflict in conflicts:
        conflict["baseline_scan_id"] = baseline_scan_id
        conflict["current_scan_id"] = current_scan_id
    return conflicts
