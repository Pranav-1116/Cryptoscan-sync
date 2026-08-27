"""Scan-to-scan drift for container scans: what changed between two runs.

Mirrors the network scanner's drift report with container semantics: new
CVEs are the headline regression, resolved CVEs the improvement; package
adds/removes/version bumps, new crypto binaries, new hardcoded secrets, and
posture transitions (PASS -> WARN -> FAIL) round out the picture.

Pure over the two scan results; ``None`` versions never compare equal.
"""

from __future__ import annotations

from typing import Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_POSTURE_RANK = {"PASS": 0, "WARN": 1, "FAIL": 2}
_IMPROVEMENT_TYPES = {"CVE_RESOLVED", "SECRET_REMOVED", "POSTURE_IMPROVED"}


def _packages(scan: dict[str, Any] | None) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for pkg in (scan or {}).get("packages") or []:
        name = str(pkg.get("name") or "").lower()
        if name:
            out[(str(pkg.get("manager") or ""), name)] = pkg
    return out


def _vulns(scan: dict[str, Any] | None) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for vuln in (scan or {}).get("vulnerabilities") or []:
        cve = str(vuln.get("cve") or "")
        if cve:
            out[(cve, str(vuln.get("package") or "").lower())] = vuln
    return out


def _binaries(scan: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for binary in (scan or {}).get("binaries") or []:
        path = str(binary.get("path") or "")
        if path:
            out[path] = binary
    return out


def _secrets(scan: dict[str, Any] | None) -> set[tuple[str, str, int]]:
    return {
        (str(secret.get("path") or ""), str(secret.get("kind") or ""), int(secret.get("line_number") or 0))
        for secret in (scan or {}).get("secrets") or []
    }


def _change(change_type: str, severity: str, detail: str, *, was: Any = None, now: Any = None) -> dict[str, Any]:
    return {"type": change_type, "severity": severity, "detail": detail, "was": was, "now": now}


def _cve_severity(vuln: dict[str, Any]) -> str:
    severity = str(vuln.get("severity") or "UNKNOWN").upper()
    if severity in {"CRITICAL"}:
        return "CRITICAL"
    if severity == "HIGH":
        return "HIGH"
    return "MEDIUM"


def diff_scans(previous: dict[str, Any] | None, current: dict[str, Any] | None) -> dict[str, Any]:
    """Diff two container scan results into a severity-ranked change report."""
    changes: list[dict[str, Any]] = []

    prev_vulns = _vulns(previous)
    cur_vulns = _vulns(current)
    for (cve, package), row in sorted(cur_vulns.items()):
        if (cve, package) not in prev_vulns:
            severity = _cve_severity(row)
            changes.append(
                _change(
                    "NEW_CVE",
                    severity,
                    f"{cve} in {package} ({str(row.get('severity') or '?').upper()})",
                    now=cve,
                )
            )
    for (cve, package) in sorted(prev_vulns):
        if (cve, package) not in cur_vulns:
            changes.append(_change("CVE_RESOLVED", "INFO", f"{cve} in {package} no longer matched", was=cve))

    prev_pkgs = _packages(previous)
    cur_pkgs = _packages(current)
    for key in sorted(set(cur_pkgs) - set(prev_pkgs)):
        pkg = cur_pkgs[key]
        changes.append(_change("PACKAGE_ADDED", "INFO", f"{key[1]} ({key[0]}) {pkg.get('version') or ''}".strip()))
    for key in sorted(set(prev_pkgs) - set(cur_pkgs)):
        changes.append(_change("PACKAGE_REMOVED", "INFO", f"{key[1]} ({key[0]}) no longer present"))
    for key in sorted(set(prev_pkgs) & set(cur_pkgs)):
        old_v, new_v = prev_pkgs[key].get("version"), cur_pkgs[key].get("version")
        if old_v and new_v and str(old_v) != str(new_v):
            changes.append(
                _change(
                    "PACKAGE_VERSION_CHANGED",
                    "INFO",
                    f"{key[1]} {old_v} -> {new_v}",
                    was=str(old_v),
                    now=str(new_v),
                )
            )

    prev_bin = _binaries(previous)
    cur_bin = _binaries(current)
    for path in sorted(set(cur_bin) - set(prev_bin)):
        changes.append(_change("CRYPTO_BINARY_ADDED", "MEDIUM", f"{path} (crypto binary)"))
    for path in sorted(set(prev_bin) - set(cur_bin)):
        changes.append(_change("CRYPTO_BINARY_REMOVED", "INFO", f"{path} no longer present"))

    new_secrets = _secrets(current) - _secrets(previous)
    gone_secrets = _secrets(previous) - _secrets(current)
    for path, kind, line in sorted(new_secrets):
        severity = "CRITICAL" if kind in {"pem-private-key", "openssh-private-key", "putty-private-key"} else "MEDIUM"
        changes.append(_change("NEW_HARDCODED_SECRET", severity, f"{kind} at {path}:{line}"))
    for path, kind, line in sorted(gone_secrets):
        changes.append(_change("SECRET_REMOVED", "INFO", f"{kind} at {path}:{line} removed"))

    prev_posture = str((previous or {}).get("risk_report", {}).get("posture") or "PASS")
    cur_posture = str((current or {}).get("risk_report", {}).get("posture") or "PASS")
    if prev_posture != cur_posture:
        degraded = _POSTURE_RANK.get(cur_posture, 0) > _POSTURE_RANK.get(prev_posture, 0)
        changes.append(
            _change(
                "POSTURE_DEGRADED" if degraded else "POSTURE_IMPROVED",
                "HIGH" if degraded else "INFO",
                f"risk posture {prev_posture} -> {cur_posture}",
                was=prev_posture,
                now=cur_posture,
            )
        )

    changes.sort(key=lambda row: SEVERITY_ORDER.get(row["severity"], 99))
    regressions = any(row["severity"] in {"CRITICAL", "HIGH"} for row in changes)
    improvements = any(row["type"] in _IMPROVEMENT_TYPES for row in changes)
    if regressions and improvements:
        verdict = "MIXED"
    elif regressions:
        verdict = "REGRESSED"
    elif improvements:
        verdict = "IMPROVED"
    else:
        verdict = "UNCHANGED"
    severity_counts = {
        level: sum(1 for row in changes if row["severity"] == level)
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    }
    return {
        "verdict": verdict,
        "change_count": len(changes),
        "severity_counts": severity_counts,
        "summary": {
            "new_cves": sum(1 for row in changes if row["type"] == "NEW_CVE"),
            "resolved_cves": sum(1 for row in changes if row["type"] == "CVE_RESOLVED"),
            "packages_added": sum(1 for row in changes if row["type"] == "PACKAGE_ADDED"),
            "packages_removed": sum(1 for row in changes if row["type"] == "PACKAGE_REMOVED"),
            "new_secrets": len(new_secrets),
            "posture": cur_posture,
        },
        "headline": changes[0]["detail"] if changes else None,
        "changes": changes,
        "previous_scan_id": (previous or {}).get("scan_id"),
        "current_scan_id": (current or {}).get("scan_id"),
    }
