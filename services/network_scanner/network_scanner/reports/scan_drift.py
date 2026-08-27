"""Scan-to-scan drift: what changed between the previous run and this one.

Point-in-time scans answer "how bad is it now"; operators also need "what
changed since yesterday" — the new weak cipher, the cert that expired
overnight, the silent TLS downgrade, the host key that changed.  This module
diffs two ``scan_hosts``-shaped result dicts (findings keyed by endpoint,
certificates keyed by fingerprint) into a severity-ranked change list with an
honest verdict: REGRESSED / IMPROVED / MIXED / UNCHANGED.

Everything is pure over the two inputs — no I/O — so drift is unit-testable
and can run anywhere scan results exist (CLI files, API payloads, stored
history).  Inputs missing a section are treated as empty, and ``None`` fields
never compare equal to values (an absent fact is not a change).
"""

from __future__ import annotations

from typing import Any, Iterable

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_TLS_VERSION_RANK = {
    "SSLv2": -2,
    "SSLv3": -1,
    "TLSv1": 0,
    "TLSv1.1": 1,
    "TLSv1.2": 2,
    "TLSv1.3": 3,
}

# issues that mean the posture actively got worse when they appear
_REGRESSION_ISSUE_PREFIXES = (
    "WEAK_",
    "DISALLOWED_",
    "CBC_",
    "INSECURE_",
    "CLIENT_RENEG",
    "CHAIN_",
    "SSH_WEAK_",
    "SSH_DSS",
    "SSH_RSA",
    "NO_HSTS",
)
_CRITICAL_ISSUES = {"CERT_REVOKED", "SSH_HOST_KEY_CHANGED"}
_IMPROVEMENT_TYPES = {"ISSUES_RESOLVED", "TLS_VERSION_UPGRADED", "STATUS_RECOVERED", "CERT_RENEWED"}


def _as_boolable_set(items: Iterable[Any] | None) -> set[str]:
    return {str(item) for item in (items or []) if item is not None}


def _findings_by_endpoint(scan: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    rows = (scan or {}).get("findings") or []
    return {str(row.get("endpoint")): row for row in rows if row.get("endpoint")}


def _certs_by_fingerprint(scan: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    rows = (scan or {}).get("certificates") or []
    return {
        str(row.get("fingerprint_sha256")): row
        for row in rows
        if row.get("fingerprint_sha256")
    }


def _change(
    change_type: str,
    severity: str,
    *,
    endpoint: str | None = None,
    detail: str = "",
    was: Any = None,
    now: Any = None,
) -> dict[str, Any]:
    return {
        "type": change_type,
        "severity": severity,
        "endpoint": endpoint,
        "detail": detail,
        "was": was,
        "now": now,
    }


def _issue_severity(issue: str) -> str:
    if issue in _CRITICAL_ISSUES:
        return "CRITICAL"
    if issue.startswith(_REGRESSION_ISSUE_PREFIXES):
        return "HIGH"
    return "MEDIUM"


def _diff_endpoint(
    endpoint: str,
    previous: dict[str, Any],
    current: dict[str, Any],
    *,
    changes: list[dict[str, Any]],
) -> None:
    prev_status = str(previous.get("status") or "")
    cur_status = str(current.get("status") or "")
    if prev_status and cur_status and prev_status != cur_status:
        degraded = cur_status != "OK" and prev_status == "OK"
        recovered = cur_status == "OK" and prev_status != "OK"
        changes.append(
            _change(
                "STATUS_RECOVERED" if recovered else "STATUS_DEGRADED",
                "INFO" if recovered else "HIGH",
                endpoint=endpoint,
                detail=f"{prev_status} -> {cur_status}",
                was=prev_status,
                now=cur_status,
            )
        )
        if degraded or recovered:
            return  # posture fields below are not comparable across statuses
    prev_crypto = previous.get("crypto") or {}
    cur_crypto = current.get("crypto") or {}
    prev_version = prev_crypto.get("tls_version")
    cur_version = cur_crypto.get("tls_version")
    if prev_version and cur_version and prev_version != cur_version:
        prev_rank = _TLS_VERSION_RANK.get(str(prev_version))
        cur_rank = _TLS_VERSION_RANK.get(str(cur_version))
        if prev_rank is not None and cur_rank is not None and cur_rank < prev_rank:
            changes.append(
                _change(
                    "TLS_VERSION_DOWNGRADED",
                    "HIGH",
                    endpoint=endpoint,
                    detail=f"negotiated {prev_version} -> {cur_version}",
                    was=prev_version,
                    now=cur_version,
                )
            )
        else:
            changes.append(
                _change(
                    "TLS_VERSION_UPGRADED" if (cur_rank or 0) > (prev_rank or 0) else "TLS_VERSION_CHANGED",
                    "INFO",
                    endpoint=endpoint,
                    detail=f"negotiated {prev_version} -> {cur_version}",
                    was=prev_version,
                    now=cur_version,
                )
            )
    prev_cipher = prev_crypto.get("cipher_suite")
    cur_cipher = cur_crypto.get("cipher_suite")
    if prev_cipher and cur_cipher and prev_cipher != cur_cipher and prev_version == cur_version:
        changes.append(
            _change(
                "CIPHER_SUITE_CHANGED",
                "INFO",
                endpoint=endpoint,
                detail=f"{prev_cipher} -> {cur_cipher}",
                was=prev_cipher,
                now=cur_cipher,
            )
        )
    prev_issues = _as_boolable_set(previous.get("policy_issues"))
    cur_issues = _as_boolable_set(current.get("policy_issues"))
    appeared = sorted(cur_issues - prev_issues)
    resolved = sorted(prev_issues - cur_issues)
    for issue in appeared:
        changes.append(
            _change(
                "POLICY_ISSUE_APPEARED",
                _issue_severity(issue),
                endpoint=endpoint,
                detail=issue,
                was=None,
                now=issue,
            )
        )
    if resolved:
        changes.append(
            _change(
                "ISSUES_RESOLVED",
                "INFO",
                endpoint=endpoint,
                detail=", ".join(resolved),
                was=resolved,
                now=[],
            )
        )


def _diff_certificates(
    previous: dict[str, dict[str, Any]],
    current: dict[str, dict[str, Any]],
    *,
    expiry_warn_days: int,
    changes: list[dict[str, Any]],
) -> None:
    def days(row: dict[str, Any]) -> int | None:
        try:
            return int(row.get("days_until_expiry"))
        except (TypeError, ValueError):
            return None

    for fingerprint, cur_row in current.items():
        prev_row = previous.get(fingerprint)
        if prev_row is None:
            continue
        prev_days, cur_days = days(prev_row), days(cur_row)
        if prev_days is None or cur_days is None:
            continue
        if prev_days > 0 >= cur_days:
            changes.append(
                _change(
                    "CERT_EXPIRED_SINCE_LAST_SCAN",
                    "CRITICAL",
                    detail=f"{cur_row.get('subject') or fingerprint[:16]} expired ({cur_days} days)",
                    was=prev_days,
                    now=cur_days,
                )
            )
        elif prev_days > expiry_warn_days >= cur_days >= 0:
            changes.append(
                _change(
                    "CERT_ENTERING_WARNING_WINDOW",
                    "HIGH",
                    detail=f"{cur_row.get('subject') or fingerprint[:16]} now expires in {cur_days} days",
                    was=prev_days,
                    now=cur_days,
                )
            )
    gone = [fp for fp in previous if fp not in current]
    added = [fp for fp in current if fp not in previous]
    cur_by_subject: dict[str, dict[str, Any]] = {}
    for fp in added:
        subject = str(current[fp].get("subject") or "")
        if subject:
            cur_by_subject[subject] = current[fp]
    for fp in gone:
        prev_row = previous[fp]
        subject = str(prev_row.get("subject") or "")
        replacement = cur_by_subject.pop(subject, None) if subject else None
        if replacement is not None:
            changes.append(
                _change(
                    "CERT_RENEWED",
                    "INFO",
                    detail=f"{subject or fp[:16]} renewed ({replacement.get('fingerprint_sha256', '')[:16]})",
                    was=fp[:16],
                    now=str(replacement.get("fingerprint_sha256", ""))[:16],
                )
            )
        else:
            changes.append(
                _change(
                    "CERT_NO_LONGER_SEEN",
                    "MEDIUM",
                    detail=f"{subject or fp[:16]} not observed this scan",
                    was=fp[:16],
                    now=None,
                )
            )
    for row in cur_by_subject.values():
        changes.append(
            _change(
                "CERT_ADDED",
                "INFO",
                detail=f"{row.get('subject') or 'new certificate'} observed",
                now=str(row.get("fingerprint_sha256", ""))[:16],
            )
        )


def diff_scans(
    previous: dict[str, Any] | None,
    current: dict[str, Any] | None,
    *,
    expiry_warn_days: int = 7,
) -> dict[str, Any]:
    """Diff two scan results into a severity-ranked change report."""
    changes: list[dict[str, Any]] = []
    prev_map = _findings_by_endpoint(previous)
    cur_map = _findings_by_endpoint(current)
    added_endpoints = sorted(set(cur_map) - set(prev_map))
    removed_endpoints = sorted(set(prev_map) - set(cur_map))
    for endpoint in added_endpoints:
        row = cur_map[endpoint]
        issues = _as_boolable_set(row.get("policy_issues"))
        worst = max((_issue_severity(issue) for issue in issues), key=lambda sev: -SEVERITY_ORDER[sev]) if issues else "INFO"
        changes.append(
            _change(
                "ENDPOINT_ADDED",
                worst,
                endpoint=endpoint,
                detail=f"new endpoint (status {row.get('status')})"
                + (f", issues: {', '.join(sorted(issues))}" if issues else ""),
            )
        )
    for endpoint in removed_endpoints:
        changes.append(
            _change(
                "ENDPOINT_REMOVED",
                "MEDIUM",
                endpoint=endpoint,
                detail=f"endpoint gone (was {prev_map[endpoint].get('status')})",
            )
        )
    for endpoint in sorted(set(prev_map) & set(cur_map)):
        _diff_endpoint(endpoint, prev_map[endpoint], cur_map[endpoint], changes=changes)
    _diff_certificates(
        _certs_by_fingerprint(previous),
        _certs_by_fingerprint(current),
        expiry_warn_days=expiry_warn_days,
        changes=changes,
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
            "endpoints_added": len(added_endpoints),
            "endpoints_removed": len(removed_endpoints),
            "issues_appeared": sum(1 for row in changes if row["type"] == "POLICY_ISSUE_APPEARED"),
            "issues_resolved": sum(1 for row in changes if row["type"] == "ISSUES_RESOLVED"),
            "certs_expired": sum(
                1 for row in changes if row["type"] == "CERT_EXPIRED_SINCE_LAST_SCAN"
            ),
        },
        "headline": changes[0]["detail"] if changes else None,
        "changes": changes,
        "previous_scan_id": (previous or {}).get("scan_id"),
        "current_scan_id": (current or {}).get("scan_id"),
    }
