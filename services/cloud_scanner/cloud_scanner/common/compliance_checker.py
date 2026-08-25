"""Flag cloud crypto compliance issues already attached to findings."""

from __future__ import annotations

from typing import Any, Iterable


WEAK_ISSUES = {
    "NO_ENCRYPTION",
    "NO_ENCRYPTION_AT_REST",
    "NO_HTTPS_ONLY",
    "WEAK_TLS_VERSION",
    "CERT_EXPIRED",
    "NO_ENV_ENCRYPTION",
    "UNENCRYPTED_PARAMETER",
    "KEY_DISABLED",
}


def issues_of(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in findings if row.get("compliance_issue") in WEAK_ISSUES or row.get("compliance_issue")]


def summary(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    rows = list(findings)
    flagged = issues_of(rows)
    counts: dict[str, int] = {}
    for row in flagged:
        key = str(row.get("compliance_issue") or "UNKNOWN")
        counts[key] = counts.get(key, 0) + 1
    return {"resources": len(rows), "issues": len(flagged), **counts}
