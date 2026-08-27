"""OT posture report: what the passive observations say about the plant."""

from __future__ import annotations

from typing import Any

_POSTURE_RANK = {"PASS": 0, "WARN": 1, "FAIL": 2}


def _issue_is_weak(issue: str | None) -> bool:
    return bool(issue) and "WEAK" in str(issue)


def build_ot_posture(*, findings: list[dict[str, Any]], devices: list[dict[str, Any]]) -> dict[str, Any]:
    """Grade passive observations into a posture verdict + issue counts.

    FAIL — a device carries matched CVEs, or unencrypted traffic was observed
    on a SAFETY_CRITICAL device.  WARN — weak crypto somewhere, or
    unencrypted traffic on non-safety devices.  PASS — everything encrypted
    with current algorithms.  Observations, not scan quality: the telemetry
    dict grades the scan itself.
    """
    protocol_counts: dict[str, int] = {}
    level_counts: dict[str, int] = {}
    issue_counts: dict[str, int] = {}
    unencrypted = 0
    weak = 0
    ips_with_cves: set[str] = set()

    for finding in findings:
        protocol = str(finding.get("protocol") or "UNKNOWN")
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        level = str(finding.get("security_level") or "UNKNOWN")
        level_counts[level] = level_counts.get(level, 0) + 1
        issue = finding.get("compliance_issue")
        if issue:
            issue_counts[str(issue)] = issue_counts.get(str(issue), 0) + 1
        if not finding.get("has_crypto"):
            unencrypted += 1
        if _issue_is_weak(issue):
            weak += 1
        device = finding.get("device") or {}
        if finding.get("vulnerabilities") and device.get("ip_address"):
            ips_with_cves.add(str(device["ip_address"]))

    unencrypted_safety = sum(
        1
        for finding in findings
        if not finding.get("has_crypto")
        and str((finding.get("device") or {}).get("criticality") or "") == "SAFETY_CRITICAL"
    )

    issues: list[str] = []
    if ips_with_cves:
        issues.append("OT_DEVICE_WITH_CVES")
    if unencrypted_safety:
        issues.append("OT_UNENCRYPTED_SAFETY_CRITICAL")
    if weak:
        issues.append("OT_WEAK_CRYPTO")
    if unencrypted > unencrypted_safety:
        issues.append("OT_UNENCRYPTED_TRAFFIC")

    fail_issues = {"OT_DEVICE_WITH_CVES", "OT_UNENCRYPTED_SAFETY_CRITICAL"}
    posture = "FAIL" if fail_issues & set(issues) else ("WARN" if issues else "PASS")

    headline = None
    if issues:
        headline = {
            "OT_DEVICE_WITH_CVES": f"{len(ips_with_cves)} device(s) with matched CVEs: {sorted(ips_with_cves)[:4]}",
            "OT_UNENCRYPTED_SAFETY_CRITICAL": f"{unencrypted_safety} unencrypted observation(s) on SAFETY_CRITICAL devices",
            "OT_WEAK_CRYPTO": f"{weak} observation(s) using weak crypto (SHA-1 MACs / RSA-1024 / legacy policies)",
            "OT_UNENCRYPTED_TRAFFIC": f"{unencrypted} unencrypted observation(s) on non-safety devices",
        }[issues[0]]

    return {
        "posture": posture,
        "policy_issues": issues,
        "headline": headline,
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "security_level_counts": dict(sorted(level_counts.items())),
        "issue_counts": dict(sorted(issue_counts.items())),
        "unencrypted_observations": unencrypted,
        "unencrypted_safety_critical": unencrypted_safety,
        "weak_crypto_observations": weak,
        "devices_with_cves": sorted(ips_with_cves),
        "device_count": len(devices),
    }


def build_ot_telemetry(*, records: int, findings: list[dict[str, Any]], devices: list[dict[str, Any]]) -> dict[str, Any]:
    """Honest scan-quality telemetry (the scan, not the plant)."""
    if records == 0:
        verdict = "SKIPPED"
    elif not findings or not devices:
        verdict = "FAILED"  # records existed but nothing protocol-matched
    else:
        verdict = "OK"
    return {
        "status": verdict,
        "records_analyzed": records,
        "findings": len(findings),
        "match_rate": round(len(findings) / records, 3) if records else None,
        "devices": len(devices),
        "packets_sent": 0,
        "mode": "PASSIVE_OBSERVATION",
    }
