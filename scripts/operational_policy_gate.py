#!/usr/bin/env python3
"""Validate the operational policy required for a bank production release.

The repository can define a safe policy shape, but it cannot self-approve a
contract, promise a regulator deadline, or prove that the policy operated over
time. The checked-in baseline is therefore deliberately ``draft``. The normal
mode validates completeness; ``--strict`` additionally requires explicit
approval metadata and is the mode a release gate should use.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "operational-policy.yaml"
SEVERITIES = ("critical", "high", "medium", "low")
SUPPORT_LEVELS = ("sev1", "sev2", "sev3", "sev4")


def _load(path: Path = POLICY) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise SystemExit("PyYAML is required: pip install pyyaml") from exc
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SystemExit(f"cannot load operational policy {path}: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise SystemExit("operational policy root must be a YAML object")
    return data


def _positive(findings: list[str], value: Any, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        findings.append(f"{name} must be a positive integer")


def validate(policy: dict[str, Any], strict: bool = False) -> list[str]:
    findings: list[str] = []
    if policy.get("schema") != "cryptoscan.operational-policy/1":
        findings.append("schema must be cryptoscan.operational-policy/1")
    status = policy.get("status")
    if status not in {"draft", "approved", "retired"}:
        findings.append("status must be draft, approved, or retired")
    if not str(policy.get("owner") or "").strip():
        findings.append("owner is required")
    if strict and status != "approved":
        findings.append("strict mode requires status=approved")
    if strict and not str(policy.get("reviewed_by") or "").strip():
        findings.append("strict mode requires reviewed_by")
    approved_at = policy.get("approved_at")
    if strict:
        if not isinstance(approved_at, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", approved_at):
            findings.append("strict mode requires approved_at in YYYY-MM-DD format")
        else:
            try:
                datetime.strptime(approved_at, "%Y-%m-%d")
            except ValueError:
                findings.append("approved_at is not a real calendar date")

    patch = policy.get("patch_remediation")
    if not isinstance(patch, dict):
        findings.append("patch_remediation must be an object")
    else:
        for severity in SEVERITIES:
            row = patch.get(severity)
            if not isinstance(row, dict):
                findings.append(f"patch_remediation.{severity} is required")
                continue
            _positive(findings, row.get("remediate_within_days"), f"patch_remediation.{severity}.remediate_within_days")
            _positive(findings, row.get("compensating_control_within_hours"), f"patch_remediation.{severity}.compensating_control_within_hours")

    incident = policy.get("incident_response")
    if not isinstance(incident, dict):
        findings.append("incident_response must be an object")
    else:
        for field in ("internal_acknowledgement_minutes", "incident_commander_assignment_minutes", "customer_initial_notification_hours", "customer_update_hours", "post_incident_review_within_days"):
            _positive(findings, incident.get(field), f"incident_response.{field}")
        if not incident.get("evidence_preservation_required") is True:
            findings.append("incident_response.evidence_preservation_required must be true")
        channels = incident.get("notification_channels")
        if not isinstance(channels, list) or len(channels) < 2 or not all(isinstance(x, str) and x.strip() for x in channels):
            findings.append("incident_response.notification_channels must contain at least two named channels")
        if not str(incident.get("regulator_notification") or "").strip():
            findings.append("incident_response.regulator_notification is required")

    support = policy.get("support_escalation")
    if not isinstance(support, dict):
        findings.append("support_escalation must be an object")
    else:
        for level in SUPPORT_LEVELS:
            row = support.get(level)
            if not isinstance(row, dict):
                findings.append(f"support_escalation.{level} is required")
                continue
            for field in ("availability", "acknowledgement_minutes", "update_minutes"):
                if field == "availability":
                    if not isinstance(row.get(field), str) or not row[field].strip():
                        findings.append(f"support_escalation.{level}.availability is required")
                else:
                    _positive(findings, row.get(field), f"support_escalation.{level}.{field}")

    backup = policy.get("backup_governance")
    if not isinstance(backup, dict):
        findings.append("backup_governance must be an object")
    else:
        for field in ("retention_days", "destruction_after_expiry_days", "restore_test_interval_days"):
            _positive(findings, backup.get(field), f"backup_governance.{field}")
        for field in ("offsite_copy_required", "encryption_required", "destruction_evidence_required"):
            if backup.get(field) is not True:
                findings.append(f"backup_governance.{field} must be true")
        if not str(backup.get("destruction_authorization") or "").strip():
            findings.append("backup_governance.destruction_authorization is required")

    access = policy.get("access_review")
    if not isinstance(access, dict):
        findings.append("access_review must be an object")
    else:
        for field in ("privileged_review_interval_days", "service_account_review_interval_days", "break_glass_review_after_use_hours", "termination_deprovision_target_hours"):
            _positive(findings, access.get(field), f"access_review.{field}")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=POLICY)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    policy = _load(args.policy)
    findings = validate(policy, strict=args.strict)
    verdict = "PASS" if not findings else "FAIL"
    mode = "strict" if args.strict else "structural"
    print(f"Operational policy gate: {verdict} ({mode}, status={policy.get('status')})")
    for finding in findings:
        print(f"FAIL  {finding}")
    report = {
        "schema": "cryptoscan.operational-policy-gate/1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "policy": str(args.policy),
        "policy_status": policy.get("status"),
        "mode": mode,
        "verdict": verdict,
        "findings": findings,
        "meaning": "Structural PASS means the draft is complete enough to review. Strict PASS requires explicit approval metadata; it does not prove observed operation or external compliance.",
    }
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
