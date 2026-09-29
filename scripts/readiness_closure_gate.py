#!/usr/bin/env python3
"""Fail-closed evidence gate for the enterprise-bank readiness gap register.

The gap register contains requirements that source code cannot satisfy by
itself. This gate gives every P0/P1 requirement a machine-readable closure
contract and rejects incomplete, stale, unbound, or unreviewed evidence.

It deliberately does *not* inspect an artifact's truth beyond its declared
status and integrity metadata. A SHA-256 digest proves that the referenced
file is the file reviewed; it does not prove that the issuer, customer,
provider, auditor, or operator made a truthful statement. Those boundaries are
recorded in the report and remain part of the approval decision.

A closure manifest is supplied by the deployment/evidence owner. It may point
to controlled files outside this repository, but it must not contain secrets in
this repository. Every PASS artifact is bound to a release commit, an
environment, a scope, a UTC capture time, a responsible owner, an issuer, a
reviewer, a digest, and explicit limitations.

Usage:
    python scripts/readiness_closure_gate.py \
      --manifest /secure/evidence/closure-manifest.json \
      --expected-commit "$GIT_COMMIT" --strict

The checked-in policy is a requirements definition, not evidence of closure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "readiness-closure-policy.json"
TIERS = ("none", "repository_control", "operational_record", "customer_attestation", "external_certification")
TIER_RANK = {name: rank for rank, name in enumerate(TIERS)}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SCHEMA = "cryptoscan.readiness-closure-manifest/1"


def _finding(code: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {"code": code, "detail": detail, **extra}


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load JSON {path}: {type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def validate_policy(policy: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if policy.get("schema") != "cryptoscan.readiness-closure-policy/1":
        findings.append(_finding("policy_schema", "policy schema is not cryptoscan.readiness-closure-policy/1"))
    gaps = policy.get("gaps")
    if not isinstance(gaps, list) or not gaps:
        return findings + [_finding("policy_gaps", "policy must contain a non-empty gaps list")]
    seen: set[str] = set()
    for index, gap in enumerate(gaps):
        if not isinstance(gap, dict):
            findings.append(_finding("policy_gap_shape", f"gap {index} must be an object"))
            continue
        gap_id = str(gap.get("id") or "")
        if not re.fullmatch(r"P[01]-[0-9]+", gap_id):
            findings.append(_finding("policy_gap_id", f"gap {index} has invalid id {gap_id!r}"))
        if gap_id in seen:
            findings.append(_finding("policy_duplicate_gap", f"duplicate gap id {gap_id}"))
        seen.add(gap_id)
        if gap.get("priority") not in {"P0", "P1"}:
            findings.append(_finding("policy_priority", f"{gap_id}: priority must be P0 or P1"))
        if not str(gap.get("title") or "").strip() or not str(gap.get("owner") or "").strip():
            findings.append(_finding("policy_metadata", f"{gap_id}: title and owner are required"))
        kinds = gap.get("required_kinds")
        if not isinstance(kinds, list) or not kinds or any(not isinstance(kind, str) or not kind.strip() for kind in kinds):
            findings.append(_finding("policy_required_kinds", f"{gap_id}: required_kinds must be non-empty strings"))
        if gap.get("minimum_tier") not in TIER_RANK or gap.get("minimum_tier") == "none":
            findings.append(_finding("policy_tier", f"{gap_id}: minimum_tier must be a non-none evidence tier"))
        age = gap.get("max_age_days")
        if not isinstance(age, int) or isinstance(age, bool) or age <= 0:
            findings.append(_finding("policy_age", f"{gap_id}: max_age_days must be a positive integer"))
    return findings


def _parse_utc(value: Any, field: str, findings: list[dict[str, Any]], gap_id: str) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        findings.append(_finding("metadata_missing", f"{gap_id}: {field} is required"))
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        findings.append(_finding("metadata_time", f"{gap_id}: {field} is not ISO-8601", field=field))
        return None
    if parsed.tzinfo is None:
        findings.append(_finding("metadata_timezone", f"{gap_id}: {field} must include a timezone", field=field))
        return None
    return parsed.astimezone(timezone.utc)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _artifact_statuses(value: Any, path: str = "root") -> list[tuple[str, str]]:
    """Collect status-like fields without treating prose/detail as statuses."""
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if str(key).lower() in {"status", "verdict", "result", "overall"} and isinstance(child, str):
                found.append((child_path, child.upper()))
            found.extend(_artifact_statuses(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_artifact_statuses(child, f"{path}[{index}]"))
    return found


def _check_artifact_file(item: dict[str, Any], gap: dict[str, Any], expected_commit: str, now: datetime, findings: list[dict[str, Any]]) -> None:
    gap_id = str(gap["id"])
    required = {
        "evidence_id", "kind", "status", "evidence_tier", "artifact_path", "artifact_sha256",
        "captured_at", "release_commit", "environment", "scope", "limitations", "owner",
        "issuer", "reviewed_by", "reviewed_at", "operator", "independent_review",
    }
    missing = sorted(field for field in required if field not in item)
    if missing:
        findings.append(_finding("artifact_metadata", f"{gap_id}: missing {', '.join(missing)}", gap_id=gap_id, kind=item.get("kind")))
        return
    if item.get("status") != "PASS":
        findings.append(_finding("artifact_not_pass", f"{gap_id}/{item.get('kind')}: status must be PASS", gap_id=gap_id, kind=item.get("kind")))
    if item.get("kind") not in set(gap.get("required_kinds", [])):
        findings.append(_finding("artifact_kind", f"{gap_id}: kind is not required by policy: {item.get('kind')}", gap_id=gap_id))
    tier = item.get("evidence_tier")
    if tier not in TIER_RANK or TIER_RANK.get(str(tier), -1) < TIER_RANK[str(gap["minimum_tier"])]:
        findings.append(_finding("artifact_tier", f"{gap_id}/{item.get('kind')}: evidence tier {tier!r} is below {gap['minimum_tier']}", gap_id=gap_id, kind=item.get("kind")))
    release_commit = str(item.get("release_commit") or "")
    if not COMMIT.fullmatch(release_commit) or release_commit != expected_commit:
        findings.append(_finding("release_binding", f"{gap_id}/{item.get('kind')}: release_commit does not match expected commit", gap_id=gap_id, kind=item.get("kind")))
    for field in ("environment", "scope", "owner", "issuer", "reviewed_by", "operator"):
        if not isinstance(item.get(field), str) or not item[field].strip():
            findings.append(_finding("metadata_empty", f"{gap_id}/{item.get('kind')}: {field} must be non-empty", gap_id=gap_id, kind=item.get("kind")))
    limitations = item.get("limitations")
    if not isinstance(limitations, list) or not limitations or any(not isinstance(value, str) or not value.strip() for value in limitations):
        findings.append(_finding("limitations_missing", f"{gap_id}/{item.get('kind')}: limitations must be a non-empty list", gap_id=gap_id, kind=item.get("kind")))
    if item.get("independent_review") is not True:
        findings.append(_finding("independent_review", f"{gap_id}/{item.get('kind')}: independent_review must be true", gap_id=gap_id, kind=item.get("kind")))
    if str(item.get("operator")) == str(item.get("reviewed_by")):
        findings.append(_finding("separation_of_duties", f"{gap_id}/{item.get('kind')}: operator and reviewer must differ", gap_id=gap_id, kind=item.get("kind")))

    captured = _parse_utc(item.get("captured_at"), "captured_at", findings, gap_id)
    reviewed = _parse_utc(item.get("reviewed_at"), "reviewed_at", findings, gap_id)
    max_age = timedelta(days=int(gap["max_age_days"]))
    if captured:
        if captured > now + timedelta(minutes=5):
            findings.append(_finding("future_artifact", f"{gap_id}/{item.get('kind')}: captured_at is in the future", gap_id=gap_id, kind=item.get("kind")))
        elif now - captured > max_age:
            findings.append(_finding("stale_artifact", f"{gap_id}/{item.get('kind')}: artifact exceeds {gap['max_age_days']} day freshness window", gap_id=gap_id, kind=item.get("kind")))
    if reviewed and captured and reviewed < captured:
        findings.append(_finding("review_before_capture", f"{gap_id}/{item.get('kind')}: reviewed_at precedes captured_at", gap_id=gap_id, kind=item.get("kind")))

    digest = str(item.get("artifact_sha256") or "").lower()
    if not SHA256.fullmatch(digest):
        findings.append(_finding("artifact_digest", f"{gap_id}/{item.get('kind')}: artifact_sha256 must be 64 lowercase hex characters", gap_id=gap_id, kind=item.get("kind")))
    else:
        raw_path = Path(str(item.get("artifact_path")))
        path = raw_path if raw_path.is_absolute() else ROOT / raw_path
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            findings.append(_finding("artifact_missing", f"{gap_id}/{item.get('kind')}: artifact_path does not exist", gap_id=gap_id, kind=item.get("kind")))
        else:
            if not resolved.is_file():
                findings.append(_finding("artifact_file", f"{gap_id}/{item.get('kind')}: artifact_path is not a regular file", gap_id=gap_id, kind=item.get("kind")))
            elif _sha256(resolved) != digest:
                findings.append(_finding("artifact_hash", f"{gap_id}/{item.get('kind')}: artifact_sha256 does not match file", gap_id=gap_id, kind=item.get("kind")))
            elif resolved.suffix.lower() == ".json":
                try:
                    payload = json.loads(resolved.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    findings.append(_finding("artifact_json", f"{gap_id}/{item.get('kind')}: JSON artifact cannot be parsed ({type(exc).__name__})", gap_id=gap_id, kind=item.get("kind")))
                else:
                    bad = [(location, status) for location, status in _artifact_statuses(payload) if status in {"FAIL", "FAILED", "ERROR", "SKIP", "PENDING", "NOT_RUN"}]
                    if bad:
                        findings.append(_finding("artifact_nested_failure", f"{gap_id}/{item.get('kind')}: artifact contains non-passing status {bad[0][1]} at {bad[0][0]}", gap_id=gap_id, kind=item.get("kind")))


def validate_manifest(policy: dict[str, Any], manifest: dict[str, Any], expected_commit: str, now: datetime | None = None) -> list[dict[str, Any]]:
    """Validate a closure manifest and return structured, non-secret findings."""
    now = now or datetime.now(timezone.utc)
    findings = []
    if manifest.get("schema") != SCHEMA:
        findings.append(_finding("manifest_schema", f"manifest schema must be {SCHEMA}"))
    if not COMMIT.fullmatch(expected_commit):
        findings.append(_finding("expected_commit", "expected commit must be a 40-character lowercase git SHA"))
    manifest_commit = str(manifest.get("release_commit") or "")
    if manifest_commit != expected_commit:
        findings.append(_finding("manifest_release_binding", "manifest release_commit does not match expected commit"))
    if not str(manifest.get("environment") or "").strip():
        findings.append(_finding("manifest_environment", "manifest environment is required"))
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return findings + [_finding("manifest_artifacts", "manifest artifacts must be a list")]
    by_gap_kind: dict[tuple[str, str], dict[str, Any]] = {}
    policy_gaps = {
        str(gap["id"]): gap
        for gap in policy.get("gaps", [])
        if isinstance(gap, dict)
        and gap.get("id")
        and isinstance(gap.get("required_kinds"), list)
        and gap.get("minimum_tier") in TIER_RANK
        and gap.get("max_age_days")
    }
    for index, item in enumerate(artifacts):
        if not isinstance(item, dict):
            findings.append(_finding("artifact_shape", f"artifact {index} must be an object"))
            continue
        gap_id = str(item.get("gap_id") or "")
        kind = str(item.get("kind") or "")
        gap = policy_gaps.get(gap_id)
        if not gap:
            findings.append(_finding("unknown_gap", f"artifact {index} references unknown gap {gap_id!r}"))
            continue
        key = (gap_id, kind)
        if key in by_gap_kind:
            findings.append(_finding("duplicate_artifact", f"duplicate artifact for {gap_id}/{kind}"))
        by_gap_kind[key] = item
        _check_artifact_file(item, gap, expected_commit, now, findings)
    for gap_id, gap in policy_gaps.items():
        for kind in gap.get("required_kinds", []):
            item = by_gap_kind.get((gap_id, kind))
            if not item or item.get("status") != "PASS":
                findings.append(_finding("gap_open", f"{gap_id}: required evidence is missing or not PASS: {kind}", gap_id=gap_id, kind=kind))
    return findings


def current_commit() -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
    return result.stdout.strip()


def render_report(policy: dict[str, Any], manifest: dict[str, Any], expected_commit: str, findings: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    gaps = policy.get("gaps", [])
    closed = sum(1 for gap in gaps if all(
        any(item.get("gap_id") == gap.get("id") and item.get("kind") == kind and item.get("status") == "PASS" for item in manifest.get("artifacts", []) if isinstance(item, dict))
        for kind in gap.get("required_kinds", [])
    ))
    return {
        "schema": "cryptoscan.readiness-closure-report/1",
        "captured_at": now.isoformat(),
        "expected_commit": expected_commit,
        "manifest_release_commit": manifest.get("release_commit"),
        "total_gaps": len(gaps),
        "closed_gaps": closed,
        "open_gaps": len(gaps) - closed,
        "verdict": "PASS" if not findings else "FAIL",
        "findings": findings,
        "boundary": "PASS means the supplied evidence envelopes are complete, current, release-bound, reviewed, and internally consistent. It does not establish the truth of external claims, certification, customer approval, legal compliance, or production operation.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=POLICY)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-commit", default=None, help="40-character release commit; defaults to HEAD")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--strict", action="store_true", help="return nonzero when any gap is open or any finding exists")
    args = parser.parse_args(argv)
    try:
        policy = load_json(args.policy)
        manifest = load_json(args.manifest)
    except ValueError as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        return 2
    policy_findings = validate_policy(policy)
    expected = args.expected_commit or current_commit()
    findings = policy_findings + validate_manifest(policy, manifest, expected)
    report = render_report(policy, manifest, expected, findings, datetime.now(timezone.utc))
    print(f"Readiness closure gate: {report['verdict']} ({report['closed_gaps']}/{report['total_gaps']} gaps closed)")
    for finding in findings:
        print(f"FAIL  {finding['code']}: {finding['detail']}")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["verdict"] == "PASS":
        return 0
    # A non-strict invocation is still a failed gate; code 2 distinguishes a
    # reportable incomplete envelope from a CLI/parse error (code 2 above).
    # Approval automation should use --strict and receive code 1.
    return 1 if args.strict else 2


if __name__ == "__main__":
    raise SystemExit(main())
