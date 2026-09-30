#!/usr/bin/env python3
"""Produce the single, honest bank-readiness evidence report.

The report is a gate, not a marketing status page. It records commit, command,
time, environment, every included artifact and explicit external-evidence
SKIP/FAIL states. Missing customer-controlled PostgreSQL, HSM, integration,
compliance or load evidence cannot become PASS by virtue of this repository.

The static engineering gate runs by default. Other checks consume artifact
paths produced by the real harnesses, or can be invoked with ``--run-...``;
those flags never manufacture provider/customer evidence. The report also
validates the operational-policy shape and can consume the aggregate P0/P1
closure manifest. Use ``--strict`` in CI or release approval: every required
category must be PASS and no SKIP is allowed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_CATEGORIES = (
    "engineering",
    "postgresql_dr",
    "hsm",
    "integrations",
    "compliance",
    "load_soak",
    "documentation",
    "operational_policy",
    "readiness_closure",
    "external_attestations",
)
OPERATIONAL_POLICY = ROOT / "config" / "operational-policy.yaml"


def status_row(category: str, status: str, detail: str, **extra: Any) -> dict:
    return {"category": category, "status": status, "detail": detail, **extra}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_metadata() -> dict[str, Any]:
    def run(*args: str) -> str:
        proc = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)
        return proc.stdout.strip()
    return {"commit": run("rev-parse", "HEAD"), "branch": run("branch", "--show-current"), "dirty": bool(run("status", "--porcelain"))}


def artifact(path: Path | None, category: str) -> dict:
    if not path:
        return status_row(category, "SKIP", "no external artifact supplied; this is not evidence")
    if not path.exists():
        return status_row(category, "FAIL", f"artifact not found: {path}")
    raw = path.read_text(encoding="utf-8", errors="replace")
    data: Any = None
    statuses = []
    if path.suffix.lower() in {".md", ".markdown"}:
        for line in raw.splitlines():
            if "verdict" in line.lower() or re.search(r"\|\s*(PASS|FAIL|SKIP|PASSED|FAILED)\s*\|", line, flags=re.I):
                statuses.extend(value.upper() for value in re.findall(r"\b(PASS|FAIL|SKIP|PASSED|FAILED)\b", line, flags=re.I))
    else:
        try:
            data = json.loads(raw)
        except Exception as exc:
            return status_row(category, "FAIL", f"artifact is not valid JSON: {exc}")
    if isinstance(data, dict):
        if isinstance(data.get("checks"), list):
            statuses += [str(x.get("status", "")).upper() for x in data["checks"] if isinstance(x, dict)]
        if isinstance(data.get("results"), list):
            statuses += [str(x.get("status", x.get("verdict", ""))).upper() for x in data["results"] if isinstance(x, dict)]
        if isinstance(data.get("phases"), dict):
            statuses += [str(x.get("status", "")).upper() for x in data["phases"].values() if isinstance(x, dict)]
        if data.get("verdict"):
            statuses.append(str(data["verdict"]).upper())
        if data.get("summary") and isinstance(data["summary"], dict):
            summary = data["summary"]
            statuses += [str(summary.get("status", "")).upper()]
            if "cycles" in summary:
                statuses.append("PASS" if int(summary.get("cycles", 0)) > 0 and int(summary.get("cycles_failed", 1)) == 0 else "FAIL")
        if "requests" in data and "error_rate" in data:
            statuses.append("PASS" if float(data.get("error_rate", 1.0)) <= 0.01 else "FAIL")
        if "cycles" in data and "cycles_failed" in data:
            statuses.append("PASS" if int(data.get("cycles", 0)) > 0 and int(data.get("cycles_failed", 1)) == 0 else "FAIL")
    forbidden = {"FAIL", "FAILED", "ERROR"}
    # An artifact may contain SKIP phases, but the category remains SKIP until
    # external evidence is complete. This prevents a report with one passing
    # probe and four skipped probes from being read as a qualified service.
    if any(value in forbidden for value in statuses):
        verdict = "FAIL"
    elif not statuses:
        verdict = "SKIP"
    elif any(value in {"SKIP", "PENDING", "NOT_RUN"} for value in statuses):
        verdict = "SKIP"
    else:
        verdict = "PASS" if all(value in {"PASS", "PASSED", "OK"} for value in statuses) else "SKIP"
    return status_row(category, verdict, f"artifact={path}; sha256={sha256(path)}", artifact=str(path), artifact_sha256=sha256(path), observed_statuses=sorted(set(statuses)))


# Dependency trees and generated output contain their own documentation and
# links. They are not product documentation and routinely contain links that
# only resolve in the package's source repository. Scanning them made the
# readiness result depend on whether `npm ci` or a local build had run.
DOCUMENTATION_IGNORED_PARTS = frozenset({
    ".git", ".venv", "venv", "node_modules", "dist", "build", "coverage",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".next", ".nuxt", "out",
})


def _ignored_path(path: Path, root: Path) -> bool:
    try:
        parts = path.resolve().relative_to(root.resolve()).parts
    except ValueError:
        return True
    return bool(DOCUMENTATION_IGNORED_PARTS.intersection(parts))


def _markdown_files(root: Path) -> list[Path]:
    return sorted(
        path for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in {".md", ".markdown"}
        and not _ignored_path(path, root)
    )


def _link_target(root: Path, source: Path, link: str) -> Path | None:
    """Resolve a Markdown link without treating URLs as filesystem paths."""
    value = link.strip()
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or value.startswith("#"):
        return None
    target = parsed.path
    if not target:
        return None
    # `/foo` is site-root-relative in Markdown, not the host filesystem root.
    if target.startswith("/"):
        return (root / target.lstrip("/")).resolve()
    return (source.parent / target).resolve()


def documentation_link_findings(root: Path = ROOT) -> tuple[list[str], int]:
    """Return broken product-documentation links and files checked.

    This function is intentionally independent of the required-file policy so
    it can be tested against a temporary miniature repository. The scan never
    descends into dependency/build directories, making the gate reproducible
    before and after a frontend/backend build.
    """
    broken: list[str] = []
    markdown = _markdown_files(root)
    for path in markdown:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for link in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
            target = _link_target(root, path, link)
            if target is not None and not target.exists():
                broken.append(f"{path.relative_to(root)} -> {link}")
    return broken, len(markdown)


def docs_check() -> dict:
    required = [
        ROOT / "docs" / "accuracy" / "BANK-READINESS.md",
        ROOT / "docs" / "accuracy" / "DUBAI-BANKS-E2E.md",
        ROOT / "BACKEND-DATABASE-GAPS.md",
        ROOT / "PRODUCTION-READINESS.md",
    ]
    missing = [str(p.relative_to(ROOT)) for p in required if not p.exists()]
    broken, checked = documentation_link_findings(ROOT)
    if missing or broken:
        return status_row(
            "documentation",
            "FAIL",
            f"missing={len(missing)} broken_links={len(broken)} checked={checked}",
            missing=missing,
            broken_links=broken[:100],
            checked_files=checked,
            ignored_directories=sorted(DOCUMENTATION_IGNORED_PARTS),
        )
    return status_row(
        "documentation",
        "PASS",
        f"checked {checked} Markdown files and required readiness documents",
        checked_files=checked,
        ignored_directories=sorted(DOCUMENTATION_IGNORED_PARTS),
    )


def operational_policy_check(path: Path = OPERATIONAL_POLICY) -> dict:
    """Validate the policy shape without treating a draft as approved.

    The operational-policy gate owns the approval boundary. This readiness
    report only records whether the checked-in/customer-supplied policy is
    structurally complete; strict approval remains a separate release action.
    """
    if not path.exists():
        return status_row("operational_policy", "FAIL", f"policy not found: {path}")
    try:
        import importlib.util

        spec = importlib.util.spec_from_file_location("operational_policy_gate", ROOT / "scripts" / "operational_policy_gate.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load operational policy validator")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        policy = module._load(path)
        findings = module.validate(policy)
    except SystemExit as exc:
        return status_row("operational_policy", "FAIL", str(exc))
    except Exception as exc:  # validator/import faults must not become a false PASS
        return status_row("operational_policy", "FAIL", f"validator error: {type(exc).__name__}")
    return status_row(
        "operational_policy",
        "PASS" if not findings else "FAIL",
        f"structural findings={len(findings)}; status={policy.get('status')}",
        policy=str(path),
        policy_status=policy.get("status"),
        findings=findings,
        approval_required="run operational_policy_gate.py --strict for release approval",
    )


def readiness_closure_check(path: Path | None = None) -> dict:
    """Collect the aggregate P0/P1 closure result without inferring evidence."""
    if path is None:
        return status_row(
            "readiness_closure",
            "SKIP",
            "no P0/P1 closure manifest supplied; external evidence is not inferred",
        )
    if not path.exists():
        return status_row("readiness_closure", "FAIL", f"closure manifest not found: {path}")
    try:
        import importlib.util

        script = ROOT / "scripts" / "readiness_closure_gate.py"
        spec = importlib.util.spec_from_file_location("readiness_closure_gate", script)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load readiness closure validator")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        policy = module.load_json(module.POLICY)
        manifest = module.load_json(path)
        expected = git_metadata()["commit"]
        findings = module.validate_policy(policy) + module.validate_manifest(policy, manifest, expected)
        report = module.render_report(policy, manifest, expected, findings, datetime.now(timezone.utc))
    except (ValueError, OSError) as exc:
        return status_row("readiness_closure", "FAIL", f"closure validation error: {type(exc).__name__}")
    except Exception as exc:  # validator faults must not become a false PASS
        return status_row("readiness_closure", "FAIL", f"closure validator error: {type(exc).__name__}")
    return status_row(
        "readiness_closure",
        report["verdict"],
        f"closed={report['closed_gaps']}/{report['total_gaps']}; findings={len(findings)}",
        manifest=str(path),
        findings=findings,
        closed_gaps=report["closed_gaps"],
        total_gaps=report["total_gaps"],
    )


def run_engineering(out: Path) -> tuple[int, Path]:
    target = out.parent / "engineering-gate.json"
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "engineering_gate.py"), "--out", str(target)], cwd=ROOT, check=False)
    return proc.returncode, target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "readiness-evidence" / "bank-readiness.json")
    ap.add_argument("--engineering", type=Path, default=None)
    ap.add_argument("--postgresql-dr", type=Path, default=None)
    ap.add_argument("--hsm", type=Path, default=None)
    ap.add_argument("--integrations", type=Path, default=None)
    ap.add_argument("--compliance", type=Path, default=None)
    ap.add_argument("--load-soak", type=Path, default=None)
    ap.add_argument("--operational-policy", type=Path, default=OPERATIONAL_POLICY)
    ap.add_argument("--readiness-closure", type=Path, default=None, help="P0/P1 closure manifest from a controlled evidence owner")
    ap.add_argument("--external-attestations", type=Path, default=None)
    ap.add_argument("--production-evidence", type=Path, default=None, help="optional signed/digest-only scripts/production_evidence.py report; retained as an additional orchestrator source")
    ap.add_argument("--run-engineering", action="store_true", help="run static engineering checks before collecting the report")
    ap.add_argument("--strict", action="store_true", help="fail on every required SKIP or FAIL")
    args = ap.parse_args(argv)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    source_state = git_metadata()
    engineering_path = args.engineering
    if args.run_engineering or engineering_path is None:
        _, engineering_path = run_engineering(args.out)

    rows = [
        artifact(engineering_path, "engineering"),
        artifact(args.postgresql_dr, "postgresql_dr"),
        artifact(args.hsm, "hsm"),
        artifact(args.integrations or args.production_evidence, "integrations"),
        artifact(args.compliance, "compliance"),
        artifact(args.load_soak, "load_soak"),
        docs_check(),
        operational_policy_check(args.operational_policy),
        readiness_closure_check(args.readiness_closure),
        artifact(args.external_attestations, "external_attestations"),
    ]
    if args.production_evidence:
        rows.append(artifact(args.production_evidence, "production_orchestrator"))
    report = {
        "schema": "cryptoscan.bank-readiness/1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "repository": source_state,
        "artifact_generation_state": git_metadata(),
        "command": " ".join([sys.executable, *sys.argv]),
        "environment": {"environment": os.getenv("ENVIRONMENT", "unset"), "ci": bool(os.getenv("CI"))},
        "required_categories": list(REQUIRED_CATEGORIES),
        "categories": rows,
        "external_evidence_boundary": "PASS means only that the supplied artifact contained no FAIL/SKIP statuses. Missing customer/provider evidence is never inferred from source code, mocks, documentation or local SoftHSM.",
    }
    statuses = {row["category"]: row["status"] for row in rows}
    report["verdict"] = "PASS" if all(statuses.get(category) == "PASS" for category in REQUIRED_CATEGORIES) else "FAIL"
    if report["verdict"] == "PASS":
        report["deployment_recommendation"] = "unattended production candidate, subject to signed approval and retained external evidence"
    elif statuses.get("engineering") == "PASS" and all(statuses.get(x) in {"SKIP", "PASS"} for x in REQUIRED_CATEGORIES):
        report["deployment_recommendation"] = "pilot or pre-production only; external qualification evidence is incomplete"
    else:
        report["deployment_recommendation"] = "do not approve production; remediation and/or evidence collection required"
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md = args.out.with_suffix(".md")
    lines = ["# Bank readiness evidence report", "", f"Captured: `{report['captured_at']}`", f"Commit: `{report['repository']['commit']}`", f"Verdict: **{report['verdict']}**", f"Recommendation: **{report['deployment_recommendation']}**", "", "| Category | Status | Detail |", "|---|---|---|"]
    lines += [f"| {row['category']} | {row['status']} | {row['detail']} |" for row in rows]
    lines += ["", "## Boundary", "", report["external_evidence_boundary"], "", "## Evidence handling", "", "Attach provider logs, database logs, test commands, signed attestations and retention metadata next to this report. A digest is integrity evidence, not proof of origin or customer execution."]
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Bank readiness verdict: {report['verdict']} -> {args.out}")
    if args.strict and report["verdict"] != "PASS":
        return 1
    return 0 if report["verdict"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
