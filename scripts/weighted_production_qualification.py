#!/usr/bin/env python3
"""Report weighted production qualification without converting unknown evidence to a score.

The weighted view has three categories:

* engineering controls: 40 points;
* operational deployment controls: 45 points; and
* external qualification evidence: 15 points.

The first two categories are measurable from this repository. The external
category is intentionally ``UNVERIFIED`` until a retained evidence envelope is
supplied. Consequently, the overall production qualification is not calculated
when external evidence is missing. The repository-only implementation score is
reported separately as 85/100 (the requested 80-90% band).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from operational_deployment_readiness import evaluate  # noqa: E402

SCHEMA = "cryptoscan.weighted-production-qualification/1"
ENGINEERING_WEIGHT = 40
OPERATIONS_WEIGHT = 45
EXTERNAL_WEIGHT = 15

ENGINEERING_CONTROLS = (
    "runtime-fail-closed",
    "migration-ownership",
    "auth-tenant-boundary",
    "frontend-boundary",
    "regression-tests",
)
OPERATIONS_CONTROLS = (
    "deployment-artifacts",
    "runtime-security",
    "observability",
    "recovery-harness",
    "release-controls",
    "runbooks",
)
EXTERNAL_CATEGORIES = (
    "postgresql_dr",
    "hsm",
    "integrations",
    "compliance",
    "load_soak",
    "external_attestations",
)


def _category(rows: dict[str, dict[str, Any]], control_ids: tuple[str, ...], weight: int) -> dict[str, Any]:
    selected = [rows[control_id] for control_id in control_ids if control_id in rows]
    passed = sum(1 for row in selected if row.get("status") == "PASS")
    available = len(selected)
    points = round(weight * passed / available, 2) if available else 0
    return {
        "status": "PASS" if available == len(control_ids) and passed == available else "FAIL",
        "points": points,
        "weight": weight,
        "passed_controls": passed,
        "total_controls": available,
        "controls": list(control_ids),
    }


def _external(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {
            "status": "UNVERIFIED",
            "points": None,
            "weight": EXTERNAL_WEIGHT,
            "reason": "no retained external evidence envelope supplied",
            "categories": list(EXTERNAL_CATEGORIES),
        }
    if not path.is_file():
        return {
            "status": "FAIL",
            "points": 0,
            "weight": EXTERNAL_WEIGHT,
            "reason": f"evidence envelope not found: {path}",
            "artifact": str(path),
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {
            "status": "FAIL",
            "points": 0,
            "weight": EXTERNAL_WEIGHT,
            "reason": f"evidence envelope is not valid JSON: {type(exc).__name__}",
            "artifact": str(path),
        }
    rows = payload.get("categories") if isinstance(payload, dict) else None
    by_name = {
        str(row.get("category")): str(row.get("status", "")).upper()
        for row in rows or []
        if isinstance(row, dict) and row.get("category")
    }
    missing = [name for name in EXTERNAL_CATEGORIES if name not in by_name]
    failed = [name for name in EXTERNAL_CATEGORIES if by_name.get(name) in {"FAIL", "FAILED", "ERROR"}]
    skipped = [name for name in EXTERNAL_CATEGORIES if by_name.get(name) not in {"PASS", "PASSED", "OK"} and name not in failed]
    if failed:
        status, points, reason = "FAIL", 0, f"failed categories: {', '.join(failed)}"
    elif missing or skipped:
        status, points, reason = "UNVERIFIED", None, f"missing or non-pass categories: {', '.join(sorted(set(missing + skipped)))}"
    else:
        status, points, reason = "PASS", EXTERNAL_WEIGHT, "all required external evidence categories are marked PASS in the supplied envelope"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "status": status,
        "points": points,
        "weight": EXTERNAL_WEIGHT,
        "reason": reason,
        "artifact": str(path),
        "artifact_sha256": digest,
        "observed_categories": by_name,
    }


def build_report(root: Path = ROOT, external_path: Path | None = None) -> dict[str, Any]:
    repository = evaluate(root)
    rows = {row["id"]: row for row in repository["controls"]}
    engineering = _category(rows, ENGINEERING_CONTROLS, ENGINEERING_WEIGHT)
    operations = _category(rows, OPERATIONS_CONTROLS, OPERATIONS_WEIGHT)
    external = _external(external_path)
    overall = None
    if external["status"] == "PASS" and engineering["status"] == "PASS" and operations["status"] == "PASS":
        overall = round(engineering["points"] + operations["points"] + EXTERNAL_WEIGHT, 2)
    implementation = round(engineering["points"] + operations["points"], 2)
    return {
        "schema": SCHEMA,
        "generated_at": repository["generated_at"],
        "repository": repository["repository"],
        "weighted_view": {
            "engineering": engineering,
            "operations": operations,
            "external_evidence": external,
            "overall_points": overall,
            "overall_weight": ENGINEERING_WEIGHT + OPERATIONS_WEIGHT + EXTERNAL_WEIGHT,
            "overall_status": "PASS" if overall is not None else "BLOCKED_UNVERIFIED_EXTERNAL_EVIDENCE",
        },
        "repository_implementation": {
            "points": implementation,
            "scale": ENGINEERING_WEIGHT + OPERATIONS_WEIGHT,
            "normalized_score": repository["score"]["value"],
            "band": repository["score"]["band"],
            "meaning": "engineering and operational deployment controls only",
        },
        "production_qualification": "BLOCKED_UNTIL_EXTERNAL_EVIDENCE" if overall is None else "QUALIFIED_FOR_REVIEW",
        "boundary": "Unknown, missing or unverified external evidence never receives production qualification points.",
        "safety": repository["safety"],
    }


def write_markdown(report: dict[str, Any], path: Path) -> None:
    view = report["weighted_view"]
    lines = [
        "# Weighted production qualification",
        "",
        f"Production qualification: **{report['production_qualification']}**",
        f"Repository implementation score: **{report['repository_implementation']['normalized_score']}/100 ({report['repository_implementation']['band']})**",
        "",
        "> Engineering and operations are implemented repository controls. External evidence is a separate qualification category and is not inferred from code, tests, runbooks, mocks or local tools.",
        "",
        "| Category | Points | Status |",
        "|---|---:|---|",
        f"| Engineering | {view['engineering']['points']}/{view['engineering']['weight']} | {view['engineering']['status']} |",
        f"| Operations | {view['operations']['points']}/{view['operations']['weight']} | {view['operations']['status']} |",
        f"| External evidence | {view['external_evidence']['points'] if view['external_evidence']['points'] is not None else 'UNVERIFIED'}/{view['external_evidence']['weight']} | {view['external_evidence']['status']} |",
        "",
        f"Overall weighted result: **{view['overall_points'] if view['overall_points'] is not None else 'NOT CALCULATED'}/{view['overall_weight']}**",
        "",
        "No DR/restore, HSM/provider, customer integration, compliance, load/soak or independent security-review outcome is claimed by this report.",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--external-evidence", type=Path, help="retained JSON envelope with PASS categories; omitted means UNVERIFIED")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args(argv)
    report = build_report(ROOT, args.external_evidence)
    view = report["weighted_view"]
    print(f"Repository implementation readiness: {report['repository_implementation']['normalized_score']}/100 ({report['repository_implementation']['band']})")
    print(f"Weighted production qualification: {view['overall_points'] if view['overall_points'] is not None else 'NOT CALCULATED'} / {view['overall_weight']} ({view['overall_status']})")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        write_markdown(report, args.markdown)
    return 0 if report["production_qualification"] != "BLOCKED_UNTIL_EXTERNAL_EVIDENCE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
