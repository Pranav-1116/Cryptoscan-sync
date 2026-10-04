#!/usr/bin/env python3
"""Measure repository operational deployment readiness without faking production evidence.

This is a repository-control score, not a production qualification score.  It
answers: "how much of the deployment control plane is implemented and
checkable in this checkout?" It deliberately reserves the remaining points
for evidence that cannot be created by source inspection: real DR/restore,
provider/HSM qualification, customer integrations, load/soak, compliance and
independent security review.

The command emits JSON and Markdown so an operator can retain the result with a
release record::

    python scripts/operational_deployment_readiness.py \
        --out /tmp/operational-deployment-readiness.json \
        --markdown /tmp/operational-deployment-readiness.md

A passing repository score supports supervised staging preparation only. It
never changes the fail-closed production qualification decision.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "cryptoscan.operational-deployment-readiness/1"
TOTAL_SCORE = 100
REPOSITORY_SCORE_CAP = 85


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    points: int
    check: Callable[[Path], tuple[bool, str]]


def _read(root: Path, relative: str) -> str:
    path = root / relative
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _present(root: Path, paths: tuple[str, ...]) -> tuple[bool, str]:
    missing = [path for path in paths if not (root / path).is_file() or (root / path).stat().st_size == 0]
    return (not missing, "all required files are present" if not missing else f"missing or empty: {', '.join(missing)}")


def _contains(root: Path, paths: tuple[str, ...], needles: tuple[str, ...], label: str) -> tuple[bool, str]:
    ok, detail = _present(root, paths)
    if not ok:
        return False, detail
    missing: list[str] = []
    for needle in needles:
        if not any(needle in _read(root, path) for path in paths):
            missing.append(needle)
    return (not missing, f"{label} is implemented" if not missing else f"{label} missing markers: {', '.join(missing)}")


def _runtime_gate(root: Path) -> tuple[bool, str]:
    paths = (
        "services/api/api/config/settings.py",
        "services/api/api/main.py",
        "services/api/api/routers/health.py",
    )
    return _contains(root, paths, ("ENVIRONMENT", "production", "validate_runtime_settings", "503"), "fail-closed runtime/readiness gate")


def _migration_ownership(root: Path) -> tuple[bool, str]:
    paths = (
        "services/database/db/connection/session.py",
        "services/database/migrations/alembic.ini",
        "docker-compose.prod.yml",
    )
    ok, detail = _present(root, paths)
    if not ok:
        return False, detail
    session = _read(root, paths[0])
    compose = _read(root, paths[2])
    markers = ("migration_status", "alembic_version", "migrate", "upgrade", "service_completed_successfully")
    missing = [marker for marker in markers if marker not in session + compose]
    return (not missing, "PostgreSQL migration ownership and startup ordering are checkable" if not missing else f"migration markers missing: {', '.join(missing)}")


def _auth_tenant(root: Path) -> tuple[bool, str]:
    paths = (
        "services/api/api/middleware/auth_middleware.py",
        "services/api/api/middleware/tenant_scope.py",
        "services/api/api/dependencies.py",
        "frontend/src/lib/api.ts",
    )
    return _contains(root, paths, ("Authorization", "tenant", "tenantFetch", "credentials"), "authenticated tenant boundary")


def _deployment_artifacts(root: Path) -> tuple[bool, str]:
    paths = (
        ".docker/api/Dockerfile",
        ".docker/worker/Dockerfile",
        ".docker/frontend/Dockerfile",
        "docker-compose.yml",
        "docker-compose.prod.yml",
        "k8s/app/20-api-deployment.yaml",
        "k8s/app/30-worker-deployment.yaml",
    )
    ok, detail = _present(root, paths)
    if not ok:
        return False, detail
    compose = _read(root, "docker-compose.prod.yml")
    k8s = _read(root, "k8s/app/20-api-deployment.yaml") + _read(root, "k8s/app/30-worker-deployment.yaml")
    missing = [marker for marker in ("service_completed_successfully", "replicas:", "resources:", "readinessProbe:") if marker not in compose + k8s]
    return (not missing, "Compose production overlay and Kubernetes workload manifests are present" if not missing else f"deployment markers missing: {', '.join(missing)}")


def _runtime_security(root: Path) -> tuple[bool, str]:
    dockerfiles = (".docker/api/Dockerfile", ".docker/worker/Dockerfile", ".docker/frontend/Dockerfile")
    k8s = ("k8s/app/20-api-deployment.yaml", "k8s/app/30-worker-deployment.yaml")
    ok, detail = _present(root, dockerfiles + k8s)
    if not ok:
        return False, detail
    text = "\n".join(_read(root, path) for path in dockerfiles + k8s) + _read(root, "docker-compose.prod.yml")
    markers = ("USER cryptoscan", "runAsNonRoot: true", "allowPrivilegeEscalation: false", "drop: [\"ALL\"]", "no-new-privileges")
    missing = [marker for marker in markers if marker not in text]
    return (not missing, "non-root and privilege-drop controls are declared" if not missing else f"runtime security markers missing: {', '.join(missing)}")


def _observability(root: Path) -> tuple[bool, str]:
    paths = (
        "services/api/api/routers/health.py",
        "services/api/api/routers/metrics.py",
        "infra/monitoring/prometheus/prometheus.yml",
        "k8s/app/20-api-deployment.yaml",
    )
    return _contains(root, paths, ("health", "ready", "metrics", "readinessProbe", "livenessProbe"), "health, readiness and metrics surfaces")


def _recovery_harness(root: Path) -> tuple[bool, str]:
    paths = (
        "scripts/db_backup.sh",
        "scripts/db_restore.sh",
        "scripts/backup_drill.py",
        "scripts/backup_evidence.py",
        "docs/admin-guide/backup-restore.md",
    )
    return _contains(root, paths, ("sha256", "restore", "backup", "verify"), "backup/restore and evidence harness")


def _release_controls(root: Path) -> tuple[bool, str]:
    paths = (
        "scripts/release_check.py",
        "scripts/deploy_prod.sh",
        "scripts/check_prod_guard.py",
        "scripts/rollback_plan.py",
        "docs/ops/production-checklist.md",
        "docs/operations/operational-deployment-readiness.md",
    )
    return _contains(root, paths, ("migrations", "production", "check", "rollback", "PLAN_ONLY"), "release, rollback and production checklist controls")


def _frontend_boundary(root: Path) -> tuple[bool, str]:
    api = _read(root, "frontend/src/lib/api.ts")
    source_root = root / "frontend" / "src"
    if not api or not source_root.is_dir():
        return False, "frontend API wrapper or source tree is missing"
    direct_fetch: list[str] = []
    direct_navigation: list[str] = []
    for path in source_root.rglob("*"):
        if not path.is_file() or path.name.endswith((".test.ts", ".test.tsx")):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = str(path.relative_to(root))
        if relative != "frontend/src/lib/api.ts" and re.search(r"\bfetch\s*\(", text):
            direct_fetch.append(relative)
        if re.search(r"(?:href|src)\s*=\s*['\"]/?api/", text):
            direct_navigation.append(relative)
    good = "tenantFetch" in api and "credentials" in api and not direct_fetch and not direct_navigation
    detail = "all frontend requests use the authenticated API boundary" if good else f"direct fetch files={direct_fetch}; direct API navigations={direct_navigation}"
    return good, detail


def _regression_tests(root: Path) -> tuple[bool, str]:
    paths = (
        "services/database/tests/unit/test_production_database_gate.py",
        "services/api/tests/unit/test_production_hardening.py",
        "services/api/tests/unit/test_ha_readiness.py",
        "services/api/tests/unit/test_events_stream.py",
        "frontend/src/lib/api.test.ts",
    )
    return _present(root, paths)


def _runbooks(root: Path) -> tuple[bool, str]:
    paths = (
        "docs/admin-guide/production.md",
        "docs/admin-guide/backup-restore.md",
        "docs/ops/production-checklist.md",
        "docs/ops/on-call-and-comms.md",
        "docs/architecture/REALTIME-PRODUCTION-READINESS.md",
    )
    return _present(root, paths)


CONTROLS: tuple[Control, ...] = (
    Control("runtime-fail-closed", "Fail-closed runtime and readiness gates", 8, _runtime_gate),
    Control("migration-ownership", "PostgreSQL migration ownership and ordering", 8, _migration_ownership),
    Control("auth-tenant-boundary", "Authenticated tenant isolation boundary", 10, _auth_tenant),
    Control("deployment-artifacts", "Production Compose and Kubernetes deployment artifacts", 10, _deployment_artifacts),
    Control("runtime-security", "Non-root and privilege-reduction controls", 8, _runtime_security),
    Control("observability", "Health, readiness and metrics surfaces", 8, _observability),
    Control("recovery-harness", "Backup, restore and evidence harnesses", 8, _recovery_harness),
    Control("release-controls", "Release and go-live control procedures", 7, _release_controls),
    Control("frontend-boundary", "Centralized authenticated frontend request boundary", 6, _frontend_boundary),
    Control("regression-tests", "Repository regression coverage for hardening", 6, _regression_tests),
    Control("runbooks", "Operational deployment and recovery runbooks", 6, _runbooks),
)


def _git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    except OSError:
        return ""
    return result.stdout.strip()


def evaluate(root: Path = ROOT, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    rows = []
    earned = 0
    for control in CONTROLS:
        try:
            passed, detail = control.check(root)
        except Exception as exc:  # a readiness diagnostic must report, not hide, a broken check
            passed, detail = False, f"checker error: {type(exc).__name__}: {exc}"
        if passed:
            earned += control.points
        rows.append({
            "id": control.control_id,
            "title": control.title,
            "status": "PASS" if passed else "FAIL",
            "points": control.points if passed else 0,
            "available_points": control.points,
            "detail": detail,
        })

    external_reserve = TOTAL_SCORE - REPOSITORY_SCORE_CAP
    band = "80-90%" if earned >= 80 else "below-80%"
    return {
        "schema": SCHEMA,
        "generated_at": now.astimezone(timezone.utc).isoformat(),
        "repository": {
            "root": str(root),
            "commit": _git(root, "rev-parse", "HEAD"),
            "branch": _git(root, "branch", "--show-current"),
            "working_tree": "clean" if not _git(root, "status", "--porcelain") else "dirty",
        },
        "score": {
            "value": earned,
            "maximum_repository_controls": REPOSITORY_SCORE_CAP,
            "overall_scale": TOTAL_SCORE,
            "band": band,
            "meaning": "implemented repository deployment controls only; not production qualification",
        },
        "external_qualification_reserve": {
            "points": external_reserve,
            "status": "UNVERIFIED",
            "categories": [
                "real PostgreSQL DR/restore and measured RPO/RTO",
                "HSM/provider qualification",
                "customer integrations and escalation",
                "target-environment load/soak",
                "compliance and independent security review",
            ],
        },
        "deployment_recommendation": "SUPERVISED_STAGING_PREPARATION" if earned >= 80 else "REMEDIATION_REQUIRED",
        "production_qualification": "BLOCKED_UNTIL_EXTERNAL_EVIDENCE",
        "controls": rows,
        "safety": {
            "destructive_commands_run": False,
            "production_changes_run": False,
            "external_evidence_inferred": False,
        },
    }


def write_markdown(report: dict, path: Path) -> None:
    score = report["score"]
    lines = [
        "# Operational deployment readiness",
        "",
        f"Repository-control score: **{score['value']}/{score['overall_scale']} ({score['band']})**",
        "",
        "> This score measures implemented, repository-checkable deployment controls. It is not a production approval and does not create DR, HSM/provider, customer, compliance, load/soak or independent-review evidence.",
        "",
        f"Generated: `{report['generated_at']}`  ",
        f"Commit: `{report['repository']['commit'] or 'unknown'}`  ",
        f"Working tree: `{report['repository']['working_tree']}`",
        "",
        "## Controls",
        "",
        "| Control | Status | Points | Detail |",
        "|---|---:|---:|---|",
    ]
    for row in report["controls"]:
        lines.append(f"| {row['title']} | **{row['status']}** | {row['points']}/{row['available_points']} | {row['detail']} |")
    lines.extend([
        "",
        "## Explicit boundary",
        "",
        f"The repository-control score is capped at `{REPOSITORY_SCORE_CAP}` points. The remaining `{report['external_qualification_reserve']['points']}` points are reserved for external qualification and remain **UNVERIFIED**.",
        "",
        "Production qualification remains **BLOCKED_UNTIL_EXTERNAL_EVIDENCE**. A passing score supports supervised staging preparation only.",
        "",
        "No destructive production, DR, restore, outage, revocation, certificate-replacement or key-rotation command is run by this diagnostic.",
    ])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args(argv)
    report = evaluate(args.root.resolve())
    print(f"Operational deployment readiness: {report['score']['value']}/{report['score']['overall_scale']} ({report['score']['band']})")
    for row in report["controls"]:
        print(f"{row['status']:<4} {row['id']}: {row['detail']}")
    print(f"Production qualification: {report['production_qualification']}")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        write_markdown(report, args.markdown)
    return 0 if report["score"]["value"] >= 80 else 1


if __name__ == "__main__":
    raise SystemExit(main())
