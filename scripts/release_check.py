#!/usr/bin/env python3
"""Production release gate — one command before you tag and deploy.

Cross-checks that the tree you are about to tag as v<VERSION> is actually a
coherent release:

  * VERSION file is semver and equals the API's declared API_VERSION
  * CHANGELOG.md carries a dated ``## [<version>]`` section
  * git tag ``v<version>`` exists (or ``--allow-untagged`` for a dry run)
    and sits on the current HEAD
  * ordered database migrations (NNNN_*) have no gaps
  * the fails-closed production config guard still rejects demo secrets
    (``scripts/check_prod_guard.py --expect-reject``)
  * when run with ENVIRONMENT=production: the real config PASSES the guard
  * the self-SBOM artifact exists and is newer than the VERSION file

Usage:
  python3 scripts/release_check.py                  # full gate
  python3 scripts/release_check.py --allow-untagged # pre-tag dry run

Exit codes: 0 = release-consistent, 1 = blocking findings (see output).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

from shared_models.release_version import (  # noqa: E402
    ERROR,
    WARN,
    Finding,
    migration_gaps,
    validate_release,
)

ROOT = Path(__file__).resolve().parents[1]


def _git(args: list[str]) -> str:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, cwd=ROOT, check=True
    ).stdout.strip()


def _head_tagged(expected_tag: str) -> bool:
    """True when HEAD carries ``expected_tag`` exactly."""
    result = subprocess.run(
        ["git", "describe", "--exact-match", "--tags", "HEAD"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == expected_tag


def _api_version() -> str:
    from api.config.settings import APISettings

    # Class-level default: no instantiation, so no environment is read.
    return str(APISettings.model_fields["API_VERSION"].default)


def _sbom_finding(version_text: str) -> Finding | None:
    sbom = ROOT / "dist" / "cryptoscan-sbom.cdx.json"
    version_file = ROOT / "VERSION"
    if not sbom.is_file():
        return Finding("sbom", WARN, "dist/cryptoscan-sbom.cdx.json missing — run 'make sbom' and archive it with the release")
    if sbom.stat().st_mtime < version_file.stat().st_mtime:
        return Finding("sbom", WARN, "SBOM predates the current VERSION — regenerate: make sbom")
    if f'"{version_text}"' not in sbom.read_text()[:4096]:
        return Finding("sbom", WARN, f"SBOM header does not carry version {version_text} — regenerate: make sbom")
    return None


_DEMO_PROD_ENV = {
    # Mirrors the CI prod-config-guard reject step: a production environment
    # still carrying demo defaults MUST be rejected.
    "ENVIRONMENT": "production",
    "SECRET_KEY": "cryptoscan-dev-secret",
    "DATABASE_URL": "sqlite:///./data/demo.db",
    "CORS_ORIGINS": "*",
}

_VALID_PROD_ENV = {
    # Mirrors the CI accept step: a fully specified production configuration
    # MUST pass (catches the guard over-tightening into unusability).
    "ENVIRONMENT": "production",
    "SECRET_KEY": "ci-only-production-guard-secret-key-0123456789abcdef",
    "ADMIN_PASSWORD_HASH": "ci-only-placeholder-hash",
    "GITHUB_WEBHOOK_SECRET": "ci-only-webhook-secret-0123456789abcdef",
    "DATABASE_URL": "postgresql://ci:ci@localhost:5432/ci",
    "CORS_ORIGINS": "https://cryptoscan.example.com",
}


def _run_guard(overrides: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(overrides)
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_prod_guard.py"), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
        check=False,
    )


def _prod_guard_findings() -> list[Finding]:
    findings: list[Finding] = []
    if _run_guard(_DEMO_PROD_ENV, "--expect-reject").returncode != 0:
        findings.append(
            Finding(
                "prod-guard-rejects-demo",
                ERROR,
                "the fails-closed production guard ACCEPTED a demo configuration — "
                "the API would boot with demo secrets; see scripts/check_prod_guard.py",
            )
        )
    if _run_guard(_VALID_PROD_ENV).returncode != 0:
        findings.append(
            Finding(
                "prod-guard-accepts-valid",
                ERROR,
                "the production guard REJECTED a fully specified production "
                "configuration — the guard has drifted too strict",
            )
        )
    if os.environ.get("ENVIRONMENT", "").lower() == "production":
        result = _run_guard({})
        if result.returncode != 0:
            findings.append(
                Finding(
                    "prod-guard-this-config",
                    ERROR,
                    "the CURRENT production environment fails its own "
                    "configuration guard",
                )
            )
    return findings


def collect(allow_untagged: bool) -> list[Finding]:
    version_text = (ROOT / "VERSION").read_text()
    changelog_text = (ROOT / "CHANGELOG.md").read_text()
    tags = _git(["tag", "--list"]).split()
    migrations_dir = ROOT / "services" / "database" / "migrations" / "versions"

    findings = validate_release(
        version_text=version_text,
        api_version=_api_version(),
        changelog_text=changelog_text,
        tags=tags,
        head_tagged=_head_tagged(f"v{version_text.strip()}"),
        allow_untagged=allow_untagged,
    )

    gaps = migration_gaps([p.name for p in migrations_dir.glob("*.py")])
    if gaps:
        findings.append(
            Finding(
                "migrations-contiguous",
                ERROR,
                f"ordered migrations have gaps at {gaps} — renumber before release",
            )
        )

    sbom = _sbom_finding(version_text.strip())
    if sbom is not None:
        findings.append(sbom)

    findings.extend(_prod_guard_findings())
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-untagged",
        action="store_true",
        help="pre-tag dry run: a missing v<version> tag warns instead of failing",
    )
    args = parser.parse_args()

    findings = collect(args.allow_untagged)
    errors = [f for f in findings if f.blocking]
    warns = [f for f in findings if not f.blocking]

    version = (ROOT / "VERSION").read_text().strip()
    if errors:
        print(f"release-check: FAIL — tree is not release-consistent for {version}")
        for finding in errors:
            print(f"  ERROR [{finding.check}] {finding.message}")
    else:
        print(f"release-check: PASS — v{version} is release-consistent")
    for finding in warns:
        print(f"  warn  [{finding.check}] {finding.message}")
    if not findings:
        print("  (no warnings)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
