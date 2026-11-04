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
  * Kubernetes runtime images use immutable OCI digests, not release tags
  * fresh production evidence: scripts/production_evidence.py runs the full
    gate (prod guard both ways, smoke, load with production rate limiting,
    DR drill where the host can run it) and appends a signed, tamper-evident
    entry to the evidence chain FOR THIS RELEASE version; any FAILED phase
    blocks the release. Opt out explicitly with --no-evidence (the output
    says plainly that the release was cut without fresh evidence).

Usage:
  python3 scripts/release_check.py                  # full gate + evidence
  python3 scripts/release_check.py --allow-untagged # pre-tag dry run
  python3 scripts/release_check.py --no-evidence    # no fresh evidence entry
  python3 scripts/release_check.py --release-manifests /secure/releases/v1/k8s
  python3 scripts/release_check.py --release-manifests /secure/releases/v1/k8s \
    --require-release-attestation --release-attestation /secure/releases/v1/k8s/release-attestation.json \
    --release-public-key /secure/trust/release-authority.pub.pem

For an approval release, also supply the controlled P0/P1 evidence envelope:

    python scripts/release_check.py --require-readiness-closure \
        --readiness-closure-manifest /secure/evidence/closure-manifest.json \
        --require-operational-policy

`--require-operational-policy` is intentionally separate: the checked-in
baseline is a draft and strict approval must be supplied for the deployment
and jurisdiction.

Exit codes: 0 = release-consistent, 1 = blocking findings (see output).
"""
from __future__ import annotations

import argparse
import json
import os
import re
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
    "METRICS_TOKEN": "ci-only-metrics-token-0123456789abcdef",
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


def _image_digest_findings(release_manifests: Path | None = None) -> list[Finding]:
    """Require the exact digest-rendered release directory.

    Source manifests under ``k8s/`` are templates. They must never be applied
    directly, but checking them here cannot prove what will actually be
    deployed. The release boundary therefore consumes the output directory and
    its ``release-image-lock.json`` produced by ``pin_release_images.py``.
    """
    if release_manifests is None:
        return [Finding(
            "immutable-image-digests",
            ERROR,
            "no rendered release manifests supplied; run pin_release_images.py "
            "and pass --release-manifests <directory>",
        )]

    root = release_manifests.resolve()
    if not root.is_dir():
        return [Finding("immutable-image-digests", ERROR, f"rendered release directory not found: {release_manifests}")]

    lock_path = root / "release-image-lock.json"
    if not lock_path.is_file():
        return [Finding("immutable-image-digests", ERROR, f"release lock missing: {lock_path}")]
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        digests = lock["digests"]
        expected = {name: str(digests[name]).lower() for name in ("api", "worker", "neo4j")}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [Finding("immutable-image-digests", ERROR, f"invalid release-image-lock.json: {type(exc).__name__}")]

    findings: list[Finding] = []
    references: list[str] = []
    for path in root.rglob("*.yaml"):
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if not re.search(r"^\s*image:\s*[^\s]+", line):
                continue
            image = line.split("image:", 1)[1].strip()
            references.append(image)
            if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image):
                findings.append(Finding("immutable-image-digests", ERROR, f"{path.relative_to(root)}:{line_no} uses mutable or malformed image reference {image}"))
    if not references:
        findings.append(Finding("immutable-image-digests", ERROR, f"no image references found under rendered release {root}"))
    for name, digest in expected.items():
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not any(f"@sha256:{digest}" in reference for reference in references):
            findings.append(Finding("immutable-image-digests", ERROR, f"release lock digest for {name} is missing or does not match a rendered image"))
    return findings


def _release_attestation_findings(
    release_manifests: Path | None,
    attestation: Path | None,
    public_key: Path | None,
    required: bool,
) -> list[Finding]:
    """Verify a detached release lock signature when production requires it."""
    if not required:
        return []
    if not release_manifests:
        return [Finding("release-attestation", ERROR, "--release-manifests is required before release attestation verification")]
    if not attestation or not public_key:
        return [Finding("release-attestation", ERROR, "--release-attestation and --release-public-key are required when attestation verification is enabled")]
    verifier = ROOT / "scripts" / "verify_release_attestation.py"
    proc = subprocess.run(
        [sys.executable, str(verifier), "--release-manifests", str(release_manifests),
         "--attestation", str(attestation), "--public-key", str(public_key)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    if proc.returncode:
        detail = (proc.stderr or proc.stdout).strip().splitlines()
        return [Finding("release-attestation", ERROR, detail[-1] if detail else "release attestation verification failed")]
    return []


def _operational_policy_findings(path: Path | None, required: bool) -> list[Finding]:
    """Require an explicitly approved operational policy for approval releases."""
    if not required:
        return []
    if not path:
        return [Finding("operational-policy", ERROR, "--operational-policy is required when operational policy enforcement is enabled")]
    verifier = ROOT / "scripts" / "operational_policy_gate.py"
    proc = subprocess.run(
        [sys.executable, str(verifier), "--policy", str(path), "--strict"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    if proc.returncode:
        lines = (proc.stdout or proc.stderr).strip().splitlines()
        return [Finding("operational-policy", ERROR, lines[-1] if lines else "strict operational policy gate failed")]
    return []


def _readiness_closure_findings(manifest: Path | None, required: bool) -> list[Finding]:
    """Require the complete P0/P1 evidence envelope for approval releases."""
    if not required:
        return []
    if not manifest:
        return [Finding(
            "readiness-closure",
            ERROR,
            "--readiness-closure-manifest is required when readiness closure is enabled",
        )]
    gate = ROOT / "scripts" / "readiness_closure_gate.py"
    proc = subprocess.run(
        [sys.executable, str(gate), "--manifest", str(manifest),
         "--expected-commit", _git(["rev-parse", "HEAD"]), "--strict"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    if proc.returncode:
        lines = (proc.stdout or proc.stderr).strip().splitlines()
        return [Finding(
            "readiness-closure",
            ERROR,
            lines[-1] if lines else "P0/P1 readiness closure gate failed",
        )]
    return []


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
    from shared_config import environment as platform_environment

    if platform_environment.is_production():
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


def _production_evidence(version_text: str) -> tuple[list[Finding], dict | None]:
    """Run the production evidence gate for this release and record the result.

    Returns (findings, evidence_info). A failing phase blocks the release;
    clean SKIPs (e.g. no docker for the DR drill) do not. evidence_info is a
    dict to surface in the summary, or None when nothing ran.
    """
    import json

    runner = ROOT / "scripts" / "production_evidence.py"
    cmd = [sys.executable, str(runner), "--release", f"v{version_text.strip()}"]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, cwd=ROOT, timeout=1800
        )
    except Exception as exc:  # noqa: BLE001 — any runner fault is blocking
        return ([Finding("production-evidence", ERROR,
                         f"evidence runner did not complete: {exc}")], None)

    # The runner prints a human summary then writes a JSON artifact; the last
    # "report written:" line carries its path for the machine-readable record.
    written = next(
        (ln.split("report written:", 1)[1].strip()
         for ln in reversed(proc.stdout.splitlines())
         if "report written:" in ln), None)
    info: dict | None = None
    if written:
        try:
            info = json.loads(Path(written).read_text())
        except Exception:  # noqa: BLE001 — fall back to the summary line
            info = None

    if proc.returncode == 0:
        if info:
            return [], {"evidence_id": info.get("evidence_id"),
                        "overall": info.get("overall"),
                        "summary": info.get("summary"),
                        "content_hash": (info.get("content_hash") or "")[:16],
                        "signing": info.get("signing"),
                        "report": written}
        return [], None

    # Non-zero: surface the failing phase(s) as a blocking finding.
    failed = [ln.strip() for ln in proc.stdout.splitlines()
              if ln.strip().startswith("FAIL")]
    detail = "; ".join(failed) if failed else (proc.stdout or proc.stderr).strip()[-400:]
    return ([Finding("production-evidence", ERROR,
                     f"production evidence gate failed for v{version_text.strip()}: {detail}")], info)


def collect(
    allow_untagged: bool,
    run_evidence: bool = True,
    release_manifests: Path | None = None,
    release_attestation: Path | None = None,
    release_public_key: Path | None = None,
    require_release_attestation: bool = False,
    readiness_closure_manifest: Path | None = None,
    require_readiness_closure: bool = False,
    operational_policy: Path | None = None,
    require_operational_policy: bool = False,
) -> tuple[list[Finding], dict | None]:
    version_text = (ROOT / "VERSION").read_text()
    changelog_text = (ROOT / "CHANGELOG.md").read_text()
    tags = _git(["tag", "--list"]).split()
    migrations_dir = ROOT / "services" / "database" / "migrations" / "versions"
    evidence_info: dict | None = None

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
    findings.extend(_image_digest_findings(release_manifests))
    findings.extend(_release_attestation_findings(
        release_manifests,
        release_attestation,
        release_public_key,
        require_release_attestation,
    ))
    findings.extend(_readiness_closure_findings(
        readiness_closure_manifest,
        require_readiness_closure,
    ))
    findings.extend(_operational_policy_findings(
        operational_policy,
        require_operational_policy,
    ))

    if run_evidence:
        ev_findings, evidence_info = _production_evidence(version_text)
        findings.extend(ev_findings)
    return findings, evidence_info


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-untagged",
        action="store_true",
        help="pre-tag dry run: a missing v<version> tag warns instead of failing",
    )
    parser.add_argument(
        "--no-evidence",
        action="store_true",
        help="skip the fresh production-evidence gate (output says plainly)",
    )
    parser.add_argument(
        "--release-manifests",
        type=Path,
        default=Path(os.environ["RELEASE_MANIFESTS"]) if os.getenv("RELEASE_MANIFESTS") else None,
        help="digest-rendered directory from pin_release_images.py",
    )
    parser.add_argument("--release-attestation", type=Path, default=Path(os.environ["RELEASE_ATTESTATION"]) if os.getenv("RELEASE_ATTESTATION") else None)
    parser.add_argument("--release-public-key", type=Path, default=Path(os.environ["RELEASE_PUBLIC_KEY"]) if os.getenv("RELEASE_PUBLIC_KEY") else None)
    parser.add_argument(
        "--require-release-attestation",
        action="store_true",
        default=os.getenv("REQUIRE_RELEASE_ATTESTATION", "").lower() in {"1", "true", "yes"},
        help="require and verify the detached Ed25519 release lock attestation",
    )
    parser.add_argument(
        "--readiness-closure-manifest",
        type=Path,
        default=Path(os.environ["READINESS_CLOSURE_MANIFEST"]) if os.getenv("READINESS_CLOSURE_MANIFEST") else None,
        help="P0/P1 closure manifest to verify for an approval release",
    )
    parser.add_argument(
        "--require-readiness-closure",
        action="store_true",
        default=os.getenv("REQUIRE_READINESS_CLOSURE", "").lower() in {"1", "true", "yes"},
        help="require every documented P0/P1 readiness gap to have current reviewed evidence",
    )
    parser.add_argument(
        "--operational-policy",
        type=Path,
        default=Path(os.environ["OPERATIONAL_POLICY"]) if os.getenv("OPERATIONAL_POLICY") else ROOT / "config" / "operational-policy.yaml",
        help="operational policy to validate when strict policy enforcement is enabled",
    )
    parser.add_argument(
        "--require-operational-policy",
        action="store_true",
        default=os.getenv("REQUIRE_OPERATIONAL_POLICY", "").lower() in {"1", "true", "yes"},
        help="require the supplied operational policy to pass --strict",
    )
    args = parser.parse_args()

    findings, evidence_info = collect(
        args.allow_untagged,
        run_evidence=not args.no_evidence,
        release_manifests=args.release_manifests,
        release_attestation=args.release_attestation,
        release_public_key=args.release_public_key,
        require_release_attestation=args.require_release_attestation,
        readiness_closure_manifest=args.readiness_closure_manifest,
        require_readiness_closure=args.require_readiness_closure,
        operational_policy=args.operational_policy,
        require_operational_policy=args.require_operational_policy,
    )
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
    if evidence_info:
        summary = evidence_info.get("summary") or {}
        print(f"  info  [production-evidence] {evidence_info.get('overall')} "
              f"({summary.get('pass')} pass / {summary.get('skip')} skip / "
              f"{summary.get('fail')} fail) "
              f"evidence={evidence_info.get('evidence_id')} "
              f"digest={evidence_info.get('content_hash')}… "
              f"{evidence_info.get('signing')}")
    elif args.no_evidence:
        print("  note  [production-evidence] SKIPPED via --no-evidence — "
              "release cut without fresh production evidence")
    if not findings:
        print("  (no warnings)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
