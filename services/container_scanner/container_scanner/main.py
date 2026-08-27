"""CLI entry for the container scanner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from container_scanner.config.settings import load_settings
from container_scanner.core.scan_context import ScanContext
from container_scanner.core.scanner import ContainerScanner
from container_scanner.cve.github_advisory_client import GitHubAdvisoryClient
from container_scanner.cve.resolver import VulnerabilityResolver
from container_scanner.workspace.cleanup_handler import ensure_cleanup
from container_scanner.workspace.workspace_manager import WorkspaceManager


def build_scanner(*, live_cve: bool, github_advisory: bool) -> ContainerScanner:
    resolver = None
    if live_cve or github_advisory:
        resolver = VulnerabilityResolver(
            live=live_cve,
            github=GitHubAdvisoryClient() if github_advisory else None,
        )
    return ContainerScanner(live_cve=live_cve, resolver=resolver)


def main(argv: list[str] | None = None) -> int:
    settings = load_settings()
    parser = argparse.ArgumentParser(description="Scan a container image or filesystem for crypto packages")
    parser.add_argument("target", help="Filesystem path, docker-save .tar, or registry image reference")
    parser.add_argument("-o", "--output", help="Write JSON result to this path")
    parser.add_argument("--live-cve", action="store_true", default=settings.live_cve)
    parser.add_argument("--github-advisory", action="store_true", default=settings.github_advisory)
    parser.add_argument("--image", action="store_true", help="Treat target as a registry image even if a path exists")
    args = parser.parse_args(argv)

    scanner = build_scanner(live_cve=args.live_cve, github_advisory=args.github_advisory)
    target = args.target
    path = Path(target)
    workspace = WorkspaceManager(settings.workspace_dir)
    workdir = workspace.create()
    context = ScanContext(target=target, live_cve=args.live_cve, workdir=str(workdir))
    try:
        from container_scanner.image.puller import ImagePullError
    except Exception:  # pragma: no cover - puller always present in-repo
        ImagePullError = RuntimeError  # type: ignore[misc,assignment]

    with ensure_cleanup(workspace, workdir):
        try:
            if args.image:
                result = scanner.scan_image(target, scan_id=context.scan_id, workdir=workdir)
            elif path.is_file() and target.endswith((".tar", ".tar.gz", ".tgz")):
                result = scanner.scan_image(target, scan_id=context.scan_id, workdir=workdir)
            elif path.exists():
                result = scanner.scan_filesystem(path, scan_id=context.scan_id)
            else:
                result = scanner.scan_image(target, scan_id=context.scan_id, workdir=workdir)
        except (FileNotFoundError, ImagePullError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
    result["scan_context"] = context.to_dict()
    text = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    risk = result.get("risk_report") or {}
    print(
        f"# kind={result.get('target_kind')} packages={len(result.get('packages') or [])} "
        f"libraries={len(result.get('libraries') or [])} "
        f"cves={len(result.get('vulnerabilities') or [])} "
        f"secrets={len(result.get('secrets') or [])} posture={risk.get('posture') or '?'}",
        file=sys.stderr,
    )
    if risk.get("headline"):
        print(f"# risk: {risk['headline']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
