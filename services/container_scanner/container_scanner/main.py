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
    parser.add_argument("target", nargs="?", default=None, help="Filesystem path, docker-save .tar, or registry image reference")
    parser.add_argument("-o", "--output", help="Write JSON result to this path")
    parser.add_argument("--live-cve", action="store_true", default=settings.live_cve)
    parser.add_argument("--github-advisory", action="store_true", default=settings.github_advisory)
    parser.add_argument("--image", action="store_true", help="Treat target as a registry image even if a path exists")
    parser.add_argument("--sbom", metavar="OUT", help="Also write a CycloneDX 1.5 SBOM to this path")
    parser.add_argument("--spdx", metavar="OUT", help="Also write an SPDX 2.3 SBOM to this path")
    parser.add_argument("--diff-scans", nargs=2, metavar=("OLD", "NEW"),
                        help="Diff two scan result JSON files and exit (no scan runs)")
    parser.add_argument("--metrics", metavar="FILE",
                        help="Render a scan/drift result JSON as Prometheus text and exit")
    args = parser.parse_args(argv)
    if not args.target and not (args.diff_scans or args.metrics):
        parser.error("target is required unless --diff-scans or --metrics is used")

    if args.diff_scans or args.metrics:
        import json as _json

        if args.diff_scans:
            from container_scanner.reports.scan_drift import diff_scans

            old_path, new_path = args.diff_scans
            report = diff_scans(_json.loads(Path(old_path).read_text()), _json.loads(Path(new_path).read_text()))
            report["diff_of"] = [old_path, new_path]
            text = _json.dumps(report, indent=2)
            if args.output:
                Path(args.output).write_text(text, encoding="utf-8")
            else:
                print(text)
            print(
                f"# drift={report['verdict']} changes={report['change_count']} headline={report['headline']}",
                file=sys.stderr,
            )
            return 0
        from container_scanner.reports.metrics import render_prometheus

        text = render_prometheus(_json.loads(Path(args.metrics).read_text()))
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text, end="")
        return 0

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
    if args.sbom:
        from container_scanner.reports.sbom import build_sbom

        Path(args.sbom).write_text(json.dumps(build_sbom(result), indent=2), encoding="utf-8")
        print(f"# sbom written to {args.sbom}", file=sys.stderr)
    if args.spdx:
        from container_scanner.reports.spdx import build_spdx

        Path(args.spdx).write_text(json.dumps(build_spdx(result), indent=2), encoding="utf-8")
        print(f"# spdx written to {args.spdx}", file=sys.stderr)
    text = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    risk = result.get("risk_report") or {}
    distro = result.get("distro") or {}
    if distro.get("id"):
        eol = distro.get("eol") or {}
        print(
            f"# distro: {distro.get('id')} {distro.get('version') or distro.get('version_id') or ''} "
            f"eol={eol.get('status') or 'UNKNOWN'}".strip(),
            file=sys.stderr,
        )
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
