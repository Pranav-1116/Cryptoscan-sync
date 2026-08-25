#!/usr/bin/env python3
"""Scan an unpacked container filesystem, docker-save archive, or registry image."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "container_scanner"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan a container image or filesystem for crypto packages")
    parser.add_argument("target", help="Filesystem path, docker-save .tar, or registry image reference")
    parser.add_argument("-o", "--output", help="Write JSON result to this path")
    parser.add_argument("--live-cve", action="store_true", help="Query OSV/NVD in addition to the local CVE DB")
    parser.add_argument("--image", action="store_true", help="Treat target as a registry image even if a path exists")
    args = parser.parse_args()

    from container_scanner.core.scanner import ContainerScanner
    from container_scanner.image.puller import ImagePullError

    scanner = ContainerScanner(live_cve=args.live_cve)
    target = args.target
    path = Path(target)
    try:
        if args.image:
            result = scanner.scan_image(target)
        elif path.is_file() and target.endswith((".tar", ".tar.gz", ".tgz")):
            result = scanner.scan_image(target)
        elif path.exists():
            result = scanner.scan_filesystem(path)
        else:
            result = scanner.scan_image(target)
    except (FileNotFoundError, ImagePullError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    text = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    print(
        f"# kind={result.get('target_kind')} packages={len(result.get('packages') or [])} "
        f"libraries={len(result.get('libraries') or [])} "
        f"cves={len(result.get('vulnerabilities') or [])}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
