#!/usr/bin/env python3
"""Scan an unpacked container filesystem or image root."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "container_scanner"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan a container filesystem for crypto packages")
    parser.add_argument("path", help="Unpacked image root or project directory")
    parser.add_argument("-o", "--output", help="Write JSON result to this path")
    args = parser.parse_args()

    from container_scanner.core.scanner import ContainerScanner

    target = Path(args.path)
    if not target.exists():
        raise SystemExit(f"path not found: {target}")
    result = ContainerScanner().scan_filesystem(target)
    text = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    print(
        f"# packages={len(result.get('packages') or [])} "
        f"libraries={len(result.get('libraries') or [])} "
        f"cves={len(result.get('vulnerabilities') or [])}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
