#!/usr/bin/env python3
"""Scan Terraform / Kubernetes / CloudFormation for crypto config."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for extra in (
    ROOT / "services" / "cloud_scanner",
    ROOT / "services" / "scanner",
):
    sys.path.insert(0, str(extra))

from cloud_scanner.core.scanner import CloudScanner  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    result = CloudScanner(live=args.live).scan_filesystem(args.path)
    json.dump(result, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
