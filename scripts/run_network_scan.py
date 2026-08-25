#!/usr/bin/env python3
"""Scan a tree or host list for TLS / certificates."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for extra in (
    ROOT / "services" / "network_scanner",
    ROOT / "services" / "scanner",
):
    sys.path.insert(0, str(extra))

from network_scanner.core.scanner import NetworkTlsScanner  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="filesystem path or host:port")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    scanner = NetworkTlsScanner(live=args.live)
    if ":" in args.target and not Path(args.target).exists():
        result = scanner.scan_hosts([args.target])
    else:
        result = scanner.scan_filesystem(args.target)
    json.dump(result, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
