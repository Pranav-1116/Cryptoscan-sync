#!/usr/bin/env python3
"""Passive OT/ICS crypto scan of a capture tree. Never sends packets."""

from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from ot_scanner.core.scanner import OtPassiveScanner  # noqa: E402


def main() -> int:
    target = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "demo" / "ot-lab")
    result = OtPassiveScanner().scan_filesystem(target)
    print(json.dumps({k: result[k] for k in ("device_count", "unencrypted", "packets_sent", "warning") if k in result}, indent=2))
    print(f"{len(result.get('findings') or [])} findings from {result.get('device_count')} devices; packets sent={result.get('packets_sent')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
