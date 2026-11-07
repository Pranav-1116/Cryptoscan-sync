#!/usr/bin/env python3
"""Report the platform stack's honest connection status.

Three states per backend: UNCONFIGURED (nothing claimed), REACHABLE
(socket probe succeeded — reachability, not health), UNREACHABLE (named,
never a quiet success). JSON with --json.

Run: .venv/bin/python scripts/stack_status.py [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "shared" / "shared_config")]

from shared_config.stack_settings import probe  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=1.0)
    args = parser.parse_args()
    status = probe(timeout=args.timeout)
    if args.json:
        print(json.dumps(status.model_dump(), indent=2, sort_keys=True))
        return 0
    print(f"{'BACKEND':<14} {'ROLE':<12} {'STATUS':<12} DETAIL")
    for row in status.checked:
        print(f"{row['name']:<14} {row['role']:<12} {row['status']:<12} {row['detail']}")
    print()
    print(status.note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
