#!/usr/bin/env python3
"""Generate/validate a wholly synthetic local banking estate. Never scans an IP range."""

import argparse
import json
from pathlib import Path
import sys

from tools.banking_sandbox.generator import generate, SCALES
from tools.banking_sandbox.catalog import PROFILES


def boolean(value):
    if value.lower() not in ("true", "false"):
        raise argparse.ArgumentTypeError("true or false required")
    return value.lower() == "true"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--banks", type=int, default=150)
    p.add_argument("--scale", type=str.lower, choices=SCALES, default="mixed")
    p.add_argument("--profile", choices=PROFILES, default="worst-case-bank")
    p.add_argument("--seed", default="ZELNX-PUBLIC-LAB-1")
    p.add_argument("--epoch", default="2030-01-01T00:00:00Z")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--max-systems", type=int, default=50000)
    for name in ("pqc", "legacy", "conflicts", "drift"):
        p.add_argument("--" + name, type=boolean, default=True)
    for name in ("crypto-complexity", "network-complexity", "vendor-complexity"):
        p.add_argument("--" + name, choices=["low", "medium", "high"], default="high")
    a = p.parse_args(argv)
    try:
        print(json.dumps(generate(**vars(a)), sort_keys=True))
        return 0
    except (ValueError, OSError) as exc:
        print("REFUSED_SYNTHETIC_ESTATE: " + str(exc), file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
