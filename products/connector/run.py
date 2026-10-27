"""Products connector CLI: Product 1 (Sandbox) → Product 2 (CryptoScan) → 6 BOMs + dashboard."""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.banking_sandbox.connector.connector import connect


def main():
    p = argparse.ArgumentParser(description="Connect sandbox estate (Product 1) to CryptoScan (Product 2): scan + 6 BOMs + validation + dashboard")
    p.add_argument("--estate", type=Path, required=True, help="Estate directory (LAB.json exists, public/ + control/)")
    p.add_argument("--output", type=Path, required=True, help="Fresh CryptoScan output directory (must not exist)")
    a = p.parse_args()
    res = connect(a.estate, a.output)
    import json, sys
    json.dump(res, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
