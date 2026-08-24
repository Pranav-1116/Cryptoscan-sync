#!/usr/bin/env python3
"""Verify a CryptoScan evidence pack (uses the in-repo verifier when available)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a CryptoScan evidence pack")
    parser.add_argument("pack", help="Path to evidence-pack.json")
    parser.add_argument("--secret", help="HMAC secret used by the issuing instance")
    args = parser.parse_args(argv)

    raw = Path(args.pack).read_text(encoding="utf-8")
    pack = json.loads(raw)

    try:
        from evidence.pack.evidence_pack import verify_evidence_pack

        report = verify_evidence_pack(pack, secret=args.secret)
    except ImportError:
        from evidence.pack.standalone_verifier import STANDALONE_VERIFIER_SOURCE

        ns: dict = {}
        exec(STANDALONE_VERIFIER_SOURCE, ns)
        report = ns["verify"](pack, secret=args.secret)

    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if report.get("result") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
