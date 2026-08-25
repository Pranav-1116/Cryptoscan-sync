#!/usr/bin/env python3
"""Merge seed hash files into the container fingerprint catalog."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "services" / "container_scanner" / "container_scanner" / "data"
sys.path.insert(0, str(ROOT / "services" / "container_scanner"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate / refresh the fingerprint database")
    parser.add_argument("--check", action="store_true", help="load seeds and print counts only")
    args = parser.parse_args()

    catalog_path = DATA / "fingerprint_db.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    from container_scanner.fingerprints.repository import FingerprintRepository

    repo = FingerprintRepository(catalog)
    hashes = len(repo._hashes)
    libraries = len(repo.libraries)
    print(f"libraries={libraries} binary_hashes={hashes} catalog={catalog_path}")
    if hashes == 0:
        raise SystemExit("no seed hashes loaded from data/seed")
    if args.check:
        return
    extra = catalog.setdefault("binary_hashes", {})
    for digest, info in repo._hashes.items():
        extra[digest] = info
    catalog_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(extra)} hashes into fingerprint_db.json")


if __name__ == "__main__":
    main()
