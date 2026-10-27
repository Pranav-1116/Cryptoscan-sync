#!/usr/bin/env python3
"""Extend data/fips_certificates.json from a downloaded CMVP dataset.

NIST publishes the validated-module list as CSV/JSON downloads from
https://csrc.nist.gov/projects/cryptographic-module-validation-program/modules
(Details > Download). This tool is OFFLINE-first — you download once, the
script normalizes the relevant columns into the registry the API consults.

Usage:
  python3 scripts/fips_lookup.py --from cspvpdl.csv            # full import
  python3 scripts/fips_lookup.py --from cspvpdl.csv --grep luna
  python3 scripts/fips_lookup.py --add "module;vendor;standard;cert"
  python3 scripts/fips_lookup.py --search "openssl fips"       # registry lookup
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cbom.integrations import load_fips_registry, save_fips_registry  # noqa: E402

REGISTRY = Path(__file__).resolve().parent.parent / "data" / "fips_certificates.json"


def import_csvpdl(path: Path, grep: str | None) -> int:
    """Import NIST CMVP 'cspvpdl' CSV (module name/vendor/cert columns)."""
    added = 0
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        try:
            csv.Sniffer().sniff(sample)  # validate the file is delimited
        except csv.Error:
            pass
        reader = csv.DictReader(fh)
        cols = {c.lower().strip(): c for c in (reader.fieldnames or [])}
        mod_c = next((cols[k] for k in cols if "module" in k), None)
        ven_c = next((cols[k] for k in cols if "vendor" in k), None)
        cert_c = next((cols[k] for k in cols if "cert" in k and "historical" not in k), None)
        std_c = next((cols[k] for k in cols if "standard" in k or "fips" in k), None)
        if not mod_c or not cert_c:
            print(f"error: cannot find module/certificate columns in {list(cols)}", file=sys.stderr)
            return 2
        entries = []
        for row in reader:
            module = (row.get(mod_c) or "").strip()
            cert = (row.get(cert_c) or "").strip()
            if not module or not cert:
                continue
            if grep and grep.lower() not in module.lower():
                continue
            entries.append({
                "module": module, "vendor": (row.get(ven_c) or "").strip() if ven_c else "",
                "standard": (row.get(std_c) or "").strip() if std_c else "FIPS 140",
                "cert": cert, "note": "imported from NIST CMVP dataset", "source": "cmvp",
            })
        if entries:
            save_fips_registry(entries, REGISTRY)
        added = len(entries)
    return added


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--from", dest="src", help="NIST CMVP CSV download to import")
    ap.add_argument("--grep", help="only import entries whose module matches")
    ap.add_argument("--add", help='add one entry: "module;vendor;standard;cert"')
    ap.add_argument("--search", help="search the current registry")
    args = ap.parse_args()

    if args.search:
        hit = __import__("cbom.integrations", fromlist=["fips_lookup"]).fips_lookup(
            args.search, load_fips_registry(REGISTRY))
        print(json.dumps(hit, indent=2))
        return 0
    if args.add:
        parts = [p.strip() for p in args.add.split(";")]
        if len(parts) < 4 or not parts[0] or not parts[3]:
            ap.error('--add expects "module;vendor;standard;cert"')
        save_fips_registry([{"module": parts[0], "vendor": parts[1], "standard": parts[2],
                             "cert": parts[3], "note": "manually recorded", "source": "manual"}],
                           REGISTRY)
        print(f"registry now has {len(load_fips_registry(REGISTRY))} entries")
        return 0
    if args.src:
        n = import_csvpdl(Path(args.src), args.grep)
        print(f"imported {n} entries; registry now has {len(load_fips_registry(REGISTRY))}")
        return 0 if n else 1
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
