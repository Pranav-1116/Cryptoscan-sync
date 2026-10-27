#!/usr/bin/env python3
"""Ingest HSM / KMS / keystore / certificate inventory exports and reconcile them with the code.

    python scripts/ingest_key_inventory.py /path/to/exports [--source /path/to/repo] [-o keys.json]

Reads ICSF CKDS/PKDS listings, TR-31 key blocks, Luna / nShield / Utimaco / PKCS#11 listings,
AWS KMS / Azure Key Vault / GCP KMS / Vault-transit JSON, keytool -list -v, RACDCERT LIST and
certificate CSV exports (see scanner/parsers/key_inventory_parser.py) and prints the key estate:

  * by system × algorithm × size, with weak (below registry floor), expired, stale (not used in
    365 days), archived / pending-deletion and exportable counts;
  * keys whose label / alias / file name is referenced from the scanned source (consumers found) and
    keys with **no consumer in any scanned repo** — orphans, or systems not yet scanned;
  * key identifiers referenced in source that are **not in any inventory** — a keystore the bank did
    not export, or a hard-coded / file-based key outside the HSM/KMS estate.

Findings carry ``source.type = KEY_INVENTORY`` plus an ``inventory`` block (label, usage, state,
dates, key store, exportability) and are written in the RawFinding JSON the API ingests.
Values of keys are never read.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import argparse
import collections
import json
import os
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in sorted(ROOT.glob("shared/*/")) + sorted(ROOT.glob("services/*/")):
    sys.path.insert(0, str(p))
os.environ.setdefault("CRYPTOSCAN_LOG_LEVEL", "warning")
os.environ["CRYPTOSCAN_KEY_INVENTORY"] = "1"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exports")
    ap.add_argument("--source", help="repository tree to reconcile against")
    ap.add_argument("--stale-days", type=int, default=365)
    ap.add_argument("-o", "--output")
    args = ap.parse_args(argv)


    import structlog

    logging.basicConfig(level=logging.ERROR)
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR))
    from shared_models.algorithm_registry import parse_algorithm
    from scanner.analysis.cascade import DependencyGraph
    from scanner.core.file_discovery import FileDiscovery
    from scanner.parsers.key_inventory_parser import parse_key_inventory_file

    root = Path(args.exports)
    files = [p for p in root.rglob("*") if p.is_file()] if root.is_dir() else [root]
    inv = []
    for f in files:
        inv.extend(parse_key_inventory_file(f, root if root.is_dir() else f.parent))
    keys = [f for f in inv if not f.inventory.get("role")]  # drop signature-digest companions for the estate table
    print(f"export files={len(files)} inventory findings={len(inv)} keys/certs={len(keys)}")

    today = date.today()
    stale_before = today - timedelta(days=args.stale_days)

    def floor(alg):
        try:
            return parse_algorithm(alg).min_key_size
        except Exception as _handler_exc:
            logger.debug(
                "expected_exception_boundary",
                extra={"error_type": type(_handler_exc).__name__},
            )
            return None

    rows = collections.Counter()
    flags = collections.defaultdict(list)
    for f in keys:
        alg, size, sysname, i = f.crypto.algorithm, f.crypto.key_size, f.metadata.library, f.inventory
        rows[(sysname, alg, size)] += 1
        label = i.get("key_label") or i.get("subject") or f.crypto.raw_transformation
        fl = floor(alg)
        if size and fl and size < fl:
            flags["weak"].append((sysname, label, f"{alg}-{size} < {fl}"))
        if alg in ("DES", "RC4", "MD5", "SHA-1", "RC2", "DSA"):
            flags["disallowed_algorithm"].append((sysname, label, alg))
        if i.get("expired"):
            flags["expired"].append((sysname, label, i.get("not_after")))
        elif i.get("not_after"):
            try:
                if datetime.fromisoformat(i["not_after"]).date() <= today + timedelta(days=90):
                    flags["expiring_90d"].append((sysname, label, i["not_after"]))
            except ValueError:
                pass
        lu = i.get("last_used")
        if lu:
            try:
                if datetime.fromisoformat(lu).date() < stale_before:
                    flags["stale"].append((sysname, label, lu))
            except ValueError:
                pass
        st = (i.get("state") or "").upper()
        if st in ("ARCHIVED", "PENDINGDELETION", "PENDING_DELETION", "DISABLED", "DESTROYED", "NOTRUST", "DESTROY_SCHEDULED"):
            flags["inactive"].append((sysname, label, i.get("state")))
        if i.get("extractable") or i.get("exportable") or (i.get("exportability") or "").startswith("exportable"):
            flags["exportable"].append((sysname, label, i.get("exportability") or "extractable"))
        if i.get("weak_binding"):
            flags["tr31_version_A"].append((sysname, label, i.get("key_block_version")))
        if i.get("rotation_enabled") is False or (sysname in ("AWS-KMS", "GCP-KMS", "Azure-KeyVault", "Vault-transit") and not i.get("rotation_enabled")):
            flags["no_rotation"].append((sysname, label, ""))

    print(f"\n{'system':<22}{'algorithm':<12}{'bits':>6}{'count':>7}")
    for (sysname, alg, size), n in sorted(rows.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2] or 0)):
        print(f"{sysname:<22}{alg:<12}{(size or '-')!s:>6}{n:>7}")
    for name in ("weak", "disallowed_algorithm", "expired", "expiring_90d", "stale", "inactive", "exportable", "tr31_version_A", "no_rotation"):
        if flags[name]:
            print(f"\n{name} ({len(flags[name])}):")
            for sysname, label, detail in flags[name][:25]:
                print(f"  {sysname:<22}{str(label):<40}{detail}")

    report = {"files": len(files), "findings": len(inv), "keys": len(keys), "by_system_algorithm_size": [{"system": s, "algorithm": a, "bits": b, "count": n} for (s, a, b), n in rows.items()],
              "flags": {k: [{"system": s, "label": l, "detail": d} for s, l, d in v] for k, v in flags.items()}}

    if args.source:
        src = Path(args.source)
        source_files = list(FileDiscovery().discover(src))
        graph = DependencyGraph.build(source_files, src)
        from evidence.intelligence.key_reconciliation import reconcile_key_inventory  # same logic as the API / worker

        key_refs = [("local", {"kind": kind, "identifier": ident, "files": len(fl), "sample_files": sorted(fl)[:3]}) for (kind, ident), fl in graph.key_refs.items()]
        rec = reconcile_key_inventory([f.model_dump() for f in keys], key_refs)
        print(f"\nreconciliation against {src} ({len(source_files)} files):")
        print(f"  keys with consumers in source: {rec['summary']['consumers']}")
        for c in rec["consumers"][:20]:
            fl = sorted({x for r in c["references"] for x in r["sample_files"]})
            print(f"    {c['system']:<18}{c['label']:<40}<- {', '.join(fl[:3])}{' …' if len(fl) > 3 else ''}")
        print(f"  keys with NO consumer in any scanned repo (orphan, or system not yet scanned): {rec['summary']['orphans']}")
        for o in rec["orphans"][:20]:
            print(f"    {o['system']:<18}{o['label']}")
        print(f"  key identifiers in source that are in NO inventory: {rec['summary']['not_in_inventory']}")
        for n in rec["not_in_inventory"][:20]:
            print(f"    {n['kind']:<10}{n['identifier']:<40}{n['files']} file(s)")
        report["reconciliation"] = {k: rec[k] for k in ("summary", "consumers", "orphans", "not_in_inventory")}

    if args.output:
        Path(args.output).write_text(json.dumps({"report": report, "findings": [f.model_dump() for f in inv]}, indent=1, default=str))
        print(f"-> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
