#!/usr/bin/env python3
"""Ingest runtime evidence (logs) and reconcile it with the static inventory.

    python scripts/ingest_runtime_logs.py /path/to/logs [--source /path/to/repo] [-o runtime.json]

Reads ICSF SMF-82 / RACDCERT / payShield audit / JSSE debug / openssl s_client /
nginx-Apache-HAProxy access / sshd / AT-TLS logs (see
scanner/parsers/runtime_log_parser.py) and prints, per algorithm:

    algorithm   runtime-occurrences   in-source?

so a bank can see three things at once: crypto that runs but is *not* in any repo
they gave us (a coverage gap or a vendor binary), crypto that is in source but
never observed (dead code or a system not yet in the log capture), and the
intersection. Findings carry ``source.type = RUNTIME_LOG`` and are written in
the same RawFinding JSON the API ingests.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("services/scanner", "shared/shared_models", "shared/shared_config", "shared/shared_logging"):
    sys.path.insert(0, str(ROOT / p))
os.environ.setdefault("CRYPTOSCAN_LOG_LEVEL", "warning")
os.environ["CRYPTOSCAN_RUNTIME_LOGS"] = "1"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs")
    ap.add_argument("--source", help="repository tree to reconcile against")
    ap.add_argument("-o", "--output")
    args = ap.parse_args(argv)

    import logging

    import structlog

    logging.basicConfig(level=logging.ERROR)
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR))
    from scanner.core.file_discovery import FileDiscovery
    from scanner.parsers.runtime_log_parser import RUNTIME_LOG_EXT
    from scanner.registry.language_scanners import scan_file

    logs = Path(args.logs)
    log_files = [p for p in FileDiscovery(extensions=tuple(RUNTIME_LOG_EXT)).discover(logs)] if logs.is_dir() else [logs]
    runtime = []
    for f in log_files:
        runtime.extend(scan_file(f, logs if logs.is_dir() else f.parent))
    runtime = [f for f in runtime if f.source.type == "RUNTIME_LOG"]
    occ = collections.Counter()
    for f in runtime:
        if f.crypto.algorithm and f.crypto.algorithm not in ("UNKNOWN", "TLS-CIPHERS"):
            occ[f.crypto.algorithm] += int(getattr(f, "occurrences", 1) or 1)

    in_source: set[str] = set()
    if args.source:
        src = Path(args.source)
        for f in FileDiscovery().discover(src):
            for x in scan_file(f, src):
                if x.crypto.algorithm and x.crypto.algorithm not in ("UNKNOWN", "TLS-CIPHERS"):
                    in_source.add(x.crypto.algorithm)

    print(f"log files={len(log_files)} runtime findings={len(runtime)}")
    print(f"{'algorithm':<14}{'runtime-occ':>12}   {'in-source' if args.source else ''}")
    for alg, n in occ.most_common():
        mark = "" if not args.source else ("yes" if alg in in_source else "NO  <- runs, not in any scanned repo")
        print(f"{alg:<14}{n:>12}   {mark}")
    if args.source:
        only_src = sorted(in_source - set(occ))
        if only_src:
            print(f"in source, never observed at runtime: {', '.join(only_src)}")
    if args.output:
        Path(args.output).write_text(json.dumps([f.model_dump() for f in runtime], indent=1, default=str))
        print(f"-> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
