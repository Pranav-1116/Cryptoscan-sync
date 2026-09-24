#!/usr/bin/env python3
"""Scan a third-party package tree (e.g. a site-packages dir) with the production scanner.

    python scripts/scan_third_party.py .venv/lib/python3.11/site-packages/pip [v]

Used for external validation: code nobody on this project wrote or labelled.
"""
import sys, os, collections
from pathlib import Path
ROOT = Path("/home/user/CryproScan")
for p in ("services/scanner", "shared/shared_models", "shared/shared_config", "shared/shared_logging"):
    sys.path.insert(0, str(ROOT / p))
os.environ.setdefault("CRYPTOSCAN_LOG_LEVEL", "warning")
import logging, structlog
logging.basicConfig(level=logging.ERROR); structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR))
from scanner.core.file_discovery import FileDiscovery
from scanner.registry.language_scanners import scan_file
root = Path(sys.argv[1])
per_file = collections.defaultdict(list)
n=0
for f in FileDiscovery().discover(root):
    n+=1
    try:
        for x in scan_file(f, root):
            per_file[str(f.relative_to(root))].append((x.source.line_number, x.crypto.algorithm, x.crypto.api_type, (x.crypto.raw_transformation or "")[:50]))
    except Exception as e:
        print("CRASH", f, e)
print(f"files={n} files_with_findings={len(per_file)} findings={sum(len(v) for v in per_file.values())}")
if len(sys.argv)>2:
    for k,v in sorted(per_file.items()):
        print("==", k)
        for r in v: print("   ", r)
