#!/usr/bin/env python3
"""Scan a third-party package tree (e.g. a site-packages dir) with the production scanner.

    python scripts/scan_third_party.py .venv/lib/python3.11/site-packages/pip [v]

Used for external validation: code nobody on this project wrote or labelled.
"""
import sys, os, collections
from pathlib import Path
# Resolve the repo from this file's own location. This used to be a hardcoded
# absolute path to one developer's checkout (and a misspelled one), so the
# external-validation tool imported nothing and could not run anywhere else --
# which is why external validation had only ever covered Python.
ROOT = Path(__file__).resolve().parents[1]
for p in ("services/scanner", "shared/shared_models", "shared/shared_config", "shared/shared_logging"):
    sys.path.insert(0, str(ROOT / p))
os.environ.setdefault("CRYPTOSCAN_LOG_LEVEL", "warning")
import logging, structlog
logging.basicConfig(level=logging.ERROR); structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR))
from scanner.core.file_discovery import FileDiscovery
from scanner.registry.language_scanners import scan_file
root = Path(sys.argv[1])
from scanner.core.constant_index import ConstantIndex
per_file = collections.defaultdict(list)
files = list(FileDiscovery().discover(root))
n=len(files)
all_findings=[]
for f in files:
    try:
        all_findings.extend(scan_file(f, root))
    except Exception as e:
        print("CRASH", f, e)
resolved = ConstantIndex.build(files).resolve(all_findings)  # same second hop as Scanner.scan
for x in all_findings:
    per_file[x.source.file_path].append((x.source.line_number, x.crypto.algorithm, x.crypto.api_type, (x.crypto.raw_transformation or "")[:50]))
print(f"files={n} files_with_findings={len(per_file)} findings={sum(len(v) for v in per_file.values())} resolved_cross_file={resolved}")
if len(sys.argv)>2:
    for k,v in sorted(per_file.items()):
        print("==", k)
        for r in v: print("   ", r)
