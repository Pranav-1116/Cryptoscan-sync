#!/usr/bin/env python3
"""Dump raw scanner findings for named corpus cases: accuracy_inspect.py <substring> [...]"""
import os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
for p in ("services/scanner", "services/scanner/tests", "shared/shared_models", "shared/shared_config", "shared/shared_logging"):
    sys.path.insert(0, str(ROOT / p))
os.environ.setdefault("CRYPTOSCAN_LOG_LEVEL", "warning")
from accuracy.corpus import CASES
from scanner.registry.language_scanners import scan_file
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    for lang, fname, code, expected, cat in CASES:
        if not any(a in fname for a in sys.argv[1:]):
            continue
        path = root / lang / fname; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(code)
        print(f"== {lang}/{fname} expected={sorted(expected)}")
        for f in scan_file(path, root):
            print(f"   L{f.source.line_number:<3} {f.crypto.algorithm!s:22} {f.crypto.api_type:16} raw={f.crypto.raw_transformation!r}")
