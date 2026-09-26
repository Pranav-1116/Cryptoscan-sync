#!/usr/bin/env python3
"""Multi-million-LOC scale evidence for the source scanner.

    python scripts/scale_evidence.py --mloc 2 --procs 1,2 [--keep]

Builds a synthetic polyglot monorepo (Java / C# / Python / JS / COBOL / Go / SQL / YAML,
realistic file sizes, ~1 crypto call per 40 files so the result is not finding-bound),
then runs ``Scanner.scan`` with ``CRYPTOSCAN_SCAN_PROCESSES`` set to each value in --procs
and prints LOC/s, files/s, peak RSS and the projected wall-clock for 10M LOC. Finding
counts must be identical across process counts (determinism check).
"""
from __future__ import annotations

import argparse
import os
import random
import resource
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("services/scanner", "shared/shared_models", "shared/shared_config", "shared/shared_logging"):
    sys.path.insert(0, str(ROOT / p))
os.environ.setdefault("CRYPTOSCAN_LOG_LEVEL", "error")

_JAVA = "package bank.{pkg};\n\nimport java.util.*;\n\npublic class {cls} {\n" + "".join(
    f"    public int method{i}(int a, int b) {{\n        int c = a * {i} + b;\n        if (c > 100) {{ return c - {i}; }}\n        return c;\n    }}\n\n" for i in range(12)) + "}}\n"
_JAVA_CRYPTO = _JAVA.replace("import java.util.*;", "import java.util.*;\nimport javax.crypto.Cipher;\nimport java.security.MessageDigest;").replace("public class {cls} {\n", "public class {cls} {\n    Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");\n    MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n")
_CS = "using System;\n\nnamespace Bank.{pkg}\n{\n    public class {cls}\n    {\n" + "".join(f"        public int Method{i}(int a) {{ var c = a * {i}; return c > 10 ? c - 1 : c; }}\n" for i in range(30)) + "    }\n}\n"
_CS_CRYPTO = _CS.replace("using System;", "using System;\nusing System.Security.Cryptography;").replace("    {\n", "    {\n        Aes aes = Aes.Create();\n        var h = SHA1.Create();\n", 1)
_PY = "import os\nimport json\n\n\nclass {cls}:\n" + "".join(f"    def method{i}(self, a, b={i}):\n        c = a * b\n        if c > 100:\n            return c - {i}\n        return c\n\n" for i in range(15))
_PY_CRYPTO = _PY.replace("import json\n", "import json\nimport hashlib\nfrom cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n").replace("class {cls}:\n", "class {cls}:\n    def enc(self, k, iv, d):\n        return Cipher(algorithms.AES(k), modes.GCM(iv)).encryptor().update(d)\n\n    def h(self, d):\n        return hashlib.md5(d).hexdigest()\n\n")
_JS = "'use strict';\nconst util = require('util');\n\n" + "".join(f"function fn{i}(a, b) {{\n  const c = a * {i} + b;\n  if (c > 100) return c - {i};\n  return c;\n}}\n\n" for i in range(15)) + "module.exports = { {cls} };\n"
_JS_CRYPTO = _JS.replace("const util = require('util');", "const util = require('util');\nconst crypto = require('crypto');\nconst c = crypto.createCipheriv('aes-256-cbc', key, iv);\nconst h = crypto.createHash('sha1');")
_COBOL = "       IDENTIFICATION DIVISION.\n       PROGRAM-ID. {cls}.\n       DATA DIVISION.\n       WORKING-STORAGE SECTION.\n" + "".join(f"       01  WS-FIELD-{i:02d}       PIC 9(9) COMP VALUE {i}.\n" for i in range(40)) + "       PROCEDURE DIVISION.\n" + "".join(f"           ADD WS-FIELD-{i:02d} TO WS-FIELD-00.\n" for i in range(1, 40)) + "           GOBACK.\n"
_COBOL_CRYPTO = _COBOL.replace("       PROCEDURE DIVISION.\n", "       PROCEDURE DIVISION.\n           CALL 'CSNBSYE' USING RC RS EXIT-LEN EXIT-DATA\n                RULE-COUNT RULE-ARRAY KEY-ID-LEN KEY-ID.\n           CALL 'CSNBOWH' USING RC RS EXIT-LEN EXIT-DATA\n                RULE-COUNT RULE-ARRAY TEXT-LEN TEXT HASH-LEN HASH.\n")
_GO = "package {pkg}\n\nimport \"fmt\"\n\n" + "".join(f"func Fn{i}(a, b int) int {{\n\tc := a*{i} + b\n\tif c > 100 {{\n\t\treturn c - {i}\n\t}}\n\tfmt.Sprint(c)\n\treturn c\n}}\n\n" for i in range(15))
_SQL = "".join(f"CREATE TABLE {{pkg}}_t{i} (id INT PRIMARY KEY, amount DECIMAL(18,2), created TIMESTAMP);\nCREATE INDEX ix_{{pkg}}_t{i} ON {{pkg}}_t{i}(created);\n" for i in range(25))
_YAML = "service:\n  name: {cls}\n  replicas: 3\n" + "".join(f"  env{i}:\n    key: value{i}\n    enabled: true\n" for i in range(30))

_KINDS = [  # (weight, ext, plain, crypto)
    (40, "java", _JAVA, _JAVA_CRYPTO), (12, "cs", _CS, _CS_CRYPTO), (12, "py", _PY, _PY_CRYPTO), (14, "js", _JS, _JS_CRYPTO),
    (8, "cbl", _COBOL, _COBOL_CRYPTO), (6, "go", _GO, _GO), (4, "sql", _SQL, _SQL), (4, "yaml", _YAML, _YAML),
]


def build(root: Path, target_loc: int, seed: int = 7) -> tuple[int, int]:
    rnd = random.Random(seed)
    weights = [k[0] for k in _KINDS]
    loc = files = 0
    while loc < target_loc:
        w, ext, plain, crypto = rnd.choices(_KINDS, weights)[0]
        pkg = f"mod{rnd.randrange(400):03d}"
        cls = f"{ext.upper()}Cls{files}"
        body = (crypto if rnd.random() < 0.025 else plain).replace("{pkg}", pkg).replace("{cls}", cls)
        d = root / ("services" if rnd.random() < 0.8 else "libs") / pkg / ("src" if ext != "sql" else "db")
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{cls}.{ext}").write_text(body)
        loc += body.count("\n")
        files += 1
    return files, loc


def run(root: Path, procs: int) -> dict:
    os.environ["CRYPTOSCAN_SCAN_PROCESSES"] = str(procs)
    from scanner.core.scanner import Scanner

    t0 = time.perf_counter()
    result = Scanner().scan(root)
    dt = time.perf_counter() - t0
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    return {"procs": procs, "seconds": dt, "files": result.summary.files_scanned if hasattr(result, "summary") else len(result.findings), "findings": len(result.findings), "rss_mb": rss}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mloc", type=float, default=1.0)
    ap.add_argument("--procs", default="1,2")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    root = Path(tempfile.mkdtemp(prefix="cryptoscan-scale-"))
    t0 = time.perf_counter()
    files, loc = build(root, int(a.mloc * 1_000_000))
    print(f"synthetic monorepo: {files} files, {loc:,} LOC at {root} (built in {time.perf_counter() - t0:.0f}s)")
    rows = []
    for p in [int(x) for x in a.procs.split(",")]:
        r = run(root, p)
        rows.append(r)
        print(f"procs={p}: {r['seconds']:.1f}s  {loc / r['seconds'] / 1000:.1f} kLOC/s  {files / r['seconds']:.0f} files/s  findings={r['findings']}  peak RSS {r['rss_mb']:.0f} MB  -> 10M LOC ≈ {10_000_000 / (loc / r['seconds']) / 60:.1f} min")
    if len({r["findings"] for r in rows}) != 1:
        print("DETERMINISM FAILURE: finding counts differ across process counts", file=sys.stderr)
        return 2
    if not a.keep:
        shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
