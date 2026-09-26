"""Reproducible end-to-end scan benchmark.

Generates a synthetic repository of N source files with deterministic
cryptographic usage patterns, scans it through the real inline pipeline
(clone → detect → evidence → policy → dedup → graph → persist), and
reports wall-clock time, throughput, and finding counts.

The original spec's acceptance criterion was "10,000 files in under 5
minutes" — pass --budget 300 to enforce it (the default). Deterministic
seeding makes runs comparable across commits.

Examples:
    python3 scripts/benchmark_scan.py                     # 10k files, 300s budget
    python3 scripts/benchmark_scan.py --files 1000        # quick run
    python3 scripts/benchmark_scan.py --files 100 --keep  # inspect the corpus
"""

from __future__ import annotations

import argparse
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Canonical import set (mirrors the Makefile PYTHONPATH) so the script and
# its pipeline subprocess run bare, without a wrapper shell.
_SERVICE_PATHS = [
    "shared/shared_config", "shared/shared_logging", "shared/shared_models",
    *[f"services/{name}" for name in (
        "api", "database", "scanner", "evidence", "normalization", "policy",
        "drift", "worker", "deduplication", "cbom", "container_scanner",
        "network_scanner", "cloud_scanner", "runtime", "graph_engine",
        "business_context", "quantum", "remediation", "reporting",
        "ot_scanner", "vendor_intel", "agility",
    )],
]


def _ensure_pythonpath() -> None:
    existing = [p for p in __import__("os").environ.get("PYTHONPATH", "").split(":") if p]
    for rel in _SERVICE_PATHS:
        path = str(ROOT / rel)
        if path not in existing:
            existing.append(path)
    __import__("os").environ["PYTHONPATH"] = ":".join(existing)


_ensure_pythonpath()

JAVA_TEMPLATES = [
    'package com.example.mod{i};\nimport javax.crypto.Cipher;\npublic class Handler{i} {{\n'
    '  void run() throws Exception {{\n    Cipher c = Cipher.getInstance("{transform}");\n'
    '    byte[] key = "{key}".getBytes();\n    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));\n  }}\n}}\n',
    'package com.example.mod{i};\nimport java.security.MessageDigest;\npublic class Digest{i} {{\n'
    '  byte[] hash(byte[] data) throws Exception {{\n'
    '    MessageDigest md = MessageDigest.getInstance("{hash}");\n    return md.digest(data);\n  }}\n}}\n',
    'package com.example.mod{i};\nimport java.security.KeyPairGenerator;\npublic class KeyGen{i} {{\n'
    '  void generate() throws Exception {{\n'
    '    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
    '    kpg.initialize({rsa_bits});\n  }}\n}}\n',
]

PY_TEMPLATES = [
    'from Crypto.Cipher import AES\nimport os\n\ndef encrypt{i}(data: bytes) -> bytes:\n'
    '    key = os.urandom({aes_bytes})\n'
    '    cipher = AES.new(key, AES.MODE_{mode})\n    return cipher.encrypt(data)\n',
    'import hashlib\n\ndef fingerprint{i}(data: bytes) -> str:\n'
    '    return hashlib.new("{py_hash}", data).hexdigest()\n',
    'from cryptography.hazmat.primitives.asymmetric import padding\n'
    'from cryptography.hazmat.primitives import hashes\n\ndef sign{i}(key, data: bytes):\n'
    '    return key.sign(data, padding.PKCS1v15(), hashes.SHA{sha2}())\n',
]

TRANSFORMS = ["AES/GCM/NoPadding", "AES/ECB/PKCS5Padding", "DESede/CBC/PKCS5Padding", "AES/CBC/PKCS5Padding"]
HASHES = ["SHA-256", "MD5", "SHA-1"]
MODES = ["GCM", "CBC", "ECB"]
PY_HASHES = ["sha256", "md5"]
SHA2 = ["256", "512"]


def build_corpus(directory: Path, total_files: int, seed: int = 1337) -> None:
    rng = random.Random(seed)
    for i in range(total_files):
        language = rng.random()
        if language < 0.5:
            template = rng.choice(JAVA_TEMPLATES)
            name = directory / "src" / f"pkg{i % 50}" / f"Handler{i}.java"
            content = template.format(
                i=i,
                transform=rng.choice(TRANSFORMS),
                hash=rng.choice(HASHES),
                rsa_bits=rng.choice([1024, 2048, 4096]),
                key=f"hardcoded-key-{i:06d}",
            )
        else:
            template = rng.choice(PY_TEMPLATES)
            name = directory / "app" / f"mod{i % 50}" / f"service{i}.py"
            content = template.format(
                i=i,
                mode=rng.choice(MODES),
                aes_bytes=rng.choice([16, 32]),
                py_hash=rng.choice(PY_HASHES),
                sha2=rng.choice(SHA2),
            )
        name.parent.mkdir(parents=True, exist_ok=True)
        name.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark the full inline scan pipeline")
    parser.add_argument("--files", type=int, default=10_000, help="corpus size (default 10,000)")
    parser.add_argument("--budget", type=float, default=300.0, help="wall-clock seconds allowed (default 300)")
    parser.add_argument("--seed", type=int, default=1337, help="deterministic corpus seed")
    parser.add_argument("--keep", action="store_true", help="keep the generated corpus on exit")
    args = parser.parse_args()

    corpus = Path(tempfile.mkdtemp(prefix="cryptoscan-bench-"))
    try:
        print(f"generating {args.files:,} files ... ", end="", flush=True)
        t0 = time.perf_counter()
        build_corpus(corpus, args.files, seed=args.seed)
        gen_seconds = time.perf_counter() - t0
        actual = sum(1 for _ in corpus.rglob("*") if _.is_file())
        print(f"{actual:,} files in {gen_seconds:.1f}s")

        env_python = str(ROOT / ".venv" / "bin" / "python")
        if not Path(env_python).exists():
            env_python = sys.executable
        cmd = [env_python, str(ROOT / "scripts" / "trigger_scan.py"), f"local://{corpus}", "--inline"]
        print("scanning (full inline pipeline) ...", flush=True)
        t1 = time.perf_counter()
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT), timeout=max(600, args.budget * 4))
        scan_seconds = time.perf_counter() - t1
        if proc.returncode != 0:
            print(proc.stdout[-2000:])
            print(proc.stderr[-2000:], file=sys.stderr)
            return 2

        import re

        matches = re.findall(r'"scan_id"\s*:\s*"([0-9a-fA-F-]{36})"', proc.stdout)
        if not matches:
            print(proc.stdout[-2000:], file=sys.stderr)
            print(proc.stderr[-2000:], file=sys.stderr)
            return 2
        scan_id = matches[-1]

        # finding counts straight from the database the pipeline wrote
        findings = -1
        try:
            code = (
                "from sqlalchemy import text\n"
                "from db.connection.session import get_engine\n"
                "e = get_engine()\n"
                "with e.connect() as c:\n"
                f"    print(c.execute(text(\"select count(*) from evidence_records where scan_id='{scan_id}'\")).scalar())\n"
            )
            out = subprocess.run(
                [env_python, "-c", code], capture_output=True, text=True, cwd=str(ROOT), timeout=120,
            )
            findings = int(out.stdout.strip() or -1)
        except Exception:
            findings = -1

        files_per_sec = args.files / scan_seconds if scan_seconds else 0.0
        print("\n===== benchmark result =====")
        print(f"files:            {actual:,}")
        print(f"scan wall clock:  {scan_seconds:.1f}s  ({files_per_sec:,.0f} files/s)")
        print(f"evidence records: {findings:,}" if findings >= 0 else "evidence records: n/a")
        print(f"scan_id:          {scan_id}")
        if scan_seconds <= args.budget:
            print(f"budget:           PASS (<= {args.budget:.0f}s)")
            return 0
        print(f"budget:           FAIL ({scan_seconds:.1f}s > {args.budget:.0f}s)")
        return 1
    finally:
        if args.keep:
            print(f"corpus kept at {corpus}")
        else:
            shutil.rmtree(corpus, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
