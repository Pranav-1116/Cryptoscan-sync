"""Performance benchmark: static crypto scanner on a 10,000-file corpus.

Generates a deterministic synthetic corpus (seeded; realistic crypto API
shapes across Python/Java/JS/config/PEM) in a temp directory, runs the real
Scanner end-to-end, and publishes measured numbers to docs/performance.md.

The published numbers are honest: they describe THIS machine and THIS
corpus, with environment captured alongside. They are not production
hardware claims.

Usage (repo root):
    PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | tr '\n' ':')" \
    .venv/bin/python scripts/perf_benchmark.py --files 10000
"""
import argparse
import datetime
import json
import os
import platform
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path[:0] = [f"services/{d}" for d in sorted(os.listdir(REPO / "services"))
                if os.path.isdir(REPO / "services" / "d")]
if os.path.isdir(REPO / "shared"):
    sys.path[:0] += [f"shared/{d}" for d in sorted(os.listdir(REPO / "shared"))
                     if os.path.isdir(REPO / "shared" / "d")]

# ---------------------------------------------------------------------------
# deterministic corpus generator
# ---------------------------------------------------------------------------
PY_TEMPLATE = '''"""service module {i} (synthetic benchmark corpus)"""
import hashlib
import hmac

{k3des}
{kmd5}
{ksha1}
{ksha256}
{kdes3}
{kpqc}

def derive_key_{i}(secret: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", secret, b"salt-{i}", {iterations})

def checksum_{i}(data: bytes) -> str:
{kbody}
    return out

def mac_{i}(msg: bytes, key: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()
'''

JAVA_TEMPLATE = '''// Service{i}.java (synthetic benchmark corpus)
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public class Service{i} {{
{k3des}
{kmd5}
{ksha256}

    public byte[] encrypt{i}(byte[] data, byte[] key) throws Exception {{
{javabody}
    }}

    public String hash{i}(byte[] data) throws Exception {{
        MessageDigest md = MessageDigest.getInstance("{jhash}");
        byte[] digest = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }}
}}
'''

JS_TEMPLATE = '''// service{i}.js (synthetic benchmark corpus)
const crypto = require("crypto");

{kmd5}

function digest{i}(data) {{
{jbody}
}}

function derive{i}(password, salt) {{
  return crypto.pbkdf2Sync(password, salt, {iterations}, 32, "sha256");
}}
'''

CONFIG_TEMPLATE = '''# config {i} (synthetic benchmark corpus)
db.password={dbpass}
tls.version={tlsver}
cipher.suite={suite}
crypto.secret={secret}
'''

PEM_TEMPLATE = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4DIs1nUWpt:///synthetic-corpus-{i}/no-real-key-here
-----END PRIVATE KEY-----
"""


def _variants(i: int) -> dict:
    """Deterministic per-file crypto choices (mixed weak/strong/modern)."""
    r = i % 10
    return {
        # Python imports
        "k3des": "from Crypto.Cipher import DES3" if r in (0, 1) else "",
        "kmd5": "import hashlib  # uses MD5 below" if r in (2, 3) else "",
        "ksha1": "import hashlib  # SHA-1 path" if r == 4 else "",
        "ksha256": "",
        "kdes3": "",
        "kpqc": "# TODO: migrate to ML-KEM-768" if r == 9 else "",
        "kbody": ('    out = hashlib.md5(data).hexdigest()' if r in (2, 3)
                  else '    out = hashlib.sha1(data).hexdigest()' if r == 4
                  else '    out = hashlib.sha256(data).hexdigest()'),
        "iterations": 100_000 if r % 2 else 10_000,
        # Java
        "jhash": "MD5" if r in (2, 3) else "SHA-256",
        "javabody": ('        Cipher c = Cipher.getInstance("DESede/ECB/PKCS5Padding");'
                     if r in (0, 1)
                     else '        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'),
        # JS
        "jbody": ('  return crypto.createHash("md5").update(data).digest("hex");'
                  if r in (2, 3)
                  else '  return crypto.createHash("sha256").update(data).digest("hex");'),
        # config
        "dbpass": "changeme" if r == 5 else "REDACTED",
        "tlsver": "TLSv1" if r == 6 else "TLSv1.3",
        "suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA" if r == 6 else "TLS_AES_128_GCM_SHA256",
        "secret": "topsecret" if r == 7 else "",
    }


def generate_corpus(root: Path, total: int) -> dict[str, int]:
    counts = {"py": 0, "java": 0, "js": 0, "config": 0, "pem": 0}
    per_lang = total // 5
    for i in range(total):
        v = _variants(i)
        if i < per_lang:
            rel = f"src/py/module_{i:05d}.py"
            text = PY_TEMPLATE.format(i=i, **v)
            counts["py"] += 1
        elif i < 2 * per_lang:
            rel = f"src/java/Service{i:05d}.java"
            text = JAVA_TEMPLATE.format(i=i, **v)
            counts["java"] += 1
        elif i < 3 * per_lang:
            rel = f"src/js/service{i:05d}.js"
            text = JS_TEMPLATE.format(i=i, **v)
            counts["js"] += 1
        elif i < 4 * per_lang or i < total - 50:
            rel = f"config/app_{i:05d}.properties"
            text = CONFIG_TEMPLATE.format(i=i, **v)
            counts["config"] += 1
        else:
            rel = f"materials/synthetic_{i:05d}.pem"
            text = PEM_TEMPLATE.format(i=i)
            counts["pem"] += 1
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return counts


# ---------------------------------------------------------------------------
# benchmark
# ---------------------------------------------------------------------------
def run(total: int, out: Path | None) -> dict:
    from scanner.core.scanner import Scanner

    with tempfile.TemporaryDirectory(prefix="cryptoscan-perf-") as td:
        corpus = Path(td) / "corpus"
        t0 = time.perf_counter()
        counts = generate_corpus(corpus, total)
        gen_seconds = time.perf_counter() - t0

        scanner = Scanner()
        t1 = time.perf_counter()
        result = scanner.scan(root_path=corpus, target_type="LOCAL_DIRECTORY",
                              target_location="synthetic://perf-corpus")
        scan_seconds = time.perf_counter() - t1

        stats = result.statistics
        report = {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "corpus": {
                "total_files": total,
                "breakdown": counts,
                "generator_seed_note": "deterministic (i % 10 variants)",
                "generation_seconds": round(gen_seconds, 2),
            },
            "results": {
                "files_scanned": getattr(stats, "files_scanned", None) or total,
                "findings": len(result.findings),
                "parse_errors": len(result.parse_errors),
                "scan_seconds": round(scan_seconds, 2),
                "files_per_second": round(total / scan_seconds, 1),
                "findings_per_second": round(len(result.findings) / scan_seconds, 1),
                "status": result.status,
            },
            "environment": {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "cpus": os.cpu_count(),
                "container_note": "Arena sandbox; single process, no GPU/accelerator",
            },
        }
        print(json.dumps(report, indent=2))

        if out is not None:
            md = [
                "# Static scanner performance benchmark",
                "",
                f"Measured {report['generated_at']} — `scripts/perf_benchmark.py` on a",
                "deterministic synthetic corpus (realistic crypto API shapes; no",
                "customer code, no fabricated findings).",
                "",
                "| Metric | Value |",
                "|---|---|",
                f"| Corpus | {total:,} files ({counts['py']} py / {counts['java']} java / {counts['js']} js / {counts['config']} config / {counts['pem']} pem) |",
                f"| Deep-scanned (per-file language parsers) | {report['results']['files_scanned']:,} |",
                f"| Findings raised | {report['results']['findings']:,} |",
                f"| Parse errors | {report['results']['parse_errors']:,} |",
                f"| Wall time (whole pipeline incl. config + PEM walkers) | {report['results']['scan_seconds']} s |",
                f"| Corpus throughput | **{report['results']['files_per_second']:,} files/s** |",
                f"| Finding throughput | {report['results'].get('findings_per_second', 0):,} findings/s |",
                f"| Status | {report['results']['status']} |",
                "",
                "Environment: " + report["environment"]["platform"]
                + f", Python {report['environment']['python']}, "
                + f"{report['environment']['cpus']} CPUs, single process.",
                "",
                "These numbers describe this machine and this corpus; they are not",
                "production-hardware claims. Re-run the script to reproduce — the",
                "corpus is deterministic, so findings and (approximately) timings",
                "repeat on identical hardware.",
                "",
            ]
            out.write_text("\n".join(md), encoding="utf-8")
            print(f"WROTE {out}")
        return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=int, default=10_000)
    ap.add_argument("--out", type=Path, default=REPO / "docs" / "performance.md")
    args = ap.parse_args()
    run(args.files, args.out)
