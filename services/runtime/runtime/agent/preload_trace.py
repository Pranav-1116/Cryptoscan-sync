"""LD_PRELOAD crypto-call tracer — runner + JSONL parser.

The C shim (``runtime/cshim/cryptoscan_trace.c``) records one JSONL line per
cryptographic operation into ``CRYPTOSCAN_TRACE_LOG``. This module:

- builds the shim when a compiler is available (``ensure_shim``),
- runs an arbitrary command under ``LD_PRELOAD`` (``trace_command``),
- parses the JSONL into runtime findings shaped exactly like the API's
  ``RuntimeFinding`` schema (``POST /api/v1/scans/runtime-findings``), with
  observation counts aggregated per (pid, function, algorithm).

Metadata only: algorithms, modes, key sizes, TLS versions — never key bytes,
IVs, or plaintext. This is the ADR-012 runtime-visibility path: no kernel
agent, no privileges, works with any dynamically-linked process.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SHIM_C = Path(__file__).resolve().parents[2] / "cshim" / "cryptoscan_trace.c"
SHIM_SO = Path(__file__).resolve().parent / "cryptoscan_trace.so"

# Functions whose algorithm field is a digest/cipher name we can report
# directly as the finding's algorithm.
_ALGO_FUNCTIONS = {
    "EVP_CipherInit_ex",
    "EVP_CipherInit_ex2",
    "EVP_DigestInit_ex",
    "EVP_DigestInit_ex2",
}
_PKEY_FUNCTIONS = {
    "EVP_PKEY_sign",
    "EVP_PKEY_verify",
    "EVP_PKEY_encrypt",
    "EVP_PKEY_decrypt",
    "EVP_PKEY_derive",
    "EVP_PKEY_keygen",
}
_TLS_FUNCTIONS = {
    "SSL_CTX_set_min_proto_version",
    "SSL_CTX_set_max_proto_version",
    "SSL_CTX_set_cipher_list",
}


def ensure_shim() -> Path | None:
    """Compile the C shim if a compiler is available; return its path."""
    if SHIM_SO.exists():
        return SHIM_SO
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None or not SHIM_C.exists():
        return None
    result = subprocess.run(
        [cc, "-O2", "-fPIC", "-shared", "-o", str(SHIM_SO), str(SHIM_C), "-ldl"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return SHIM_SO


def parse_trace_log(log_path: str | Path) -> list[dict[str, Any]]:
    """Parse shim JSONL into aggregated RuntimeFinding-shaped dicts.

    Aggregation: same (pid, function, algorithm, mode, key_size) counts as
    repeated observations of the same crypto operation.
    """
    rows: list[dict[str, Any]] = []
    path = Path(log_path)
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        rows.append(row)

    grouped: dict[tuple, dict[str, Any]] = {}
    for row in rows:
        function = str(row.get("function") or "")
        algorithm = str(row.get("algorithm") or "").strip() or "UNKNOWN"
        mode = str(row.get("mode") or "").strip() or None
        key_size = row.get("key_size")
        key_size = int(key_size) if isinstance(key_size, (int, float)) and key_size else None
        pid = row.get("pid")
        process = str(row.get("process") or "unknown")
        key = (pid, function, algorithm, mode, key_size)
        entry = grouped.setdefault(
            key,
            {
                "process_name": process,
                "pid": pid,
                "function": function,
                "algorithm": algorithm,
                "mode": mode,
                "key_size": key_size,
                "observation_count": 0,
                "extra": {"source": "ld-preload"},
            },
        )
        entry["observation_count"] += 1
        if function in _TLS_FUNCTIONS:
            for field in ("tls_min_version", "tls_max_version", "cipher_list"):
                if row.get(field) is not None:
                    entry["extra"][field] = row[field]
    return list(grouped.values())


def trace_command(
    argv: list[str],
    *,
    log_path: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run ``argv`` under the shim and return {findings, returncode, log}.

    ``log_path`` defaults to a temp file; the findings are parsed from it
    after the command exits.
    """
    shim = ensure_shim()
    if shim is None:
        raise RuntimeError(
            "cryptoscan_trace shim unavailable: no C compiler or missing cshim source"
        )
    import tempfile

    own_log = log_path is None
    path = Path(log_path) if log_path else Path(tempfile.mkstemp(suffix=".jsonl")[1])
    run_env = dict(os.environ)
    run_env["LD_PRELOAD"] = str(shim) + (":" + run_env["LD_PRELOAD"] if run_env.get("LD_PRELOAD") else "")
    run_env["CRYPTOSCAN_TRACE_LOG"] = str(path)
    if env:
        run_env.update(env)
    result = subprocess.run(argv, env=run_env, capture_output=True, text=True)
    findings = parse_trace_log(path)
    if own_log:
        try:
            path.unlink()
        except OSError:
            pass
    return {
        "findings": findings,
        "returncode": result.returncode,
        "stdout": result.stdout[:4000],
        "stderr": result.stderr[:4000],
    }


def main(argv: list[str] | None = None) -> int:
    """CLI: ``python -m runtime.agent.preload_trace -- <command...>``"""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in {"-h", "--help"}:
        print("usage: cryptoscan-runtime trace -- <command> [args...]")
        print("       (sets LD_PRELOAD + CRYPTOSCAN_TRACE_LOG; prints findings JSON)")
        return 0 if argv and argv[0] in {"-h", "--help"} else 2
    if argv[0] == "--":
        argv = argv[1:]
    result = trace_command(argv)
    print(json.dumps(result["findings"], indent=2))
    print(f"# returncode={result['returncode']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
