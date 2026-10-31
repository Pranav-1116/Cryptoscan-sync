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
    "SSL_CTX_set_ciphersuites",
    "gnutls_priority_set_direct",
    "gnutls_handshake",
}

#: extra JSON fields the parser carries into a finding, per function. A hook can
#: record more than an algorithm name (a TLS version, a priority string); the
#: parser has to know to carry it, or the field is written and thrown away.
_EXTRA_FIELDS: dict[str, tuple[str, ...]] = {
    "SSL_CTX_set_min_proto_version": ("tls_min_version",),
    "SSL_CTX_set_max_proto_version": ("tls_max_version",),
    "SSL_CTX_set_cipher_list": ("cipher_list",),
    "SSL_CTX_set_ciphersuites": ("ciphersuites",),
    "gnutls_priority_set_direct": ("priority", "priority_accepted"),
    "gnutls_handshake": ("tls_version", "key_exchange"),
}

#: Which crypto stack each interposed symbol belongs to. The point of naming it
#: is the GnuTLS half: a process that links libgnutls and no libcrypto used to
#: produce nothing at all, and "nothing observed" read the same as "nothing ran".
HOOK_FAMILIES: dict[str, str] = {
    "openssl": "libcrypto/libssl (EVP_*, SSL_CTX_*)",
    "gnutls": "libgnutls (gnutls_*)",
}


def hook_family(symbol: str) -> str:
    """The crypto stack an interposed symbol belongs to."""
    return "gnutls" if symbol.startswith("gnutls_") else "openssl"


# Why the last ensure_shim() returned None. A compile failure used to be
# indistinguishable from "this host has no compiler", which hid a real build
# break (the shim stopped compiling under GCC 14) behind a benign-looking
# message for as long as nobody ran the compiler by hand.
LAST_SHIM_ERROR: str | None = None


def ensure_shim() -> Path | None:
    """Compile the C shim if a compiler is available; return its path.

    On failure returns None and records the reason in ``LAST_SHIM_ERROR``.
    """
    global LAST_SHIM_ERROR
    if SHIM_SO.exists():
        # A cached .so older than its source is the wrong artifact: it would be
        # loaded, seen to exist, and silently miss every hook added since. That
        # is how a tracer reports "not observed" for a stack it now supports.
        try:
            if SHIM_SO.stat().st_mtime >= SHIM_C.stat().st_mtime:
                return SHIM_SO
        except OSError:
            pass
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        LAST_SHIM_ERROR = "no C compiler on PATH (looked for gcc, cc)"
        return None
    if not SHIM_C.exists():
        LAST_SHIM_ERROR = f"shim source missing at {SHIM_C}"
        return None
    result = subprocess.run(
        [cc, "-O2", "-fPIC", "-shared", "-o", str(SHIM_SO), str(SHIM_C), "-ldl"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        LAST_SHIM_ERROR = (
            f"{cc} exited {result.returncode} compiling {SHIM_C.name}: "
            f"{(result.stderr or result.stdout or '').strip()[:800]}"
        )
        return None
    LAST_SHIM_ERROR = None
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
            for field in _EXTRA_FIELDS.get(function, ()):
                if row.get(field) is not None:
                    entry["extra"][field] = row[field]
    return list(grouped.values())


def hook_symbols(source: str | Path | None = None) -> tuple[str, ...]:
    """The symbols the shim actually interposes, read from the C source.

    Every interposed definition is a top-level ``int <symbol>(`` in the shim. This
    parses the shipped source rather than a hand-kept list, so a hook that is
    deleted from the C file disappears from the coverage report in the same
    commit — the report cannot claim a hook that no longer exists.

    ``services/runtime/tests/test_preload_trace.py`` confirms the parse against
    ``nm -D`` on the compiled object, so this is a reading of the artifact and
    not a guess about it.
    """
    import re

    path = Path(source) if source is not None else SHIM_C
    text = path.read_text(encoding="utf-8", errors="replace")
    return tuple(sorted({m.group(1) for m in re.finditer(r"^int ([A-Za-z_][A-Za-z0-9_]*)\(", text, re.M)}))


def shim_coverage(source: str | Path | None = None) -> dict[str, Any]:
    """Which crypto stacks the tracer can see, measured from the shim source."""
    symbols = hook_symbols(source)
    by_family: dict[str, list[str]] = {family: [] for family in HOOK_FAMILIES}
    for symbol in symbols:
        by_family.setdefault(hook_family(symbol), []).append(symbol)
    return {
        "schema": "cryptoscan.shim-coverage/1",
        "source": str(Path(source) if source is not None else SHIM_C),
        "symbols": by_family,
        "counts": {family: len(items) for family, items in by_family.items()},
        "total": len(symbols),
        "note": (
            "these are the symbols the shim interposes. A process that links a stack not listed "
            "here — Go's own crypto/tls, ring/rustls, the JVM's JCE, a statically linked OpenSSL — "
            "produces no observation, and that silence is not evidence of no use"
        ),
    }


def trace_command(
    argv: list[str],
    *,
    log_path: str | Path | None = None,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
    timeout: float | None = None,
    capture_limit: int = 4000,
    stdin: str | None = None,
) -> dict[str, Any]:
    """Run ``argv`` under the shim and return {findings, returncode, log}.

    ``log_path`` defaults to a temp file; the findings are parsed from it after
    the command exits. ``timeout`` (seconds) exists for the case this runner is
    pointed at something it did not write: the child is started in its own
    process group and the group is killed on expiry, because killing only the
    direct child leaves anything it forked running. A timed-out run is reported
    as ``timed_out: True`` with the observations it managed to write before the
    kill — the partial evidence is still evidence.
    """
    shim = ensure_shim()
    if shim is None:
        raise RuntimeError(f"cryptoscan_trace shim unavailable: {LAST_SHIM_ERROR}")
    import signal
    import tempfile
    import time

    own_log = log_path is None
    path = Path(log_path) if log_path else Path(tempfile.mkstemp(suffix=".jsonl")[1])
    run_env = dict(os.environ)
    run_env["LD_PRELOAD"] = str(shim) + (":" + run_env["LD_PRELOAD"] if run_env.get("LD_PRELOAD") else "")
    run_env["CRYPTOSCAN_TRACE_LOG"] = str(path)
    if env:
        run_env.update(env)
    started = time.monotonic()
    timed_out = False
    # a new session gives the child (and anything it forks) a process group of
    # its own, so the timeout can take the whole tree down
    process = subprocess.Popen(
        argv, env=run_env, cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        stdin=subprocess.PIPE if stdin is not None else None,
        start_new_session=True,
    )
    try:
        out, err = process.communicate(input=stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):  # already gone / not ours
            process.kill()
        out, err = process.communicate()
    duration_ms = int((time.monotonic() - started) * 1000)
    findings = parse_trace_log(path)
    if own_log:
        try:
            path.unlink()
        except OSError:
            pass
    return {
        "findings": findings,
        "returncode": process.returncode,
        "timed_out": timed_out,
        "duration_ms": duration_ms,
        "stdout": (out or "")[:capture_limit],
        "stderr": (err or "")[:capture_limit],
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
