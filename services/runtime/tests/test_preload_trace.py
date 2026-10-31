"""LD_PRELOAD crypto-call tracer — parser unit tests + real-process E2E.

The E2E test compiles the C shim (skipped when no compiler is available) and
runs the *real* openssl CLI under LD_PRELOAD, asserting the tracer observed
the actual cipher/digest operations. This is the ADR-012 runtime-visibility
path: no kernel agent, no privileges.
"""

from __future__ import annotations

import ctypes.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from runtime.agent.preload_trace import (
    SHIM_C,
    SHIM_SO,
    ensure_shim,
    parse_trace_log,
    trace_command,
)

_HAS_CC = shutil.which("gcc") or shutil.which("cc")
_HAS_OPENSSL = shutil.which("openssl") is not None


def _write_log(tmp_path: Path, lines: list[dict]) -> Path:
    path = tmp_path / "trace.jsonl"
    path.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
    return path


def test_parse_trace_log_aggregates(tmp_path):
    path = _write_log(
        tmp_path,
        [
            {"ts": 1, "pid": 42, "process": "openssl", "function": "EVP_CipherInit_ex", "algorithm": "AES-256-CBC", "mode": "", "key_size": 32},
            {"ts": 2, "pid": 42, "process": "openssl", "function": "EVP_CipherInit_ex", "algorithm": "AES-256-CBC", "mode": "", "key_size": 32},
            {"ts": 3, "pid": 42, "process": "openssl", "function": "EVP_DigestInit_ex", "algorithm": "SHA2-256", "mode": "", "key_size": 0},
            {"ts": 4, "pid": 43, "process": "nginx", "function": "SSL_CTX_set_min_proto_version", "algorithm": "TLS", "mode": "", "key_size": 0, "tls_min_version": 771},
            {"not": "json"},
        ],
    )
    findings = parse_trace_log(path)
    by_key = {(f["pid"], f["function"], f["algorithm"]) for f in findings}
    assert (42, "EVP_CipherInit_ex", "AES-256-CBC") in by_key
    assert (43, "SSL_CTX_set_min_proto_version", "TLS") in by_key
    cipher = next(f for f in findings if f["algorithm"] == "AES-256-CBC")
    assert cipher["observation_count"] == 2
    assert cipher["key_size"] == 32
    tls = next(f for f in findings if f["function"] == "SSL_CTX_set_min_proto_version")
    assert tls["extra"]["tls_min_version"] == 771


def test_parse_missing_log_returns_empty(tmp_path):
    assert parse_trace_log(tmp_path / "nope.jsonl") == []


def test_parse_missing_algorithm_stays_unknown(tmp_path):
    path = _write_log(
        tmp_path,
        [{"pid": 42, "process": "openssl", "function": "EVP_DigestInit_ex", "algorithm": ""}],
    )
    assert parse_trace_log(path)[0]["algorithm"] == "UNKNOWN"


def test_malformed_lines_skipped(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text("{broken\n{\"ts\":1,\"pid\":1,\"process\":\"p\",\"function\":\"f\",\"algorithm\":\"A\",\"mode\":\"\",\"key_size\":0}\n")
    findings = parse_trace_log(path)
    assert len(findings) == 1
    assert findings[0]["algorithm"] == "A"


@pytest.mark.skipif(not _HAS_CC, reason="no C compiler available")
def test_shim_compiles():
    shim = ensure_shim()
    assert shim is not None and shim.exists()
    assert SHIM_SO.exists()


@pytest.mark.skipif(not (_HAS_CC and _HAS_OPENSSL), reason="requires C compiler + openssl CLI")
def test_trace_real_openssl_cipher(tmp_path):
    """Run `openssl enc -aes-256-cbc` under the shim and see it traced."""
    log = tmp_path / "trace.jsonl"
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"hello cryptoscan tracer" * 10)
    result = trace_command(
        ["openssl", "enc", "-aes-256-cbc", "-in", str(payload), "-out", str(tmp_path / "out.bin"), "-pass", "pass:test1234", "-nosalt"],
        log_path=log,
    )
    assert result["returncode"] == 0, result["stderr"]
    assert log.exists()
    algos = {f["algorithm"] for f in result["findings"]}
    assert "AES-256-CBC" in algos, f"expected AES-256-CBC in {algos}"
    # key_size must reflect the cipher, never the key bytes
    for f in result["findings"]:
        if f["algorithm"] == "AES-256-CBC":
            assert f["key_size"] in (32, None)


@pytest.mark.skipif(not (_HAS_CC and _HAS_OPENSSL), reason="requires C compiler + openssl CLI")
def test_trace_real_openssl_digest(tmp_path):
    log = tmp_path / "trace.jsonl"
    payload = tmp_path / "payload.txt"
    payload.write_text("hash me please")
    result = trace_command(
        ["openssl", "dgst", "-sha256", str(payload)],
        log_path=log,
    )
    assert result["returncode"] == 0, result["stderr"]
    functions = {f["function"] for f in result["findings"]}
    assert "EVP_DigestInit_ex" in functions or "EVP_DigestInit_ex2" in functions
    algos = {f["algorithm"] for f in result["findings"]}
    assert "SHA2-256" in algos or "SHA-256" in algos or "SHA256" in algos


@pytest.mark.skipif(not _HAS_CC, reason="requires C compiler")
@pytest.mark.parametrize(
    ("kind", "function", "expected"),
    [
        ("digest", "EVP_DigestInit_ex", "SHA256"),
        ("cipher", "EVP_CipherInit_ex", "AES-256-CBC"),
    ],
)
def test_first_evp_call_resolves_algorithm(tmp_path, kind, function, expected):
    """A process making only one EVP call must not lose its algorithm name."""
    libcrypto = ctypes.util.find_library("crypto")
    assert libcrypto is not None
    # Use a fresh process for each call: tracing the openssl CLI can mask a
    # first-call bug when its setup happens to invoke EVP more than once.
    script = """
import ctypes
import sys

lib = ctypes.CDLL(sys.argv[2], mode=ctypes.RTLD_GLOBAL)
shim = ctypes.CDLL(None)  # RTLD_DEFAULT includes the LD_PRELOAD interposer
kind = sys.argv[1]
name = b"SHA256" if kind == "digest" else b"aes-256-cbc"
selector = getattr(lib, "EVP_get_digestbyname" if kind == "digest" else "EVP_get_cipherbyname")
selector.argtypes = [ctypes.c_char_p]
selector.restype = ctypes.c_void_p
algorithm = selector(name)
assert algorithm, name
new_ctx = getattr(lib, "EVP_MD_CTX_new" if kind == "digest" else "EVP_CIPHER_CTX_new")
new_ctx.restype = ctypes.c_void_p
ctx = new_ctx()
assert ctx
init = getattr(shim, "EVP_DigestInit_ex" if kind == "digest" else "EVP_CipherInit_ex")
init.restype = ctypes.c_int
if kind == "digest":
    init.argtypes = [ctypes.c_void_p] * 3
    rc = init(ctx, algorithm, None)
else:
    init.argtypes = [ctypes.c_void_p] * 5 + [ctypes.c_int]
    rc = init(ctx, algorithm, None, None, None, 1)
assert rc == 1
"""
    result = trace_command(
        [sys.executable, "-S", "-c", script, kind, libcrypto],
        log_path=tmp_path / "first-call.jsonl",
        timeout=10,
    )
    assert result["returncode"] == 0, result["stderr"]
    observed = [f for f in result["findings"] if f["function"] == function]
    assert len(observed) == 1, result["findings"]
    allowed = {expected, "SHA2-256"} if kind == "digest" else {expected}
    assert observed[0]["algorithm"].upper() in allowed


@pytest.mark.skipif(not (_HAS_CC and _HAS_OPENSSL), reason="requires C compiler + openssl CLI")
def test_trace_command_rejects_when_no_shim(monkeypatch, tmp_path):
    """Without a compiler the runner raises a clear error instead of failing silently."""
    if shutil.which("gcc") or shutil.which("cc"):
        pytest.skip("compiler present; the no-shim path is covered by unit logic")
    from runtime.agent import preload_trace

    monkeypatch.setattr(preload_trace, "ensure_shim", lambda: None)
    with pytest.raises(RuntimeError, match="shim unavailable"):
        trace_command(["true"])


# --------------------------------------------------------------------------- #
# a second native TLS stack: GnuTLS
# --------------------------------------------------------------------------- #


def test_the_coverage_report_is_read_from_the_shim_source():
    from runtime.agent.preload_trace import HOOK_FAMILIES, hook_symbols, shim_coverage

    coverage = shim_coverage()
    assert coverage["schema"] == "cryptoscan.shim-coverage/1"
    assert coverage["total"] == len(hook_symbols())
    assert set(coverage["counts"]) == set(HOOK_FAMILIES)
    # both stacks are interposed, and the OpenSSL half is not the whole story
    assert coverage["counts"]["openssl"] >= 10
    assert coverage["counts"]["gnutls"] >= 5
    assert "TLS 1.3" not in coverage["note"]  # the note describes the limit, not a feature


@pytest.mark.skipif(not _HAS_CC, reason="no C compiler available")
def test_the_parsed_hooks_are_the_symbols_the_compiled_shim_exports(tmp_path):
    """The report must describe the artifact, not a comment about it.

    `hook_symbols()` parses the C source; `nm -D` reads the built object. If a
    hook is declared but not exported (a `static`, a typo in the signature, a
    section the linker drops), the two disagree and this fails.
    """
    cc = shutil.which("gcc") or shutil.which("cc")
    built = tmp_path / "shim.so"
    compiled = subprocess.run(
        [cc, "-O2", "-fPIC", "-shared", "-o", str(built), str(SHIM_C), "-ldl"],
        capture_output=True, text=True,
    )
    assert compiled.returncode == 0, compiled.stderr
    exported = set()
    for line in subprocess.run(
        ["nm", "-D", "--defined-only", str(built)], capture_output=True, text=True
    ).stdout.splitlines():
        parts = line.split()
        if parts and parts[-1].startswith(("EVP_", "SSL_", "gnutls_")):
            exported.add(parts[-1])
    from runtime.agent.preload_trace import hook_symbols

    assert set(hook_symbols()) == exported
    assert {symbol for symbol in exported if symbol.startswith("gnutls_")} == {
        "gnutls_cipher_init",
        "gnutls_handshake",
        "gnutls_hash_init",
        "gnutls_hmac_init",
        "gnutls_priority_set_direct",
    }


def test_the_shim_is_rebuilt_when_its_source_is_newer(monkeypatch, tmp_path):
    """A stale .so would be loaded and silently miss the hook it was rebuilt for."""
    from runtime.agent import preload_trace

    source = tmp_path / "cryptoscan_trace.c"
    source.write_text("int a_hook(void) { return 0; }\n")
    built = tmp_path / "shim.so"
    built.write_text("stale\n")
    os.utime(built, (1_000_000, 1_000_000))  # older than the source

    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        Path(argv[argv.index("-o") + 1]).write_text("fresh\n")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(preload_trace, "SHIM_C", source)
    monkeypatch.setattr(preload_trace, "SHIM_SO", built)
    monkeypatch.setattr(preload_trace.subprocess, "run", fake_run)
    assert preload_trace.ensure_shim() == built
    assert calls, "a newer source must trigger a rebuild"
    assert built.read_text() == "fresh\n"


def test_a_gnutls_finding_carries_its_algorithm_and_tls_fields(tmp_path):
    path = _write_log(
        tmp_path,
        [
            {
                "ts": 1, "pid": 7, "process": "wget",
                "function": "gnutls_cipher_init", "algorithm": "AES-256-GCM",
                "mode": "", "key_size": 32,
            },
            {
                "ts": 2, "pid": 7, "process": "wget",
                "function": "gnutls_handshake", "algorithm": "AES-256-GCM", "mode": "",
                "key_size": 0, "tls_version": "TLS1.3", "key_exchange": "ECDHE-RSA",
            },
            {
                "ts": 3, "pid": 7, "process": "wget",
                "function": "gnutls_priority_set_direct", "algorithm": "GnuTLS", "mode": "",
                "key_size": 0, "priority": "SECURE256:+SECURE192:-VERS-ALL:+VERS-TLS1.3",
                "priority_accepted": True,
            },
            {
                "ts": 4, "pid": 7, "process": "wget",
                "function": "gnutls_hmac_init", "algorithm": "HMAC-SHA256", "mode": "",
                "key_size": 32,
            },
        ],
    )
    findings = {(f["function"]): f for f in parse_trace_log(path)}
    assert findings["gnutls_cipher_init"]["algorithm"] == "AES-256-GCM"
    assert findings["gnutls_cipher_init"]["key_size"] == 32
    assert findings["gnutls_hmac_init"]["key_size"] == 32
    # the negotiated facts and the configured policy are carried, not dropped
    assert findings["gnutls_handshake"]["extra"]["tls_version"] == "TLS1.3"
    assert findings["gnutls_handshake"]["extra"]["key_exchange"] == "ECDHE-RSA"
    priority = findings["gnutls_priority_set_direct"]["extra"]
    assert priority["priority"].startswith("SECURE256")
    assert priority["priority_accepted"] is True
    for finding in findings.values():
        assert finding["extra"]["source"] == "ld-preload"


def test_every_hook_writes_fields_the_parser_carries():
    """A hook whose JSON field the parser ignores has recorded nothing usable."""
    import re

    from runtime.agent.preload_trace import SHIM_C, _EXTRA_FIELDS, _TLS_FUNCTIONS, hook_symbols

    source = SHIM_C.read_text(encoding="utf-8")
    # every interposed symbol that emits an "extra" field must have a parser entry
    emitted = {
        symbol: set(re.findall(r'\\"([a-z_]+)\\":', body))
        for symbol, body in _bodies(source, hook_symbols())
    }
    for symbol, fields in emitted.items():
        declared = set(_EXTRA_FIELDS.get(symbol, ()))
        assert fields <= declared, f"{symbol} writes {fields - declared} which parse_trace_log drops"
        if fields:
            assert symbol in _TLS_FUNCTIONS or symbol.startswith("gnutls_"), symbol


def _bodies(source: str, symbols) -> list[tuple[str, str]]:
    """Split the C source into (symbol, body) for each interposed definition."""
    import re

    out = []
    for symbol in symbols:
        start = re.search(rf"^int {re.escape(symbol)}\(", source, re.M)
        assert start is not None, symbol
        end = source.find("\n}\n", start.end())
        out.append((symbol, source[start.start():end]))
    return out


#: A stand-in for libgnutls. This host has no libgnutls, and the alternative to
#: a stand-in is claiming the GnuTLS hooks work without ever calling one. The
#: fake records the call it received (so forwarding is proven), and answers the
#: name getters the shim resolves through dlsym, so the *whole* path is exercised:
#: interposed symbol → real function → metadata getter → JSONL line.
_FAKE_GNUTLS_C = r"""
#include <stdio.h>
#include <stdlib.h>

typedef struct { unsigned int size; unsigned char *data; } datum;

int gnutls_cipher_init(void **handle, int cipher, const datum *key, const datum *iv) {
    const char *marker = getenv("FAKE_GNUTLS_MARKER");
    if (marker) {
        FILE *f = fopen(marker, "a");
        if (f) { fprintf(f, "cipher_init cipher=%d key_size=%u\n", cipher, key ? key->size : 0u); fclose(f); }
    }
    if (handle) *handle = (void *)0x1;
    return 0;
}

int gnutls_hash_init(void **dig, int algorithm) { if (dig) *dig = (void *)0x1; return 0; }

int gnutls_hmac_init(void **dig, int algorithm, const void *key, unsigned long keylen) {
    if (dig) *dig = (void *)0x1;
    return 0;
}

const char *gnutls_cipher_get_name(int cipher) {
    return cipher == 10 ? "AES-256-GCM" : "UNKNOWN-CIPHER";
}
const char *gnutls_hash_get_name(int algorithm) { return algorithm == 6 ? "SHA256" : "UNKNOWN-HASH"; }
const char *gnutls_mac_get_name(int algorithm) { return algorithm == 6 ? "SHA256" : "UNKNOWN-MAC"; }
const char *gnutls_protocol_get_name(int version) { return "TLS1.3"; }
const char *gnutls_kx_get_name(int kx) { return "ECDHE-RSA"; }
int gnutls_cipher_get(void *session) { return 10; }
int gnutls_protocol_get_version(void *session) { return 10; }
int gnutls_kx_get(void *session) { return 10; }
"""


@pytest.mark.skipif(not _HAS_CC, reason="no C compiler available")
def test_gnutls_calls_are_forwarded_and_their_metadata_recorded(tmp_path):
    cc = shutil.which("gcc") or shutil.which("cc")
    fake = tmp_path / "libfakegnutls.so"
    source = tmp_path / "fake_gnutls.c"
    source.write_text(_FAKE_GNUTLS_C)
    compiled = subprocess.run(
        [cc, "-O2", "-fPIC", "-shared", "-o", str(fake), str(source)], capture_output=True, text=True
    )
    assert compiled.returncode == 0, compiled.stderr

    marker = tmp_path / "marker.txt"
    log = tmp_path / "gnutls.jsonl"
    driver = """
import ctypes
import sys

class Datum(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint), ("data", ctypes.c_void_p)]

fake = ctypes.CDLL(sys.argv[1], mode=ctypes.RTLD_GLOBAL)   # the library, after the shim
shim = ctypes.CDLL(None)                                   # resolves to LD_PRELOAD first
init = shim.gnutls_cipher_init
init.restype = ctypes.c_int
init.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_int,
                 ctypes.POINTER(Datum), ctypes.POINTER(Datum)]
secret = b"SECRETKEYBYTESDONOTLOG0123456789"
buf = (ctypes.c_ubyte * len(secret)).from_buffer_copy(secret)
key = Datum(size=32, data=ctypes.cast(buf, ctypes.c_void_p))
handle = ctypes.c_void_p()
assert init(ctypes.byref(handle), 10, ctypes.byref(key), None) == 0
hash_init = shim.gnutls_hash_init
hash_init.restype = ctypes.c_int
hash_init.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_int]
dig = ctypes.c_void_p()
assert hash_init(ctypes.byref(dig), 6) == 0
"""
    driver_path = tmp_path / "driver.py"
    driver_path.write_text(driver)
    result = trace_command(
        [sys.executable, "-S", str(driver_path), str(fake)],
        log_path=log,
        env={"FAKE_GNUTLS_MARKER": str(marker)},
        timeout=20,
    )
    assert result["returncode"] == 0, result["stderr"]

    # 1. the call was forwarded to the library, with its arguments intact
    assert marker.exists(), "the shim swallowed the call instead of forwarding it"
    assert "cipher_init cipher=10 key_size=32" in marker.read_text()

    # 2. the shim recorded it, with names resolved from the library's own getters
    findings = {f["function"]: f for f in result["findings"]}
    assert findings["gnutls_cipher_init"]["algorithm"] == "AES-256-GCM"
    assert findings["gnutls_cipher_init"]["key_size"] == 32
    assert findings["gnutls_hash_init"]["algorithm"] == "SHA256"

    # 3. key material never reaches the log, at any key size
    raw = log.read_text()
    assert "SECRETKEY" not in raw
    assert "SECRETKEY" not in json.dumps(result["findings"])
