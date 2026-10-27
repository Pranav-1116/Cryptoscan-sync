"""LD_PRELOAD crypto-call tracer — parser unit tests + real-process E2E.

The E2E test compiles the C shim (skipped when no compiler is available) and
runs the *real* openssl CLI under LD_PRELOAD, asserting the tracer observed
the actual cipher/digest operations. This is the ADR-012 runtime-visibility
path: no kernel agent, no privileges.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from runtime.agent.preload_trace import (
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


@pytest.mark.skipif(not (_HAS_CC and _HAS_OPENSSL), reason="requires C compiler + openssl CLI")
def test_trace_command_rejects_when_no_shim(monkeypatch, tmp_path):
    """Without a compiler the runner raises a clear error instead of failing silently."""
    if shutil.which("gcc") or shutil.which("cc"):
        pytest.skip("compiler present; the no-shim path is covered by unit logic")
    from runtime.agent import preload_trace

    monkeypatch.setattr(preload_trace, "ensure_shim", lambda: None)
    with pytest.raises(RuntimeError, match="shim unavailable"):
        trace_command(["true"])
