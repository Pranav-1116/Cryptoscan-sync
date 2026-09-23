"""Opt-in dynamic analysis (ADR-012 LD_PRELOAD tracer) — policy, preflight, findings.

The point of these tests is the *refusals* as much as the runs: the scanner must
never execute a sample by accident, and must never let "nothing was executed"
read as "nothing found".
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from devsecops import dynamic_scan as dyn

# the binary fixtures are shared with the scanner suite, loaded by path because
# the tests directory is not a package
_spec = importlib.util.spec_from_file_location(
    "binary_scan_fixtures", Path(__file__).with_name("test_binary_scan.py"))
binary_scan_fixtures = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("binary_scan_fixtures", binary_scan_fixtures)
_spec.loader.exec_module(binary_scan_fixtures)
_elf64 = binary_scan_fixtures._elf64

CC = shutil.which("gcc") or shutil.which("cc")
OPENSSL = shutil.which("openssl")
SLEEP = shutil.which("sleep")
IS_X86 = os.uname().machine.lower() in {"x86_64", "amd64"}

_TRACER = None


def _tracer_available() -> bool:
    """Whether the shim can be built here (two tests actually execute something)."""
    global _TRACER
    if _TRACER is None:
        from runtime.agent.preload_trace import ensure_shim

        _TRACER = ensure_shim() is not None
    return _TRACER


def _allowed_env(monkeypatch, root: Path, **extra) -> None:
    monkeypatch.setenv("BINARY_EXECUTION_ENABLED", "true")
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(root))
    monkeypatch.setenv("BINARY_EXECUTION_ALLOWLIST", str(root))
    for key, value in extra.items():
        monkeypatch.setenv(key, str(value))


def _executable(root: Path, name: str = "sample.bin", **kwargs) -> Path:
    """A real ELF on disk, marked executable — parse_bytes must accept it."""
    path = root / name
    path.write_bytes(_elf64(soname=name, **kwargs))
    path.chmod(0o755)
    return path


def _compiled(root: Path, source: str, name: str = "sample") -> Path:
    """A runnable ELF built from C (needs a compiler)."""
    src = root / f"{name}.c"
    src.write_text(source)
    target = root / name
    subprocess.run([CC, "-o", str(target), str(src)], check=True, capture_output=True)
    target.chmod(0o755)
    return target


# --------------------------------------------------------------------------- #
# policy
# --------------------------------------------------------------------------- #

def test_execution_is_off_until_the_host_says_so(monkeypatch):
    monkeypatch.delenv("BINARY_EXECUTION_ENABLED", raising=False)
    policy = dyn.ExecutionPolicy.from_env()
    assert policy.allowed is False
    result = dyn.dynamic_scan("/bin/true", policy=policy)
    assert result["executed"] is False
    assert any("execution is disabled" in reason for reason in result["refusals"])
    assert [f["code"] for f in result["findings"]] == ["BIN-DYNAMIC-REFUSED"]


def test_the_timeout_from_the_environment_is_clamped(monkeypatch):
    monkeypatch.setenv("BINARY_EXECUTION_TIMEOUT", "999")
    assert dyn.ExecutionPolicy.from_env().timeout == dyn.MAX_TIMEOUT
    monkeypatch.setenv("BINARY_EXECUTION_TIMEOUT", "0")
    assert dyn.ExecutionPolicy.from_env().timeout == 1
    monkeypatch.setenv("BINARY_EXECUTION_TIMEOUT", "not-a-number")
    assert dyn.ExecutionPolicy.from_env().timeout == dyn.DEFAULT_TIMEOUT


def test_a_dry_run_is_the_preflight_and_says_no_process_ran(monkeypatch, tmp_path):
    _allowed_env(monkeypatch, tmp_path)
    sample = _executable(tmp_path)
    result = dyn.dynamic_scan(sample, execute=False)
    assert result["executed"] is False
    assert any("dry run" in reason for reason in result["refusals"])
    assert result["findings"][0]["code"] == "BIN-DYNAMIC-DRY-RUN"
    assert result["findings"][0]["severity"] == "INFO"
    assert "Nothing was executed" in result["findings"][0]["detail"]


def test_the_limits_are_stated_not_implied(monkeypatch, tmp_path):
    _allowed_env(monkeypatch, tmp_path)
    limits = " ".join(dyn.dynamic_scan(_executable(tmp_path))["limits"])
    assert "no kernel sandbox" in limits and "no network namespace" in limits
    assert "process group" in limits


# --------------------------------------------------------------------------- #
# preflight refusals
# --------------------------------------------------------------------------- #

def test_a_static_binary_is_refused_because_preloading_cannot_reach_it(monkeypatch, tmp_path):
    _allowed_env(monkeypatch, tmp_path)
    sample = _executable(tmp_path)
    real = dyn.preflight.__globals__  # noqa: F841 — readability only
    from devsecops import binary_scan as bs

    original = bs.parse_bytes
    monkeypatch.setattr(bs, "parse_bytes", lambda data, **kw: {**original(data, **kw), "static": True})
    result = dyn.dynamic_scan(sample)
    assert any("statically linked" in reason for reason in result["refusals"])


def test_an_untraceable_format_is_refused(monkeypatch, tmp_path):
    _allowed_env(monkeypatch, tmp_path)
    sample = _executable(tmp_path)
    from devsecops import binary_scan as bs

    original = bs.parse_bytes
    monkeypatch.setattr(bs, "parse_bytes", lambda data, **kw: {**original(data, **kw), "format": "text"})
    result = dyn.dynamic_scan(sample)
    assert any("not an executable container" in reason for reason in result["refusals"])


@pytest.mark.skipif(not IS_X86, reason="architecture-mismatch case assumes an x86-64 host")
def test_an_architecture_mismatch_is_refused(monkeypatch, tmp_path):
    _allowed_env(monkeypatch, tmp_path)
    sample = _executable(tmp_path)
    from devsecops import binary_scan as bs

    original = bs.parse_bytes
    monkeypatch.setattr(bs, "parse_bytes", lambda data, **kw: {**original(data, **kw), "arch": "aarch64"})
    result = dyn.dynamic_scan(sample)
    assert any("architecture mismatch" in reason for reason in result["refusals"])


def test_a_path_outside_the_source_roots_is_refused(monkeypatch, tmp_path):
    _allowed_env(monkeypatch, tmp_path / "allowed")
    sample = _executable(tmp_path)
    result = dyn.dynamic_scan(sample)
    assert any("outside the configured source roots" in reason for reason in result["refusals"])


def test_a_path_outside_the_allowlist_is_refused(monkeypatch, tmp_path):
    _allowed_env(monkeypatch, tmp_path)
    monkeypatch.setenv("BINARY_EXECUTION_ALLOWLIST", str(tmp_path / "somewhere-else"))
    result = dyn.dynamic_scan(_executable(tmp_path))
    assert any("not under BINARY_EXECUTION_ALLOWLIST" in reason for reason in result["refusals"])
    assert result["checks"]["policy"]["allowlist"], "the allowlist is reported back"


def test_a_non_executable_file_is_refused(monkeypatch, tmp_path):
    _allowed_env(monkeypatch, tmp_path)
    sample = _executable(tmp_path)
    sample.chmod(0o644)
    result = dyn.dynamic_scan(sample)
    assert any("not executable" in reason for reason in result["refusals"])


def test_a_missing_file_is_refused(monkeypatch, tmp_path):
    _allowed_env(monkeypatch, tmp_path)
    result = dyn.dynamic_scan(tmp_path / "nope")
    assert any("not a file" in reason for reason in result["refusals"])


def test_every_refusal_is_a_finding_so_absence_is_not_confused_with_silence(monkeypatch, tmp_path):
    monkeypatch.delenv("BINARY_EXECUTION_ENABLED", raising=False)
    result = dyn.dynamic_scan(_executable(tmp_path))
    codes = [f["code"] for f in result["findings"]]
    assert codes == ["BIN-DYNAMIC-REFUSED"]
    assert "not that the sample was quiet" in result["findings"][0]["detail"]


def test_the_run_budget_stops_a_flood(monkeypatch, tmp_path):
    _allowed_env(monkeypatch, tmp_path, BINARY_EXECUTION_MAX_RUNS_PER_HOUR="2")
    monkeypatch.setattr(dyn, "_RUNS", [time.monotonic(), time.monotonic()])
    result = dyn.dynamic_scan(_executable(tmp_path))
    assert any("run budget is spent" in reason for reason in result["refusals"])
    assert result["checks"]["runs_last_hour"] == 2


def test_arguments_are_bounded(monkeypatch, tmp_path):
    _allowed_env(monkeypatch, tmp_path)
    sample = _executable(tmp_path)
    assert any("arguments must be at most" in reason
               for reason in dyn.dynamic_scan(sample, args=["x"] * (dyn.MAX_ARGS + 1))["refusals"])
    assert any("arguments must be at most" in reason
               for reason in dyn.dynamic_scan(sample, args=["x" * (dyn.MAX_ARG_CHARS + 1)])["refusals"])


# --------------------------------------------------------------------------- #
# classification of what was observed
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(("algorithm", "key_size", "severity", "category"), [
    ("MD5", None, "HIGH", "classically-broken"),
    ("AES-256-ECB", 32, "HIGH", None),          # registry: ECB is DISALLOWED
    ("AES-128-CBC", 16, "MEDIUM", "symmetric-marginal"),
    ("AES-256-GCM", 32, "INFO", "symmetric-strong"),
    ("CHACHA20-POLY1305", 32, "INFO", "symmetric-strong"),
])
def test_an_observed_algorithm_gets_the_platform_verdict(algorithm, key_size, severity, category):
    verdict = dyn.classify_observation(algorithm, key_size)
    assert dyn.severity_for(verdict) == severity
    if category:
        assert verdict["category"] == category


def test_an_unnameable_cipher_is_flagged_as_unidentified_not_as_clean():
    verdict = dyn.classify_observation("UNKNOWN")
    assert verdict["recognised"] is False
    assert verdict["vulnerable"] is False
    assert dyn.severity_for(verdict) == "LOW"


def test_an_ecb_observation_is_high_because_the_registry_disallows_the_mode():
    verdict = dyn.classify_observation("AES-256-ECB", 32)
    assert verdict["registry_status"] == "DISALLOWED"
    assert dyn.severity_for(verdict) == "HIGH"


def _observation(algorithm: str, *, pid: int = 42, function: str = "EVP_CipherInit_ex",
                 key_size: int | None = None, count: int = 3) -> dict:
    return {"process_name": "sample", "pid": pid, "function": function, "algorithm": algorithm,
            "mode": None, "key_size": key_size, "observation_count": count,
            "extra": {"source": "ld-preload"}}


def _run_result(*observations: dict, **overrides) -> dict:
    base = {"target": "/tmp/sample", "executed": True, "returncode": 0, "timed_out": False,
            "duration_ms": 1200, "sha256_before": "a" * 64, "sha256_after": "a" * 64,
            "changed": False, "observations": list(observations), "findings": [],
            "checks": {"policy": {"timeout_seconds": 10}}, "stdout": "", "stderr": ""}
    base.update(overrides)
    return base


def test_every_observation_becomes_a_finding_with_its_count_and_evidence():
    findings = dyn._observation_findings(
        _run_result(_observation("AES-128-CBC", key_size=16),
                    _observation("UNKNOWN", pid=43)),
        Path("/tmp/sample"))
    codes = [f["code"] for f in findings]
    assert codes[0] == "BIN-DYNAMIC-EXECUTED"
    assert "BIN-DYNAMIC-UNIDENTIFIED-CIPHER" in codes
    entry = next(f for f in findings if f["code"] == "BIN-DYNAMIC-CRYPTO-CALL")
    assert entry["severity"] == "MEDIUM"
    assert entry["observation_count"] == 3
    assert "AES-256" in entry["title"]
    assert "never records key material" in entry["detail"]


def test_a_run_with_no_crypto_calls_says_it_is_not_evidence_of_absence():
    findings = dyn._observation_findings(_run_result(), Path("/tmp/sample"))
    codes = [f["code"] for f in findings]
    assert "BIN-DYNAMIC-NO-CRYPTO-CALLS" in codes
    entry = next(f for f in findings if f["code"] == "BIN-DYNAMIC-NO-CRYPTO-CALLS")
    assert "not evidence of absence" in entry["detail"]


def test_a_timeout_and_a_self_modifying_sample_are_both_findings():
    findings = dyn._observation_findings(
        _run_result(_observation("AES-256-GCM", key_size=32), timed_out=True, returncode=-9,
                    sha256_after="b" * 64, changed=True),
        Path("/tmp/sample"))
    codes = {f["code"]: f["severity"] for f in findings}
    assert codes["BIN-DYNAMIC-TIMEOUT"] == "MEDIUM"
    assert codes["BIN-DYNAMIC-BINARY-CHANGED"] == "HIGH"


def test_a_non_zero_exit_is_recorded_with_its_stderr():
    findings = dyn._observation_findings(_run_result(returncode=3, stderr="cannot open config"),
                                         Path("/tmp/sample"))
    entry = next(f for f in findings if f["code"] == "BIN-DYNAMIC-EXIT-NONZERO")
    assert entry["severity"] == "LOW"
    assert "cannot open config" in entry["detail"]


# --------------------------------------------------------------------------- #
# hand-off to the runtime ingest
# --------------------------------------------------------------------------- #

def test_the_payload_is_the_shape_the_runtime_ingest_accepts():
    result = _run_result(_observation("AES-128-CBC", key_size=16),
                         _observation("UNKNOWN", pid=43))
    result["observations"][0]["extra"]["tls_min_version"] = 0x0301  # TLS1_VERSION
    payload = dyn.to_runtime_findings(result, hostname="host-a")
    assert payload["scanner_id"] == dyn.DEFAULT_SCANNER_ID
    first = payload["findings"][0]
    assert first["process_name"] == "sample" and first["pid"] == 42
    assert first["algorithm"] == "AES-128-CBC"
    assert first["tls_version"] == "TLSv1.0"
    assert first["hostname"] == "host-a"
    assert first["observation_count"] == 3
    assert first["extra"]["kind"] == "binary-dynamic"
    assert first["extra"]["target_sha256"] == "a" * 64
    assert first["extra"]["classification"]["observed_algorithm"] == "AES-128-CBC"
    assert set(first) <= {"process_name", "pid", "hostname", "function", "tls_version",
                          "cipher_suite", "algorithm", "key_size", "observation_count", "extra"}


@pytest.mark.parametrize(("recorded", "expected"), [
    (0x0301, "TLSv1.0"), (0x0302, "TLSv1.1"), (0x0303, "TLSv1.2"), (0x0304, "TLSv1.3"),
    (0x0300, "SSLv3"), (None, None), ("TLSv1.3", "TLSv1.3"), (9999, "version-9999"),
])
def test_a_protocol_code_becomes_the_name_the_ingest_compares(recorded, expected):
    """The ingest flags weak versions by name — a raw OpenSSL code must not slip through."""
    assert dyn.tls_version_name(recorded) == expected


def test_only_observations_are_sent_not_our_own_bookkeeping():
    payload = dyn.to_runtime_findings(_run_result(timed_out=True))
    assert payload["findings"] == []
    assert dyn.to_runtime_findings({"observations": []})["findings"] == []


def test_a_machine_key_is_sent_as_an_api_key_not_as_a_bearer_token():
    """The auth middleware reads Bearer as a session token: a key sent that way 401s."""
    assert dyn.auth_header("csk_abc") == {"X-API-Key": "csk_abc"}
    assert dyn.auth_header("eyJhbGciOi.session") == {"Authorization": "Bearer eyJhbGciOi.session"}


def test_the_submission_sends_the_key_in_the_right_header(monkeypatch):
    captured: dict = {}

    class _Response:
        status = 200

        def read(self) -> bytes:
            return b'{"accepted": 3}'

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    def _urlopen(request, timeout=None):  # noqa: ARG001
        captured["headers"] = dict(request.headers)
        captured["url"] = request.full_url
        captured["body"] = request.data
        return _Response()

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    out = dyn.submit_findings({"scanner_id": "s", "findings": [{"pid": 1}]},
                              api_base="http://api.test/", token="csk_key")
    assert out["status"] == 200 and out["response"] == {"accepted": 3}
    assert captured["url"] == "http://api.test/api/v1/scans/runtime-findings"
    assert captured["headers"]["X-api-key"] == "csk_key"
    assert "Authorization" not in captured["headers"]


def test_submitting_needs_a_real_url_and_reports_the_refusal(monkeypatch):
    payload = {"scanner_id": "x", "findings": []}
    with pytest.raises(RuntimeError, match="http"):
        dyn.submit_findings(payload, api_base="not-a-url", token="t")

    def _boom(*_a, **_kw):
        raise OSError("connection refused")

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    with pytest.raises(RuntimeError, match="could not reach"):
        dyn.submit_findings(payload, api_base="http://127.0.0.1:9", token="t")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_the_cli_defaults_to_the_preflight_and_writes_json(monkeypatch, tmp_path, capsys):
    _allowed_env(monkeypatch, tmp_path)
    sample = _executable(tmp_path)
    out = tmp_path / "result.json"
    assert dyn.main([str(sample), "--json", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "not executed" in printed and "refused" in printed
    assert json.loads(out.read_text())["executed"] is False


def test_the_cli_exits_four_when_asked_to_run_and_refused(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("BINARY_EXECUTION_ENABLED", raising=False)
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    code = dyn.main([str(_executable(tmp_path)), "--execute", "--json", "-"])
    assert code == 4
    assert json.loads(capsys.readouterr().out)["executed"] is False


@pytest.mark.skipif(not (CC and SLEEP and _tracer_available()), reason="needs a compiler and the shim")
def test_the_cli_exits_two_when_it_cannot_submit_and_keeps_the_payload(monkeypatch, tmp_path, capsys):
    _allowed_env(monkeypatch, tmp_path)
    monkeypatch.delenv("CRYPTOSCAN_API_BASE", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_API_URL", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_API_KEY", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_TOKEN", raising=False)
    sample = _compiled(tmp_path, "int main(void){return 0;}\n")
    code = dyn.main([str(sample), "--execute", "--submit", "--json", "-"])
    err = capsys.readouterr().err
    assert code == 2
    assert "replayed" in err


def test_submit_without_execute_is_refused(monkeypatch, tmp_path, capsys):
    _allowed_env(monkeypatch, tmp_path)
    monkeypatch.setenv("CRYPTOSCAN_API_BASE", "http://127.0.0.1:9")
    monkeypatch.setenv("CRYPTOSCAN_API_KEY", "t")
    assert dyn.main([str(_executable(tmp_path)), "--submit"]) == 4


# --------------------------------------------------------------------------- #
# a real run, with a real tracer
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not (CC and OPENSSL and SLEEP and _tracer_available()),
                    reason="needs a compiler, openssl, sleep and the shim")
def test_a_real_run_under_the_tracer_observes_and_classifies(monkeypatch, tmp_path):
    root = Path(OPENSSL).parent
    _allowed_env(monkeypatch, root)
    result = dyn.dynamic_scan(OPENSSL, args=["dgst", "-md5", "/etc/hostname"], execute=True, timeout=20)
    assert result["executed"] is True and result["refusals"] == []
    algorithms = {row["algorithm"].upper() for row in result["observations"]}
    assert "MD5" in algorithms, algorithms
    entry = next(f for f in result["findings"] if f.get("algorithm") == "MD5")
    assert entry["severity"] == "HIGH"
    assert dyn.to_runtime_findings(result)["findings"], "observations are shippable"


@pytest.mark.skipif(not (CC and SLEEP and _tracer_available()),
                    reason="needs a compiler, sleep and the shim")
def test_a_sample_that_hangs_is_killed_with_its_whole_process_group(monkeypatch, tmp_path):
    root = Path(SLEEP).parent
    _allowed_env(monkeypatch, root)
    marker = str(31 + int(time.time()) % 7)  # a duration nothing else on this host uses
    started = time.monotonic()
    result = dyn.dynamic_scan(SLEEP, args=[marker], execute=True, timeout=1)
    elapsed = time.monotonic() - started
    assert result["timed_out"] is True
    assert elapsed < 15, f"timeout did not bite: {elapsed:.1f}s"
    assert any(f["code"] == "BIN-DYNAMIC-TIMEOUT" for f in result["findings"])
    if shutil.which("pgrep"):
        leftover = subprocess.run(["pgrep", "-f", f"sleep {marker}"], capture_output=True, text=True)
        assert leftover.returncode != 0, f"the killed process group left {leftover.stdout.strip()} behind"


@pytest.mark.skipif(not (CC and _tracer_available()), reason="needs a compiler and the shim")
def test_a_scratch_working_directory_is_used_and_removed(monkeypatch, tmp_path):
    _allowed_env(monkeypatch, tmp_path)
    sample = _compiled(tmp_path, "#include <stdio.h>\n"
                                 "int main(void){FILE*f=fopen(\"marker.txt\",\"w\");"
                                 "if(!f)return 7;fputs(\"x\",f);fclose(f);return 0;}\n")
    before = {p.name for p in Path("/tmp").glob("cryptoscan-dynamic-*")}
    result = dyn.dynamic_scan(sample, execute=True)
    after = {p.name for p in Path("/tmp").glob("cryptoscan-dynamic-*")}
    assert result["executed"] is True and result["returncode"] == 0
    assert after == before, "the scratch directory outlived the run"
    assert not (tmp_path / "marker.txt").exists(), "the sample wrote into the sample's own directory"


@pytest.mark.skipif(not (CC and _tracer_available()), reason="needs a compiler and the shim")
def test_the_sample_never_sees_a_credential(monkeypatch, tmp_path):
    _allowed_env(monkeypatch, tmp_path)
    monkeypatch.setenv("MY_API_TOKEN", "super-secret-value")
    sample = _compiled(tmp_path, "#include <stdlib.h>\n#include <string.h>\n"
                                 "int main(void){const char*v=getenv(\"MY_API_TOKEN\");"
                                 "return (v && strlen(v)>0) ? 5 : 0;}\n")
    result = dyn.dynamic_scan(sample, execute=True)
    assert result["returncode"] == 0, "the sample saw a value in a credential-shaped variable"


@pytest.mark.skipif(not CC, reason="needs a compiler to build a fake sample")
def test_a_sample_the_loader_refuses_is_a_refusal_not_a_crash(monkeypatch, tmp_path):
    """A fabricated ELF header passes the static parse but the kernel says no."""
    _allowed_env(monkeypatch, tmp_path)
    result = dyn.dynamic_scan(_executable(tmp_path, name="not-really-elf"), execute=True)
    assert result["executed"] is False
    assert any("could not be started" in reason for reason in result["refusals"])
    assert any(f["code"] == "BIN-DYNAMIC-REFUSED" for f in result["findings"])
