"""Opt-in dynamic analysis: run a sample under the ADR-012 LD_PRELOAD tracer.

The binary scanner is static by default and stays that way. Nothing is executed
unless three things are all true: the caller asked for it, the platform is
configured to allow it, and the sample passes the preflight below. When it does
run, it runs under the *existing* runtime tracer (no kernel agent, no
privileges, no new sandbox) which records cryptographic operations as JSONL —
algorithms, modes, key sizes, TLS versions, never key bytes.

What this is not
----------------
There is no gVisor, no seccomp, no network namespace, no user separation. What
bounds a run is: an explicit allow, a path inside the configured source roots,
a wall-clock timeout that kills the whole process group, a scratch working
directory, a blanked credential environment, and a per-process run budget. Every
one of those limits is reported in the result under ``limits`` so an operator
never mistakes "it ran here" for "it was sandboxed". ADR-012 is the decision
record; this module is that decision applied to a sample the scanner was handed.
"""

from __future__ import annotations

import hashlib
import os
import sys
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: environment variables blanked before a sample runs (never handed a credential)
SECRET_ENV_PATTERNS = (
    "TOKEN", "PASSWORD", "PASSWD", "SECRET", "API_KEY", "APIKEY", "PRIVATE_KEY",
    "AWS_", "AZURE_", "GCP_", "GOOGLE_", "KUBECONFIG", "SSH_AUTH_SOCK", "GITHUB_",
    "GITLAB_", "SLACK_", "STRIPE_", "DATABASE_URL", "REDIS_URL", "VAULT_",
)

DEFAULT_TIMEOUT = 10
MAX_TIMEOUT = 60
MAX_ARGS = 32
MAX_ARG_CHARS = 200
#: how many samples one process will execute per hour before refusing (fail-closed:
#: the scanner must not become an execution service because someone found the flag)
DEFAULT_MAX_RUNS_PER_HOUR = 20

#: fallback verdict when the quantum risk package is unavailable — deliberately
#: conservative: an unknown algorithm is not called safe
_FALLBACK_RISK: dict[str, Any] = {
    "vulnerable": True, "category": "unknown", "threat_type": "UNCLASSIFIED",
    "base_vulnerability": 40, "recommended_replacement": None,
    "notes": "no classification available for this algorithm name",
}


def classify_observation(algorithm: str | None, key_size: int | None = None) -> dict[str, Any]:
    """Registry + quantum verdict for something observed at runtime.

    Reuses the platform's own classifiers — ``shared_models.algorithm_registry``
    for the policy verdict and ``quantum.risk.classify`` for the quantum one — so
    an observation made at runtime lands on the same verdict as the same
    algorithm found statically. The tracer reports suite-style names
    ("AES-128-CBC"); the base name is what carries the Grover verdict, so the
    quantum lookup is normalised, while the registry sees the full name with its
    mode (which is how ECB gets caught).
    """
    name = str(algorithm or "UNKNOWN")
    verdict: dict[str, Any] = {"observed_algorithm": name,
                               "recognised": name.strip().upper() not in {"", "UNKNOWN"}}
    try:
        from shared_models.algorithm_registry import parse_algorithm

        info = parse_algorithm(name)
        verdict.update({"registry_status": info.status, "registry_canonical": info.canonical,
                        "registry_key_size": info.key_size, "quantum_impact": info.quantum_impact})
    except Exception:  # noqa: BLE001 — the scanner must not depend on the registry
        verdict["registry_status"] = None
    try:
        from quantum.risk import classify

        lookup = name.upper().replace("_", "-")
        for prefix in ("AES-128", "AES-192", "AES-256"):
            if lookup.startswith(prefix):
                lookup = prefix
                break
        verdict.update(dict(classify(lookup, key_size=key_size)))
        verdict["looked_up_as"] = lookup
    except Exception:  # noqa: BLE001
        verdict.update(dict(_FALLBACK_RISK))
    if not verdict["recognised"]:
        verdict["vulnerable"] = False
        verdict["category"] = "unidentified"
        verdict["threat_type"] = "UNIDENTIFIED"
        verdict["recommended_replacement"] = None
    return verdict


def severity_for(verdict: dict[str, Any]) -> str:
    """Disallowed-or-broken → HIGH, quantum-weakened → MEDIUM, unidentified → LOW."""
    if not verdict.get("recognised", True):
        return "LOW"
    if str(verdict.get("registry_status")) in {"DISALLOWED", "DEPRECATED"}:
        return "HIGH"
    if str(verdict.get("threat_type")) == "CLASSICALLY_BROKEN":
        return "HIGH"
    if verdict.get("vulnerable"):
        return "MEDIUM"
    return "INFO"


_RUNS: list[float] = []


@dataclass(frozen=True)
class ExecutionPolicy:
    """Whether and how a sample may be executed on this host."""

    allowed: bool = False
    allowlist: tuple[str, ...] = ()
    timeout: int = DEFAULT_TIMEOUT
    max_timeout: int = MAX_TIMEOUT
    max_runs_per_hour: int = DEFAULT_MAX_RUNS_PER_HOUR
    source_roots: tuple[str, ...] = ()
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_env(cls) -> ExecutionPolicy:
        """Read the policy from the environment (execution is off unless asked for)."""
        enabled = os.environ.get("BINARY_EXECUTION_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}
        allowlist = tuple(entry.strip() for entry in
                          os.environ.get("BINARY_EXECUTION_ALLOWLIST", "").split(os.pathsep)
                          if entry.strip())
        timeout = os.environ.get("BINARY_EXECUTION_TIMEOUT", "").strip()
        try:
            seconds = int(timeout) if timeout else DEFAULT_TIMEOUT
        except ValueError:
            seconds = DEFAULT_TIMEOUT
        budget = os.environ.get("BINARY_EXECUTION_MAX_RUNS_PER_HOUR", "").strip()
        try:
            per_hour = int(budget) if budget else DEFAULT_MAX_RUNS_PER_HOUR
        except ValueError:
            per_hour = DEFAULT_MAX_RUNS_PER_HOUR
        roots = [entry.strip() for entry in
                 (os.environ.get("CRYPTOSCAN_SOURCE_ROOTS", "") or "").split(os.pathsep)
                 if entry.strip()]
        roots += [entry for entry in (os.environ.get("WORKSPACE_BASE_PATH"),
                                      os.environ.get("SOURCE_ROOT")) if entry]
        return cls(allowed=enabled, allowlist=allowlist,
                   timeout=max(1, min(seconds, MAX_TIMEOUT)),
                   max_runs_per_hour=max(0, per_hour),
                   source_roots=tuple(roots),
                   reasons=(("execution enabled by BINARY_EXECUTION_ENABLED",) if enabled else ()))

    def public(self) -> dict[str, Any]:
        return {"enabled": self.allowed, "allowlist": list(self.allowlist),
                "timeout_seconds": self.timeout, "max_runs_per_hour": self.max_runs_per_hour,
                "source_roots": list(self.source_roots)}


def preflight(path: str | Path, policy: ExecutionPolicy | None = None) -> dict[str, Any]:
    """Decide whether this sample may run, and say why not when it may not.

    Every refusal is a reason string: a scanner that quietly declines to run
    something, and reports "no dynamic findings", is worse than one that never
    had the feature.
    """
    policy = policy or ExecutionPolicy.from_env()
    target = Path(path).expanduser()
    refusals: list[str] = []
    checks: dict[str, Any] = {"path": str(target), "policy": policy.public()}

    if os.name != "posix":
        refusals.append("dynamic analysis needs a POSIX host (LD_PRELOAD)")
    if not policy.allowed:
        refusals.append("execution is disabled; set BINARY_EXECUTION_ENABLED=true to allow it "
                        "(ADR-012: opt-in, never a default)")
    if not target.is_file():
        refusals.append(f"target is not a file: {target}")
    else:
        resolved = str(target.resolve())
        checks["resolved"] = resolved
        if policy.allowlist and not any(resolved.startswith(prefix) for prefix in policy.allowlist):
            refusals.append(f"{resolved} is not under BINARY_EXECUTION_ALLOWLIST "
                            f"({', '.join(policy.allowlist)})")
        if policy.source_roots and not any(resolved.startswith(str(Path(root).expanduser()))
                                           for root in policy.source_roots):
            refusals.append("target is outside the configured source roots")
        if not os.access(resolved, os.X_OK):
            refusals.append("the file is not executable (no execute permission)")

    if target.is_file():
        try:
            from devsecops import binary_scan as bs

            record = bs.parse_bytes(target.read_bytes()[: 4 * 1024 * 1024], name=target.name)
            checks["format"] = record.get("format")
            checks["arch"] = record.get("arch") or record.get("machine")
            checks["static"] = bool(record.get("static"))
            if record.get("format") not in {"elf", "pe", "macho"}:
                refusals.append(f"format {record.get('format') or 'unknown'} is not an executable "
                                "container (elf/pe/macho)")
            if record.get("static"):
                refusals.append("the binary is statically linked, so the LD_PRELOAD tracer "
                                "cannot be loaded into it")
            host = _host_arch()
            checks["host_arch"] = host
            arch = str(record.get("arch") or "").lower()
            if host and arch and not _arch_matches(arch, host):
                refusals.append(f"architecture mismatch: sample is {arch}, host is {host} "
                                "(the loader would refuse it)")
        except Exception as exc:  # noqa: BLE001 — an unreadable file is a refusal, not a crash
            refusals.append(f"the sample could not be parsed for preflight: {type(exc).__name__}: {exc}")

    tracer, tracer_error = _tracer_available()
    checks["tracer"] = "ld_preload" if tracer else None
    if tracer is None:
        refusals.append(f"the LD_PRELOAD tracer is unavailable: {tracer_error}")

    budget = _run_budget(policy)
    checks["runs_last_hour"] = budget["used"]
    if budget["exhausted"]:
        refusals.append(f"the run budget is spent ({budget['used']}/{policy.max_runs_per_hour} "
                        "in the last hour)")

    return {"runnable": not refusals, "refusals": refusals, "checks": checks}


def dynamic_scan(
    path: str | Path,
    *,
    args: list[str] | None = None,
    timeout: int | None = None,
    policy: ExecutionPolicy | None = None,
    cwd: str | Path | None = None,
    execute: bool = False,
) -> dict[str, Any]:
    """Preflight a sample, and run it under the tracer only when asked and allowed.

    ``execute=False`` is the dry run: the preflight and the refusals, with no
    process started. That is what the endpoint returns by default, so an operator
    can see exactly what would happen before anything runs.
    """
    policy = policy or ExecutionPolicy.from_env()
    checks = preflight(path, policy)
    result: dict[str, Any] = {
        "target": checks["checks"].get("resolved") or str(path),
        "executed": False,
        "runnable": checks["runnable"],
        "refusals": list(checks["refusals"]),
        "checks": checks["checks"],
        "observations": [],
        "findings": [],
        "tracer": checks["checks"].get("tracer"),
        "duration_ms": 0,
        "timed_out": False,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "sha256_before": None,
        "sha256_after": None,
        "changed": False,
        "limits": limits_statement(policy),
    }
    argument_list = _validate_args(args)
    result["args"] = argument_list
    if argument_list is None:
        result["refusals"].append(f"arguments must be at most {MAX_ARGS} entries of "
                                  f"{MAX_ARG_CHARS} characters, without NUL bytes")
    if not execute:
        result["refusals"].append("dry run: execute was not requested")
    result["runnable"] = result["runnable"] and not result["refusals"]

    if result["refusals"] or argument_list is None:
        result["findings"] = _refusal_findings(result, checks)
        return result

    target = Path(str(result["target"]))
    before = _sha256(target)
    try:
        run = _execute(target, argument_list, timeout=timeout, policy=policy, cwd=cwd)
    except OSError as exc:
        # the loader refused it (exec format, missing interpreter, permission on a
        # parent directory): still a decided outcome, and still a finding
        result["refusals"].append(f"the sample could not be started: {type(exc).__name__}: {exc}")
        result["runnable"] = False
        result["findings"] = _refusal_findings(result, checks)
        return result
    after = _sha256(target)
    observations = run.get("findings") or []
    result.update({
        "executed": True,
        "observations": observations,
        "tracer": "ld_preload",
        "duration_ms": run.get("duration_ms", 0),
        "timed_out": bool(run.get("timed_out")),
        "returncode": run.get("returncode"),
        "stdout": run.get("stdout", ""),
        "stderr": run.get("stderr", ""),
        "sha256_before": before,
        "sha256_after": after,
        "changed": bool(before and after and before != after),
    })
    result["findings"] = _observation_findings(result, target)
    return result


def limits_statement(policy: ExecutionPolicy | None = None) -> list[str]:
    """What is *not* isolating this run. Stated because it is not implied."""
    policy = policy or ExecutionPolicy.from_env()
    return [
        "no kernel sandbox: the sample runs as this process's user, with this user's filesystem access",
        "no network namespace: the sample can reach whatever this host can reach",
        f"wall-clock timeout of {policy.timeout}s kills the process group; a sample that forks "
        "faster than it is killed is only bounded, not contained",
        "the working directory is a scratch directory that is removed afterwards, which is not a "
        "filesystem boundary for absolute paths",
        "the environment is blanked of credentials before the run",
        "the ADR-012 tracer observes dynamically linked crypto calls (OpenSSL/BoringSSL/libcrypto); "
        "a sample that carries its own crypto implementation is invisible to it",
    ]


# --------------------------------------------------------------------------- #
# execution
# --------------------------------------------------------------------------- #

def _execute(target: Path, args: list[str], *, timeout: int | None,
             policy: ExecutionPolicy, cwd: str | Path | None) -> dict[str, Any]:
    """Run ``target`` under the tracer in a scratch directory."""
    from runtime.agent.preload_trace import trace_command

    scratch = Path(cwd) if cwd else Path(tempfile.mkdtemp(prefix="cryptoscan-dynamic-"))
    own_scratch = cwd is None
    log = Path(tempfile.mkstemp(prefix="cryptoscan-trace-", suffix=".jsonl")[1])
    try:
        run = trace_command(
            [str(target), *args],
            log_path=log,
            env=_blank_secrets(os.environ),
            cwd=scratch,
            timeout=float(timeout or policy.timeout),
        )
    finally:
        _mark_run()
        try:
            log.unlink()
        except OSError:
            pass
        if own_scratch:
            shutil.rmtree(scratch, ignore_errors=True)
    return run


def _blank_secrets(env: dict[str, str]) -> dict[str, str]:
    """A copy of the environment with credential-shaped variables emptied."""
    blanked: dict[str, str] = {}
    for key in env:
        upper = key.upper()
        if any(pattern in upper for pattern in SECRET_ENV_PATTERNS):
            blanked[key] = ""
    return blanked


def _validate_args(args: list[str] | None) -> list[str] | None:
    """Bound and sanity-check the arguments the caller wants to pass."""
    if args is None:
        return []
    if len(args) > MAX_ARGS:
        return None
    cleaned: list[str] = []
    for entry in args:
        text = str(entry)
        if "\x00" in text or len(text) > MAX_ARG_CHARS:
            return None
        cleaned.append(text)
    return cleaned


def _sha256(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _tracer_available() -> tuple[str | None, str]:
    try:
        from runtime.agent.preload_trace import ensure_shim

        shim = ensure_shim()
    except Exception as exc:  # noqa: BLE001 — a missing tracer is a refusal, not a crash
        return None, f"{type(exc).__name__}: {exc}"
    if shim is None:
        return None, "no C compiler available to build the shim, or the shim source is missing"
    return str(shim), ""


def _host_arch() -> str | None:
    try:
        import platform

        return platform.machine().lower() or None
    except Exception:  # noqa: BLE001
        return None


def _arch_matches(sample_arch: str, host_arch: str) -> bool:
    """Coarse but honest: x86-64 vs aarch64 vs 32-bit, not microarchitecture."""
    families = (
        ("x86-64", ("x86-64", "x86_64", "amd64")),
        ("x86", ("i386", "i486", "i586", "i686", "x86", "ia-32")),
        ("aarch64", ("aarch64", "arm64")),
        ("arm", ("arm", "armhf", "armv7")),
        ("riscv", ("riscv", "risc-v")),
        ("ppc", ("ppc", "powerpc")),
        ("s390", ("s390",)),
    )

    def family(name: str) -> str | None:
        for label, tokens in families:
            if any(token in name for token in tokens):
                return label
        return None

    sample_family, host_family = family(sample_arch), family(host_arch)
    if sample_family is None or host_family is None:
        return True  # unknown on either side: do not refuse on a guess
    return sample_family == host_family


def _run_budget(policy: ExecutionPolicy) -> dict[str, Any]:
    now = time.monotonic()
    while _RUNS and now - _RUNS[0] > 3600:
        _RUNS.pop(0)
    used = len(_RUNS)
    return {"used": used, "limit": policy.max_runs_per_hour,
            "exhausted": used >= policy.max_runs_per_hour}


def _mark_run() -> None:
    _RUNS.append(time.monotonic())


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #

def _refusal_findings(result: dict[str, Any], checks: dict[str, Any]) -> list[dict[str, Any]]:
    """One finding per refusal: not running something is a result too."""
    findings: list[dict[str, Any]] = []
    dry_run = any("dry run" in reason for reason in result["refusals"])
    others = [reason for reason in result["refusals"] if "dry run" not in reason]
    if dry_run and not others:
        findings.append({
            "code": "BIN-DYNAMIC-DRY-RUN", "severity": "INFO",
            "title": "Dynamic analysis not requested — this is the preflight only",
            "detail": ("Nothing was executed. The checks say what would have to be true for this "
                       "sample to run: " + "; ".join(f"{key}={value}" for key, value in
                                                      checks["checks"].items() if key != "policy")),
            "path": result["target"],
        })
    for reason in others:
        findings.append({
            "code": "BIN-DYNAMIC-REFUSED", "severity": "INFO",
            "title": "Sample not executed",
            "detail": f"Refused: {reason}. Absence of dynamic findings here means nothing was run, "
                      "not that the sample was quiet.",
            "path": result["target"],
        })
    if result["checks"].get("tracer") is None and result["checks"].get("policy", {}).get("enabled"):
        findings.append({
            "code": "BIN-DYNAMIC-TRACER-UNAVAILABLE", "severity": "LOW",
            "title": "The LD_PRELOAD tracer could not be built on this host",
            "detail": ("Dynamic analysis needs the C shim; without a compiler (or with the shim "
                       "source missing) nothing can be observed. Static results are unaffected."),
            "path": result["target"],
        })
    return findings


def _observation_findings(result: dict[str, Any], target: Path) -> list[dict[str, Any]]:
    """Turn observed crypto operations into findings with their evidence."""
    findings: list[dict[str, Any]] = []
    observations = result.get("observations") or []
    duration = result.get("duration_ms", 0) / 1000
    findings.append({
        "code": "BIN-DYNAMIC-EXECUTED", "severity": "INFO",
        "title": f"Sample executed under the LD_PRELOAD tracer ({len(observations)} crypto observations)",
        "detail": (f"Ran for {duration:.2f}s with a {result['checks'].get('policy', {}).get('timeout_seconds')}s "
                   f"timeout; exit code {result['returncode']}"
                   + ("; killed at the timeout" if result.get("timed_out") else "")
                   + f". sha256 before {str(result.get('sha256_before'))[:16]}, after "
                     f"{str(result.get('sha256_after'))[:16]}. This is what the sample *did*, not what it "
                     "might do: no path it did not take is covered."),
        "path": str(target),
        "observations": len(observations),
    })
    if not observations:
        findings.append({
            "code": "BIN-DYNAMIC-NO-CRYPTO-CALLS", "severity": "INFO",
            "title": "No dynamically linked crypto calls observed",
            "detail": ("The sample ran and the tracer saw no OpenSSL/libcrypto calls. A sample that "
                       "carries its own crypto implementation, or that performs none in this run, "
                       "looks the same here — this is not evidence of absence."),
            "path": str(target),
        })
    for row in observations:
        algorithm = str(row.get("algorithm") or "UNKNOWN")
        verdict = classify_observation(algorithm, row.get("key_size"))
        replacement = verdict.get("recommended_replacement")
        suffix = ""
        if verdict.get("vulnerable"):
            suffix = f" ({verdict.get('category')}"
            suffix += f"; replace with {replacement})" if replacement else ")"
        elif str(verdict.get("registry_status")) in {"DISALLOWED", "DEPRECATED"}:
            suffix = f" (registry says {verdict.get('registry_status')})"
        code = ("BIN-DYNAMIC-UNIDENTIFIED-CIPHER" if not verdict.get("recognised", True)
                else "BIN-DYNAMIC-CRYPTO-CALL")
        findings.append({
            "code": code, "severity": severity_for(verdict),
            "title": f"{row.get('function')} used {algorithm}{suffix}",
            "detail": (f"Observed {row.get('observation_count')} time(s) in pid {row.get('pid')} "
                       f"({row.get('process_name') or 'unknown'}); key size {row.get('key_size')}, mode "
                       f"{row.get('mode') or '—'}"
                       + (f", TLS version {tls_version_name(row.get('extra', {}).get('tls_min_version'))}"
                          if row.get("extra", {}).get("tls_min_version") is not None else "")
                       + f". {verdict.get('notes') or ''} Metadata only — the tracer never records key material."),
            "path": str(target),
            "algorithm": algorithm,
            "function": row.get("function"),
            "observation_count": row.get("observation_count"),
            "risk": verdict,
        })
    if result.get("timed_out"):
        findings.append({
            "code": "BIN-DYNAMIC-TIMEOUT", "severity": "MEDIUM",
            "title": "The sample was killed at the timeout",
            "detail": (f"It did not exit within {result['checks'].get('policy', {}).get('timeout_seconds')}s "
                       "and its process group was killed. The observations above are what it managed "
                       "before the kill; a longer run might observe more."),
            "path": str(target),
        })
    if result.get("returncode") not in (0, None) and not result.get("timed_out"):
        findings.append({
            "code": "BIN-DYNAMIC-EXIT-NONZERO", "severity": "LOW",
            "title": f"The sample exited with code {result['returncode']}",
            "detail": (result.get("stderr") or "")[-500:] or "no stderr was captured",
            "path": str(target),
        })
    if result.get("changed"):
        findings.append({
            "code": "BIN-DYNAMIC-BINARY-CHANGED", "severity": "HIGH",
            "title": "The sample's own bytes changed while it ran",
            "detail": (f"sha256 {str(result.get('sha256_before'))[:16]} → "
                       f"{str(result.get('sha256_after'))[:16]}. A binary that rewrites itself at "
                       "runtime (self-modifying code, an updater, a dropper) invalidates any static "
                       "result taken before the run — rescan it."),
            "path": str(target),
        })
    return findings


# --------------------------------------------------------------------------- #
# hand-off to the runtime-findings ingest (ADR-012 evidence chain)
# --------------------------------------------------------------------------- #

DEFAULT_SCANNER_ID = "ld-preload-agent-v1.0"

#: OpenSSL protocol version constants, as the shim sees them. The ingest compares
#: TLS versions by name (WEAK_TLS_VERSIONS), so a raw 0x0301 must become "TLSv1.0"
#: here or a weak-version observation would arrive as an unreadable integer.
TLS_VERSION_NAMES = {
    0x0000: "TLSv1.0-any",  # an API call with version 0 means "any version"
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
    0xFEFF: "DTLSv1.0",
    0xFEFE: "DTLSv1.1",
    0xFEFD: "DTLSv1.2",
    0xFEFC: "DTLSv1.3",
}


def tls_version_name(value: Any) -> str | None:
    """Readable TLS version for whatever the tracer recorded (a code, or a name)."""
    if value is None or value == "":
        return None
    if isinstance(value, str) and not value.strip().isdigit():
        return value.strip()
    try:
        code = int(value)
    except (TypeError, ValueError):
        return str(value)
    return TLS_VERSION_NAMES.get(code, f"version-{code}")


def to_runtime_findings(
    result: dict[str, Any],
    *,
    hostname: str | None = None,
    scanner_id: str = DEFAULT_SCANNER_ID,
) -> dict[str, Any]:
    """Shape a dynamic-scan result as a ``POST /scans/runtime-findings`` body.

    The endpoint already speaks the platform's runtime-finding dialect, so the
    tracer's own aggregated rows are handed over as-is — the algorithm, key size,
    mode, pid and count are the observation, and the classification rides along
    in ``extra`` so the registry verdict is reproducible from the stored row.
    Only real observations are sent: "we did not execute" is a static-scan fact
    and belongs in the scan report, not in the runtime picture.
    """
    findings: list[dict[str, Any]] = []
    sha = result.get("sha256_before")
    for row in result.get("observations") or []:
        extra = dict(row.get("extra") or {})
        recorded = extra.pop("tls_min_version", None)
        tls_version = tls_version_name(recorded)
        algorithm = str(row.get("algorithm") or "UNKNOWN")
        extra.update({
            "kind": "binary-dynamic",
            "source": "ld-preload",
            "runner": "devsecops.dynamic_scan",
            "mode": row.get("mode"),
            "target_sha256": sha,
            "classification": classify_observation(algorithm, row.get("key_size")),
        })
        if recorded is not None:
            extra["tls_min_proto_code"] = recorded
        findings.append({
            "process_name": row.get("process_name") or "unknown",
            "pid": row.get("pid"),
            "hostname": hostname,
            "function": row.get("function"),
            "tls_version": tls_version,
            "cipher_suite": None,
            "algorithm": algorithm,
            "key_size": row.get("key_size"),
            "observation_count": int(row.get("observation_count") or 1),
            "extra": extra,
        })
    return {"scanner_id": scanner_id, "findings": findings}


def auth_header(token: str) -> dict[str, str]:
    """The right header for this credential.

    A platform API key goes in ``X-API-Key`` — the auth middleware reads a
    ``Bearer`` value as a *session* token, so sending a machine key that way is a
    401 even though the key is valid (and it is the sort of 401 that wastes an
    afternoon). Anything else is treated as a session/bearer token.
    """
    if token.startswith("csk_"):
        return {"X-API-Key": token}
    return {"Authorization": f"Bearer {token}"}


def submit_findings(
    payload: dict[str, Any],
    *,
    api_base: str,
    token: str,
    verify: bool = True,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """POST a shaped payload to the API. Raises RuntimeError with the body on refusal."""
    import json
    import urllib.error
    import urllib.request

    url = api_base.rstrip("/") + "/api/v1/scans/runtime-findings"
    if not url.startswith(("http://", "https://")):
        raise RuntimeError(f"api base must be an http(s) URL, got {api_base!r}")
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **auth_header(token)},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 — scheme checked above
            body = json.loads(response.read().decode("utf-8") or "{}")
            return {"status": response.status, "url": url, "response": body}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"ingest refused ({exc.code}) at {url}: {detail}") from exc
    except OSError as exc:  # URLError, gaierror, SSLError, timeouts
        reason = getattr(exc, "reason", None) or exc
        raise RuntimeError(f"could not reach {url}: {reason}") from exc


def api_credentials() -> tuple[str | None, str | None]:
    """The API base and token this host is configured with, if any."""
    return (os.environ.get("CRYPTOSCAN_API_BASE") or os.environ.get("CRYPTOSCAN_API_URL"),
            os.environ.get("CRYPTOSCAN_API_KEY") or os.environ.get("CRYPTOSCAN_TOKEN"))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _parse_args(argv: list[str] | None) -> Any:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m devsecops.dynamic_scan",
        description="Run a sample under the ADR-012 LD_PRELOAD tracer and report what it did. "
                    "Nothing is executed without --execute and an explicit policy allow.",
    )
    parser.add_argument("sample", help="path to the sample")
    parser.add_argument("--arg", action="append", default=[],
                        help="argument to pass to the sample (repeatable; use --arg=-x for one that "
                             "starts with a dash, or put everything after a bare -- )")
    parser.add_argument("--cwd", default=None, help="working directory for the run (default: a scratch dir)")
    parser.add_argument("--timeout", type=int, default=None, help="wall-clock timeout in seconds")
    parser.add_argument("--execute", action="store_true",
                        help="actually run the sample (default: preflight only, nothing is executed)")
    parser.add_argument("--json", default=None,
                        help="write the full JSON result here ('-' for stdout instead of the summary)")
    parser.add_argument("--submit", action="store_true",
                        help="send the observations to the API runtime-findings ingest (needs --execute)")
    parser.add_argument("--api", default=None, help="API base URL (default: CRYPTOSCAN_API_BASE)")
    parser.add_argument("--token", default=None,
                        help="API key (csk_…, sent as X-API-Key) or session token "
                             "(default: CRYPTOSCAN_API_KEY)")
    parser.add_argument("--hostname", default=None, help="hostname to attribute the observations to")
    parser.add_argument("--no-verify-tls", action="store_true", help="skip TLS verification when submitting")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Exit 0 = did what was asked; 4 = refused; 2 = submission failed; 1 = error."""
    import json

    # everything after a bare "--" belongs to the sample, so a sample's own
    # flags never have to be escaped into --arg=… form
    raw = list(sys.argv[1:] if argv is None else argv)
    sample_args: list[str] = []
    if "--" in raw:
        split = raw.index("--")
        raw, sample_args = raw[:split], raw[split + 1:]
    args = _parse_args(raw)
    args.arg = list(args.arg) + sample_args
    result = dynamic_scan(args.sample, args=args.arg, timeout=args.timeout, cwd=args.cwd, execute=args.execute)
    payload = to_runtime_findings(result, hostname=args.hostname)

    if args.json == "-":
        print(json.dumps(result, indent=2))
    elif args.json:
        Path(args.json).write_text(json.dumps(result, indent=2), encoding="utf-8")

    submitted: dict[str, Any] | None = None
    exit_code = 0
    if args.submit:
        if not result["executed"]:
            why = "; ".join(result["refusals"]) or "no reason recorded"
            print(f"--submit needs a run that executed; this one did not: {why}", file=sys.stderr)
            return 4
        token = args.token or api_credentials()[1]
        api_base = args.api or api_credentials()[0]
        if not token or not api_base:
            print("--submit needs --api/--token or CRYPTOSCAN_API_BASE/CRYPTOSCAN_API_KEY; "
                  "the payload is in the JSON result and can be replayed", file=sys.stderr)
            exit_code = 2
        else:
            try:
                submitted = submit_findings(payload, api_base=api_base, token=token,
                                            verify=not args.no_verify_tls)
            except RuntimeError as exc:
                print(f"submission failed: {exc}", file=sys.stderr)
                exit_code = 2

    if args.json != "-":
        _print_summary(result, payload, submitted)
    if args.execute and not result["executed"]:
        # "run it" was the instruction and no process ran: that is the loudest outcome
        return max(exit_code, 4)
    return exit_code


def _print_summary(result: dict[str, Any], payload: dict[str, Any],
                   submitted: dict[str, Any] | None) -> None:
    """Human-readable form of what happened; the JSON is the machine contract."""
    import json

    status = "executed" if result["executed"] else "not executed"
    print(f"{result['target']}: {status}")
    if result["refusals"]:
        for reason in result["refusals"]:
            print(f"  refused: {reason}")
    print(f"  tracer: {result['tracer'] or 'unavailable'}   duration: {result['duration_ms']} ms"
          + ("   killed at timeout" if result["timed_out"] else ""))
    if result["executed"]:
        print(f"  exit code: {result['returncode']}   sha256 changed: {result['changed']}")
    for finding in result["findings"]:
        print(f"  [{finding['severity']:<6}] {finding['code']}: {finding['title']}")
    print(f"  runtime findings shaped: {len(payload['findings'])} (scanner_id {payload['scanner_id']})")
    if submitted:
        print(f"  submitted: HTTP {submitted['status']} → "
              + json.dumps(submitted["response"])[:400])


if __name__ == "__main__":  # pragma: no cover — CLI entry point
    raise SystemExit(main())
