"""SSH host-key scanning: ``ssh-keyscan`` + TOFU fingerprint drift detection.

SSH is the other door into every host, and its keys are almost never
monitored.  This module fetches a host's public keys exactly like a client
on first contact (``ssh-keyscan``), fingerprints each one
(``ssh-keygen -lf``), applies key-type policy, and compares against a
caller-supplied baseline so a **changed host key** — the classic MITM or
compromise indicator — is reported instead of silently trusted.

Honesty rules, as everywhere in the deep probes:

* missing ``ssh-keyscan``/``ssh-keygen`` binaries -> ``LOCAL_UNSUPPORTED``,
  never a silent skip;
* a port that offers no keys -> ``SSH_UNREACHABLE`` with the raw stderr fact;
* key-type policy is explicit: ``ssh-dss`` is DISALLOWED (DSA), bare
  ``ssh-rsa`` is legacy (SHA-1-era type name; ``rsa-sha2-*`` is the modern
  negotiation), RSA < 2048 bits is DISALLOWED via the shared registry;
* without a baseline the drift verdict is ``FIRST_OBSERVATION`` — trust on
  first use is stated, not assumed.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

SCAN_TYPES = ("rsa", "ecdsa", "ed25519")
_KEY_LINE = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)$")
_FP_LINE = re.compile(
    r"^\s*(\d+)\s+(SHA256:\S+)\s+(.*?)\s*\((\w+)\)\s*$"
)
_WEAK_TYPE_ISSUES = {
    "ssh-dss": "SSH_DSS_HOST_KEY",
    "ssh-rsa": "SSH_RSA_HOST_KEY",
}
_TYPE_LABELS = {
    "RSA": "ssh-rsa",
    "DSA": "ssh-dss",
    "ECDSA": "ecdsa-sha2-nistp256",
    "ED25519": "ssh-ed25519",
}


def split_ssh_target(target: str) -> tuple[str, int]:
    """``host``/`host:port`/``[v6]:port`` -> (host, port), default 22."""
    text = str(target).strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return host, int(rest.lstrip(":") or 22)
    if text.count(":") == 1:
        host, port_s = text.rsplit(":", 1)
        if port_s.isdigit():
            return host, int(port_s)
    return text, 22


def parse_keyscan_output(text: str) -> list[dict[str, str]]:
    """Pure: ``[host]:port key-type key-data`` lines -> records."""
    records: list[dict[str, str]] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _KEY_LINE.match(line)
        if not match:
            continue
        records.append({"host_field": match.group(1), "key_type": match.group(2), "key_data": match.group(3)})
    return records


def parse_fingerprint_line(line: str) -> dict[str, Any] | None:
    """Pure: ``2048 SHA256:xxx [h]:p (RSA)`` -> bits/fingerprint/label."""
    match = _FP_LINE.match(line or "")
    if not match:
        return None
    return {
        "bits": int(match.group(1)),
        "fingerprint_sha256": match.group(2),
        "comment": match.group(3),
        "key_type_label": match.group(4),
    }


def classify_host_key(key_type: str, bits: int | None) -> dict[str, Any]:
    """Key-type + size policy with registry backing where it applies."""
    issues: list[str] = []
    status = "OK"
    if key_type in _WEAK_TYPE_ISSUES:
        issues.append(_WEAK_TYPE_ISSUES[key_type])
        status = "DISALLOWED" if key_type == "ssh-dss" else "WEAK"
    registry_status = None
    quantum_impact = None
    if key_type.startswith("ssh-rsa") or key_type.startswith("ssh-dss"):
        try:
            from shared_models.algorithm_registry import parse_algorithm

            info = parse_algorithm(f"RSA-{bits}" if key_type.startswith("ssh-rsa") else f"DSA-{bits}")
            registry_status = info.status
            quantum_impact = info.quantum_impact
            if info.status == "DISALLOWED":
                status = "DISALLOWED"
                if "SSH_WEAK_HOST_KEY" not in issues:
                    issues.append("SSH_WEAK_HOST_KEY")
        except Exception:  # noqa: BLE001 — registry unavailable: degrade, don't crash
            pass
    return {
        "status": status,
        "registry_status": registry_status,
        "quantum_impact": quantum_impact,
        "policy_issues": issues,
    }


def compare_host_keys(
    baseline: dict[str, str] | None,
    observed: list[dict[str, Any]],
) -> dict[str, Any]:
    """Pure TOFU comparison: FIRST_OBSERVATION / UNCHANGED / CHANGED."""
    # only keys that were actually fingerprinted participate in drift — an
    # unfingerprinted key's identity is unknowable, not "None"
    seen = {
        str(key.get("key_type")): str(key.get("fingerprint_sha256"))
        for key in observed
        if key.get("key_type") and key.get("fingerprint_sha256")
    }
    if not baseline:
        return {
            "status": "FIRST_OBSERVATION",
            "changes": [],
            "added": sorted(seen),
            "removed": [],
            "observed": seen,
        }
    changes = []
    for key_type, fingerprint in sorted(seen.items()):
        was = baseline.get(key_type)
        if was and was != fingerprint:
            changes.append({"key_type": key_type, "was": was, "now": fingerprint})
    added = sorted(key_type for key_type in seen if key_type not in baseline)
    removed = sorted(key_type for key_type in baseline if key_type not in seen)
    status = "CHANGED" if (changes or removed) else "UNCHANGED"
    return {"status": status, "changes": changes, "added": added, "removed": removed, "observed": seen}


def _fingerprint_keydata(binary: str, key_data: str, key_type: str, host_field: str) -> dict[str, Any] | None:
    with tempfile.TemporaryDirectory(prefix="cryptoscan-ssh-") as tmp:
        path = Path(tmp) / "hostkey"
        # known_hosts format: host key-type key-data
        path.write_text(f"{host_field} {key_type} {key_data}\n")
        try:
            proc = subprocess.run(  # noqa: S603 — fixed argv, local diagnostic tool
                [binary, "-lf", str(path)], capture_output=True, text=True, timeout=6
            )
        except (subprocess.TimeoutExpired, OSError):
            return None
    if proc.returncode != 0:
        return None
    return parse_fingerprint_line(proc.stdout.splitlines()[0] if proc.stdout else "")


def scan_ssh_host_keys(
    host: str,
    port: int = 22,
    *,
    timeout: float = 8.0,
    baseline: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Fetch + fingerprint + classify one host's SSH public keys."""
    finding: dict[str, Any] = {
        "endpoint": f"{host}:{port}",
        "status": "OK",
        "keys": [],
        "policy_issues": [],
        "key_drift": None,
        "method": "ssh-keyscan",
    }
    keyscan = shutil.which("ssh-keyscan")
    keygen = shutil.which("ssh-keygen")
    if not keyscan or not keygen:
        finding["status"] = "LOCAL_UNSUPPORTED"
        finding["method"] = "ssh-binaries-missing"
        finding["detail"] = "ssh-keyscan/ssh-keygen not found on this host"
        return finding
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, local diagnostic tool
            [keyscan, "-p", str(port), "-T", str(int(max(2, timeout))), "-t", ",".join(SCAN_TYPES), host],
            capture_output=True,
            text=True,
            timeout=max(4.0, timeout) + 4.0,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        finding["status"] = "SSH_UNREACHABLE"
        finding["detail"] = f"{type(exc).__name__}: {exc}"[:200]
        return finding
    records = parse_keyscan_output(proc.stdout or "")
    if not records:
        finding["status"] = "SSH_UNREACHABLE"
        finding["detail"] = (proc.stderr or "no host keys offered").strip().splitlines()[-1][:200]
        return finding
    issues: list[str] = []
    for record in records:
        key: dict[str, Any] = {
            "key_type": record["key_type"],
            "key_data": record["key_data"],
        }
        fingerprint = _fingerprint_keydata(keygen, record["key_data"], record["key_type"], record["host_field"])
        if fingerprint:
            key["bits"] = fingerprint["bits"]
            key["fingerprint_sha256"] = fingerprint["fingerprint_sha256"]
        else:
            key["bits"] = None
            key["fingerprint_sha256"] = None
        verdict = classify_host_key(record["key_type"], key.get("bits"))
        key["verdict"] = verdict
        issues.extend(verdict["policy_issues"])
        finding["keys"].append(key)
    drift = compare_host_keys(baseline, finding["keys"])
    finding["key_drift"] = drift
    if drift["status"] == "CHANGED":
        issues.append("SSH_HOST_KEY_CHANGED")
    finding["policy_issues"] = sorted(set(issues))
    finding["compliance_issue"] = finding["policy_issues"][0] if finding["policy_issues"] else None
    return finding


def ssh_probe_telemetry(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate SSH findings — same honest-verdict style as TLS telemetry."""
    statuses: dict[str, int] = {}
    weak = changed = 0
    for row in findings:
        status = str(row.get("status") or "UNKNOWN")
        statuses[status] = statuses.get(status, 0) + 1
        issues = row.get("policy_issues") or []
        if any(issue in {"SSH_DSS_HOST_KEY", "SSH_RSA_HOST_KEY", "SSH_WEAK_HOST_KEY"} for issue in issues):
            weak += 1
        if "SSH_HOST_KEY_CHANGED" in issues:
            changed += 1
    probed = len(findings)
    ok = statuses.get("OK", 0)
    if probed == 0:
        verdict = "SKIPPED"
    elif ok == 0:
        verdict = "FAILED"
    elif ok < probed or weak or changed:
        verdict = "PARTIAL"
    else:
        verdict = "OK"
    return {
        "status": verdict,
        "probed": probed,
        "ok": ok,
        "statuses": statuses,
        "ssh_weak_host_keys": weak,
        "ssh_host_key_changes": changed,
    }
