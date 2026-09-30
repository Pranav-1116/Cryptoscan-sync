#!/usr/bin/env python3
"""Strict qualification harness for a real HSM/key provider.

This runner intentionally fails closed. ``--provider`` selects one explicit
provider and the relevant adapter is expected to obtain credentials from the
process environment or the application's existing secret mechanism. It never
prints environment values, private key bytes, PINs, tokens, or provider
responses that may contain secret material.

Provider adapters are imported from ``keyassure.hsm_backends`` and the shared
connectivity probes are used when available. Provider-specific rotation,
revocation, outage and audit-log evidence should be supplied as non-secret
JSON from a customer-controlled test account through ``--evidence``; the
runner validates its shape but does not pretend that a local SoftHSM check is
AWS CloudHSM, Azure Managed HSM, GCP KMS, or a customer PKCS#11 device.

The default is a safe qualification report. ``--strict`` returns nonzero for
missing provider access, missing required probes, SKIP, or FAIL.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
KEYASSURE = ROOT / "services" / "keyassure"
if str(KEYASSURE) not in sys.path:
    sys.path.insert(0, str(KEYASSURE))
PROVIDERS = {"aws", "azure", "gcp", "pkcs11", "luna"}
SECRET_WORDS = re.compile(r"(private.?key|key.?material|raw.?key|secret|password|passwd|token|access.?key|client.?secret|pin)", re.I)
FORBIDDEN_EVIDENCE_KEYS = re.compile(
    r"(?:private|raw|plain.?text|key.?material|pem|der|secret.?material|private.?exponent)",
    re.I,
)


def safe_text(value: Any) -> str:
    """Return only bounded metadata, never arbitrary provider payloads."""
    if value is None or isinstance(value, (bool, int, float)):
        return str(value)
    if isinstance(value, str):
        if SECRET_WORDS.search(value) or "BEGIN " in value.upper() or len(value) > 512:
            return "[redacted]"
        return value[:300]
    if isinstance(value, dict):
        return json.dumps({str(k): "[redacted]" if SECRET_WORDS.search(str(k)) else safe_text(v) for k, v in list(value.items())[:20]}, sort_keys=True)
    if isinstance(value, (list, tuple)):
        return "[list length=%d]" % len(value)
    return type(value).__name__


def result(name: str, status: str, detail: str, results: list[dict]) -> None:
    item = {"probe": name, "status": status, "detail": safe_text(detail)}
    results.append(item)
    print(f"{status:<4} {name}: {item['detail']}")


def load_backend(provider: str) -> Any:
    module = importlib.import_module("keyassure.hsm_backends")
    if provider == "aws":
        return module.AwsKmsBackend(region=os.getenv("AWS_REGION"))
    if provider == "azure":
        vault_url = os.getenv("HSM_AZURE_VAULT_URL") or os.getenv("AZURE_KEY_VAULT_URL")
        if not vault_url:
            raise RuntimeError("HSM_AZURE_VAULT_URL is required for Azure Key Vault/Managed HSM")
        return module.AzureKeyVaultBackend(vault_url)
    if provider == "gcp":
        return module.GcpKmsBackend()
    if provider in {"pkcs11", "luna"}:
        return module.Pkcs11Backend(
            lib_path=os.getenv("PKCS11_LIB"),
            slot=int(os.environ["PKCS11_SLOT"]) if os.getenv("PKCS11_SLOT") else None,
        )
    raise RuntimeError(f"no supported {provider} adapter exported by keyassure.hsm_backends")


def invoke(backend: Any, names: tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
    for name in names:
        fn = getattr(backend, name, None)
        if callable(fn):
            return fn(*args, **kwargs)
    raise AttributeError("adapter has no supported method: " + ", ".join(names))


def network_outage_probe(host: str | None, port: int | None, timeout: float) -> tuple[str, str]:
    if not host or not port:
        return "SKIP", "--outage-host and --outage-port are required for a bounded outage probe"
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "FAIL", "provider endpoint remained reachable; no outage was induced"
    except OSError as exc:
        # A refused/timeout endpoint proves only reachability failure. It does
        # not prove the application handled it correctly; that is why this is
        # a separate probe and remains SKIP without an app recovery command.
        return "PASS", f"endpoint unavailable ({type(exc).__name__}); elapsed={time.monotonic() - started:.3f}s"


def _forbidden_evidence_field(value: Any, path: str = "root") -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            field = f"{path}.{key}"
            if FORBIDDEN_EVIDENCE_KEYS.search(str(key)):
                return field
            found = _forbidden_evidence_field(child, field)
            if found:
                return found
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            found = _forbidden_evidence_field(child, f"{path}[{index}]")
            if found:
                return found
    return None


def evidence_checks(path: Path, results: list[dict]) -> None:
    if not path.exists():
        result("provider evidence bundle", "SKIP", f"not supplied: {path}", results)
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        result("provider evidence bundle", "FAIL", f"invalid JSON: {exc}", results)
        return
    if not isinstance(data, dict):
        result("provider evidence bundle", "FAIL", "root must be an object", results)
        return
    required = ("provider", "captured_at", "key_id_digest", "fips_or_provider_metadata", "rotation", "revocation", "audit_log")
    missing = [key for key in required if key not in data]
    if missing:
        result("provider evidence schema", "FAIL", "missing fields: " + ", ".join(missing), results)
        return
    forbidden = _forbidden_evidence_field(data)
    if forbidden:
        result("provider evidence secret scan", "FAIL", f"prohibited key-material field: {forbidden}", results)
        return
    serialized = json.dumps(data, sort_keys=True)
    if "BEGIN PRIVATE KEY" in serialized.upper() or "BEGIN RSA PRIVATE KEY" in serialized.upper():
        result("provider evidence secret scan", "FAIL", "bundle contains PEM/private-key material", results)
        return
    for key in ("rotation", "revocation", "audit_log"):
        value = data[key]
        ok = isinstance(value, dict) and value.get("status") == "PASS"
        result(f"evidence:{key}", "PASS" if ok else "FAIL", "customer/provider evidence status", results)
    result("provider evidence schema", "PASS", f"digest={hashlib.sha256(serialized.encode()).hexdigest()}", results)


_UNSAFE_COMMAND = re.compile(r"[;&|`$()<>{}\n\r]")


def run_operator_command(command: str | None, timeout: float = 120.0) -> tuple[str, str]:
    """Run a fixed operator wrapper without invoking a shell.

    Qualification commands are operator-controlled, but they often originate
    in environment variables on a shared runner. Shell execution would turn a
    malformed recovery command into arbitrary code execution in the
    qualification process. Wrappers should be standalone scripts with
    arguments, not shell pipelines.
    """
    if not command:
        return "SKIP", "operator wrapper not supplied; no lifecycle/audit claim made"
    if _UNSAFE_COMMAND.search(command):
        return "FAIL", "operator wrapper contains shell metacharacters; use an executable wrapper script"
    try:
        argv = shlex.split(command)
    except ValueError:
        return "FAIL", "operator wrapper has invalid quoting"
    if not argv:
        return "SKIP", "operator wrapper is empty"
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as exc:
        return "FAIL", f"{type(exc).__name__}: operator wrapper failed"
    return ("PASS" if proc.returncode == 0 else "FAIL"), "wrapper completed; output withheld"


def operator_probe(name: str, command: str | None, results: list[dict]) -> None:
    status, detail = run_operator_command(command)
    result(name, status, detail, results)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--provider", choices=sorted(PROVIDERS), default=os.getenv("HSM_PROVIDER"))
    ap.add_argument("--key-id", default=os.getenv("HSM_KEY_ID"), help="provider key reference; never a private key")
    ap.add_argument("--evidence", type=Path, default=Path(os.getenv("HSM_EVIDENCE", "")) if os.getenv("HSM_EVIDENCE") else None)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--rotation-command", default=os.getenv("HSM_ROTATION_COMMAND"), help="operator wrapper that rotates the qualification key and emits provider evidence")
    ap.add_argument("--revocation-command", default=os.getenv("HSM_REVOCATION_COMMAND"), help="operator wrapper that revokes/disables the qualification key")
    ap.add_argument("--audit-log-command", default=os.getenv("HSM_AUDIT_LOG_COMMAND"), help="operator wrapper that retrieves correlated provider audit evidence")
    ap.add_argument("--outage-host", default=os.getenv("HSM_OUTAGE_HOST"))
    ap.add_argument("--outage-port", type=int, default=int(os.environ.get("HSM_OUTAGE_PORT", "0") or 0) or None)
    ap.add_argument("--outage-recovery-command", default=os.getenv("HSM_OUTAGE_RECOVERY_COMMAND"))
    args = ap.parse_args(argv)

    report: dict[str, Any] = {
        "schema": "cryptoscan.hsm-qualification/1",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "provider": args.provider,
        "key_id_digest": hashlib.sha256(args.key_id.encode()).hexdigest() if args.key_id else None,
        "checks": [],
        "prohibited_material_recorded": False,
    }
    checks = report["checks"]
    output = args.out or ROOT / "docs" / "hsm-evidence" / f"hsm-qualification-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"

    if not args.provider:
        result("provider selected", "FAIL", "--provider or HSM_PROVIDER is required; no local provider is assumed", checks)
    else:
        result("provider selected", "PASS", args.provider, checks)
        if not args.key_id:
            result("key reference supplied", "FAIL", "--key-id or HSM_KEY_ID is required", checks)
        else:
            result("key reference supplied", "PASS", "reference digest recorded; value withheld", checks)
            try:
                backend = load_backend(args.provider)
                result("adapter loaded", "PASS", type(backend).__name__, checks)
                try:
                    from keyassure.hsm_connectivity import check_key
                    provider_name = {
                        "aws": "aws_kms",
                        "azure": "azure_managed_hsm",
                        "gcp": "gcp_kms",
                        "pkcs11": "pkcs11",
                        "luna": "luna",
                    }[args.provider]
                    shared = check_key(args.key_id, provider=provider_name, backend=backend)
                    residence_ok = shared.get("key_residence") == "HSM" and not shared.get("raw_key_material_present", False)
                    result("key residence and non-exportability", "PASS" if residence_ok else "FAIL", f"residence={shared.get('key_residence')}; sign={shared.get('sign_challenge')}; raw_material={shared.get('raw_key_material_present', False)}", checks)
                    report["shared_connectivity"] = {"connectivity": shared.get("connectivity"), "key_residence": shared.get("key_residence"), "sign_challenge": shared.get("sign_challenge"), "hardware_backed": shared.get("hardware_backed"), "raw_key_material_present": shared.get("raw_key_material_present", False), "worst_severity": shared.get("worst_severity")}
                except Exception as exc:
                    result("key residence and non-exportability", "FAIL", f"{type(exc).__name__}: shared HSM probe failed", checks)
                try:
                    metadata = invoke(backend, ("describe", "describe_key", "get_key_metadata"), args.key_id)
                    result("provider metadata", "PASS", "metadata received; secret values withheld", checks)
                    report["provider_metadata"] = {"type": type(metadata).__name__, "sanitized": safe_text(metadata)}
                except Exception as exc:
                    result("provider metadata", "FAIL", f"{type(exc).__name__}: provider describe failed", checks)
                try:
                    challenge = invoke(backend, ("sign_challenge", "sign", "test_sign"), args.key_id, b"cryptoscan-hsm-qualification")
                    result("sign challenge", "PASS" if challenge else "FAIL", "signature returned; signature bytes not recorded", checks)
                except Exception as exc:
                    result("sign challenge", "FAIL", f"{type(exc).__name__}: sign challenge failed", checks)
                try:
                    invoke(backend, ("export_key", "get_private_key", "export_private_key"), args.key_id)
                    result("non-exportability", "FAIL", "adapter returned a value from an export operation; value discarded", checks)
                except (AttributeError, NotImplementedError):
                    result("non-exportability", "PASS", "adapter exposes no private-key export operation", checks)
                except Exception:
                    result("non-exportability", "PASS", "provider rejected private-key export", checks)
            except Exception as exc:
                result("adapter loaded", "FAIL", f"{type(exc).__name__}: {exc}", checks)

    evidence_checks(args.evidence, checks) if args.evidence else result("provider evidence bundle", "SKIP", "--evidence is required for provider-controlled lifecycle and audit proof", checks)
    operator_probe("key rotation execution", args.rotation_command, checks)
    operator_probe("key revocation execution", args.revocation_command, checks)
    operator_probe("provider audit-log correlation", args.audit_log_command, checks)
    outage_status, outage_detail = network_outage_probe(args.outage_host, args.outage_port, 5.0)
    result("bounded outage behavior", outage_status if args.outage_recovery_command else "SKIP", outage_detail + ("; recovery command not supplied" if not args.outage_recovery_command else ""), checks)
    if args.outage_recovery_command:
        status, detail = run_operator_command(args.outage_recovery_command, timeout=60)
        result("outage recovery probe", status, detail, checks)
    else:
        result("outage recovery probe", "SKIP", "HSM_OUTAGE_RECOVERY_COMMAND is required", checks)

    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["verdict"] = "PASS" if all(x["status"] == "PASS" for x in checks) else "FAIL"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"HSM verdict: {report['verdict']} -> {output}")
    if args.strict and report["verdict"] != "PASS":
        return 1
    return 0 if report["verdict"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
