"""Unified realtime network crypto adapter.

Runs the existing TLS/certificate scanner and, when explicitly enabled by the
operator, the existing IPsec/IKE and DNSSEC probes in one structured result.
Each mode keeps its own observed output and errors, so a failed TLS probe is
not reported as a DNSSEC or IPsec verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from typing import Any


def _evidence(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _status(data: Any) -> str:
    """Normalize scanner output without turning probe errors into PASS."""
    if not isinstance(data, dict):
        return "PASS"
    state = str(data.get("scan_status") or data.get("status") or "").upper()
    if state in {"FAILED", "ERROR", "PROBE_ERROR", "FAIL"}:
        return "FAIL"
    if state in {"BLOCKED", "UNAVAILABLE", "PREFLIGHT", "SKIP", "DEGRADED"}:
        return state
    rows = data.get("findings") or data.get("probes") or data.get("zones") or []
    if isinstance(rows, list) and any(
        isinstance(row, dict) and str(row.get("status") or "").upper()
        in {"FAILED", "ERROR", "PROBE_ERROR"}
        for row in rows
    ):
        return "FAIL"
    return "PASS"


def _annotate(data: Any) -> Any:
    if isinstance(data, dict):
        for key in ("findings", "certificates", "probes", "zones"):
            rows = data.get(key)
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, dict) and not row.get("evidence_reference"):
                        row["evidence_reference"] = _evidence(row)
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run realtime network TLS/IPsec/DNSSEC crypto scans")
    parser.add_argument("target", help="operator-authorized host:port or DNS zone")
    parser.add_argument("--ipsec", action="store_true", help="also run the explicit IKE/IPsec probe")
    parser.add_argument("--dnssec", action="store_true", help="also run the DNSSEC zone probe")
    parser.add_argument("--full", action="store_true", help="enable revocation/renegotiation checks")
    args = parser.parse_args(argv)

    # Optional scanner dependencies (including YAML-backed settings) are
    # imported inside the guarded preflight so the CLI always emits JSON.
    try:
        from network_scanner.config.settings import load_settings
        from network_scanner.core.scanner import NetworkTlsScanner
    except (ImportError, ModuleNotFoundError) as exc:
        result = {
            "scanner": "network", "target": args.target, "scan_status": "PREFLIGHT",
            "modes": {"tls": "UNAVAILABLE", "ipsec": "SKIP", "dnssec": "SKIP"},
            "findings": [], "errors": [{"mode": "preflight", "status": "UNAVAILABLE", "error": str(exc)}],
        }
        print(json.dumps(result, sort_keys=True, default=str))
        return 2

    try:
        timeout = load_settings().timeout
    except Exception:
        timeout = 5.0
    scanner = NetworkTlsScanner(live=True, timeout=timeout)
    result: dict[str, Any] = {
        "scanner": "network", "target": args.target, "findings": [], "modes": {},
    }
    errors: list[dict[str, str]] = []

    try:
        tls = _annotate(scanner.scan_hosts(
            [args.target], scan_versions=True, scan_ciphers=True,
            check_chain_sent=True, check_renegotiation=args.full,
            live_revocation=args.full,
        ))
        result["tls"] = tls
        result["certificates"] = tls.get("certificates") or []
        result["findings"].extend(tls.get("findings") or tls.get("alerts") or [])
        result["modes"]["tls"] = _status(tls)
    except Exception as exc:  # noqa: BLE001
        errors.append({"mode": "tls", "status": "FAIL", "error": str(exc)})
        result["tls"] = {"status": "FAILED", "error": str(exc)}
        result["modes"]["tls"] = "FAIL"

    if args.ipsec:
        try:
            ipsec = _annotate(scanner.scan_ipsec_hosts([args.target]))
            result["ipsec"] = ipsec
            result["modes"]["ipsec"] = _status(ipsec)
        except Exception as exc:  # noqa: BLE001
            errors.append({"mode": "ipsec", "status": "FAIL", "error": str(exc)})
            result["ipsec"] = {"status": "FAILED", "error": str(exc)}
            result["modes"]["ipsec"] = "FAIL"
    else:
        result["ipsec"] = {"status": "SKIP", "reason": "operator did not enable IPsec probe"}
        result["modes"]["ipsec"] = "SKIP"

    if args.dnssec:
        try:
            dnssec = _annotate(scanner.scan_dnssec_zones([args.target]))
            result["dnssec"] = dnssec
            result["modes"]["dnssec"] = _status(dnssec)
        except Exception as exc:  # noqa: BLE001
            errors.append({"mode": "dnssec", "status": "FAIL", "error": str(exc)})
            result["dnssec"] = {"status": "FAILED", "error": str(exc)}
            result["modes"]["dnssec"] = "FAIL"
    else:
        result["dnssec"] = {"status": "SKIP", "reason": "operator did not enable DNSSEC probe"}
        result["modes"]["dnssec"] = "SKIP"

    result["errors"] = errors
    active = [value for value in result["modes"].values() if value != "SKIP"]
    result["scan_status"] = (
        "FAIL" if active and all(value == "FAIL" for value in active)
        else "DEGRADED" if errors or any(value in {"DEGRADED", "BLOCKED", "UNAVAILABLE"} for value in active)
        else "PASS"
    )
    result["evidence_reference"] = _evidence(result)
    print(json.dumps(result, sort_keys=True, default=str))
    return 0 if result["scan_status"] in {"PASS", "DEGRADED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
