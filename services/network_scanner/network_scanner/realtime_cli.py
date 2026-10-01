"""Unified realtime network crypto adapter.

Runs the existing TLS/certificate scanner and, when explicitly enabled by the
operator, the existing IPsec/IKE and DNSSEC probes in one structured result.
Each mode keeps its own observed output and errors, so a failed TLS probe is
not reported as a DNSSEC or IPsec verdict.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from network_scanner.config.settings import load_settings
from network_scanner.core.scanner import NetworkTlsScanner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run realtime network TLS/IPsec/DNSSEC crypto scans")
    parser.add_argument("target", help="operator-authorized host:port or DNS zone")
    parser.add_argument("--ipsec", action="store_true", help="also run the explicit IKE/IPsec probe")
    parser.add_argument("--dnssec", action="store_true", help="also run the DNSSEC zone probe")
    parser.add_argument("--full", action="store_true", help="enable revocation/renegotiation checks")
    args = parser.parse_args(argv)
    try:
        timeout = load_settings().timeout
    except Exception:
        timeout = 5.0
    scanner = NetworkTlsScanner(live=True, timeout=timeout)
    result: dict[str, Any] = {"scanner": "network", "target": args.target, "findings": []}
    errors: list[dict[str, str]] = []

    try:
        tls = scanner.scan_hosts(
            [args.target], scan_versions=True, scan_ciphers=True,
            check_chain_sent=True, check_renegotiation=args.full,
            live_revocation=args.full,
        )
        result["tls"] = tls
        result["certificates"] = tls.get("certificates") or []
        result["findings"].extend(tls.get("findings") or tls.get("alerts") or [])
    except Exception as exc:  # noqa: BLE001
        errors.append({"mode": "tls", "error": str(exc)})
        result["tls"] = {"status": "FAILED", "error": str(exc)}

    if args.ipsec:
        try:
            result["ipsec"] = scanner.scan_ipsec_hosts([args.target])
        except Exception as exc:  # noqa: BLE001
            errors.append({"mode": "ipsec", "error": str(exc)})
            result["ipsec"] = {"status": "FAILED", "error": str(exc)}
    else:
        result["ipsec"] = {"status": "SKIP", "reason": "operator did not enable IPsec probe"}

    if args.dnssec:
        try:
            result["dnssec"] = scanner.scan_dnssec_zones([args.target])
        except Exception as exc:  # noqa: BLE001
            errors.append({"mode": "dnssec", "error": str(exc)})
            result["dnssec"] = {"status": "FAILED", "error": str(exc)}
    else:
        result["dnssec"] = {"status": "SKIP", "reason": "operator did not enable DNSSEC probe"}

    result["errors"] = errors
    tls_failed = (result.get("tls") or {}).get("status") == "FAILED"
    result["scan_status"] = "FAIL" if tls_failed and not (args.ipsec or args.dnssec) else "DEGRADED" if errors else "PASS"
    print(json.dumps(result, sort_keys=True, default=str))
    return 0 if result["scan_status"] in {"PASS", "DEGRADED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
