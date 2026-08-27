"""CLI entry for the network TLS scanner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from network_scanner.config.settings import load_settings
from network_scanner.core.scan_context import ScanContext
from network_scanner.core.scanner import NetworkTlsScanner


def main(argv: list[str] | None = None) -> int:
    settings = load_settings()
    parser = argparse.ArgumentParser(description="Scan a tree or host list for TLS / certificates")
    parser.add_argument("target", nargs="?", default=None, help="Filesystem path or host:port")
    parser.add_argument("--discover", metavar="CIDR", default=None, help="Sweep a subnet (e.g. 10.0.0.0/24) for open TLS ports")
    parser.add_argument("--ports", default="443,8443", help="Ports for --discover (comma-separated)")
    parser.add_argument("--scan", action="store_true", help="Scan discovered endpoints immediately")
    parser.add_argument("--scan-versions", action="store_true", help="Probe the TLS version floor per endpoint")
    parser.add_argument("--scan-ciphers", action="store_true", help="Probe weak-cipher acceptance per endpoint")
    parser.add_argument("--check-renegotiation", action="store_true", help="Probe RFC 5746 secure + client-initiated renegotiation")
    parser.add_argument("--check-chain", action="store_true", help="Fetch and analyze the certificate chain as sent")
    parser.add_argument("--live-revocation", action="store_true", help="Live OCSP query + CRL fetch/lookup per endpoint")
    parser.add_argument("-o", "--output", help="Write JSON result to this path")
    parser.add_argument("--live", action="store_true", default=settings.live)
    parser.add_argument("--sni", default=None, help="Override SNI for the probe")
    parser.add_argument("--starttls", default=None,
                        help="STARTTLS protocol: auto|smtp|imap|pop3|ftp|ldap|postgresql|off (default: auto for known ports)")
    parser.add_argument("--workers", type=int, default=None, help="Parallel probes (default 8)")
    args = parser.parse_args(argv)

    scanner = NetworkTlsScanner(live=args.live, timeout=settings.timeout, workers=args.workers)
    if args.discover:
        from network_scanner.discovery.subnet_discoverer import discover_subnet

        ports = [int(p) for p in args.ports.split(",") if p.strip().isdigit()]
        result = discover_subnet(args.discover, ports)
        if args.scan and result.get("endpoints"):
            scanned = scanner.scan_hosts(
                result["endpoints"],
                scan_versions=args.scan_versions,
                scan_ciphers=args.scan_ciphers,
                check_renegotiation=args.check_renegotiation,
                check_chain_sent=args.check_chain,
                live_revocation=args.live_revocation,
            )
            result["scan"] = {key: scanned[key] for key in ("probe_telemetry", "certificates", "alerts") if key in scanned}
        result["scan_context"] = {"mode": "subnet-discovery", "cidr": args.discover, "ports": ports}
        _emit(result, args.output)
        return 0
    target = args.target
    if not target:
        parser.error("target (host:port or path) or --discover CIDR is required")
    if ":" in target and not Path(target).exists():
        context = ScanContext.for_hosts(target, live=True, timeout=settings.timeout)
        result = scanner.scan_hosts(
            [target],
            scan_id=context.scan_id,
            sni=args.sni,
            starttls=args.starttls if args.starttls != "auto" else "auto",
            scan_versions=args.scan_versions,
            scan_ciphers=args.scan_ciphers,
            check_renegotiation=args.check_renegotiation,
            check_chain_sent=args.check_chain,
            live_revocation=args.live_revocation,
        )
    else:
        context = ScanContext.for_path(target, live=args.live, timeout=settings.timeout)
        result = scanner.scan_filesystem(target, scan_id=context.scan_id)
    result["scan_context"] = context.to_dict()
    _emit(result, args.output)
    return 0


def _emit(result, output) -> None:
    text = json.dumps(result, indent=2, default=str)
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    raise SystemExit(main())
