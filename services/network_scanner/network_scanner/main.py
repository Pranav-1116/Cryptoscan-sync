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
    parser.add_argument("target", help="Filesystem path or host:port")
    parser.add_argument("-o", "--output", help="Write JSON result to this path")
    parser.add_argument("--live", action="store_true", default=settings.live)
    parser.add_argument("--sni", default=None, help="Override SNI for the probe")
    parser.add_argument("--starttls", default=None,
                        help="STARTTLS protocol: auto|smtp|imap|pop3|ftp|ldap|postgresql|off (default: auto for known ports)")
    parser.add_argument("--workers", type=int, default=None, help="Parallel probes (default 8)")
    args = parser.parse_args(argv)

    scanner = NetworkTlsScanner(live=args.live, timeout=settings.timeout, workers=args.workers)
    target = args.target
    if ":" in target and not Path(target).exists():
        context = ScanContext.for_hosts(target, live=True, timeout=settings.timeout)
        result = scanner.scan_hosts(
            [target],
            scan_id=context.scan_id,
            sni=args.sni,
            starttls=args.starttls if args.starttls != "auto" else "auto",
        )
    else:
        context = ScanContext.for_path(target, live=args.live, timeout=settings.timeout)
        result = scanner.scan_filesystem(target, scan_id=context.scan_id)
    result["scan_context"] = context.to_dict()
    text = json.dumps(result, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
