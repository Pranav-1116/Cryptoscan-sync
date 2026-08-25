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
    args = parser.parse_args(argv)

    scanner = NetworkTlsScanner(live=args.live, timeout=settings.timeout)
    target = args.target
    if ":" in target and not Path(target).exists():
        context = ScanContext.for_hosts(target, live=True, timeout=settings.timeout)
        result = scanner.scan_hosts([target], scan_id=context.scan_id)
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
