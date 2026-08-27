"""CLI entry for the passive OT scanner. Never sends packets."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Passively scan OT/ICS logs and captures for crypto posture")
    parser.add_argument("path", help="Log file or directory of captures (key=value lines, JSON, JSONL)")
    parser.add_argument("-o", "--output", help="Write JSON result to this path")
    parser.add_argument("--metrics", action="store_true", help="Print Prometheus text instead of JSON")
    args = parser.parse_args(argv)

    from ot_scanner.core.scanner import OtPassiveScanner

    result = OtPassiveScanner().scan_filesystem(args.path)
    if args.metrics:
        from ot_scanner.reports.metrics import render_prometheus

        text = render_prometheus(result)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text, end="")
    else:
        text = json.dumps(result, indent=2, default=str)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text)
    risk = result.get("risk_report") or {}
    print(
        f"# mode={result.get('mode')} devices={result.get('device_count', 0)} "
        f"findings={len(result.get('findings') or [])} unencrypted={result.get('unencrypted', 0)} "
        f"posture={risk.get('posture') or '?'} packets_sent={result.get('packets_sent', 0)}",
        file=sys.stderr,
    )
    if risk.get("headline"):
        print(f"# risk: {risk['headline']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
