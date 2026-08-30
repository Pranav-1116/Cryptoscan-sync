"""CLI entry for the cloud / IaC scanner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cloud_scanner.config.settings import load_settings
from cloud_scanner.core.result_submitter import ResultSubmitter
from cloud_scanner.core.scanner import CloudScanner


def main(argv: list[str] | None = None) -> int:
    settings = load_settings()
    parser = argparse.ArgumentParser(description="Scan Terraform / Kubernetes / CloudFormation for crypto config")
    parser.add_argument("path", nargs="?", default=".", help="Filesystem root to scan")
    parser.add_argument("-o", "--output", help="Write JSON result to this path")
    parser.add_argument("--live", action="store_true", default=settings.live)
    parser.add_argument("--submit", action="store_true", default=settings.submit_results)
    parser.add_argument("--zelix", action="store_true",
                        help="Run the ZELNX Cloud Discovery Engine (read-only, "
                             "INVENTORY_ONLY + CRYPTO_DISCOVERY by default)")
    parser.add_argument("--zelix-modes", default="INVENTORY_ONLY,CRYPTO_DISCOVERY",
                        help="Comma-separated ZELNX scan modes: INVENTORY_ONLY, "
                             "CRYPTO_DISCOVERY, DEEP_CRYPTO_DISCOVERY, "
                             "CONTINUOUS_MONITORING, EVENT_DRIVEN")
    parser.add_argument("--zelix-cycles", type=int, default=1, metavar="N",
                        help="ZELNX continuous-monitoring cycles (default 1)")
    parser.add_argument("--zelix-currency", default="USD",
                        help="Cost intelligence currency (USD/EUR/GBP/INR)")
    args = parser.parse_args(argv)

    settings.validate_for_production()
    if args.zelix:
        return _zelix(args)
    result = CloudScanner(live=args.live).scan_filesystem(args.path)
    if args.submit:
        result["submit"] = ResultSubmitter(api_url=settings.api_url).submit(result)
    text = json.dumps(result, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    live_scan = result.get("live_scan") or {}
    if live_scan.get("status") == "FAILED":
        print(
            f"cloud scan FAILED: {live_scan.get('error_count', 0)} errors, "
            "0 resources — refusing to report an empty success",
            file=__import__("sys").stderr,
        )
        return 2
    return 0


def _zelix(args) -> int:
    """Run the ZELNX Cloud Discovery Engine.

    Default: no live adapters — discovery runs over injected/static
    adapters; an empty run is a valid, honest inventory (read-only).
    """
    from cloud_scanner.enterprise import ZelixCloudDiscoveryEngine

    modes = [token.strip().upper() for token in str(args.zelix_modes).split(",") if token.strip()]
    engine = ZelixCloudDiscoveryEngine(
        providers=[],
        modes=modes,
        options={"currency": args.zelix_currency},
    )
    reports = engine.run(cycles=max(1, args.zelix_cycles))
    result = engine.report()
    result["scan"]["cycles_run"] = len(reports)
    text = json.dumps(result, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
