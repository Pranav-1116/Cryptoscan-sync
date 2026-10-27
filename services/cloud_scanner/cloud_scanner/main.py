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
    parser.add_argument("--zelix-live", action="store_true",
                        help="Run the ZELNX Live Cloud Intelligence Engine "
                             "(24/7 live monitoring, read-only; demo event "
                             "stream unless --zelix-live-events is given)")
    parser.add_argument("--zelix-live-events", metavar="JSON",
                        help="Path to a JSON list of raw provider event "
                             "payloads for the live engine")
    parser.add_argument("--zelix-live-cycles", type=int, default=1, metavar="N",
                        help="Live monitoring cycles (default 1)")
    parser.add_argument("--zelix-live-region", default="UAE",
                        help="Regional collector region (UAE/EU/USA)")
    args = parser.parse_args(argv)

    settings.validate_for_production()
    if args.zelix:
        return _zelix(args)
    if args.zelix_live:
        return _zelix_live(args)
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


def _zelix_live(args) -> int:
    """Run the ZELNX Live Cloud Intelligence Engine.

    Reads raw provider payloads from ``--zelix-live-events`` (JSON list)
    or falls back to the built-in demo stream.  Always read-only: only
    metadata/observations are emitted, never key material or secret
    values.
    """
    from cloud_scanner.enterprise.live.collector import CollectorConfig, RegionalCollector
    from cloud_scanner.enterprise.live.connectors import (
        aws_connector,
        azure_connector,
        gcp_connector,
    )
    from cloud_scanner.enterprise.live.demo import demo_raw_events, demo_resolvers
    from cloud_scanner.enterprise.live.engine import LiveCloudEngine

    raw_events = demo_raw_events()
    if args.zelix_live_events:
        payload = Path(args.zelix_live_events).read_text(encoding="utf-8")
        raw_events = json.loads(payload)
    by_provider: dict[str, list] = {"aws": [], "azure": [], "gcp": []}
    for row in raw_events:
        provider = str(row.get("provider") or "").lower()
        if provider in by_provider:
            by_provider[provider].append(row)
    connectors = []
    if by_provider["aws"]:
        connectors.append(aws_connector(event_source=lambda rows=by_provider["aws"]: rows,
                                        organization_id="org-zelnx"))
    if by_provider["azure"]:
        connectors.append(azure_connector(event_source=lambda rows=by_provider["azure"]: rows,
                                          organization_id="org-zelnx"))
    if by_provider["gcp"]:
        connectors.append(gcp_connector(event_source=lambda rows=by_provider["gcp"]: rows,
                                        organization_id="org-zelnx"))
    resolvers = demo_resolvers()
    engine = LiveCloudEngine(
        connectors=connectors,
        resolve_dependencies=resolvers["find_dependencies"],
        find_cert_consumers=resolvers["find_cert_consumers"],
        find_cross_cloud_impact=resolvers["find_cross_cloud_impact"],
        detect_algorithm=resolvers["detect_algorithm"],
    )
    region = str(args.zelix_live_region).upper()
    if region not in ("UAE", "EU", "USA"):
        region = "UAE"
    collector = RegionalCollector(
        CollectorConfig(collector_id=f"collector-{region.lower()}", region=region),
        process=lambda event: {"event_id": event.event_id},
    )
    engine.control_plane.register(collector)
    engine.health_snapshot(collector_id=collector.config.collector_id,
                           heartbeat_ok=True, auth_ok=True)
    cycles = max(1, args.zelix_live_cycles)
    report = None
    for index in range(cycles):
        report = engine.cycle(cycle_number=index + 1)
    text = json.dumps(report.to_dict(), indent=2, default=str) if report else "{}"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
