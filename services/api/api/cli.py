"""``cryptoscan`` entry point for the bank-owned control plane.

Installed scan/collect commands use the bank's API and never collect from the
operator's terminal. Schedule, tick, coverage and BOM reads also go through that
API; the bank-server daemon and some legacy twin commands still use local database
handlers. ``session_factory`` keeps those handlers testable without making them
the default operator path.

A queued job receipt is not a finding, and a schedule only reprojects already
retained evidence. Exit 2 means incomplete, exit 3 means the requested capability
or authority was refused; neither becomes a fabricated success response.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Callable, Sequence

EXIT_OK = 0
EXIT_INCOMPLETE = 2
EXIT_ERROR = 1
EXIT_REFUSED = 3

DEFAULT_PLANES = None  # every plane


REMOTE_SCAN_FLAGS = ("server", "system", "target", "path", "dry_run", "manifest", "wait",
                     "remote_static", "remote_runtime", "remote_network")


def _remote_scan_requested(args: argparse.Namespace) -> bool:
    """Legacy injected handlers may opt into remote mode; installed scan always uses it."""
    return any(getattr(args, flag, None) for flag in REMOTE_SCAN_FLAGS)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptoscan",
        description="CryptoScan — bank-owned control plane client; collectors run on bank servers",
    )
    parser.add_argument("--version", action="version", version="cryptoscan 1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="submit an exact job through the bank-owned API")
    scan.add_argument("--scope", default="production", help="scope label recorded with the run")
    scan.add_argument("--estate", default="default", help="estate name (tenant-visible label)")
    scan.add_argument(
        "--tenant",
        default=None,
        help="tenant id to scope the read to (default: unscoped, as the API does for a platform run)",
    )
    scan.add_argument(
        "--plane",
        action="append",
        dest="planes",
        metavar="PLANE",
        help="restrict to a plane (repeatable). Omitting it runs every plane.",
    )
    scan.add_argument("--no-persist", action="store_true", help="build the report without storing the run")
    scan.add_argument("--no-boms", action="store_true", help="skip the BOM projections")
    scan.add_argument("--json", action="store_true", help="emit the full report as JSON")
    scan.add_argument(
        "--allow-partial",
        action="store_true",
        help="exit 0 even when coverage is incomplete (the incompleteness is still printed and stored)",
    )
    # Remote mode: the CLI becomes a control-plane client and collects nothing itself.
    # Any of these switches selects it, so an operator cannot believe they scanned
    # locally when they actually submitted work to the control plane (or vice versa).
    scan.add_argument("--server", default=None,
                      help="control-plane base URL; selects remote mode")
    scan.add_argument("--system", default=None, help="remote: trigger a scan for one system")
    scan.add_argument("--target", default=None, help="remote: submit a collection job for a target")
    scan.add_argument("--path", default=None,
                      help="remote: approved absolute source path on the control plane (never this terminal)")
    scan.add_argument("--branch", default="main", help="local source is not Git-attested; non-default branches are refused")
    scan.add_argument("--target-revision", dest="target_revision", type=int, default=None,
                      help="remote: the target revision the operator read (required with --target)")
    scan.add_argument("--static", dest="remote_static", action="store_true",
                      help="remote: only the static plane (recorded in the request, not assumed)")
    scan.add_argument("--runtime", dest="remote_runtime", action="store_true",
                      help="remote: only the runtime plane")
    scan.add_argument("--network", dest="remote_network", action="store_true",
                      help="remote: only the network plane")
    scan.add_argument("--dry-run", dest="dry_run", action="store_true",
                      help="remote: print the platform's collection plan and collect nothing")
    scan.add_argument("--manifest", default=None,
                      help="remote: read the scan definition (scope, planes) from a JSON/YAML manifest")
    scan.add_argument("--wait", action="store_true", help="remote: follow the job until it finishes")
    scan.add_argument("--token", default=None, help="remote: session token (default: stored)")
    scan.add_argument("--api-key", dest="api_key", default=None, help="remote: machine credential")
    scan.add_argument("--ca", default=None, help="remote: CA bundle")
    scan.add_argument("--client-cert", dest="client_cert", default=None, help="remote: mTLS certificate")
    scan.add_argument("--client-key", dest="client_key", default=None, help="remote: mTLS key")
    scan.add_argument("--insecure", action="store_true", help="remote: skip TLS verification (lab only)")

    collect = sub.add_parser(
        "collect",
        help="submit an authorized target or system job to the bank-owned control plane",
    )
    collect.add_argument("--endpoints", default="",
                         help="comma-separated endpoints; omitted = every scope destination")
    collect.add_argument("--protocol", default="TLS", choices=["TLS", "mTLS", "STARTTLS"])
    collect.add_argument("--timeout", type=float, default=5.0)
    collect.add_argument("--inventory", default="default", help="which approved scope to use")
    collect.add_argument("--versions", action="store_true", help="also negotiate every supported TLS version")
    collect.add_argument("--ciphers", action="store_true", help="also enumerate cipher suites")
    collect.add_argument("--tenant", default=None)
    collect.add_argument("--scope", default="production", help="scope label recorded with the estate run")
    collect.add_argument("--json", action="store_true", help="emit one JSON document")
    collect.add_argument("--no-estate", action="store_true", help="collect only; do not run the estate job")
    collect.add_argument("--allow-partial", action="store_true")
    # The boundary, made explicit: local collection remains available for a single node, but
    # it is a mode you choose, and --submit hands the work to the control plane instead.
    collect.add_argument("--submit", action="store_true",
                         help="hand the work to the control plane instead of collecting here")
    collect.add_argument("--server", default=None, help="control-plane base URL (with --submit)")
    collect.add_argument("--system", default=None, help="with --submit: trigger a system scan")
    collect.add_argument("--target", default=None, help="with --submit: submit a target job")
    collect.add_argument("--target-revision", dest="target_revision", type=int, default=None)
    collect.add_argument("--wait", action="store_true", help="with --submit: follow the job")
    collect.add_argument("--token", default=None)
    collect.add_argument("--api-key", dest="api_key", default=None)

    schedule = sub.add_parser("schedule", help="save, list, pause or resume retained estate schedules")
    schedule_sub = schedule.add_subparsers(dest="schedule_command", required=True)
    add = schedule_sub.add_parser("add", help="save a cadence for the estate job")
    add.add_argument("name")
    add.add_argument("--every", default=None, help="interval, e.g. 15m, 6h, 1d")
    add.add_argument("--cron", default=None, help="five-field UTC cron, e.g. '0 2 * * *'")
    add.add_argument("--scope", default="production")
    add.add_argument("--estate", default="default")
    add.add_argument("--plane", action="append", dest="planes", metavar="PLANE")
    add.add_argument("--disabled", action="store_true", help="save it without scheduling it yet")
    add.add_argument("--tenant", default=None)
    add.add_argument("--json", action="store_true")
    listing = schedule_sub.add_parser("list", help="show saved schedules and their last outcome")
    listing.add_argument("--tenant", default=None)
    listing.add_argument("--json", action="store_true")
    remove = schedule_sub.add_parser("remove", help="refused for audit retention; use disable to pause")
    remove.add_argument("identifier")
    remove.add_argument("--tenant", default=None)
    toggle_on = schedule_sub.add_parser("enable", help="re-enable a paused schedule")
    toggle_on.add_argument("identifier")
    toggle_on.add_argument("--tenant", default=None)
    toggle_off = schedule_sub.add_parser("disable", help="pause a schedule without deleting it")
    toggle_off.add_argument("identifier")
    toggle_off.add_argument("--tenant", default=None)

    tick = sub.add_parser("tick", help="run every schedule that is due (safe to run from cron or a sidecar)")
    tick.add_argument("--worker", default="cryptoscan-tick", help="worker id recorded on the lease")
    tick.add_argument("--lease-seconds", type=int, default=900)
    tick.add_argument("--limit", type=int, default=20)
    tick.add_argument("--tenant", default=None)
    tick.add_argument("--json", action="store_true")

    serve = sub.add_parser(
        "serve",
        help="run the estate loop continuously (the 24/7 scheduler; SIGTERM stops it cleanly)",
    )
    serve.add_argument("--worker", default="cryptoscan-daemon", help="daemon identity recorded on every lease")
    serve.add_argument("--poll", type=float, default=30.0,
                       help="longest wait between cycles, in seconds (a due schedule wakes it sooner)")
    serve.add_argument("--lease-seconds", type=int, default=900)
    serve.add_argument("--limit", type=int, default=20)
    serve.add_argument("--tenant", default=None,
                       help="tenant to scope the daemon to (default: platform-wide, as the schedules are)")
    serve.add_argument("--once", action="store_true", help="run exactly one cycle and exit (cron compatibility)")
    serve.add_argument("--max-cycles", type=int, default=None, help="stop after N cycles (tests and drills)")
    serve.add_argument("--events", action="store_true",
                       help="publish run/plane events to the realtime bus (default: on unless --no-events)")
    serve.add_argument("--no-events", action="store_true", help="do not publish realtime events")
    serve.add_argument("--json", action="store_true")

    coverage = sub.add_parser("coverage", help="print the coverage matrix of the latest stored run")
    coverage.add_argument("--tenant", default=None)
    coverage.add_argument("--json", action="store_true")

    twin = sub.add_parser("twin", help="operate the Digital Twin (spec 94)")
    twin_sub = twin.add_subparsers(dest="twin_command", required=True)
    twin_graph = twin_sub.add_parser(
        "graph-load",
        help="load the twin graph export into the configured graph store (dry-run by default)",
    )
    twin_graph.add_argument("--tenant", default=None)
    twin_graph.add_argument("--database", default=None, help="target Neo4j database (default: server default)")
    twin_graph.add_argument("--batch-size", type=int, default=500)
    twin_graph.add_argument("--apply", action="store_true",
                            help="actually write; without it the command only prints the plan")
    twin_graph.add_argument("--prune-missing", action="store_true",
                            help="after a verified load, delete estate nodes the export no longer has")
    twin_graph.add_argument("--json", action="store_true")

    twin_verify = twin_sub.add_parser(
        "graph-verify",
        help="ask the graph store whether it still equals this projection, id by id",
    )
    twin_verify.add_argument("--tenant", default=None)
    twin_verify.add_argument("--database", default=None)
    twin_verify.add_argument("--json", action="store_true")

    twin_traversal = twin_sub.add_parser(
        "graph-traversal",
        help="ask the graph store the twin's own blast-radius question and compare the answers",
    )
    twin_traversal.add_argument("asset", help="asset id or name to start from")
    twin_traversal.add_argument("--depth", type=int, default=3)
    twin_traversal.add_argument("--tenant", default=None)
    twin_traversal.add_argument("--database", default=None)
    twin_traversal.add_argument("--json", action="store_true")

    twin_sim = twin_sub.add_parser(
        "simulate",
        help="run a scenario on a copy of the twin (never on the estate)",
    )
    twin_sim.add_argument("--from", dest="source", required=True, help="algorithm, protocol or version to replace")
    twin_sim.add_argument("--to", dest="target", default=None, help="replacement (required for REPLACE_ALGORITHM)")
    twin_sim.add_argument("--kind", default="REPLACE_ALGORITHM",
                          choices=["REPLACE_ALGORITHM", "RETIRE_ALGORITHM", "DISABLE_PROTOCOL", "UPGRADE_COMPONENT"])
    twin_sim.add_argument("--key-size", type=int, default=None)
    twin_sim.add_argument("--label", default=None)
    twin_sim.add_argument("--save", action="store_true",
                          help="store the result, quarantined: never counted as estate state")
    twin_sim.add_argument("--tenant", default=None)
    twin_sim.add_argument("--json", action="store_true")

    twin_assets = twin_sub.add_parser(
        "assets",
        help="browse the durable asset catalogue (across observations, including stale rows)",
    )
    twin_assets.add_argument("--type", dest="asset_type", default=None)
    twin_assets.add_argument("--environment", default=None)
    twin_assets.add_argument("--owner", default=None)
    twin_assets.add_argument("--lifecycle", default=None, help="ACTIVE | STALE")
    twin_assets.add_argument("--q", default=None)
    twin_assets.add_argument("--limit", type=int, default=50)
    twin_assets.add_argument("--tenant", default=None)
    twin_assets.add_argument("--json", action="store_true")

    twin_asset = twin_sub.add_parser("asset", help="everything the catalogue knows about one asset")
    twin_asset.add_argument("identifier")
    twin_asset.add_argument("--tenant", default=None)
    twin_asset.add_argument("--json", action="store_true")

    twin_algorithms = twin_sub.add_parser(
        "algorithms",
        help="who uses which algorithm, per usage state (capability is not use)",
    )
    twin_algorithms.add_argument("--q", default=None, help="algorithm, protocol, curve or asset name")
    twin_algorithms.add_argument("--type", dest="asset_type", default=None)
    twin_algorithms.add_argument("--tenant", default=None)
    twin_algorithms.add_argument("--json", action="store_true")

    twin_history = twin_sub.add_parser(
        "history",
        help="what an asset's facts said over time, current value first (needs the catalogue)",
    )
    twin_history.add_argument("identifier", help="asset id or exact name")
    twin_history.add_argument("--tenant", default=None)
    twin_history.add_argument("--json", action="store_true")

    twin_why = twin_sub.add_parser(
        "why",
        help="why the twin believes a fact, and where the evidence for it stops",
    )
    twin_why.add_argument("identifier", help="asset id or exact name")
    twin_why.add_argument("--fact", required=True,
                          help="fact type, e.g. environment, attribute:region, crypto:algorithm")
    twin_why.add_argument("--tenant", default=None)
    twin_why.add_argument("--json", action="store_true")

    twin_evidence = twin_sub.add_parser(
        "evidence",
        help="stored evidence records: collector, source, confidence, age",
    )
    twin_evidence.add_argument("--target", default=None, help="asset id or collector target")
    twin_evidence.add_argument("--type", dest="evidence_type", default=None,
                               help="OBSERVED | CONFIGURED | INFERRED | ...")
    twin_evidence.add_argument("--limit", type=int, default=50)
    twin_evidence.add_argument("--tenant", default=None)
    twin_evidence.add_argument("--json", action="store_true")

    twin_conflicts = twin_sub.add_parser(
        "conflicts",
        help="every disagreement the twin is holding, classified and never resolved",
    )
    twin_conflicts.add_argument("--tenant", default=None)
    twin_conflicts.add_argument("--json", action="store_true")

    twin_lifecycle = twin_sub.add_parser(
        "lifecycle",
        help="which phases of the twin's loop are running, and where it breaks",
    )
    twin_lifecycle.add_argument("--tenant", default=None)
    twin_lifecycle.add_argument("--json", action="store_true")

    twin_intel = twin_sub.add_parser(
        "intel",
        help="weak, unidentified and post-quantum cryptography across the estate",
    )
    twin_intel.add_argument("--tenant", default=None)
    twin_intel.add_argument("--limit", type=int, default=50)
    twin_intel.add_argument("--json", action="store_true")

    twin_algorithm = twin_sub.add_parser(
        "algorithm",
        help="everything the estate holds about one algorithm, in use and capability apart",
    )
    twin_algorithm.add_argument("name")
    twin_algorithm.add_argument("--tenant", default=None)
    twin_algorithm.add_argument("--limit", type=int, default=50)
    twin_algorithm.add_argument("--json", action="store_true")

    twin_trust = twin_sub.add_parser(
        "trust-paths",
        help="certificate chains as the evidence describes them, and where each one stops",
    )
    twin_trust.add_argument("--tenant", default=None)
    twin_trust.add_argument("--limit", type=int, default=50)
    twin_trust.add_argument("--json", action="store_true")

    twin_search = twin_sub.add_parser(
        "search",
        help="search assets, artefacts, edges, evidence, facts and changes in one call",
    )
    twin_search.add_argument("query", help="asset, algorithm, collector, region, change…")
    twin_search.add_argument("--kind", dest="kinds", action="append",
                             help="ASSETS | CRYPTO | RELATIONSHIPS | EVIDENCE | FACTS | CHANGES (repeatable)")
    twin_search.add_argument("--limit", type=int, default=10)
    twin_search.add_argument("--tenant", default=None)
    twin_search.add_argument("--json", action="store_true")

    twin_placement = twin_sub.add_parser(
        "placement",
        help="where everything belongs: bank -> region -> data centre -> cloud -> environment",
    )
    twin_placement.add_argument("--tenant", default=None)
    twin_placement.add_argument("--json", action="store_true")

    twin_changes = twin_sub.add_parser(
        "changes",
        help="what changed between observations (the live change feed)",
    )
    twin_changes.add_argument("--severity", default=None, help="CRITICAL | WARNING | INFO | BASELINE")
    twin_changes.add_argument("--kind", default=None, help="e.g. CRYPTO_DEMOTED, ASSET_ADDED")
    twin_changes.add_argument("--unacknowledged", action="store_true", help="only entries nobody has seen")
    twin_changes.add_argument("--limit", type=int, default=50)
    twin_changes.add_argument("--tenant", default=None)
    twin_changes.add_argument("--json", action="store_true")

    twin_detect = twin_sub.add_parser(
        "detect",
        help="compare the two newest observations now and record what moved",
    )
    twin_detect.add_argument("--tenant", default=None)
    twin_detect.add_argument("--json", action="store_true")

    twin_ack = twin_sub.add_parser("ack", help="mark a detected change as seen")
    twin_ack.add_argument("identifier", help="change event id")
    twin_ack.add_argument("--note", default=None)
    twin_ack.add_argument("--tenant", default=None)
    twin_ack.add_argument("--json", action="store_true")

    twin_sims = twin_sub.add_parser("simulations", help="list stored simulations (quarantined)")
    twin_sims.add_argument("--tenant", default=None)
    twin_sims.add_argument("--limit", type=int, default=20)
    twin_sims.add_argument("--json", action="store_true")

    _register_remote_commands(sub, twin_sub)

    boms = sub.add_parser("boms", help="print the six BOMs of the latest stored run")
    boms.add_argument("--tenant", default=None)
    boms.add_argument("--bom", default=None, help="print one BOM (SBOM|CBOM|HBOM|NBOM|VBOM|TECHBOM)")
    boms.add_argument("--json", action="store_true")

    return parser


def _session(session_factory: Callable[[], Any] | None = None) -> Any:
    """Open a session against the same database the API uses."""
    if session_factory is not None:
        return session_factory()
    from db.connection.session import SessionLocal, configure_session, init_db

    init_db()
    configure_session()
    return SessionLocal()


def _print_coverage(report: dict[str, Any]) -> None:
    coverage = report.get("coverage") or {}
    summary = coverage.get("summary") or {}
    expected = summary.get("expected") or 0
    if not expected:
        # printing "None%" invites reading an empty store as a finished scan
        print("coverage   NOT_OBSERVED — 0 expected targets: an empty store is not an empty estate")
    else:
        print(f"coverage   {summary.get('coverage_percent')}% of {expected} expected targets "
              f"({summary.get('collected')} attempted)")
    header = f"  {'plane':<12} {'expected':>8} {'collected':>9}  status"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for row in coverage.get("targets") or []:
        print(f"  {row['target']:<12} {row['expected']:>8} {row['collected']:>9}  {row['status']}")
        detail = row.get("reason") or row.get("impact")
        if detail and row["status"] != "COMPLETE":
            print(f"    └─ {detail}")


def _print_change(report: dict[str, Any]) -> None:
    """Say what moved since the previous run — or say that nothing did."""
    change = report.get("change") or {}
    severity = change.get("severity")
    if not severity:
        return
    headline = change.get("headline") or ""
    print(f"change     {severity}  {headline}")
    if change.get("next_action"):
        print(f"  next: {change['next_action']}")
    if severity == "NO_BASELINE":
        print("  (first stored run: this becomes the comparison baseline)")


def _print_summary(report: dict[str, Any]) -> None:
    summary = report.get("summary") or {}
    print(f"estate     {report.get('estate')} (scope {report.get('scope')})")
    print(f"projection {report.get('projection_id')}   run {report.get('run_id')}")
    print(f"assets     {summary.get('assets')}   evidence {summary.get('evidence')}   "
          f"relationships {summary.get('relationships')}")
    workflow = report.get("unknown_workflow") or {}
    print(f"open work  {workflow.get('open_work')}   "
          f"(unknown assets {workflow.get('by_state', {}).get('UNKNOWN_UNRESOLVED', 0)})")
    counts = report.get("bom_counts") or {}
    if counts:
        print("BOMs       " + "  ".join(f"{kind}:{count}" for kind, count in sorted(counts.items())))
    pqc = report.get("pqc") or {}
    for layer, bucket in sorted((pqc.get("layers") or {}).items()):
        print(f"pqc        {layer:<18} {bucket.get('readiness')}")


def _verdict_exit_code(report: dict[str, Any], allow_partial: bool, *, quiet: bool = False) -> int:
    """Exit code for a verdict; ``quiet`` keeps ``--json`` output parseable."""
    verdict = report.get("verdict")
    if verdict == "COMPLETE" or allow_partial:
        return EXIT_OK
    return EXIT_INCOMPLETE


def _print_verdict(report: dict[str, Any], allow_partial: bool) -> int:
    verdict = report.get("verdict")
    print(f"verdict    {verdict}")
    if verdict != "COMPLETE":
        print(f"  {report.get('verdict_detail')}")
        if report.get("failed_planes"):
            print("  failed planes: " + ", ".join(report["failed_planes"]))
        if allow_partial:
            print("  --allow-partial: exiting 0 anyway; the stored run still records incomplete coverage")
            return EXIT_OK
        print("  an incomplete estate is NOT_OBSERVED, not a clean scan — pass --allow-partial to accept it")
        return EXIT_INCOMPLETE
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace, session_factory: Callable[[], Any] | None) -> int:
    if _remote_scan_requested(args):
        from api import cli_remote

        return cli_remote.scan_remote(args, session_factory)
    from api import estate_discovery
    from db.tenancy import tenant_scope

    session = _session(session_factory)
    try:
        with tenant_scope(args.tenant):
            report = estate_discovery.run(
                session,
                estate=args.estate,
                scope=args.scope,
                planes=args.planes or DEFAULT_PLANES,
                persist=not args.no_persist,
                include_boms=not args.no_boms,
                previous=(estate_discovery.previous_report(session, tenant_id=args.tenant)
                          if not args.no_persist else None),
            )
    finally:
        close = getattr(session, "close", None)
        if callable(close):
            close()

    if args.json:
        # one document on stdout so `cryptoscan scan --json | jq` works
        print(json.dumps(report, indent=2, default=str))
        return _verdict_exit_code(report, args.allow_partial, quiet=True)
    else:
        _print_summary(report)
        _print_change(report)
        _print_coverage(report)
        for collector in report.get("collectors") or []:
            if collector["status"] in {"FAILED", "NOT_ATTEMPTED", "PARTIAL"}:
                print(f"  {collector['plane']:<12} {collector['status']:<12} {collector.get('impact') or ''}")
    return _print_verdict(report, args.allow_partial)


def _latest_report(session: Any) -> dict[str, Any] | None:
    from db import tenancy
    from shared_models.estate_graph import build_graph

    from db.repositories.scan_run_repository import ScanRunRepository

    runs = ScanRunRepository(session).list_runs(limit=1, target_kind="estate-discovery",
                                                owner=tenancy.current_tenant())
    if not runs:
        return None
    payload = (runs[0].result or {}).get("estate_discovery") or {}
    graph = build_graph(payload)
    projections = graph.project_all()
    return {
        "run_id": runs[0].id,
        "estate": payload.get("estate"),
        "scope": payload.get("scope"),
        "projection_id": graph.fingerprint(),
        "summary": graph.summary(),
        "coverage": graph.coverage(),
        "unknown_workflow": graph.unknown_workflow(),
        "pqc": graph.pqc_readiness(),
        "collectors": payload.get("collectors") or [],
        "boms": projections["boms"],
        "bom_counts": projections["counts"],
    }


def _cmd_coverage(args: argparse.Namespace, session_factory: Callable[[], Any] | None) -> int:
    from db.tenancy import tenant_scope

    session = _session(session_factory)
    try:
        with tenant_scope(args.tenant):
            report = _latest_report(session)
    finally:
        close = getattr(session, "close", None)
        if callable(close):
            close()
    if report is None:
        print("no estate discovery has been stored — run: cryptoscan scan --scope production")
        return EXIT_INCOMPLETE
    if args.json:
        print(json.dumps({"run_id": report["run_id"], **report["coverage"]}, indent=2, default=str))
    else:
        _print_coverage(report)
    return EXIT_OK


def _cmd_boms(args: argparse.Namespace, session_factory: Callable[[], Any] | None) -> int:
    from db.tenancy import tenant_scope

    session = _session(session_factory)
    try:
        with tenant_scope(args.tenant):
            report = _latest_report(session)
    finally:
        close = getattr(session, "close", None)
        if callable(close):
            close()
    if report is None:
        print("no estate discovery has been stored — run: cryptoscan scan --scope production")
        return EXIT_INCOMPLETE
    if args.bom:
        kind = args.bom.upper()
        bom = (report.get("boms") or {}).get(kind)
        if bom is None:
            print(f"unknown BOM {args.bom!r} — expected one of {', '.join(sorted(report.get('boms') or {}))}")
            return EXIT_ERROR
        print(json.dumps(bom, indent=2, default=str))
        return EXIT_OK
    if args.json:
        print(json.dumps({"run_id": report["run_id"], "projection_id": report["projection_id"],
                          "boms": report["boms"], "counts": report["bom_counts"]}, indent=2, default=str))
        return EXIT_OK
    print(f"projection {report['projection_id']} (run {report['run_id']})")
    for kind, count in sorted((report.get("bom_counts") or {}).items()):
        print(f"  {kind:<8} {count:>5} components")
    return EXIT_OK


def _collect_boundary_notice() -> None:
    """Say, on every local collection, that this process is the collector.

    ``collect`` is the one operation the CLI can still perform itself, which is a deviation
    from "the CLI is not the scanner". Printing it every time is the difference between a
    documented exception and a silent one.
    """
    print(
        "boundary: collecting from THIS process (single-node mode). The supported bank "
        "deployment submits work instead: cryptoscan collect --submit --server <control-plane>",
        file=sys.stderr,
    )


def _cmd_collect(args: argparse.Namespace, session_factory: Callable[[], Any] | None) -> int:
    """Collect evidence (bounded by the approved scope), then project the estate.

    Both halves run in one process against one database, which is the point: an
    operator does not have to remember that observation and projection are two
    steps, and the estate job reads the evidence this run just stored.

    ``--submit`` is the bank-deployment shape: the control plane collects, this process
    only asks. Whichever path runs, the boundary is printed rather than assumed.
    """
    if getattr(args, "submit", False):
        from api import cli_remote

        return cli_remote.collect_remote(args, session_factory)
    _collect_boundary_notice()
    from api import estate_discovery
    from api.network_collect import CollectRefused, collect_network
    from db.tenancy import tenant_scope

    endpoints = [item.strip() for item in str(args.endpoints or "").split(",") if item.strip()]
    session = _session(session_factory)
    try:
        with tenant_scope(args.tenant):
            try:
                result = collect_network(
                    session,
                    endpoints=endpoints,
                    protocol=args.protocol,
                    timeout=args.timeout,
                    inventory_id=args.inventory,
                    scan_versions=args.versions,
                    scan_ciphers=args.ciphers,
                    user="cryptoscan-cli",
                )
            except CollectRefused as exc:
                print(f"refused    {exc.code}: {exc.reason}")
                print("           nothing was collected — the approved scope decides what may be probed")
                return EXIT_REFUSED

            payload: dict[str, Any] = {"collection": result}
            if args.json:
                if args.no_estate:
                    print(json.dumps(result, indent=2, default=str))
                    return EXIT_OK
            else:
                summary = result.get("summary") or {}
                scope_name = (result.get("scope") or {}).get("scope_name")
                print(f"collected  {len(result.get('evidence') or [])} endpoint records "
                      f"under scope {scope_name}")
                observed = int(summary.get("observed") or 0)
                unknown = int(summary.get("records") or 0) - observed
                print(f"tls        {observed} observed, {unknown} not observed (a refused handshake is "
                      f"UNKNOWN, never safe)")
                print(f"run        {result['run_id']}")

            if args.no_estate:
                return EXIT_OK
            report = estate_discovery.run(session, scope=args.scope)
            if args.json:
                payload["estate"] = {
                    "verdict": report.get("verdict"),
                    "verdict_detail": report.get("verdict_detail"),
                    "coverage": report.get("coverage"),
                    "bom_counts": report.get("bom_counts"),
                    "collectors": report.get("collectors"),
                }
                print(json.dumps(payload, indent=2, default=str))
                return _verdict_exit_code(report, args.allow_partial, quiet=True)
            _print_coverage(report)
            return _print_verdict(report, args.allow_partial)
    finally:
        close = getattr(session, "close", None)
        if callable(close):
            close()


def _cmd_schedule(args: argparse.Namespace, session_factory: Callable[[], Any] | None) -> int:
    """Manage saved cadences. A schedule is a row, not an entry in someone's crontab."""
    from api import estate_schedule
    from db.tenancy import tenant_scope

    session = _session(session_factory)
    try:
        with tenant_scope(args.tenant):
            action = args.schedule_command
            try:
                if action == "add":
                    row = estate_schedule.create_schedule(
                        session,
                        name=args.name,
                        tenant_id=args.tenant,
                        scope=args.scope,
                        estate=args.estate,
                        every=args.every,
                        cron=args.cron,
                        planes=args.planes,
                        enabled=not args.disabled,
                        user="cryptoscan-cli",
                    )
                    payload = estate_schedule.as_dict(row)
                    if args.json:
                        print(json.dumps(payload, indent=2, default=str))
                    else:
                        cadence = payload["cadence"]
                        shown = (f"every {cadence['every']}" if "every" in cadence
                                 else f"cron {cadence['cron']} (UTC)")
                        print(f"saved      {payload['name']} — {shown}, "
                              f"{'enabled' if payload['enabled'] else 'paused'}")
                        print(f"next run   {payload['next_run_at']}")
                    return EXIT_OK
                if action == "list":
                    rows = [estate_schedule.as_dict(row) for row in
                            estate_schedule.list_schedules(session, tenant_id=args.tenant)]
                    if args.json:
                        print(json.dumps({"schedules": rows}, indent=2, default=str))
                        return EXIT_OK
                    if not rows:
                        print("no schedules saved — add a persisted-evidence projection: cryptoscan schedule add nightly --every 6h --plane STATIC")
                        return EXIT_OK
                    print(f"  {'name':<20} {'state':<8} {'next run':<26} last verdict")
                    print("  " + "-" * 78)
                    for row in rows:
                        state = "enabled" if row["enabled"] else "paused"
                        last = row["last_run"]["verdict"] or "never run"
                        print(f"  {row['name']:<20} {state:<8} {row['next_run_at'] or '-':<26} {last}")
                    return EXIT_OK
                if action == "remove":
                    removed = estate_schedule.delete_schedule(session, args.identifier,
                                                              tenant_id=args.tenant)
                    print(f"removed    {args.identifier} ({removed})")
                    return EXIT_OK
                if action in {"enable", "disable"}:
                    row = estate_schedule.set_enabled(session, args.identifier, action == "enable",
                                                      tenant_id=args.tenant)
                    payload = estate_schedule.as_dict(row)
                    state = "enabled" if action == "enable" else "paused"
                    print(f"{state:<10} {payload['name']} — next run {payload['next_run_at']}")
                    return EXIT_OK
            except estate_schedule.ScheduleError as exc:
                print(f"refused    {exc.code}: {exc.reason}")
                return EXIT_REFUSED
            print(f"unknown schedule command {action!r}")
            return EXIT_ERROR
    finally:
        close = getattr(session, "close", None)
        if callable(close):
            close()


def _cmd_tick(args: argparse.Namespace, session_factory: Callable[[], Any] | None) -> int:
    """Run what is due. Safe from cron(8) or a sidecar: the lease prevents doubles."""
    from api import estate_schedule
    from db.tenancy import tenant_scope

    session = _session(session_factory)
    try:
        with tenant_scope(args.tenant):
            result = estate_schedule.tick(
                session,
                worker=args.worker,
                lease_seconds=args.lease_seconds,
                limit=args.limit,
                tenant_id=args.tenant,
                exact_tenant=args.tenant is not None,
            )
            if args.json:
                print(json.dumps(result, indent=2, default=str))
            elif not result["ran"]:
                print("idle       nothing was due (a schedule that another worker holds is not due here)")
            else:
                print(f"ran        {len(result['ran'])} schedule(s) as {result['worker']}")
                for item in result["ran"]:
                    if item["status"] == "OK":
                        print(f"  {item['schedule']:<20} {item['verdict']:<18} "
                              f"coverage {item.get('coverage_state')}  run {item.get('run_id')}")
                    else:
                        print(f"  {item['schedule']:<20} ERROR  {item.get('error')}")
            return EXIT_OK if all(item["status"] == "OK" for item in result["ran"]) else EXIT_INCOMPLETE
    finally:
        close = getattr(session, "close", None)
        if callable(close):
            close()


def _cmd_serve(args: argparse.Namespace, session_factory: Callable[[], Any] | None) -> int:
    """Run the estate loop until stopped — the difference between a demo and a service."""
    import signal

    from api.estate_daemon import EstateDaemon
    from api.estate_events import bus_publisher
    from db.tenancy import current_tenant, tenant_scope

    def factory() -> Any:
        return _session(session_factory)

    def publish_estate_event(event_type, payload):
        bus_publisher(tenant_id=current_tenant())(event_type, payload)

    publisher = None if args.no_events else publish_estate_event
    daemon = EstateDaemon(
        factory,
        worker=args.worker,
        poll_seconds=args.poll,
        lease_seconds=args.lease_seconds,
        limit=args.limit,
        publisher=publisher,
    )

    previous = {}
    for name in ("SIGTERM", "SIGINT"):
        signum = getattr(signal, name, None)
        if signum is None:  # pragma: no cover - Windows
            continue
        try:
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, daemon.stop)
        except (ValueError, OSError):  # pragma: no cover - not the main thread
            pass

    cycles = 1 if args.once else args.max_cycles
    try:
        with tenant_scope(args.tenant):
            if args.once:
                # a single cycle still writes the heartbeat, so a cron-driven
                # deployment is visible to the same liveness probe as the daemon
                cycle = daemon.run_cycle()
                result = {"model": "cryptoscan.estate-daemon/1", "mode": "once", **cycle,
                          "heartbeat": daemon.heartbeat(state="STOPPED")}
            else:
                result = daemon.run_forever(max_cycles=cycles)
    finally:
        for signum, handler in previous.items():
            try:
                signal.signal(signum, handler)
            except (ValueError, OSError):  # pragma: no cover
                pass

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    elif args.once:
        print(f"cycle      claimed {result.get('claimed', 0)} schedule(s); "
              f"next wake {result.get('next_wake_at') or 'unscheduled'}")
        for item in result.get("ran") or []:
            print(f"  {item['schedule']:<20} {item['status']:<6} {item.get('verdict') or item.get('error')}")
        if not result.get("ran"):
            print(f"  idle — {daemon.idle_reason}")
    else:
        print(f"stopped    {result.get('cycles')} cycle(s), {result.get('runs')} run(s), "
              f"{result.get('failures')} failed cycle(s)")
        if result.get("last_error"):
            print(f"  last error: {result['last_error']}")
    # a failed *run* is as incomplete as a failed cycle: exiting 0 here would tell
    # a supervisor the cycle was fine while a schedule produced nothing
    failed_runs = int(result.get("failed_runs") or 0) + sum(
        1 for item in (result.get("ran") or []) if item.get("status") != "OK"
    )
    failed_cycles = int(result.get("failures") or 0)
    return EXIT_OK if (failed_cycles + failed_runs) == 0 else EXIT_INCOMPLETE



def _cmd_twin(args: argparse.Namespace, session_factory: Callable[[], Any] | None) -> int:
    """Graph-store load, simulation and simulation history (spec 94 §17, §20)."""
    if getattr(args, "twin_command", None) in REMOTE_TWIN_COMMANDS:
        from api import cli_remote

        return cli_remote.twin_remote(args, session_factory)
    from api import (
        estate_catalog,
        estate_change_feed,
        estate_conflicts,
        estate_crypto_intel,
        estate_lifecycle,
        estate_trust,
        estate_graph_loader,
        estate_observations,
        estate_search,
        estate_simulation_store,
    )
    from api.estate_twin_graph import latest_twin_graph
    from db.repositories.scan_run_repository import ScanRunRepository
    from db.tenancy import current_tenant, tenant_scope
    from shared_models import estate_twin
    from shared_models.estate_graph import build_graph

    session = _session(session_factory)
    try:
        with tenant_scope(getattr(args, "tenant", None)):


            if args.twin_command == "assets":
                rows = estate_catalog.list_assets(
                    session,
                    tenant_id=args.tenant,
                    asset_type=args.asset_type,
                    environment=args.environment,
                    owner=args.owner,
                    lifecycle=args.lifecycle,
                    q=args.q,
                    limit=args.limit,
                )
                if args.json:
                    print(json.dumps(
                        {"count": len(rows), "assets": [estate_catalog.public_asset(r) for r in rows]},
                        indent=2, default=str))
                elif not rows:
                    print("no catalogue records match — that is not 'the bank has no assets'.")
                    print("  the catalogue holds what has been observed; run `cryptoscan scan` first")
                else:
                    for row in rows:
                        print(f"  {row.asset_type:<16} {row.name:<32} {row.lifecycle_state:<6} "
                              f"seen {row.observation_count}×  {row.environment or ''}")
                        print(f"    {row.asset_id}  ev={row.evidence_count}  owner={row.owner or '—'}")
                return EXIT_OK

            if args.twin_command == "asset":
                detail = estate_catalog.asset_detail(session, args.identifier, tenant_id=args.tenant)
                if detail is None:
                    print(
                        f"no catalogue record for {args.identifier!r} — it may simply never have been "
                        "observed",
                        file=sys.stderr,
                    )
                    return EXIT_INCOMPLETE
                if args.json:
                    print(json.dumps(detail, indent=2, default=str))
                else:
                    asset = detail["asset"]
                    print(f"{asset['name']}  ({asset['asset_type']})")
                    print(f"  id          {asset['asset_id']}")
                    print(f"  lifecycle   {asset['lifecycle_state']} — seen {asset['observation_count']}×, "
                          f"first {asset['first_seen_at']}, last {asset['last_seen_at']}")
                    print(f"  owner       {asset['owner'] or '—'}")
                    print(f"  evidence    {asset['evidence_count']} record(s)")
                    for item in detail["crypto"]:
                        label = item["algorithm"] or item["protocol"] or item["curve"] or "?"
                        print(f"  crypto      {label:<20} {item['usage_state']:<12} {item['layer'] or ''}")
                    for edge in detail["relationships"]:
                        print(f"  edge        {edge['predicate']:<16} → {edge['object_name'] or edge['object_id']}"
                              f"  (basis {edge['basis']})")
                    for edge in detail["unresolved_candidates"]:
                        print(f"  candidate   {edge['predicate']:<16} → {edge['object_name'] or edge['object_id']}"
                              f"  REFUSED: {edge['reason']}")
                return EXIT_OK

            if args.twin_command == "algorithms":
                body = estate_catalog.registry(
                    session, tenant_id=args.tenant, query=args.q, asset_type=args.asset_type
                )
                if args.json:
                    print(json.dumps(body, indent=2, default=str))
                elif not body["algorithms"]:
                    print("no cryptographic artefacts recorded yet — nothing has been observed")
                else:
                    for entry in body["algorithms"][:30]:
                        states = ", ".join(f"{state} {count}" for state, count in sorted(entry["usage_states"].items()))
                        print(f"  {entry['algorithm']:<18} {entry['asset_count']:>3} asset(s)  [{states}]")
                        for item in entry["assets"][:4]:
                            print(f"      {item['asset_type']:<14} {item['asset_name']}  ({item['usage_state']})")
                    print(f"\n{body['meaning']}")
                return EXIT_OK

            if args.twin_command == "conflicts":
                graph_for_conflicts = latest_twin_graph(session, args.tenant)
                body = estate_conflicts.survey(
                    session, graph_for_conflicts, tenant_id=args.tenant
                )
                if args.json:
                    print(json.dumps(body, indent=2, default=str))
                elif not body["count"]:
                    print("no conflict in what has been observed — which is not a statement that "
                          "the bank's sources agree")
                else:
                    print(f"{body['count']} conflict(s): {body['real_count']} real, "
                          f"{body['explained_count']} explained, "
                          f"{body['by_classification']['UNKNOWN']} unclassified")
                    for item in body["conflicts"][:20]:
                        name = item.get("asset_name") or item["asset_id"]
                        print(f"  {'!' if item['classification'] == 'REAL' else ' '} "
                              f"{name} · {item['field']} · {item['classification']}")
                        for value in item["values"][:4]:
                            print(f"      {value['value']!r} from {value['source']} "
                                  f"({value['evidence_type']}, {value['layer']})")
                        print(f"      {item['reason']}")
                return EXIT_OK

            if args.twin_command == "intel":
                current = latest_twin_graph(session, args.tenant)
                if current is None:
                    print("no stored estate discovery — the twin is NOT_OBSERVED, so there is "
                          "no cryptography to read. That is not a clean answer.", file=sys.stderr)
                    return EXIT_INCOMPLETE
                body = estate_crypto_intel.survey(current, limit=args.limit)
                if args.json:
                    print(json.dumps(body, indent=2, default=str))
                else:
                    weak = body["weak"]
                    unknown = body["unknown"]
                    pqc = body["pqc"]
                    print(f"{body['artifacts_examined']} crypto artefact(s) examined")
                    print(f"  weak      {weak['count']} ({weak['in_use_count']} in use, "
                          f"{weak['capability_only_count']} capability only)")
                    for item in weak["entries"][:10]:
                        mark = "!" if item["in_use"] else " "
                        name = item.get("asset_name") or item["asset_id"]
                        print(f"  {mark} {name} · {item['algorithm']} · {item['status']} · "
                              f"{item['usage_state']} · {item['layer']}")
                    print(f"  unknown   {unknown['count']} "
                          f"({unknown['unrecognised_count']} unrecognised, "
                          f"{unknown['mislabelled_count']} version strings in an algorithm fact)")
                    print(f"  post-quantum {pqc['vulnerable_artifacts']} artefact(s) on Shor-broken "
                          f"algorithms, {pqc['pending_migration_count']} in use, "
                          f"{pqc['vendor_bound_blocker_count']} vendor-bound blocker(s)")
                    print()
                    print(body["next_action"])
                return EXIT_OK

            if args.twin_command == "algorithm":
                current = latest_twin_graph(session, args.tenant)
                if current is None:
                    print("no stored estate discovery — nothing can be said about this "
                          "algorithm, which is not the same as 'nothing uses it'.",
                          file=sys.stderr)
                    return EXIT_INCOMPLETE
                body = estate_crypto_intel.algorithm(current, args.name, limit=args.limit)
                if args.json:
                    print(json.dumps(body, indent=2, default=str))
                else:
                    if not body["found"]:
                        print(f"no observation asserts {body['query']!r} — not a statement that "
                              "the estate does not use it")
                    else:
                        print(f"{body['algorithm']} · {body['status']} · "
                              f"{body['artifacts']} artefact(s): {body['in_use']} in use, "
                              f"{body['capability_only']} capability only")
                        for asset_type, count in body["by_asset_type"].items():
                            print(f"  {asset_type:<18} {count}")
                        for asset in body["assets"][:10]:
                            print(f"    {asset['asset_name'] or asset['asset_id']}: "
                                  f"{', '.join(asset['algorithms'])}")
                    if body.get("next_action"):
                        print()
                        print(body["next_action"])
                return EXIT_OK

            if args.twin_command == "trust-paths":
                current = latest_twin_graph(session, args.tenant)
                if current is None:
                    print("no stored estate discovery — no chain can be walked, which is not "
                          "an estate with no certificates.", file=sys.stderr)
                    return EXIT_INCOMPLETE
                body = estate_trust.survey(current, limit=args.limit)
                if args.json:
                    print(json.dumps(body, indent=2, default=str))
                else:
                    print(f"{body['count']} certificate chain(s), longest {body['longest_chain']} link(s)")
                    for status, count in body["by_status"].items():
                        print(f"  {status:<14} {count}")
                    for entry in body["chains"][:10]:
                        name = entry["asset_name"] or entry["asset_id"]
                        path = " -> ".join(
                            (step["asset_name"] or step["asset_id"] or "?")
                            + ("" if step["present"] else " (not collected)")
                            for step in entry["chain"]
                        )
                        print(f"  {name}: {entry['status']} · {path}")
                    if body["broken_count"] or body["unjudged_count"]:
                        print()
                        print("a broken chain usually means the authority was not collected — "
                              "it is not proof the certificate is untrusted")
                return EXIT_OK

            if args.twin_command == "lifecycle":
                body = estate_lifecycle.survey(
                    session, latest_twin_graph(session, args.tenant), tenant_id=args.tenant
                )
                if args.json:
                    print(json.dumps(body, indent=2, default=str))
                else:
                    for phase in body["phases"]:
                        print(f"  {phase['phase']:<12} {phase['status']:<14} {phase['question']}")
                        if phase["status"] != "CONNECTED":
                            print(f"      {phase['detail']}")
                    print()
                    if body["loop_closed"]:
                        print(body["meaning"])
                    else:
                        print(f"the loop does not close: it breaks first at "
                              f"{body['first_break']}. {body['meaning']}")
                return EXIT_OK

            if args.twin_command == "search":
                try:
                    result = estate_search.search(
                        session,
                        args.query,
                        tenant_id=args.tenant,
                        kinds=args.kinds,
                        limit=args.limit,
                    )
                except ValueError as exc:
                    print(f"search refused: {exc}", file=sys.stderr)
                    return EXIT_INCOMPLETE
                if args.json:
                    print(json.dumps(result, indent=2, default=str))
                else:
                    print(f"{result['matched']} match(es) for {result['query']!r}")
                    for name, group in result["groups"].items():
                        if not group["count"]:
                            continue
                        print(f"\n{name} — {group['count']}"
                              f"{' (truncated)' if group.get('truncated') else ''}")
                        for hit in group["hits"][:args.limit]:
                            print(f"  {hit['label'][:90]}")
                            if hit.get("usage_states"):
                                states = ", ".join(f"{state} {count}"
                                                   for state, count in sorted(hit["usage_states"].items()))
                                print(f"      {states}")
                    if not result["matched"]:
                        print("  nothing recorded matches — that is not evidence the bank has none")
                return EXIT_OK

            if args.twin_command == "history":
                detail = estate_observations.history(session, args.identifier, tenant_id=args.tenant)
                if args.json:
                    print(json.dumps(detail, indent=2, default=str))
                elif detail["fact_count"] == 0:
                    print(f"no recorded fact for {args.identifier!r} — not observed, or "
                          "catalogued before per-fact history existed", file=sys.stderr)
                else:
                    print(f"{args.identifier} · {detail['fact_count']} fact(s)")
                    for fact in detail["facts"]:
                        mark = {"CURRENT": " ", "HISTORICAL": "-", "CONFLICT": "!"}[fact["state"]]
                        current = ", ".join(fact["current_values"]) or "(no longer observed)"
                        print(f" {mark} {fact['fact_type']:<34} {current}")
                        for window in fact["timeline"]:
                            if window["state"] == "CURRENT":
                                continue
                            print(f"     was {window['value']!r} until "
                                  f"{window['last_seen_at'] or 'unknown'} "
                                  f"(seen {window['observation_count']}x)")
                    if detail["conflicted_facts"]:
                        print(f" disputes  {', '.join(detail['conflicted_facts'])} — "
                              "both values still asserted, nothing chosen")
                return EXIT_OK if detail["fact_count"] else EXIT_INCOMPLETE

            if args.twin_command == "why":
                answer = estate_observations.why(
                    session, args.identifier, args.fact, tenant_id=args.tenant
                )
                if answer is None:
                    print(
                        f"nothing to explain: no observation of {args.fact!r} for "
                        f"{args.identifier!r}. Absence of an explanation is not evidence "
                        "that the fact is false.",
                        file=sys.stderr,
                    )
                    return EXIT_INCOMPLETE
                if args.json:
                    print(json.dumps(answer, indent=2, default=str))
                else:
                    print(f"{answer['asset_name']} · {answer['fact_type']} · {answer['resolution']}")
                    print(f"  value      {', '.join(answer['current_values']) or '(not observed)'}")
                    for item in answer["observations"]:
                        print(f"  window     {item['value']!r} {item['state'].lower()} "
                              f"{item['first_seen_at']} → {item['last_seen_at']}")
                    for record in answer["evidence"]:
                        print(f"  evidence   {record['evidence_type']:<18} {record['collector']} "
                              f"via {record['source']} ({record['evidence_id']})")
                    print(f"  limit      {answer['limit']}")
                return EXIT_OK

            if args.twin_command == "evidence":
                rows = estate_observations.evidence_for(
                    session,
                    target=args.target,
                    evidence_type=args.evidence_type,
                    limit=args.limit,
                    tenant_id=args.tenant,
                )
                if args.json:
                    print(json.dumps(rows, indent=2, default=str))
                elif rows["count"] == 0:
                    print("no stored evidence — nothing has been observed and recorded yet",
                          file=sys.stderr)
                else:
                    print(f"{rows['count']} evidence record(s)")
                    for record in rows["records"]:
                        print(f"  {record['evidence_type']:<20} {record['collector'] or '-':<22} "
                              f"{record['observation_count']:>3}x  {record['evidence_id']}")
                return EXIT_OK if rows["count"] else EXIT_INCOMPLETE

            if args.twin_command in {
                "changes", "assets", "asset", "algorithms", "history", "why", "evidence", "search"
            }:
                # records of past observations: readable even when the current twin
                # cannot be rebuilt, and saying otherwise would hide the history
                # exactly when it matters
                graph = None
            elif args.twin_command == "ack":
                graph = None
            else:
                graph = latest_twin_graph(session, getattr(args, "tenant", None))
            if graph is None and args.twin_command not in {
                "changes", "ack", "detect", "assets", "asset", "algorithms",
                "history", "why", "evidence", "search", "conflicts", "lifecycle",
                "intel", "algorithm", "trust-paths", "graph-traversal",
            }:
                
                print(
                    "no stored estate discovery — the twin is NOT_OBSERVED, not empty. "
                    "Run `cryptoscan scan` or POST /estate/evidence/discover first.",
                    file=sys.stderr,
                )
                return EXIT_INCOMPLETE

            if args.twin_command == "placement":
                placement = estate_twin.placement_model(graph)
                if args.json:
                    print(json.dumps(placement, indent=2, default=str))
                else:
                    print(f"estate     {placement['bank']}")
                    print(f"levels     observed: {', '.join(placement['levels_observed'])}")
                    if placement["levels_unobserved"]:
                        print(f"           not observed: {', '.join(placement['levels_unobserved'])}")
                    for region in placement["regions"]:
                        print(f"  region   {region['name']:<20} {region['assets']} asset(s)")
                    for dc in placement["data_centers"]:
                        print(f"  dc       {dc['name']:<20} {dc['assets']} asset(s)")
                    for cloud in placement["cloud_environments"]:
                        print(f"  cloud    {cloud['name']:<20} {cloud['assets']} asset(s)")
                    for env in placement["environments"]:
                        print(f"  env      {env['name']:<20} {env['assets']} asset(s)")
                    if placement["unplaced_count"]:
                        print(f"  unplaced {placement['unplaced_count']} asset(s) with no environment "
                              "or site in any evidence")
                    for row in placement["unassigned"]:
                        print(f"  no {row['level'].lower():<17} {row['assets']} asset(s) — "
                              f"{row['reason'].split('.')[0]}")
                return EXIT_OK

            if args.twin_command == "graph-verify":
                export = estate_twin.graph_export(graph)
                driver = None
                try:
                    from graph_engine.connection.neo4j_driver import get_driver

                    driver = get_driver()
                except Exception:  # pragma: no cover - optional dependency
                    driver = None
                result = estate_graph_loader.parity(
                    export, driver=driver, database=args.database
                )
                if args.json:
                    print(json.dumps(result, indent=2, default=str))
                else:
                    print(f"store      {result['status']}")
                    print(f"expected   {result['expected']['nodes']} node(s), "
                          f"{result['expected']['relationships']} relationship(s)")
                    if result.get("store"):
                        printed = ", ".join(f"{label} {count}"
                                            for label, count in result["store"]["nodes"].items())
                        print(f"stored     {printed}")
                    for label, ids in result["missing"].items():
                        print(f"missing    {label}: {', '.join(ids[:5])}")
                    for label, ids in result["unexpected"].items():
                        print(f"extra      {label}: {', '.join(ids[:5])}")
                    for rel_type, diff in result["relationship_differences"].items():
                        print(f"differs    {rel_type}: expected {diff['expected']}, "
                              f"stored {diff['stored']}")
                    print(f"traversal  {result['traversal_parity']} — {result['traversal_note']}")
                    if result.get("note"):
                        print(f"  {result['note']}")
                    if result.get("error"):
                        print(f"  {result['error']}", file=sys.stderr)
                return EXIT_OK if result.get("ok") else EXIT_INCOMPLETE

            if args.twin_command == "graph-traversal":
                export = estate_twin.graph_export(graph)
                impact_result = estate_twin.impact(
                    graph, {"asset": args.asset}, depth=args.depth
                )
                driver = None
                try:
                    from graph_engine.connection.neo4j_driver import get_driver

                    driver = get_driver()
                except Exception:  # pragma: no cover - optional dependency
                    driver = None
                result = estate_graph_loader.traversal_parity(
                    export, impact_result, driver=driver, database=args.database
                )
                if args.json:
                    print(json.dumps(result, indent=2, default=str))
                else:
                    print(f"traversal  {result['status']} at depth {result['depth']}")
                    print(f"twin       {result['in_process']['count']} asset(s) reachable")
                    if result.get("store"):
                        print(f"store      {result['store']['count']} asset(s) reachable")
                    if result["only_in_twin"]:
                        print(f"only twin  {', '.join(result['only_in_twin'][:5])}")
                    if result["only_in_store"]:
                        print(f"only store {', '.join(result['only_in_store'][:5])}")
                    if result.get("note"):
                        print(f"  {result['note']}")
                return EXIT_OK if result.get("ok") else EXIT_INCOMPLETE

            if args.twin_command == "graph-load":
                export = estate_twin.graph_export(graph)
                driver = None
                if args.apply:
                    try:
                        from graph_engine.connection.neo4j_driver import get_driver

                        driver = get_driver()
                    except Exception:  # pragma: no cover - optional dependency
                        driver = None
                result = estate_graph_loader.load(
                    export,
                    driver=driver,
                    database=args.database,
                    batch_size=args.batch_size,
                    dry_run=not args.apply,
                    prune_missing=args.prune_missing,
                )
                if args.json:
                    print(json.dumps(result, indent=2, default=str))
                else:
                    print(f"export     {result['projection_id'][:16]} · estate {result['estate']}")
                    print(f"expected   {result['expected']['nodes']} node(s), "
                          f"{result['expected']['relationships']} relationship(s), "
                          f"{result['expected']['unresolved']} unresolved candidate(s)")
                    print(f"statements {result['statements']}")
                    if result["dry_run"]:
                        print("mode       DRY RUN — nothing was written (pass --apply to write)")
                    else:
                        print(f"verify     {result['verification']}"
                              + (f" {result['verified']}" if result.get("verified") else ""))
                        if result.get("error"):
                            print(f"  {result['error']}", file=sys.stderr)
                return EXIT_OK if result.get("ok", True) or result["dry_run"] else EXIT_INCOMPLETE

            if args.twin_command == "simulate":
                scenario = {
                    "kind": args.kind,
                    "from": args.source,
                    "to": args.target,
                    "key_size": args.key_size,
                    "label": args.label,
                }
                result = estate_twin.simulate(graph, scenario)
                if args.save and result.get("status") == "SIMULATED":
                    row, created = estate_simulation_store.record_simulation(
                        session, result, tenant_id=args.tenant, created_by="cli", label=args.label
                    )
                    result["simulation_record"] = estate_simulation_store.public_simulation(
                        row, current_projection_id=graph.fingerprint()
                    )
                    result["persisted"] = created or "already stored (observation counter advanced)"
                if args.json:
                    print(json.dumps(result, indent=2, default=str))
                elif result.get("status") != "SIMULATED":
                    print(f"simulation {result.get('status')} — {result.get('detail')}")
                else:
                    print(f"simulation {result['simulation_id']} · {result['kind']}")
                    print(f"  matched    {result['matched_evidence']} evidence record(s), "
                          f"{len(result.get('affected_assets') or [])} asset(s)")
                    print(f"  live twin  {'UNCHANGED' if result.get('live_projection_unchanged') else 'MODIFIED'}")
                    for kind, counts in (result.get("bom_diff") or {}).items():
                        if counts["counts"]["added"] or counts["counts"]["removed"] or counts["counts"]["changed"]:
                            print(f"  {kind:<9} +{counts['counts']['added']} -{counts['counts']['removed']} "
                                  f"~{counts['counts']['changed']}")
                    for blocker in (result.get("blockers") or [])[:5]:
                        print(f"  blocker    {blocker.get('kind')}: {blocker.get('detail')}")
                    if args.save:
                        print("  stored     quarantined — never counted as estate state")
                return EXIT_OK if result.get("status") == "SIMULATED" else EXIT_INCOMPLETE




            if args.twin_command == "placement":
                placement = estate_twin.placement_model(graph)
                if args.json:
                    print(json.dumps(placement, indent=2, default=str))
                else:
                    print(f"estate     {placement['bank']}")
                    print(f"levels     observed: {', '.join(placement['levels_observed'])}")
                    if placement["levels_unobserved"]:
                        print(f"           not observed: {', '.join(placement['levels_unobserved'])}")
                    for region in placement["regions"]:
                        print(f"  region   {region['name']:<20} {region['assets']} asset(s)")
                    for dc in placement["data_centers"]:
                        print(f"  dc       {dc['name']:<20} {dc['assets']} asset(s)")
                    for cloud in placement["cloud_environments"]:
                        print(f"  cloud    {cloud['name']:<20} {cloud['assets']} asset(s)")
                    for env in placement["environments"]:
                        print(f"  env      {env['name']:<20} {env['assets']} asset(s)")
                    if placement["unplaced_count"]:
                        print(f"  unplaced {placement['unplaced_count']} asset(s) with no environment "
                              "or site in any evidence")
                    for row in placement["unassigned"]:
                        print(f"  no {row['level'].lower():<17} {row['assets']} asset(s) — "
                              f"{row['reason'].split('.')[0]}")
                return EXIT_OK

            if args.twin_command == "assets":
                rows = estate_catalog.list_assets(
                    session,
                    tenant_id=args.tenant,
                    asset_type=args.asset_type,
                    environment=args.environment,
                    owner=args.owner,
                    lifecycle=args.lifecycle,
                    q=args.q,
                    limit=args.limit,
                )
                if args.json:
                    print(json.dumps(
                        {"count": len(rows), "assets": [estate_catalog.public_asset(r) for r in rows]},
                        indent=2, default=str))
                elif not rows:
                    print("no catalogue records match — that is not 'the bank has no assets'.")
                    print("  the catalogue holds what has been observed; run `cryptoscan scan` first")
                else:
                    for row in rows:
                        print(f"  {row.asset_type:<16} {row.name:<32} {row.lifecycle_state:<6} "
                              f"seen {row.observation_count}×  {row.environment or ''}")
                        print(f"    {row.asset_id}  ev={row.evidence_count}  owner={row.owner or '—'}")
                return EXIT_OK

            if args.twin_command == "asset":
                detail = estate_catalog.asset_detail(session, args.identifier, tenant_id=args.tenant)
                if detail is None:
                    print(
                        f"no catalogue record for {args.identifier!r} — it may simply never have been "
                        "observed",
                        file=sys.stderr,
                    )
                    return EXIT_INCOMPLETE
                if args.json:
                    print(json.dumps(detail, indent=2, default=str))
                else:
                    asset = detail["asset"]
                    print(f"{asset['name']}  ({asset['asset_type']})")
                    print(f"  id          {asset['asset_id']}")
                    print(f"  lifecycle   {asset['lifecycle_state']} — seen {asset['observation_count']}×, "
                          f"first {asset['first_seen_at']}, last {asset['last_seen_at']}")
                    print(f"  owner       {asset['owner'] or '—'}")
                    print(f"  evidence    {asset['evidence_count']} record(s)")
                    for item in detail["crypto"]:
                        label = item["algorithm"] or item["protocol"] or item["curve"] or "?"
                        print(f"  crypto      {label:<20} {item['usage_state']:<12} {item['layer'] or ''}")
                    for edge in detail["relationships"]:
                        print(f"  edge        {edge['predicate']:<16} → {edge['object_name'] or edge['object_id']}"
                              f"  (basis {edge['basis']})")
                    for edge in detail["unresolved_candidates"]:
                        print(f"  candidate   {edge['predicate']:<16} → {edge['object_name'] or edge['object_id']}"
                              f"  REFUSED: {edge['reason']}")
                return EXIT_OK

            if args.twin_command == "algorithms":
                body = estate_catalog.registry(
                    session, tenant_id=args.tenant, query=args.q, asset_type=args.asset_type
                )
                if args.json:
                    print(json.dumps(body, indent=2, default=str))
                elif not body["algorithms"]:
                    print("no cryptographic artefacts recorded yet — nothing has been observed")
                else:
                    for entry in body["algorithms"][:30]:
                        states = ", ".join(f"{state} {count}" for state, count in sorted(entry["usage_states"].items()))
                        print(f"  {entry['algorithm']:<18} {entry['asset_count']:>3} asset(s)  [{states}]")
                        for item in entry["assets"][:4]:
                            print(f"      {item['asset_type']:<14} {item['asset_name']}  ({item['usage_state']})")
                    print(f"\n{body['meaning']}")
                return EXIT_OK

            if args.twin_command == "changes":
                body = estate_change_feed.feed(
                    session,
                    tenant_id=args.tenant,
                    severity=args.severity,
                    kind=args.kind,
                    include_acknowledged=not args.unacknowledged,
                    limit=args.limit,
                )
                if args.json:
                    print(json.dumps(body, indent=2, default=str))
                elif not body["count"] and body.get("filtered"):
                    print("no change events match this filter — the feed is not empty, the filter is narrow")
                    print("  `cryptoscan twin changes` shows everything recorded")
                elif not body["count"]:
                    print("no changes recorded — nothing moved while the collectors were running.")
                    print("  an empty feed is not a safe estate: check the run history and coverage")
                else:
                    print(f"{body['count']} change event(s), {body['unacknowledged']} unacknowledged")
                    for event in body["events"]:
                        mark = "" if event["acknowledged"] else " *"
                        print(f"  {event['severity']:<8} {event['first_detected_at'] or '?':<26} "
                              f"{event['headline']}{mark}")
                        for change in (event["changes"] or [])[:6]:
                            before = "" if change.get("before") is None else f" {change['before']} →"
                            print(f"      {change['kind']:<24} {change['subject']}{before} "
                                  f"{change.get('after') if change.get('after') is not None else ''}")
                    if body["unacknowledged"]:
                        print("  * = not acknowledged: `cryptoscan twin ack <event_id>`")
                return EXIT_OK

            if args.twin_command == "detect":
                runs = ScanRunRepository(session).list_runs(
                    limit=2, target_kind="estate-discovery", owner=args.tenant or current_tenant()
                )
                if not runs:
                    print(
                        "nothing has been observed yet, so there is nothing to compare — run "
                        "`cryptoscan scan` first",
                        file=sys.stderr,
                    )
                    return EXIT_INCOMPLETE
                current = latest_twin_graph(session, args.tenant)
                previous = None
                if len(runs) > 1:
                    payload = (runs[1].result or {}).get("estate_discovery") or {}
                    previous = build_graph(payload)
                detection = estate_change_feed.observe(
                    session,
                    previous,
                    current,
                    tenant_id=args.tenant,
                    run_id=runs[0].id,
                    trigger="cli",
                    detected_by="cli",
                )
                recorded = detection.get("recorded") or {}
                if args.json:
                    print(json.dumps(detection, indent=2, default=str))
                else:
                    print(f"severity   {detection['severity']}")
                    print(f"verdict    {detection['verdict']}")
                    print(f"headline   {detection['headline']}")
                    for change in (detection["changes"] or [])[:12]:
                        print(f"  {change['kind']:<24} {change['detail']}")
                    if detection.get("next_action"):
                        print(f"  next: {detection['next_action']}")
                    if recorded.get("created"):
                        print(f"  recorded {recorded['event_id']}")
                    elif recorded.get("event_id"):
                        print(f"  already recorded as {recorded['event_id']}")
                    else:
                        print(f"  not recorded: {recorded.get('note') or recorded.get('error')}")
                    if detection.get("baseline_error"):
                        print(f"  baseline unknown: {detection['baseline_error']}")
                return EXIT_OK

            if args.twin_command == "ack":
                row = estate_change_feed.acknowledge(
                    session, args.identifier, tenant_id=args.tenant, user="cli", note=args.note
                )
                if row is None:
                    print(f"no change event {args.identifier!r} for this tenant", file=sys.stderr)
                    return EXIT_INCOMPLETE
                if args.json:
                    print(json.dumps(estate_change_feed.public_event(row), indent=2, default=str))
                else:
                    print(f"acknowledged {row.event_id} by {row.acknowledged_by} "
                          f"at {row.acknowledged_at} — findings unchanged")
                return EXIT_OK

            if args.twin_command == "simulations":
                rows = estate_simulation_store.list_simulations(session, tenant_id=args.tenant, limit=args.limit)
                payload = [
                    estate_simulation_store.public_simulation(row, current_projection_id=graph.fingerprint())
                    for row in rows
                ]
                if args.json:
                    print(json.dumps(
                        {"simulations": payload, "count": len(payload), **estate_simulation_store.QUARANTINE},
                        indent=2, default=str))
                elif not payload:
                    print("no stored simulations — nothing has been asked of a copy yet")
                else:
                    for entry in payload:
                        print(f"{entry['simulation_id']:<28} {entry['kind']:<20} "
                              f"{entry['freshness'].split(' —')[0]:<8} "
                              f"{len(entry['affected_assets'])} asset(s)  {entry['label'] or ''}")
                return EXIT_OK

        return EXIT_ERROR
    finally:
        close = getattr(session, "close", None)
        if callable(close):
            close()


def _register_remote_commands(sub, twin_sub) -> None:
    """Attach the control-plane commands (``api/cli_remote.py``) to this parser."""
    from api import cli_remote

    cli_remote.register_remote_commands(sub, twin_sub)


COMMANDS: dict[str, Callable[[argparse.Namespace, Callable[[], Any] | None], int]] = {
    "schedule": _cmd_schedule,
    "tick": _cmd_tick,
    "serve": _cmd_serve,
    "collect": _cmd_collect,
    "scan": _cmd_scan,
    "coverage": _cmd_coverage,
    "boms": _cmd_boms,
    "twin": _cmd_twin,
}

# The bank operator commands in main() are routed to cli_remote. In-process
# handlers remain for the server daemon and injected tests; their remaining twin
# subcommands must migrate before the installed CLI is API-only in every mode.
from api import cli_remote as _cli_remote  # noqa: E402  (after COMMANDS, to avoid a cycle)

COMMANDS.update(_cli_remote.COMMANDS)

#: remediation is a control-plane write, so it belongs here rather than in the in-process
#: handler: proposing work against a local database would be a queue nobody can see
REMOTE_TWIN_COMMANDS = frozenset({"status", "snapshot", "diff", "remediation", "remediate",
                                  "reconcile"})


def main(argv: Sequence[str] | None = None, session_factory: Callable[[], Any] | None = None) -> int:
    """Operator scan/collect commands use the in-bank API, never this terminal's collectors."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if session_factory is None and args.command == "scan":
        from api import cli_remote

        try:
            return cli_remote.scan_remote(args)
        except Exception as exc:  # noqa: BLE001 — a failed control-plane call is not a scan
            print(f"cryptoscan scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return EXIT_ERROR
    if session_factory is None and args.command == "collect" and not args.submit:
        print("refused: the operator CLI does not collect locally; use --submit with a registered, authorized target", file=sys.stderr)
        return EXIT_REFUSED
    if session_factory is None and args.command in {"schedule", "tick", "coverage", "boms"}:
        from api import cli_remote

        try:
            remote = {"schedule": cli_remote.schedule_remote, "tick": cli_remote.tick_remote,
                      "coverage": cli_remote.coverage_remote, "boms": cli_remote.boms_remote}
            return remote[args.command](args)
        except Exception as exc:  # noqa: BLE001 — never fall back to an operator-terminal database
            print(f"cryptoscan {args.command} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return EXIT_ERROR
    local_service = args.command == "serve" or (
        args.command == "twin" and args.twin_command not in REMOTE_TWIN_COMMANDS)
    if session_factory is None and local_service and not os.getenv("DATABASE_URL", "").startswith(
        ("postgresql://", "postgresql+psycopg2://", "postgresql+psycopg://")
    ):
        print(f"refused: {args.command} is a bank-server service operation; no explicit PostgreSQL estate is configured",
              file=sys.stderr)
        return EXIT_REFUSED
    handler = COMMANDS.get(args.command)
    if handler is None:
        parser.error(f"unknown command {args.command!r}")
        return EXIT_ERROR
    try:
        return handler(args, session_factory)
    except Exception as exc:  # noqa: BLE001 - a CLI must print the failure and exit non-zero
        print(f"cryptoscan {args.command} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
