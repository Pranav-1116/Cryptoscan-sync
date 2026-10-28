"""``cryptoscan`` CLI — the operator's entry point to the estate pipeline (spec 93 §18).

The directive opens with ``cryptoscan scan --scope production``: one command, one
estate-discovery job, six BOMs. Until now that pipeline existed only behind
``POST /estate/evidence/scan`` — fine for the console, useless for the operator
who runs it from a cron unit, a jump host or a change ticket.

This module is the real command, not a demo wrapper:

* it opens the **same database** the API uses (``init_db`` + ``configure_session``),
  so what it stores is what the console reads back;
* it runs the **same** ``api.estate_discovery.run`` job, so the CLI and the API
  cannot drift apart;
* it prints the coverage matrix, the collector verdicts, the unknown work and the
  six BOM counts, and it exits **non-zero** when coverage is incomplete — unless
  the operator explicitly passes ``--allow-partial``, which records the decision
  in the output instead of hiding it.

Exit codes: ``0`` coverage complete, ``2`` partial coverage (a plane failed, was
short-read, or had no adapter), ``1`` the job could not run at all.

Refusals that matter: there is no ``--force`` that turns a failed collector into a
pass, no ``--skip-planes`` that silently reports full coverage, and ``--json``
carries the same limitations the API returns.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable, Sequence

EXIT_OK = 0
EXIT_INCOMPLETE = 2
EXIT_ERROR = 1
EXIT_REFUSED = 3

DEFAULT_PLANES = None  # every plane


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptoscan",
        description="CryptoScan — one estate discovery, six BOM projections (spec 93)",
    )
    parser.add_argument("--version", action="version", version="cryptoscan 1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run one estate-discovery job and project the six BOMs")
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

    collect = sub.add_parser(
        "collect",
        help="collect crypto evidence inside the approved scope, then build the estate and the six BOMs",
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

    schedule = sub.add_parser("schedule", help="save, list, enable or remove scheduled estate runs")
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
    remove = schedule_sub.add_parser("remove", help="delete a schedule by name or id")
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


def _cmd_collect(args: argparse.Namespace, session_factory: Callable[[], Any] | None) -> int:
    """Collect evidence (bounded by the approved scope), then project the estate.

    Both halves run in one process against one database, which is the point: an
    operator does not have to remember that observation and projection are two
    steps, and the estate job reads the evidence this run just stored.
    """
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
                        print("no schedules saved — add one: cryptoscan schedule add nightly --every 6h")
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
    from db.tenancy import tenant_scope

    def factory() -> Any:
        return _session(session_factory)

    publisher = None if args.no_events else bus_publisher(tenant_id=args.tenant)
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


COMMANDS: dict[str, Callable[[argparse.Namespace, Callable[[], Any] | None], int]] = {
    "schedule": _cmd_schedule,
    "tick": _cmd_tick,
    "serve": _cmd_serve,
    "collect": _cmd_collect,
    "scan": _cmd_scan,
    "coverage": _cmd_coverage,
    "boms": _cmd_boms,
}


def main(argv: Sequence[str] | None = None, session_factory: Callable[[], Any] | None = None) -> int:
    """Entry point. ``session_factory`` exists for tests; production uses the real database."""
    parser = _build_parser()
    args = parser.parse_args(argv)
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
