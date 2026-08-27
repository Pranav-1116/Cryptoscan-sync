"""Runtime crypto discovery CLI.

Subcommands:
  tap       observing TLS forward proxy -> session records (JSONL)
  processes process-level crypto library scan of this host
  import    parse existing captures (openssl s_client / tap JSONL)
  once      process scan + optional submit to the platform API
"""

from __future__ import annotations

import argparse
import json
import sys


def _cmd_tap(args: argparse.Namespace) -> int:
    from runtime.agent.tls_tap import TLSTap
    from runtime.config.settings import load_settings

    settings = load_settings()
    upstream_host, _, upstream_port = args.upstream.rpartition(":")
    if not upstream_host or not upstream_port.isdigit():
        print("upstream must be host:port", file=sys.stderr)
        return 2
    jsonl = args.jsonl or settings.session_jsonl
    tap = TLSTap(upstream_host=upstream_host, upstream_port=int(upstream_port), session_jsonl=jsonl)
    port = tap.start(args.listen_host, args.listen_port)
    print(f"tls-tap listening on {args.listen_host}:{port} -> {upstream_host}:{upstream_port}")
    if jsonl:
        print(f"sessions appended to {jsonl}")
    try:
        import time

        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        tap.stop()
        print(json.dumps(tap.summary(), indent=2))
    return 0


def _cmd_processes(args: argparse.Namespace) -> int:
    from runtime.agent.process_discovery import scan_processes
    from runtime.config.settings import load_settings

    base = args.base or load_settings().proc_base
    result = scan_processes(base)
    result["processes"] = result["processes"][: args.top] if args.top else result["processes"]
    print(json.dumps(result, indent=2))
    return 0


def _cmd_import(args: argparse.Namespace) -> int:
    from runtime.agent.capture_parsers import parse_sclient_output, parse_tap_jsonl
    from runtime.core.collector import collect

    text = open(args.path, encoding="utf-8", errors="replace").read()
    if args.format == "sclient":
        parsed = parse_sclient_output(text)
        session = {
            "sni": args.host or None,
            "negotiated": {
                "cipher_suite": parsed.get("cipher_suite"),
                "negotiated_version": parsed.get("tls_version"),
            },
            "certificate": None,
        }
        payload = collect(sessions=[session], scanner_id="sclient-import-v1.0")
    else:
        sessions = parse_tap_jsonl(args.path)
        payload = collect(sessions=sessions, scanner_id="tap-import-v1.0")
    print(json.dumps(payload, indent=2, default=str))
    return 0


def _cmd_once(args: argparse.Namespace) -> int:
    from runtime.agent.process_discovery import scan_processes
    from runtime.config.settings import load_settings
    from runtime.core.collector import collect
    from runtime.core.submitter import RuntimeSubmitter

    settings = load_settings()
    process_scan = scan_processes(args.base or settings.proc_base)
    payload = collect(process_scan=process_scan)
    if args.submit:
        result = RuntimeSubmitter(api_url=settings.api_url, token=settings.api_token).submit(payload)
        payload["submit"] = result
        print(json.dumps(result, indent=2), file=sys.stderr)
    print(json.dumps({**payload, "processes": None}, indent=2, default=str))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptoscan-runtime", description="Runtime crypto discovery agent")
    sub = parser.add_subparsers(dest="command", required=True)

    tap = sub.add_parser("tap", help="observing TLS forward proxy")
    tap.add_argument("--listen-host", default="0.0.0.0")
    tap.add_argument("--listen-port", type=int, default=8443)
    tap.add_argument("--upstream", required=True, help="host:port of the real TLS endpoint")
    tap.add_argument("--jsonl", default=None, help="session JSONL output file")
    tap.set_defaults(func=_cmd_tap)

    processes = sub.add_parser("processes", help="process-level crypto library scan")
    processes.add_argument("--base", default=None, help="/proc base (default: /proc)")
    processes.add_argument("--top", type=int, default=None, help="limit process rows")
    processes.set_defaults(func=_cmd_processes)

    imp = sub.add_parser("import", help="import existing captures")
    imp.add_argument("path")
    imp.add_argument("--format", choices=["sclient", "jsonl"], default="sclient")
    imp.add_argument("--host", default=None, help="hostname for s_client imports")
    imp.set_defaults(func=_cmd_import)

    once = sub.add_parser("once", help="process scan + submit")
    once.add_argument("--base", default=None)
    once.add_argument("--submit", action="store_true")
    once.set_defaults(func=_cmd_once)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
