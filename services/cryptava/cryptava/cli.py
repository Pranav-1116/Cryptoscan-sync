"""``cryptava`` command line.

    cryptava enroll  --server URL --agent-id ID --token TOKEN   # once per host
    cryptava collect [--print] [--output FILE]                  # read the host, send nothing
    cryptava run     [--once | --interval SECONDS]              # collect → sign → send
    cryptava status                                             # identity + last run
    cryptava version
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import sys
import threading
from typing import Any

from cryptava import __version__
from cryptava.agent import client_for, collect, build_payload, enroll, heartbeat, run_once, summarise
from cryptava.config import DEFAULT_STATE_DIR, ConfigError, State, load_config
from cryptava.signing import SigningKey
from cryptava.transport import TransportError

EXIT_OK, EXIT_USAGE, EXIT_TRANSPORT, EXIT_NOT_ENROLLED = 0, 2, 3, 4


def _out(data: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2, sort_keys=True, default=str))
        return
    if isinstance(data, dict) and "planes" in data:
        print(f"host        {data.get('host')}")
        print(f"agent       {data.get('contributor') or '(not enrolled)'}")
        counts = data.get("counts") or {}
        print(f"collected   {counts.get('assets')} assets · {counts.get('evidence')} evidence · "
              f"{counts.get('relationships')} relationships · signed={data.get('signed')}")
        for plane in data["planes"]:
            print(f"  {plane['status']:<9} {plane['plane']:<22} {plane['reason']}")
        return
    print(json.dumps(data, indent=2, sort_keys=True, default=str))


def brief_status(identity: dict[str, Any] | None, last: dict[str, Any] | None) -> str:
    """``CONNECTED <name> · last report 12:00:05Z · HBOM complete …`` — for scripts and humans."""
    if not identity:
        return "NOT ENROLLED  (waiting for enrolment — see `docker logs` of this agent)"
    name = identity.get("name") or identity.get("contributor") or identity.get("agent_id")
    server = identity.get("server") or ""
    if not last:
        return f"ENROLLED      {name} -> {server} · first report not sent yet"
    summary = last.get("summary") or {}
    planes = " ".join(
        f"{str(p.get('plane', '')).split(' ')[0]}:{str(p.get('status', '')).lower()}"
        for p in summary.get("planes") or [])
    when = summary.get("observed_at") or "?"
    if last.get("delivered"):
        signature = ((last.get("response") or {}).get("authenticity") or "").lower()
        verified = " · signature verified" if signature == "valid" else (f" · signature {signature}" if signature else "")
        return f"CONNECTED     {name} -> {server} · last report {when}{verified} · {planes}"
    return f"NOT DELIVERED {name} -> {server} · {last.get('error') or 'unknown error'} (retries every cycle)"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptava", description="CryptoScan host agent (HBOM · SBOM · CBOM · NBOM · VBOM · TechBOM)")
    # global options are accepted before or after the sub-command
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=argparse.SUPPRESS,
                        help="config file (default /etc/cryptava/cryptava.toml or .json)")
    common.add_argument("--state-dir", default=argparse.SUPPRESS,
                        help=f"identity + key directory (default {DEFAULT_STATE_DIR})")
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="machine-readable output")
    for action in common._actions:
        parser._add_action(action)
    parser.set_defaults(config=None, state_dir=None, json=False)
    sub = parser.add_subparsers(dest="command", required=True)
    _add = sub.add_parser

    def add_parser(name: str, **kwargs: Any) -> argparse.ArgumentParser:
        return _add(name, parents=[common], **kwargs)

    sub.add_parser = add_parser  # type: ignore[method-assign]

    e = sub.add_parser("enroll", help="activate this host with a one-time token from the console")
    e.add_argument("--server", help="console URL, e.g. https://cryptoscan.bank.example")
    e.add_argument("--agent-id")
    e.add_argument("--token", help="one-time enrolment token (or CRYPTAVA_ENROLLMENT_TOKEN)")
    e.add_argument("--name", help="agent name, with a provisioning key (e.g. mrdn-prod-dc1-swiftgw01)")
    e.add_argument("--provision-key-env", default="CRYPTAVA_PROVISION_KEY",
                   help="environment variable holding an admin API key for one-step rollout")
    e.add_argument("--force", action="store_true", help="re-enrol even if an identity exists")

    c = sub.add_parser("collect", help="read the host and show what would be sent (sends nothing)")
    c.add_argument("--print", dest="print_payload", action="store_true", help="print the full observation")
    c.add_argument("--output", help="write the full observation to this file")

    r = sub.add_parser("run", help="collect, sign and send — once or on a schedule")
    mode = r.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true")
    mode.add_argument("--interval", type=int, help="seconds between collections (overrides config)")

    st = sub.add_parser("status", help="show this agent's identity and last run")
    st.add_argument("--brief", action="store_true", help="one line: connected or not, and the six BOM results")
    sub.add_parser("version")
    return parser


def _state(args: argparse.Namespace, config: dict[str, Any]) -> State:
    return State(args.state_dir or config.get("state_dir") or os.environ.get("CRYPTAVA_STATE_DIR") or DEFAULT_STATE_DIR)


def _loop(config: dict[str, Any], state: State, interval: int, as_json: bool) -> int:
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    beat = max(15, int(config.get("heartbeat_interval") or 60))
    jitter = max(0, int(config.get("jitter") or 0))
    stop.wait(random.uniform(0, min(jitter, interval)))  # nosec B311 — scheduling jitter, not crypto
    while not stop.is_set():
        try:
            result = run_once(config, state)
            _out({"delivered": result.get("delivered"), "error": result.get("error"),
                  **{k: result["summary"][k] for k in ("observed_at", "state_hash", "counts")},
                  "response": result.get("response")}, True)
        except Exception as exc:  # noqa: BLE001 — the service keeps running and retries
            print(f"cryptava: cycle failed: {exc}", file=sys.stderr, flush=True)
        sys.stdout.flush()
        deadline = interval
        while deadline > 0 and not stop.is_set():
            wait = min(beat, deadline)
            if stop.wait(wait):
                break
            deadline -= wait
            if deadline > 0:
                identity = state.identity()
                if identity:
                    try:
                        heartbeat(client_for(config, identity), identity, healthy=True,
                                  buffered=1 if state.spool_path.exists() else 0)
                    except TransportError as exc:
                        print(f"cryptava: heartbeat failed: {exc}", file=sys.stderr, flush=True)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "version":
        print(f"cryptava {__version__}")
        return EXIT_OK
    try:
        config = load_config(args.config)
    except (ConfigError, ValueError) as exc:
        print(f"cryptava: {exc}", file=sys.stderr)
        return EXIT_USAGE
    state = _state(args, config)

    try:
        if args.command == "enroll":
            if args.server:
                config["server"] = args.server.rstrip("/")
            if state.identity() and not args.force:
                print("cryptava: this host is already enrolled (use --force to re-enrol)", file=sys.stderr)
                return EXIT_USAGE
            token = args.token or os.environ.get("CRYPTAVA_ENROLLMENT_TOKEN")
            identity = enroll(config, state, agent_id=args.agent_id, token=token,
                              name=args.name or config.get("name"),
                              provision_key=os.environ.get(args.provision_key_env))
            _out({"enrolled": True, **identity}, args.json)
            return EXIT_OK

        if args.command == "collect":
            identity = state.identity()
            key = None
            if identity and state.key_path.exists():
                try:
                    key = SigningKey.load(state.key_path)
                except (OSError, ValueError):
                    key = None
            contributor = (identity or {}).get("contributor") or config.get("name")
            ctx = collect(config)
            payload = build_payload(ctx, config, contributor=contributor, key=key)
            if args.output:
                with open(args.output, "w") as handle:
                    json.dump(payload, handle, indent=2, sort_keys=True)
                    handle.write("\n")
            if args.print_payload:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                _out(summarise(ctx, payload), args.json)
            return EXIT_OK

        if args.command == "run":
            if not state.identity():
                print("cryptava: not enrolled — run `cryptava enroll` first", file=sys.stderr)
                return EXIT_NOT_ENROLLED
            interval = args.interval or int(config.get("interval") or 3600)
            if args.once:
                result = run_once(config, state)
                if args.json:
                    _out(result, True)
                else:
                    _out(result["summary"], False)
                    if result.get("delivered"):
                        response = result.get("response") or {}
                        print(f"sent        {response.get('state')} · authenticity={response.get('authenticity')} "
                              f"· run={response.get('run_id')}")
                    else:
                        print(f"NOT SENT    {result.get('error')}")
                return EXIT_OK if result.get("delivered") else EXIT_TRANSPORT
            return _loop(config, state, interval, args.json)

        if args.command == "status":
            identity = state.identity()
            last = None
            try:
                last = json.loads(state.last_run_path.read_text())
            except (OSError, ValueError):
                pass
            if getattr(args, "brief", False):
                print(brief_status(identity, last))
                return EXIT_OK if identity else EXIT_NOT_ENROLLED
            _out({
                "version": __version__,
                "enrolled": bool(identity),
                "identity": {k: v for k, v in (identity or {}).items() if k != "api_key"} or None,
                "key_file": str(state.key_path) if state.key_path.exists() else None,
                "pending_undelivered_observation": state.spool_path.exists(),
                "last_run": last and {"delivered": last.get("delivered"), "error": last.get("error"),
                                      "observed_at": (last.get("summary") or {}).get("observed_at"),
                                      "planes": (last.get("summary") or {}).get("planes"),
                                      "response": last.get("response")},
            }, True)
            return EXIT_OK if identity else EXIT_NOT_ENROLLED
    except TransportError as exc:
        print(f"cryptava: {exc}", file=sys.stderr)
        return EXIT_TRANSPORT
    return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
