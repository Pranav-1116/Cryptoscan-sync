"""Operator tools. No arbitrary network scan/target/credentials options exist."""

import argparse
import json
from pathlib import Path
from tools.banking_sandbox.common import dump


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("validate")
    s.add_argument("--root", type=Path, required=True)
    s.add_argument("--full-schemas", action="store_true")
    for name in ("scan", "score-static", "compare-facts", "lb-compare", "lb-scan", "drift", "failures"):
        s = sub.add_parser(name)
        s.add_argument("--output", type=Path, required=True)
        if name != "failures":
            s.add_argument("--root", type=Path, required=True)
        if name in ("score-static", "compare-facts", "lb-compare"):
            s.add_argument("--results", type=Path, required=True)
    s = sub.add_parser("serve")
    s.add_argument("--root", type=Path, required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s = sub.add_parser("lb-live")
    s.add_argument("--output", type=Path, required=True)
    s = sub.add_parser("connect")
    s.add_argument("--estate", type=Path, required=True)
    s.add_argument("--output", type=Path, required=True)
    s = sub.add_parser("serve-output")
    s.add_argument("--output", type=Path, required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s = sub.add_parser("live-synthetic")
    s.add_argument("--estate", type=Path, required=True)
    s.add_argument("--output", type=Path, required=True)
    s.add_argument("--port-base", type=int, default=21000)
    s.add_argument("--max-services", type=int, default=20)
    s.add_argument("--duration", type=float, default=12.0)
    s = sub.add_parser("live-daemon")
    s.add_argument("--estate", type=Path, required=True)
    s.add_argument("--port-base", type=int, default=21000)
    s.add_argument("--max-services", type=int, default=20)
    sub.add_parser("modes")
    a = p.parse_args()
    if a.command == "validate":
        from tools.banking_sandbox.validator import integrity

        value = integrity(a.root, a.full_schemas)
    elif a.command == "connect":
        from tools.banking_sandbox.connector.connector import connect

        value = connect(a.estate, a.output)
    elif a.command == "lb-live":
        from tools.banking_sandbox.load_balancers.live import run

        value = run(a.output)
    elif a.command == "lb-scan":
        from tools.banking_sandbox.harness import run_static

        value = run_static(a.root, a.output, mode="lb-config")
    elif a.command == "scan":
        from tools.banking_sandbox.harness import run_static

        value = run_static(a.root, a.output)
    elif a.command == "score-static":
        from tools.banking_sandbox.validator import score_static

        value = score_static(a.root, a.results)
        dump(a.output, value)
    elif a.command == "lb-compare":
        from tools.banking_sandbox.load_balancers.validator import compare

        value = compare(a.root, a.results)
        dump(a.output, value)
    elif a.command == "compare-facts":
        from tools.banking_sandbox.validator import compare_facts

        value = compare_facts(a.root, a.results)
        dump(a.output, value)
    elif a.command == "serve-output":
        from tools.banking_sandbox.connector.dashboard import serve_output

        return serve_output(a.output, a.host, a.port)
    elif a.command == "live-synthetic":
        from tools.banking_sandbox.live_synthetic import run_live

        value = run_live(a.estate, a.output, port_base=a.port_base, max_services=a.max_services, duration=a.duration)
    elif a.command == "live-daemon":
        from tools.banking_sandbox.live_synthetic import run_daemon

        return run_daemon(a.estate, port_base=a.port_base, max_services=a.max_services)
    else:
        from tools.banking_sandbox import operations

        if a.command == "serve":
            return operations.serve(a.root, a.host, a.port)
        if a.command == "drift":
            value = operations.apply_drift(a.root, a.output)
        elif a.command == "failures":
            value = operations.failures(a.output)
        else:
            value = operations.modes()
    print(json.dumps(value, sort_keys=True, indent=2))
    return 2 if isinstance(value, dict) and value.get("failure") else 0


if __name__ == "__main__":
    raise SystemExit(main())
