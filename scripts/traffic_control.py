#!/usr/bin/env python3
"""Read-only Linux preflight; optional loopback drill in a disposable namespace ONLY."""

import argparse
import sys
from _bootstrap import bootstrap

bootstrap()
from collect_oci_evidence import exclusive_output
from inventory.oci_evidence import read_public, strict_json
from inventory.linux_traffic_preflight import collect_preflight
from inventory.linux_traffic_drill import run_drill
from shared_models.linux_traffic_control import PreflightSpec, TrafficPreflight, DrillAuthorization, preflight_report
from shared_models.host_collection import digest
from pydantic import RootModel


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "report", "isolated-drill"):
        command = commands.add_parser(name)
        command.add_argument("--input", required=True)
        command.add_argument("--expected-sha256", required=True)
        command.add_argument("--output", required=True)
        if name == "isolated-drill":
            command.add_argument("--acknowledge-disposable-namespace-only", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        raw = read_public(args.input, 65536)
        strict_json(raw)
        if args.command == "preflight":
            value = collect_preflight(PreflightSpec.model_validate_json(raw), args.expected_sha256)
            status = 0 if preflight_report(value)["recorded_checks_complete"] else 2
        elif args.command == "isolated-drill":
            value = run_drill(DrillAuthorization.model_validate_json(raw), args.expected_sha256)
            status = 0 if value.verdict == "APPLIED_AND_ROLLED_BACK_IN_OWNED_NAMESPACE" else 2
        else:
            capture = TrafficPreflight.model_validate_json(raw)
            if digest(capture) != args.expected_sha256:
                raise ValueError("Preflight hash mismatch")
            value = RootModel[dict](preflight_report(capture))
            status = 0
        exclusive_output(args.output, value)
        print("OUTPUT_SHA256=" + digest(value))
        return status
    except (ValueError, OSError, UnicodeError, RecursionError):
        print("REFUSED_LINUX_TRAFFIC_OPERATION", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
