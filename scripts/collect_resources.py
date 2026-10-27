#!/usr/bin/env python3
"""Read-only Linux traffic/storage capture using one explicit approved scope file."""

import argparse
import sys
from _bootstrap import bootstrap

bootstrap()

from collect_oci_evidence import exclusive_output
from inventory.oci_evidence import read_public, strict_json
from inventory.resource_monitoring import collect_resources
from shared_models.host_collection import digest
from shared_models.resource_monitoring import ResourceAuthorization, ResourceCapture, resource_report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    collect = sub.add_parser("collect")
    collect.add_argument("--authorization", required=True)
    collect.add_argument("--approved-record-sha256", required=True)
    report = sub.add_parser("report")
    report.add_argument("--capture", required=True)
    report.add_argument("--expected-capture-sha256", required=True)
    for command in (collect, report):
        command.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            raw = read_public(args.authorization, 65536)
            strict_json(raw)
            value = collect_resources(ResourceAuthorization.model_validate_json(raw), args.approved_record_sha256)
            exclusive_output(args.output, value)
            print("RESOURCE_CAPTURE_SHA256=" + digest(value))
            return (
                0
                if all(n.status == "MEASURED" for n in value.network)
                and all(s.status == "MEASURED" for s in value.storage)
                else 2
            )
        raw = read_public(args.capture, 131072)
        strict_json(raw)
        capture = ResourceCapture.model_validate_json(raw)
        if digest(capture) != args.expected_capture_sha256:
            raise ValueError("Capture commitment mismatch")
        # Reuse the exclusive no-follow writer; it accepts typed models only.
        from pydantic import RootModel

        exclusive_output(args.output, RootModel[dict](resource_report(capture)))
        print("RETAINED_RESOURCE_REPORT_NOT_ENFORCEMENT")
        return 0
    except (ValueError, OSError, UnicodeError, RecursionError):
        print("REFUSED_RESOURCE_CAPTURE", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
