#!/usr/bin/env python3
"""Collect exact OCI metadata for a separately authorized offline job handoff."""

import argparse
import sys
from _bootstrap import bootstrap

bootstrap()

from collect_oci_evidence import exclusive_output
from inventory.oci_evidence import read_public, strict_json
from inventory.oci_job_capture import capture_oci_job
from shared_models.oci_collection import OciTarget
from shared_models.oci_intake import OciCaptureBinding


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--binding", required=True)
    parser.add_argument("--approved-target-sha256", required=True)
    parser.add_argument("--approved-binding-sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        target_raw, binding_raw = read_public(args.target, 65536), read_public(args.binding, 65536)
        strict_json(target_raw)
        strict_json(binding_raw)
        target = OciTarget.model_validate_json(target_raw)
        binding = OciCaptureBinding.model_validate_json(binding_raw)
        result = capture_oci_job(target, binding, args.approved_target_sha256, args.approved_binding_sha256)
        exclusive_output(args.output, result)
        print("SCOPED_BOUND_OCI_RETURN" if result.evidence.status == "COMPLETED" else "RETAINED_BOUND_OCI_GAPS")
        return 0 if result.evidence.status == "COMPLETED" else 2
    except (ValueError, OSError, RecursionError):
        print("REFUSED_BOUND_OCI_CAPTURE", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
