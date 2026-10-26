#!/usr/bin/env python3
"""Explicit local OCI candidate capture or pure retained-evidence materialization."""

import argparse
import json
import os
from pathlib import PurePosixPath
import sys

from _bootstrap import bootstrap

bootstrap()

from inventory.oci_evidence import OciRefused, collect_oci, read_public, strict_json
from shared_models.oci_collection import OciEvidence, OciTarget
from shared_models.oci_projection import materialize_oci


def exclusive_output(path, value):
    """Pin no-follow ancestor directories; never overwrite an existing output."""
    p = PurePosixPath(path)
    if not p.is_absolute() or str(p) != path or ".." in p.parts or path.startswith("//"):
        raise ValueError("Canonical absolute output path required")
    fd = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in p.parts[1:-1]:
            child = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        out = os.open(p.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        with os.fdopen(out, "w") as stream:
            json.dump(value.model_dump(mode="json"), stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("collect")
    capture.add_argument("--target", required=True)
    capture.add_argument("--approved-target-sha256", required=True)
    project = commands.add_parser("materialize")
    project.add_argument("--evidence", required=True)
    project.add_argument("--approved-evidence-sha256", required=True)
    for command in (capture, project):
        command.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            raw = read_public(args.target, 65536)
            strict_json(raw)
            target = OciTarget.model_validate_json(raw)
            result = collect_oci(target, args.approved_target_sha256)
            code = 0 if result.status == "COMPLETED" else 2
        else:
            raw = read_public(args.evidence, 4 * 1024 * 1024)
            strict_json(raw)
            evidence = OciEvidence.model_validate_json(raw)
            result = materialize_oci(evidence, args.approved_evidence_sha256)
            code = 0
        exclusive_output(args.output, result)
        print("SCOPED_IMAGE_METADATA" if code == 0 else "RETAINED_IMAGE_GAPS")
        return code
    except (OciRefused, ValueError, OSError, RecursionError):
        # No raw exception, path, image environment, labels or private bytes.
        print("REFUSED_OCI_EVIDENCE", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
