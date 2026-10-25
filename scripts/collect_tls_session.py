#!/usr/bin/env python3
"""Explicit approved single TLS session; no discovery, retry or application traffic."""

import argparse
import os
from pathlib import Path
import sys
from _bootstrap import bootstrap

bootstrap()
from inventory.collection import ApprovedTlsSessionCollector
from inventory.qualification_files import read_json
from shared_models.collection import TargetSpec
from shared_models.tpm_quote_verification import canonical, sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", type=Path, required=True)
    p.add_argument("--approved-target-sha256", required=True)
    p.add_argument("--acknowledge-active-tls", action="store_true", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument(
        "--include-key-share", action="store_true", help="Explicit TLS 1.3 public ServerHello evidence profile"
    )
    p.add_argument(
        "--include-hybrid", action="store_true", help="Explicit actual X25519MLKEM768 profile with optional provider"
    )
    args = p.parse_args()
    try:
        target = TargetSpec.model_validate(read_json(args.target))
        if sha(target) != args.approved_target_sha256:
            raise ValueError("Reviewed target changed")
        collector = (
            ApprovedTlsSessionCollector(include_key_share=args.include_key_share, include_hybrid=args.include_hybrid)
            if args.include_key_share or args.include_hybrid
            else ApprovedTlsSessionCollector()
        )
        collector.validate_scope(target)
        # Reserve the private output before active IO. No path-read/exists race or overwrite.
        with os.fdopen(
            os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600), "wb"
        ) as output:
            snapshot = collector.collect(target)
            output.write(canonical(snapshot))
            output.flush()
            os.fsync(output.fileno())
        return 0 if all(r.status == "PARSED" for r in snapshot.receipts) else 2
    except Exception:
        print("TLS_SESSION_REFUSED: scope, platform, time, budget or output; no retry", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
