#!/usr/bin/env python3
"""Approved offline OCI metadata candidate. No registry/daemon/layer access."""

import argparse
from pathlib import Path
import sys
from _bootstrap import bootstrap

bootstrap()
from inventory.qualification_files import read_json, exclusive_public
from inventory.collection import OfflineOciMetadataCollector
from shared_models.collection import TargetSpec
from shared_models.tpm_quote_verification import canonical, sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", type=Path, required=True)
    p.add_argument("--approved-target-sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        target = TargetSpec.model_validate(read_json(args.target))
        if sha(target) != args.approved_target_sha256:
            raise ValueError("Reviewed target changed")
        snapshot = OfflineOciMetadataCollector().collect(target)
        exclusive_public(args.output, canonical(snapshot))
        return 0 if all(r.status == "PARSED" for r in snapshot.receipts) else 2
    except Exception:
        print("OCI_METADATA_REFUSED: scope, source, platform, budget or output; no fallback", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
