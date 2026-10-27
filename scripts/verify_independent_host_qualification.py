#!/usr/bin/env python3
"""Verify actual retained native artifacts + separately signed external reviews.

Missing native evidence/reviewer signatures is a blocker, not skip-to-PASS.
"""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys
from _bootstrap import bootstrap

bootstrap()
from inventory.qualification_files import read_json, read_public, exclusive_public
from shared_models.qualification_acceptance import AcceptancePolicy, EvidenceIndex, SignedReview, verify_acceptance
from shared_models.tpm_quote_verification import canonical


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--policy", type=Path, required=True)
    p.add_argument("--index", type=Path, required=True)
    p.add_argument("--reviews", type=Path, required=True, help="JSON list of externally signed review envelopes")
    p.add_argument(
        "--artifacts", type=Path, required=True, help="Explicit public files named by exact SHA256, no discovery"
    )
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        policy = AcceptancePolicy.model_validate(read_json(args.policy))
        index = EvidenceIndex.model_validate(read_json(args.index))
        values = read_json(args.reviews)
        if not isinstance(values, list) or not 2 <= len(values) <= 20:
            raise ValueError("Bounded separate reviews required")
        reviews = [SignedReview.model_validate(value) for value in values]
        required = set(index.native.values()) | {h for values in index.checks.values() for h in values}
        if len(required) > 256:
            raise ValueError("Artifact count bound")
        artifacts = {}
        total = 0
        for digest in sorted(required):
            data = read_public(args.artifacts / digest, min(2 * 1024 * 1024, 16 * 1024 * 1024 - total))
            total += len(data)
            artifacts[digest] = data
        report = verify_acceptance(policy, index, reviews, artifacts, datetime.now(timezone.utc))
        exclusive_public(args.output, canonical(report))
        return 0
    except Exception:
        print(
            "QUALIFICATION_BLOCKED: missing, changed, expired, failed or untrusted evidence/review; no production enablement",
            file=sys.stderr,
        )
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
