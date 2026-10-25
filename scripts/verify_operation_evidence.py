#!/usr/bin/env python3
"""Offline public operation proof; no provider calls, credentials or private keys."""

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from _bootstrap import bootstrap

bootstrap()
from inventory.qualification_files import read_json, ChallengeStore
from shared_models.operation_evidence import OperationApproval, OperationEvidence, verify_operation
from shared_models.tpm_quote_verification import canonical, sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approval", type=Path, required=True)
    p.add_argument("--approved-sha256", required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--state-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    try:
        approval = OperationApproval.model_validate(read_json(a.approval))
        if sha(approval) != a.approved_sha256:
            raise ValueError("Reviewed approval changed")
        evidence = OperationEvidence.model_validate(read_json(a.evidence))
        report = verify_operation(approval, evidence, datetime.now(timezone.utc))
        with ChallengeStore(a.state_dir) as ledger:
            with os.fdopen(
                os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb"
            ) as output:
                # Atomic single-verifier replay fence stores the recoverable public result.
                ledger.write(sha(approval)[:32], ".operation-accepted.json", canonical(report))
                output.write(canonical(report))
                output.flush()
                os.fsync(output.fileno())
        return 0
    except Exception:
        print(
            "OPERATION_EVIDENCE_REFUSED: scope, signature, replay, window or output; no provider operation executed",
            file=sys.stderr,
        )
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
