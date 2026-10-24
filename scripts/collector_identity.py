#!/usr/bin/env python3
"""Prepare exact public signing bytes or verify approval-pinned collector proof.

External signer supplies detached Ed25519 signature; no private key arguments.
Approval JSON must be retrieved from the trusted scoped API, not supplied as a
self-authenticating trust anchor. API intake independently uses its stored row.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from _bootstrap import bootstrap

bootstrap()
from shared_models.collector_identity import (
    CollectorIdentityPolicy,
    CollectorAttestation,
    prepare_statement,
    statement_bytes,
    verify_collector,
)
from shared_models.host_collection import HostSnapshot
from shared_models.qualified_export import bounded_json


def read(path, limit):
    with open(path, "rb") as source:
        return bounded_json(source.read(limit + 1), max_bytes=limit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["prepare", "verify"])
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--proof", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        approval = read(args.approval, 131072)
        snapshot = HostSnapshot.model_validate(read(args.snapshot, 1500000))
        payload = approval["payload"]
        policy = CollectorIdentityPolicy.model_validate(payload["collector_identity"])
        # Legacy SQLite API row metadata serializes naive UTC. This is trusted
        # approval-row metadata, not a relaxation of manifest/snapshot clocks.
        earliest = datetime.fromisoformat(approval["created_at"].replace("Z", "+00:00"))
        if earliest.tzinfo is None:
            earliest = earliest.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if payload["manifest_sha256"] != snapshot.manifest_sha256 or now >= snapshot.manifest.expires_at:
            raise ValueError("Scope/expiry mismatch")
        if args.operation == "prepare":
            if args.proof is not None or not earliest <= snapshot.started_at <= snapshot.finished_at <= now:
                raise ValueError("Invalid preparation scope")
            raw = statement_bytes(
                prepare_statement(snapshot, approval["subject_id"], payload["collector_nonce"], policy, now)
            )
        else:
            if args.proof is None:
                raise ValueError("Proof required")
            proof = CollectorAttestation.model_validate(read(args.proof, 8192))
            verdict = verify_collector(
                policy, proof, snapshot, approval["subject_id"], payload["collector_nonce"], earliest, now
            )
            raw = json.dumps(
                {
                    "signature": "PASS",
                    **verdict,
                    "host_identity_attested": False,
                    "production_execution_qualified": False,
                },
                sort_keys=True,
            ).encode()
        with os.fdopen(
            os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600), "wb"
        ) as out:
            out.write(raw)
        return 0
    except (ValueError, OSError, KeyError, TypeError):
        print("Collector identity refused: scope/key/time/signature/output mismatch; no private key handled")
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
